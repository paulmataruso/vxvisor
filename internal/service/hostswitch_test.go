package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/config"
	"vdxclone/internal/netdrv"
)

// Host switching: port-group / VXLAN / storage-overlay validation, the
// storage-NIC route check, NIC team edits and vSwitch MTU. Every host hook is
// stubbed, and every refusal case is built to fail before anything is realized
// (the VXLAN cases use an underlay that doesn't exist, checked last, as the
// backstop) — nothing here touches a device, nft or systemd.

const noSuchNIC = "vxnosuch0"

func hostSwitchService(t *testing.T) (*Service, int64) {
	t.Helper()
	s, a, _, _ := egressTestService(t)
	s.cfg = &config.Config{}
	s.net = netdrv.New(s.db)
	dir := t.TempDir()
	stubVar(t, &netplanGlob, filepath.Join(dir, "*.yaml"))
	addrs := hostAddrs
	hostAddrs = func() []string { return []string{"10.0.0.1/24", "127.0.0.1/8"} }
	t.Cleanup(func() { hostAddrs = addrs })
	return s, a
}

func stubVar[T any](t *testing.T, v *T, x T) {
	t.Helper()
	old := *v
	*v = x
	t.Cleanup(func() { *v = old })
}

func orgAdmin(org int64) *Principal {
	return &Principal{User: &auth.User{ID: 2, Username: "tenant"}, OrgID: org, OrgRole: "admin"}
}

func wantErr(t *testing.T, what string, err error, sub string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Errorf("%s: want an error mentioning %q, got %v", what, sub, err)
	}
}

func count(t *testing.T, s *Service, q string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// TestCreatePortGroupValidation: the admin form's free text is checked before
// anything is recorded — VLAN 2–4094, a real vSwitch bridge, sane addressing.
func TestCreatePortGroupValidation(t *testing.T) {
	s, a := hostSwitchService(t)
	if _, err := s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vsA','vdsvsA','')`); err != nil {
		t.Fatal(err)
	}
	pg := func(mut func(*netdrv.Network)) netdrv.Network {
		n := netdrv.Network{Name: "Prod", Mode: "bridge", Bridge: "vdsvsA", VLANID: 20}
		mut(&n)
		return n
	}
	before := count(t, s, `SELECT COUNT(*) FROM networks`)
	cases := []struct {
		name   string
		n      netdrv.Network
		routed bool
		want   string
	}{
		{"VLAN 1", pg(func(n *netdrv.Network) { n.VLANID = 1 }), false, "VLAN 1 is the vSwitch's untagged default"},
		{"VLAN 4095", pg(func(n *netdrv.Network) { n.VLANID = 4095 }), false, "out of range"},
		{"negative VLAN", pg(func(n *netdrv.Network) { n.VLANID = -3 }), false, "out of range"},
		{"tenant bridge", pg(func(n *netdrv.Network) { n.Bridge = "vdxt5" }), false, "is not a vSwitch"},
		{"host device", pg(func(n *netdrv.Network) { n.Bridge = "lo" }), false, "is not a vSwitch"},
		{"vSwitch name, not bridge", pg(func(n *netdrv.Network) { n.Bridge = "vsA" }), false, "is not a vSwitch"},
		{"no bridge", pg(func(n *netdrv.Network) { n.Bridge = "" }), false, "pick the vSwitch"},
		{"user with bridge", pg(func(n *netdrv.Network) { n.Mode, n.VLANID = "user", 0 }), false, "doesn't use a vSwitch"},
		{"user with VLAN", pg(func(n *netdrv.Network) { n.Mode, n.Bridge = "user", "" }), false, "doesn't use a vSwitch"},
		{"overlay without cluster", pg(func(n *netdrv.Network) { n.Mode, n.Bridge, n.VLANID = "overlay", "", 0 }), false, "cluster overlay is not turned on"},
		{"unknown type", pg(func(n *netdrv.Network) { n.Mode = "macvtap" }), false, "unknown port group type"},
		{"empty name", pg(func(n *netdrv.Network) { n.Name = "  " }), false, "name of 1–64"},
		{"control char", pg(func(n *netdrv.Network) { n.Name = "a\nb" }), false, "control characters"},
		{"routed non-vxlan", pg(func(n *netdrv.Network) {}), true, "only a VXLAN network can be routed"},
		{"bad CIDR", pg(func(n *netdrv.Network) { n.CIDR = "10.0.0.0/33" }), false, "not an IPv4 CIDR"},
		{"v6 CIDR", pg(func(n *netdrv.Network) { n.CIDR = "fd00::/64" }), false, "not an IPv4 CIDR"},
		{"gateway outside", pg(func(n *netdrv.Network) { n.CIDR, n.Gateway = "10.20.0.0/24", "10.21.0.1" }), false, "not an IPv4 address inside"},
		{"gateway without CIDR", pg(func(n *netdrv.Network) { n.Gateway = "10.20.0.1" }), false, "set the subnet"},
		{"pool one end", pg(func(n *netdrv.Network) { n.CIDR, n.PoolStart = "10.20.0.0/24", "10.20.0.10" }), false, "both ends"},
		{"pool outside", pg(func(n *netdrv.Network) { n.CIDR, n.PoolStart, n.PoolEnd = "10.20.0.0/24", "10.20.0.10", "10.20.1.10" }), false, "must be IPv4 addresses inside"},
		{"pool reversed", pg(func(n *netdrv.Network) { n.CIDR, n.PoolStart, n.PoolEnd = "10.20.0.0/24", "10.20.0.90", "10.20.0.10" }), false, "starts after it ends"},
	}
	for _, c := range cases {
		_, err := s.CreatePortGroup(egressAdmin, c.n, c.routed, "")
		wantErr(t, c.name, err, c.want)
	}
	if _, err := s.CreatePortGroup(orgAdmin(a), pg(func(*netdrv.Network) {}), false, ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("an org admin must not use the instance port-group form, got %v", err)
	}
	// The internal path refuses VLAN 1 too.
	_, err := s.CreateNetwork(egressAdmin, netdrv.Network{Name: "x", Mode: "bridge", Bridge: "vdsvsA", VLANID: 1}, "")
	wantErr(t, "CreateNetwork VLAN 1", err, "VLAN 1")
	if got := count(t, s, `SELECT COUNT(*) FROM networks`); got != before {
		t.Fatalf("refused port groups must record nothing (%d -> %d rows)", before, got)
	}

	// A valid one is recorded, its subnet in network form. (Untagged, so no
	// VLAN is programmed on the vSwitch.)
	id, err := s.CreatePortGroup(egressAdmin, pg(func(n *netdrv.Network) {
		n.VLANID = 0
		n.Name, n.CIDR, n.Gateway, n.PoolStart, n.PoolEnd = " Prod ", "10.20.0.7/24", "10.20.0.1", "10.20.0.10", "10.20.0.90"
	}), false, "")
	if err != nil {
		t.Fatal(err)
	}
	var name, cidr, bridge string
	s.db.QueryRow(`SELECT name,cidr,bridge FROM networks WHERE id=?`, id).Scan(&name, &cidr, &bridge)
	if name != "Prod" || cidr != "10.20.0.0/24" || bridge != "vdsvsA" {
		t.Fatalf("recorded %q %q %q, want Prod 10.20.0.0/24 vdsvsA", name, cidr, bridge)
	}
	if count(t, s, `SELECT COUNT(*) FROM audit_log WHERE action='network.create'`) != 1 {
		t.Fatalf("a created port group must be audited")
	}

	// The cluster overlay type always lands on the cluster bridge, untagged.
	s.cfg.Cluster.Overlay, s.cfg.Cluster.Bridge, s.cfg.Network.Mode = true, "vdxbr0", "bridge"
	_, err = s.CreatePortGroup(egressAdmin, netdrv.Network{Name: "ov", Mode: "overlay", Bridge: "vdsvsA"}, false, "")
	wantErr(t, "overlay on another bridge", err, "always uses the cluster bridge vdxbr0")
	id, err = s.CreatePortGroup(egressAdmin, netdrv.Network{Name: "ov", Mode: "overlay"}, false, "")
	if err != nil {
		t.Fatal(err)
	}
	var br string
	s.db.QueryRow(`SELECT bridge FROM networks WHERE id=?`, id).Scan(&br)
	if br != "vdxbr0" {
		t.Fatalf("overlay port group bridge = %q, want the cluster bridge", br)
	}
}

// TestVXLANPortGroupValidation: every VXLAN field is checked (no unit-file
// injection, sane ranges, a host-unique VNI, a local IP this host holds, an
// underlay that exists) before a row is recorded or a device is built.
func TestVXLANPortGroupValidation(t *testing.T) {
	s, _ := hostSwitchService(t)
	vx := func(mut func(*netdrv.Network)) netdrv.Network {
		n := netdrv.Network{Name: "vx", Mode: "vxlan", VNI: 5000, Underlay: noSuchNIC, VXLANPeers: "10.0.0.2"}
		mut(&n)
		return n
	}
	s.db.Exec(`INSERT INTO storage_overlays(name,vni,underlay_dev,local_ip,overlay_cidr) VALUES('stor',6000,'eth0','10.0.0.1','10.10.0.1/24')`)
	s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vni) VALUES(1,'other','vxlan','',6001)`)
	s.db.Exec(`INSERT INTO net_segments(seg_type,seg_id,org_id,net_id) VALUES('vxlan',6002,1,99)`)
	s.cfg.Cluster.Overlay, s.cfg.Cluster.VNI = true, 6003
	before := count(t, s, `SELECT COUNT(*) FROM networks`)
	cases := []struct {
		name   string
		n      netdrv.Network
		routed bool
		want   string
	}{
		{"underlay injection", vx(func(n *netdrv.Network) { n.Underlay = "eth0\nExecStart=/bin/sh -c id" }), false, "underlay"},
		{"underlay option", vx(func(n *netdrv.Network) { n.Underlay = "-batch" }), false, "underlay"},
		{"local injection", vx(func(n *netdrv.Network) { n.VXLANLocal = "10.0.0.1\nExecStart=/bin/sh" }), false, "local"},
		{"peer injection", vx(func(n *netdrv.Network) { n.VXLANPeers = "10.0.0.2\nExecStart=/bin/sh" }), false, "peer"},
		{"peer hostname", vx(func(n *netdrv.Network) { n.VXLANPeers = "10.0.0.2,evil.example" }), false, "peer"},
		{"VNI 0", vx(func(n *netdrv.Network) { n.VNI = 0 }), false, "VNI"},
		{"VNI too big", vx(func(n *netdrv.Network) { n.VNI = 1 << 24 }), false, "VNI"},
		{"low port", vx(func(n *netdrv.Network) { n.DstPort = 53 }), false, "port"},
		{"tiny MTU", vx(func(n *netdrv.Network) { n.MTU = 100 }), false, "MTU"},
		{"VLAN on vxlan", vx(func(n *netdrv.Network) { n.VLANID = 5 }), false, "has no VLAN"},
		{"VNI of a storage overlay", vx(func(n *netdrv.Network) { n.VNI = 6000 }), false, `storage overlay "stor"`},
		{"VNI of a port group", vx(func(n *netdrv.Network) { n.VNI = 6001 }), false, `port group "other"`},
		{"VNI of a tenant segment", vx(func(n *netdrv.Network) { n.VNI = 6002 }), false, "a tenant network"},
		{"VNI of the cluster overlay", vx(func(n *netdrv.Network) { n.VNI = 6003 }), false, "cluster overlay"},
		{"local not on host", vx(func(n *netdrv.Network) { n.VXLANLocal = "10.9.9.9" }), false, "not an address of this host"},
		{"bad subnet", vx(func(n *netdrv.Network) { n.CIDR = "nope" }), false, "not an IPv4 CIDR"},
		{"routed without subnet", vx(func(n *netdrv.Network) {}), true, "routed VXLAN network needs"},
		{"underlay missing", vx(func(n *netdrv.Network) {}), false, "was not found on this host"},
	}
	for _, c := range cases {
		_, err := s.CreatePortGroup(egressAdmin, c.n, c.routed, "")
		wantErr(t, c.name, err, c.want)
	}
	if got := count(t, s, `SELECT COUNT(*) FROM networks`); got != before {
		t.Fatalf("refused VXLAN networks must record nothing (%d -> %d rows)", before, got)
	}
}

// TestStorageOverlayValidation: an overlay can't take another device's name
// (bringing it up deletes any link of that name) or smuggle values into its
// boot unit, and its VNI must be free.
func TestStorageOverlayValidation(t *testing.T) {
	s, a := hostSwitchService(t)
	s.db.Exec(`INSERT INTO net_bonds(name,mode,members) VALUES('vxteam1','balance-alb','vxe1')`)
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vsA','vdsvsA','vxteam1')`)
	s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vni) VALUES(1,'pg','vxlan','',7001)`)
	type ov struct{ name, dev, local, cidr, peers string }
	base := ov{"vxstor", noSuchNIC, "10.0.0.1", "10.10.0.1/24", "10.0.0.2"}
	cases := []struct {
		what string
		o    ov
		vni  int
		want string
	}{
		{"existing device", ov{"lo", base.dev, base.local, base.cidr, base.peers}, 7000, "already exists on this host"},
		{"reserved prefix", ov{"vdxbr0", base.dev, base.local, base.cidr, base.peers}, 7000, "reserved"},
		{"a team's name", ov{"vxteam1", base.dev, base.local, base.cidr, base.peers}, 7000, "NIC team or vSwitch"},
		{"a vSwitch bridge", ov{"vdsvsA", base.dev, base.local, base.cidr, base.peers}, 7000, "NIC team or vSwitch"},
		{"a vSwitch name", ov{"vsA", base.dev, base.local, base.cidr, base.peers}, 7000, "NIC team or vSwitch"},
		{"bad name", ov{"a b", base.dev, base.local, base.cidr, base.peers}, 7000, "invalid interface name"},
		{"dev injection", ov{base.name, "eth0\nExecStart=/bin/sh", base.local, base.cidr, base.peers}, 7000, "underlay"},
		{"local injection", ov{base.name, base.dev, "10.0.0.1\nExecStart=/bin/sh", base.cidr, base.peers}, 7000, "local"},
		{"cidr injection", ov{base.name, base.dev, base.local, "10.10.0.1/24\nExecStart=/bin/sh", base.peers}, 7000, "overlay"},
		{"peer injection", ov{base.name, base.dev, base.local, base.cidr, "10.0.0.2\nExecStart=/bin/sh"}, 7000, "peer"},
		{"network address", ov{base.name, base.dev, base.local, "10.10.0.0/24", base.peers}, 7000, "must be this host's address"},
		{"VNI of a port group", base, 7001, `port group "pg"`},
		{"local not on host", ov{base.name, base.dev, "10.0.0.9", base.cidr, base.peers}, 7000, "not an address of this host"},
		{"underlay missing", base, 7000, "was not found on this host"},
	}
	for _, c := range cases {
		err := s.AddStorageOverlay(egressAdmin, c.o.name, c.o.dev, c.o.local, c.o.cidr, c.o.peers, c.vni, 0, 0, "")
		wantErr(t, c.what, err, c.want)
	}
	if err := s.AddStorageOverlay(orgAdmin(a), base.name, base.dev, base.local, base.cidr, base.peers, 7000, 0, 0, ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("an org admin must not add a storage overlay, got %v", err)
	}
	if n := count(t, s, `SELECT COUNT(*) FROM storage_overlays`); n != 0 {
		t.Fatalf("refused overlays must record nothing, got %d rows", n)
	}
}

// TestVXLANHostIsolation: VXLAN port groups are fenced off from the host unless
// the admin routes them (created routed, or in the host routing config), and the
// ingress guard lists every VNI with its own peers.
func TestVXLANHostIsolation(t *testing.T) {
	s, _ := hostSwitchService(t)
	mk := func(name, cidr string, vni int, peers string, nat int) int64 {
		id, err := s.net.CreateNetwork(netdrv.Network{OrgID: 1, Name: name, Mode: "vxlan", CIDR: cidr, VNI: vni, VXLANPeers: peers})
		if err != nil {
			t.Fatal(err)
		}
		s.db.Exec(`UPDATE networks SET nat=? WHERE id=?`, nat, id)
		return id
	}
	fenced := mk("fenced", "10.50.0.0/24", 100, "10.0.0.2,10.0.0.3", 0)
	bare := mk("bare", "", 101, "10.0.0.4", 0)
	mk("routed", "10.51.0.0/24", 102, "", 1)
	mk("ospf", "10.60.1.0/24", 103, "10.0.0.5", 0)
	s.db.Exec(`UPDATE routing_config SET config_json=? WHERE id=1`, `{"ospf":{"enabled":true,"networks":[{"cidr":"10.60.0.0/16","area":"0"}]}}`)
	brF, _ := netdrv.VNINetworkNames(fenced)
	brB, _ := netdrv.VNINetworkNames(bare)
	if got, want := strings.Join(s.vxlanIsolatedBridges(), ","), brF+","+brB; got != want {
		t.Fatalf("isolated bridges = %s, want %s (routed + OSPF-advertised left out)", got, want)
	}
	s.db.Exec(`INSERT INTO storage_overlays(name,vni,underlay_dev,local_ip,overlay_cidr,dstport,peers) VALUES('stor',200,'eth0','10.0.0.1','10.10.0.1/24',8472,'10.0.0.9')`)
	s.cfg.Cluster.Overlay, s.cfg.Cluster.VNI, s.cfg.Network.Mode = true, 42, "bridge"
	rs := netdrv.RenderVXLANGuard(s.vxlanListeners())
	for _, want := range []string{
		"udp dport 4789 @th,96,24 100 ip saddr { 10.0.0.2, 10.0.0.3 } accept",
		"udp dport 4789 @th,96,24 101 ip saddr { 10.0.0.4 } accept",
		"udp dport 4789 @th,96,24 42 accept", // the cluster overlay learns its peers
		"udp dport 8472 @th,96,24 200 ip saddr { 10.0.0.9 } accept",
		"udp dport 4789 counter drop",
		"udp dport 8472 counter drop",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("guard missing %q:\n%s", want, rs)
		}
	}
	if strings.Contains(rs, "@th,96,24 102 ") {
		t.Errorf("a VNI with no peers must not be accepted from anyone:\n%s", rs)
	}
}

// TestStorageTargetRoute: the storage-NIC rule checks every address a target
// resolves to and the interface the kernel would actually use to reach it.
func TestStorageTargetRoute(t *testing.T) {
	s, _ := hostSwitchService(t)
	_, _, err := s.guardStorageTarget("10.40.0.9")
	wantErr(t, "no storage iface", err, "no dedicated storage interface")
	s.db.Exec(`INSERT INTO settings(key,value) VALUES('storage_iface','vxstor0')`)
	stubVar(t, &ifaceAddrs, func(name string) []string {
		if name == "vxstor0" {
			return []string{"fe80::1/64", "10.40.0.5/24"}
		}
		return nil
	})
	routes := map[string]string{"10.40.0.9": "vxstor0", "10.40.0.10": "eth0"}
	stubVar(t, &routeDev, func(ip string) (string, error) {
		if d, ok := routes[ip]; ok {
			return d, nil
		}
		return "", errors.New("no route")
	})
	stubVar(t, &lookupHost, func(h string) ([]string, error) {
		switch h {
		case "nas.lan":
			return []string{"10.40.0.9"}, nil
		case "mixed.lan":
			return []string{"10.40.0.9", "192.168.1.9"}, nil
		}
		return nil, errors.New("no such host")
	})
	for _, ok := range []string{"10.40.0.9", "[10.40.0.9]", " nas.lan ", "10.40.0.5"} {
		iface, src, err := s.guardStorageTarget(ok)
		if err != nil || iface != "vxstor0" || src != "10.40.0.5" {
			t.Errorf("%q: got %q %q %v, want vxstor0 10.40.0.5", ok, iface, src, err)
		}
	}
	for _, c := range []struct{ host, want string }{
		{"10.40.0.10", "leaves through eth0, not the storage interface vxstor0"},
		{"10.99.0.1", "not on the storage subnet 10.40.0.0/24"},
		{"mixed.lan", "resolves to 192.168.1.9"},
		{"nx.lan", "can't resolve"},
		{"10.40.0.77", "can't check the route"},
		{"", "address is required"},
	} {
		_, _, err := s.guardStorageTarget(c.host)
		wantErr(t, c.host, err, c.want)
	}
	// Every Ceph monitor and the iSCSI portal host go through the same check —
	// refused here before anything is mounted or discovered.
	err = s.AddCeph(egressAdmin, "ceph1", "10.40.0.9:6789,10.40.0.10:6789", "/", "admin", "x", "", "")
	wantErr(t, "second Ceph monitor via mgmt", err, "leaves through eth0")
	err = s.AddCeph(egressAdmin, "ceph1", "[v2:10.40.0.9:3300,v1:10.99.0.1:6789]", "/", "admin", "x", "", "")
	wantErr(t, "Ceph address vector off-subnet", err, "not on the storage subnet")
	err = s.AddCeph(egressAdmin, "ceph1", " , ", "/", "admin", "x", "", "")
	wantErr(t, "no Ceph monitors", err, "at least one Ceph monitor")
	_, err = s.ISCSIDiscover(egressAdmin, "10.40.0.10:3260")
	wantErr(t, "iSCSI portal via mgmt", err, "leaves through eth0")

	stubVar(t, &ifaceAddrs, func(string) []string { return nil })
	_, _, err = s.guardStorageTarget("10.40.0.9")
	wantErr(t, "storage iface down", err, "no IPv4 address")
}

func TestStorageHost(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.5:3260":     "10.0.0.5",
		"[fd00::5]:3260":    "fd00::5",
		"fd00::5":           "fd00::5",
		"v2:10.0.0.5:3300":  "10.0.0.5",
		"[v2:10.0.0.5:3300": "10.0.0.5",
		"v1:10.0.0.6:6789]": "10.0.0.6",
		" nas.lan ":         "nas.lan",
		"10.0.0.7":          "10.0.0.7",
	} {
		if got := storageHost(in); got != want {
			t.Errorf("storageHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetplanDefines(t *testing.T) {
	_, _ = hostSwitchService(t)
	dir := filepath.Dir(netplanGlob)
	f := filepath.Join(dir, "90-vdx-vswitch0.yaml")
	yaml := `# managed by vdxd
network:
  version: 2
  ethernets:
    eno1: {}
    eno2: {}
  bonds:
    bond0:
      interfaces: [eno1, eno2]
      parameters:
        mode: 802.3ad
  bridges:
    "vSwitch0":
      interfaces: [bond0]
`
	if err := os.WriteFile(f, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		section, name, want string
	}{
		{"bonds", "bond0", f},
		{"bridges", "vSwitch0", f},
		{"bonds", "vSwitch0", ""},
		{"bonds", "eno1", ""},
		{"bonds", "parameters", ""},
		{"bonds", "interfaces", ""},
		{"ethernets", "eno2", f},
	} {
		if got := netplanDefines(c.section, c.name); got != c.want {
			t.Errorf("netplanDefines(%s, %s) = %q, want %q", c.section, c.name, got, c.want)
		}
	}
}

// TestEditBond: a team's members, mode and hash change in place; new members
// must be free NICs; netplan-owned and management teams are refused with a
// pointer to netplan; nothing changes on a refusal.
func TestEditBond(t *testing.T) {
	s, a := hostSwitchService(t)
	state := map[string]netdrv.BondState{
		"vxteam1": {Mode: "balance-alb", Hash: "layer2", Members: []string{"vxe1", "vxe2"}},
	}
	stubVar(t, &teamState, func(name string) (netdrv.BondState, error) {
		if st, ok := state[name]; ok {
			return st, nil
		}
		return netdrv.BondState{}, errors.New("not a bond")
	})
	var applied []netdrv.BondState
	var applyErr error
	stubVar(t, &teamApply, func(name string, cur, want netdrv.BondState) error {
		applied = append(applied, want)
		return applyErr
	})
	s.db.Exec(`INSERT INTO net_bonds(name,mode,members) VALUES('vxteam1','balance-alb','vxe1,vxe2')`)
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vsB','vdsvsB','vxe8')`)
	s.db.Exec(`INSERT INTO settings(key,value) VALUES('storage_iface','vxe9')`)

	for _, c := range []struct {
		what, name, mode string
		members          []string
		want             string
	}{
		{"unknown team", "vxnone", "lacp", []string{"vxe1"}, "unknown NIC team"},
		{"no members", "vxteam1", "lacp", []string{" ", ""}, "at least one NIC"},
		{"bad member", "vxteam1", "lacp", []string{"a b"}, "can't be a member"},
		{"itself", "vxteam1", "lacp", []string{"vxteam1"}, "can't be a member"},
		{"bad mode", "vxteam1", "roundrobin", []string{"vxe1"}, "unknown bond mode"},
		{"storage NIC", "vxteam1", "balance-alb", []string{"vxe1", "vxe9"}, "storage interface"},
		{"another vSwitch's adapter", "vxteam1", "balance-alb", []string{"vxe1", "vxe8"}, `uplink of vSwitch "vsB"`},
	} {
		err := s.EditBond(egressAdmin, c.name, c.mode, "layer3+4", c.members, "")
		wantErr(t, c.what, err, c.want)
	}
	if err := s.EditBond(orgAdmin(a), "vxteam1", "lacp", "", []string{"vxe1"}, ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("an org admin must not edit a team, got %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("refusals must not touch the team, applied %v", applied)
	}

	// No change = nothing applied (hash is ignored by a non-hashing mode).
	if err := s.EditBond(egressAdmin, "vxteam1", "balance-alb", "layer3+4", []string{"vxe2", "vxe1"}, ""); err != nil || len(applied) != 0 {
		t.Fatalf("an unchanged team must be a no-op: err=%v applied=%v", err, applied)
	}

	// The driver failing leaves the record alone.
	applyErr = errors.New("boom")
	wantErr(t, "apply failure", s.EditBond(egressAdmin, "vxteam1", "lacp", "layer2+3", []string{"vxe1", "vxe3"}, ""), "boom")
	if b, _ := s.net.BondByName("vxteam1"); b.Mode != "balance-alb" {
		t.Fatalf("a failed edit must not change the record, mode=%q", b.Mode)
	}
	applyErr, applied = nil, nil

	if err := s.EditBond(egressAdmin, "vxteam1", "lacp", "layer2+3", []string{"vxe1", "vxe3", "vxe1"}, ""); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Mode != "802.3ad" || applied[0].Hash != "layer2+3" || strings.Join(applied[0].Members, ",") != "vxe1,vxe3" {
		t.Fatalf("applied %+v, want 802.3ad layer2+3 vxe1,vxe3", applied)
	}
	b, _ := s.net.BondByName("vxteam1")
	if b.Mode != "lacp/layer2+3" || strings.Join(b.Members, ",") != "vxe1,vxe3" {
		t.Fatalf("recorded %q %v, want lacp/layer2+3 [vxe1 vxe3]", b.Mode, b.Members)
	}
	if count(t, s, `SELECT COUNT(*) FROM audit_log WHERE action='bond.edit' AND target_id='vxteam1'`) != 1 {
		t.Fatalf("an edit must be audited")
	}

	// The Edit-team modal's view of it, live and from the record.
	state["vxteam1"] = netdrv.BondState{Mode: "802.3ad", Hash: "layer2+3", Members: []string{"vxe1", "vxe3"}}
	s.db.Exec(`INSERT INTO net_bonds(name,mode,members) VALUES('vxteam2','etherchannel/layer2','vxe5,vxe6')`)
	d := s.TeamDetails(egressAdmin)
	if got := d["vxteam1"]; got.Mode != "lacp" || got.Hash != "layer2+3" || got.Locked != "" {
		t.Errorf("vxteam1 detail = %+v", got)
	}
	if got := d["vxteam2"]; got.Mode != "etherchannel" || got.Hash != "layer2" || strings.Join(got.Members, ",") != "vxe5,vxe6" {
		t.Errorf("vxteam2 detail (from the record) = %+v", got)
	}
	if len(s.TeamDetails(orgAdmin(a))) != 0 {
		t.Errorf("an org admin must see no team details")
	}

	// A team the host's netplan defines is refused with the file to edit.
	f := filepath.Join(filepath.Dir(netplanGlob), "60-teams.yaml")
	os.WriteFile(f, []byte("network:\n  bonds:\n    vxteam1:\n      interfaces: [vxe1]\n"), 0o644)
	applied = nil
	err := s.EditBond(egressAdmin, "vxteam1", "active-backup", "", []string{"vxe1"}, "")
	wantErr(t, "netplan team", err, f)
	wantErr(t, "netplan team", err, "netplan apply")
	if len(applied) != 0 || s.TeamDetails(egressAdmin)["vxteam1"].Locked == "" {
		t.Fatalf("a netplan team must be locked and untouched")
	}
}

// TestEditBondMgmt: the management team is never edited live. Needs a loopback
// address to stand in for the admin listener.
func TestEditBondMgmt(t *testing.T) {
	s, _ := hostSwitchService(t)
	s.cfg.Server.Addr = "127.0.0.1:8766"
	mgmt := s.mgmtIface()
	if mgmt == "" {
		t.Skip("no interface holds 127.0.0.1 here")
	}
	stubVar(t, &teamApply, func(string, netdrv.BondState, netdrv.BondState) error {
		t.Fatalf("the management team must never be applied")
		return nil
	})
	s.db.Exec(`INSERT INTO net_bonds(name,mode,members) VALUES('vxmgmt0','lacp','vxe1,vxe2')`)
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vSwitch0',?,'vxmgmt0')`, mgmt)
	err := s.EditBond(egressAdmin, "vxmgmt0", "lacp", "", []string{"vxe1"}, "")
	wantErr(t, "mgmt team", err, "carries host management")
	wantErr(t, "mgmt team", err, "netplan try")
	err = s.SetVSwitchMTU(egressAdmin, "vSwitch0", 9000, "")
	wantErr(t, "mgmt vSwitch MTU", err, "carries host management")
}

func TestSetVSwitchMTU(t *testing.T) {
	s, a := hostSwitchService(t)
	type call struct {
		bridge, uplink string
		mtu            int
	}
	var calls []call
	var applyErr error
	stubVar(t, &mtuApply, func(bridge, uplink string, mtu int) error {
		calls = append(calls, call{bridge, uplink, mtu})
		return applyErr
	})
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vsA','vdsvsA','vxe1')`)
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vsN','vdsvsN','vxe2')`)
	os.WriteFile(filepath.Join(filepath.Dir(netplanGlob), "50-br.yaml"), []byte("network:\n  bridges:\n    vdsvsN:\n      interfaces: [vxe2]\n"), 0o644)

	for _, c := range []struct {
		what, name string
		mtu        int
		want       string
	}{
		{"too small", "vsA", 1000, "out of range"},
		{"too big", "vsA", 9217, "out of range"},
		{"unknown", "nope", 9000, "unknown vSwitch"},
		{"netplan bridge", "vsN", 9000, "netplan apply"},
	} {
		wantErr(t, c.what, s.SetVSwitchMTU(egressAdmin, c.name, c.mtu, ""), c.want)
	}
	if err := s.SetVSwitchMTU(orgAdmin(a), "vsA", 9000, ""); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("an org admin must not set a vSwitch MTU, got %v", err)
	}
	applyErr = errors.New("boom")
	wantErr(t, "apply failure", s.SetVSwitchMTU(egressAdmin, "vsA", 9000, ""), "boom")
	if s.VSwitchMTUs(egressAdmin)["vsA"] != 0 {
		t.Fatalf("a failed MTU change must not be recorded")
	}
	applyErr, calls = nil, nil
	if err := s.SetVSwitchMTU(egressAdmin, "vsA", 9000, ""); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != (call{"vdsvsA", "vxe1", 9000}) {
		t.Fatalf("applied %+v, want the bridge + its physical adapter at 9000", calls)
	}
	if s.VSwitchMTUs(egressAdmin)["vsA"] != 9000 || len(s.VSwitchMTUs(orgAdmin(a))) != 0 {
		t.Fatalf("recorded MTUs = %v", s.VSwitchMTUs(egressAdmin))
	}
	if count(t, s, `SELECT COUNT(*) FROM audit_log WHERE action='vswitch.mtu'`) != 1 {
		t.Fatalf("an MTU change must be audited")
	}
}
