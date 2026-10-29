package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"vdxclone/internal/config"
	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// lifecycleService is a fresh-DB service on the fake management host, with
// netplan pointed at an empty temp dir (returned) and every kernel-changing
// hook recording instead of running.
type hostCalls struct{ bonds, vswitches, vlans, linksUp []string }

func lifecycleService(t *testing.T, h *fakeHost) (*Service, string, *hostCalls) {
	t.Helper()
	s, _, _, _ := egressTestService(t)
	s.cfg = &config.Config{}
	s.net = netdrv.New(s.db)
	stubHost(t, h)
	dir := t.TempDir()
	calls := &hostCalls{}
	oldDirs, oldDir := netplanReadDirs, netplanDir
	oldBond, oldVS, oldVlans, oldUppers, oldWait, oldUp := ensureBond, ensureVSwitch, ensureVSwitchVlans, vlanUpperVIDs, mgmtWait, linkUp
	t.Cleanup(func() {
		netplanReadDirs, netplanDir = oldDirs, oldDir
		ensureBond, ensureVSwitch, ensureVSwitchVlans, vlanUpperVIDs, mgmtWait, linkUp = oldBond, oldVS, oldVlans, oldUppers, oldWait, oldUp
	})
	netplanReadDirs, netplanDir = []string{dir}, dir
	mgmtWait = 0
	vlanUpperVIDs = func(string) []int { return nil }
	ensureBond = func(name, mode, hash string, members []string) error {
		calls.bonds = append(calls.bonds, fmt.Sprintf("%s %s %q %s", name, mode, hash, strings.Join(members, ",")))
		h.ifs = append(h.ifs, hostinfo.Iface{Name: name, Type: "bond"})
		for i := range h.ifs {
			if slices.Contains(members, h.ifs[i].Name) {
				h.ifs[i].Master = name
			}
		}
		return nil
	}
	ensureVSwitch = func(bridge, uplink string) error {
		calls.vswitches = append(calls.vswitches, bridge+" "+uplink)
		h.ifs = append(h.ifs, hostinfo.Iface{Name: bridge, Type: "bridge"})
		for i := range h.ifs {
			if uplink != "" && h.ifs[i].Name == uplink {
				h.ifs[i].Master = bridge
			}
		}
		return nil
	}
	ensureVSwitchVlans = func(bridge, uplink string, tagged, self []int) error {
		calls.vlans = append(calls.vlans, fmt.Sprintf("%s %s %v", bridge, uplink, tagged))
		return nil
	}
	linkUp = func(n string) error { calls.linksUp = append(calls.linksUp, n); return nil }
	return s, dir, calls
}

func mustExec(t *testing.T, s *Service, q string, args ...any) int64 {
	t.Helper()
	res, err := s.db.Exec(q, args...)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	id, _ := res.LastInsertId()
	return id
}

const mgmtNetplanYAML = `network:
  version: 2
  renderer: networkd
  ethernets:
    eno1: {dhcp4: no}
    eno2: {dhcp4: no}
  bonds:
    bond0:
      interfaces: [eno1, eno2]
      parameters: {mode: balance-alb}
  bridges:
    vSwitch0:
      interfaces: [bond0]
      addresses: [172.16.0.163/24]
`

// TestDeleteVSwitchInUse: the management vSwitch and any vSwitch something is on
// is refused with the reason (the page shows the same), nothing is deleted;
// a free one is deleted.
func TestDeleteVSwitchInUse(t *testing.T) {
	h := mgmtHost()
	h.ifs = append(h.ifs, hostinfo.Iface{Name: "vxeno7", Type: "physical", Master: "vdsprod"})
	s, dir, _ := lifecycleService(t, h)
	var org int64
	s.db.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&org)
	uid := mustExec(t, s, `INSERT INTO users(username,password_hash) VALUES('u1','x')`)
	reset := func() {
		for _, q := range []string{`DELETE FROM sessions`, `DELETE FROM containers`, `DELETE FROM networks`, `DELETE FROM tenant_uplinks`,
			`DELETE FROM vrouter_legs`, `DELETE FROM vrouters`, `DELETE FROM net_vswitches`, `UPDATE ext_trunks SET iface='vxtest0'`} {
			s.db.Exec(q)
		}
		os.Remove(filepath.Join(dir, "60-prod.yaml"))
		h.ifs = slices.DeleteFunc(h.ifs, func(it hostinfo.Iface) bool { return it.Name == "vdxt0a1b2c3" })
		mustExec(t, s, `INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vSwitch0','vSwitch0','bond0'),('prod','vdsprod','vxeno7')`)
	}
	pg := func() int64 {
		return mustExec(t, s, `INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'lab','bridge','vdsprod',20)`, org)
	}
	cases := []struct {
		use, vs, want string
		set           func()
	}{
		{"management", "vSwitch0", "carries host management", func() {}},
		{"netplan", "prod", "defined in netplan", func() {
			os.WriteFile(filepath.Join(dir, "60-prod.yaml"), []byte("network:\n  bridges:\n    vdsprod: {}\n"), 0o600)
		}},
		{"instance", "prod", `instance(s) on its port groups (web1 (in Trash))`, func() {
			mustExec(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,network_id,deleted_at) VALUES('s1','web1',?,'(install from ISO)','/x',?,datetime('now'))`, uid, pg())
		}},
		{"container", "prod", "container(s) attached (ct1)", func() { mustExec(t, s, `INSERT INTO containers(name,bridge) VALUES('ct1','vdsprod')`) }},
		{"live tap", "prod", "VM/container NICs attached (vdxt0a1b2c3)", func() {
			h.ifs = append(h.ifs, hostinfo.Iface{Name: "vdxt0a1b2c3", Type: "tap", Master: "vdsprod"})
		}},
		{"port group", "prod", "still has port groups (lab)", func() { pg() }},
		{"trunk", "prod", "uplink vxeno7 is a tenant egress trunk", func() { s.db.Exec(`UPDATE ext_trunks SET iface='vxeno7'`) }},
		{"tenant uplink", "prod", `tenant uplink "wan" egresses through vSwitch "prod"`, func() {
			mustExec(t, s, `INSERT INTO tenant_uplinks(org_id,name,mode,egress_bridge) VALUES(?,'wan','access','vdsprod')`, org)
		}},
		{"vRouter", "prod", `vRouter "edge" has a link on vSwitch "prod"`, func() {
			vr := mustExec(t, s, `INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge','netns')`, org)
			mustExec(t, s, `INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,phys_iface,iface_name,cidr) VALUES(?,0,'transit','vr1-wan','vxeno7','eth0','192.0.2.2/30')`, vr)
		}},
	}
	for _, c := range cases {
		reset()
		c.set()
		err := s.DeleteVSwitch(egressAdmin, c.vs, "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want a refusal mentioning %q, got %v", c.use, c.want, err)
		}
		if got := s.VSwitchesInUse(egressAdmin)[c.vs]; got != err.Error() {
			t.Fatalf("%s: the page must show the same reason, got %q", c.use, got)
		}
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM net_vswitches WHERE name=?`, c.vs).Scan(&n)
		if n != 1 {
			t.Fatalf("%s: a refused delete must keep the vSwitch", c.use)
		}
	}

	// Management can't be identified: every vSwitch delete fails closed.
	reset()
	h.defaults = nil
	if err := s.DeleteVSwitch(egressAdmin, "prod", ""); !errors.Is(err, errMgmtUnknown) {
		t.Fatalf("unknown management must fail closed, got %v", err)
	}
	h.defaults = []string{"vSwitch0"}

	reset()
	if err := s.DeleteVSwitch(egressAdmin, "prod", ""); err != nil {
		t.Fatalf("a free vSwitch must delete: %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM net_vswitches WHERE name='prod'`).Scan(&n)
	if n != 0 {
		t.Fatalf("the free vSwitch's record must be gone")
	}
	if err := s.DeleteVSwitch(egressAdmin, "nope", ""); err == nil || !strings.Contains(err.Error(), "unknown vSwitch") {
		t.Fatalf("an unknown vSwitch is an error, got %v", err)
	}
	if err := s.DeleteVSwitch(&Principal{OrgID: org, OrgRole: "owner"}, "prod", ""); err != ErrUnauthorized {
		t.Fatalf("org admins can't delete vSwitches, got %v", err)
	}
}

// TestDeletePortGroupInUse: a port group with instances (Trash included), a
// vRouter leg, the containers of its bridge, or a tenant owner is refused; a
// free one is deleted. A router deleting its own internal network bypasses it.
func TestDeletePortGroupInUse(t *testing.T) {
	s, _, _ := lifecycleService(t, mgmtHost())
	org := egressAdmin.OrgID
	uid := mustExec(t, s, `INSERT INTO users(username,password_hash) VALUES('u1','x')`)
	net := func(name, bridge string, vlan int) netdrv.Network {
		id := mustExec(t, s, `INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,?,'bridge',?,?)`, org, name, bridge, vlan)
		n, _ := s.net.GetNetwork(org, id)
		return n
	}
	cases := []struct {
		use, want string
		set       func() netdrv.Network
	}{
		{"instance", `1 instance(s) use port group "web" (web1)`, func() netdrv.Network {
			n := net("web", "vdsprod", 20)
			mustExec(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,network_id) VALUES('s1','web1',?,'(install from ISO)','/x',?)`, uid, n.ID)
			return n
		}},
		{"trashed instance", `(old1 (in Trash))`, func() netdrv.Network {
			n := net("web", "vdsprod", 20)
			mustExec(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,network_id,deleted_at) VALUES('s2','old1',?,'(install from ISO)','/x',?,datetime('now'))`, uid, n.ID)
			return n
		}},
		{"router leg", `vRouter "edge" has a leg on port group "inside"`, func() netdrv.Network {
			n := net("inside", "vr1-inside", 0)
			vr := mustExec(t, s, `INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge','netns')`, org)
			mustExec(t, s, `INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr) VALUES(?,1,'internal','vr1-inside',?,'eth1','10.1.0.1/24')`, vr, n.ID)
			return n
		}},
		{"router VLAN leg", `vRouter "edge2" has a leg`, func() netdrv.Network {
			n := net("wan", "vdsprod", 30)
			vr := mustExec(t, s, `INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge2','netns')`, org)
			mustExec(t, s, `INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,vlan_id,iface_name,cidr) VALUES(?,1,'uplink','vdsprod',30,'eth1','203.0.113.2/29')`, vr)
			return n
		}},
		{"containers", "container(s) ct1 are on port group", func() netdrv.Network {
			mustExec(t, s, `INSERT INTO containers(name,bridge) VALUES('ct1','vdsprod')`)
			return net("VM Network", "vdsprod", 0)
		}},
		{"tenant vSwitch", `tenant vSwitch "default"'s own network`, func() netdrv.Network {
			n := net("default", "vdxt9", 0)
			mustExec(t, s, `INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'default',?)`, org, n.ID)
			return n
		}},
	}
	for _, c := range cases {
		for _, q := range []string{`DELETE FROM sessions`, `DELETE FROM containers`, `DELETE FROM tenant_networks`, `DELETE FROM vrouter_legs`, `DELETE FROM vrouters`, `DELETE FROM networks`} {
			s.db.Exec(q)
		}
		n := c.set()
		err := s.DeleteNetwork(egressAdmin, n.ID, "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want a refusal mentioning %q, got %v", c.use, c.want, err)
		}
		if got := s.PortGroupsInUse(egressAdmin)[n.ID]; got != err.Error() {
			t.Fatalf("%s: the page must show the same reason, got %q", c.use, got)
		}
		if _, err := s.net.GetNetwork(org, n.ID); err != nil {
			t.Fatalf("%s: a refused delete must keep the port group", c.use)
		}
	}
	// The router deleting its own internal network isn't blocked by its own leg.
	s.db.Exec(`DELETE FROM tenant_networks`)
	s.db.Exec(`DELETE FROM networks`)
	n := net("inside", "vr1-inside", 0)
	vr := mustExec(t, s, `INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge3','netns')`, org)
	mustExec(t, s, `INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr) VALUES(?,1,'internal','vr1-inside',?,'eth1','10.1.0.1/24')`, vr, n.ID)
	if err := s.deleteNetwork(egressAdmin, n.ID, ""); err != nil {
		t.Fatalf("the owner's internal delete must not be blocked: %v", err)
	}
	// A free one deletes; a missing one is an error.
	free := net("spare", "vdsprod", 40)
	if err := s.DeleteNetwork(egressAdmin, free.ID, ""); err != nil {
		t.Fatalf("a free port group must delete: %v", err)
	}
	if err := s.DeleteNetwork(egressAdmin, free.ID, ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("deleting a missing port group is an error, got %v", err)
	}
}

// TestReensureVSwitches: after a "reboot" the vdxd-made team and vSwitch come
// back, netplan's management devices are left alone, a team whose NIC is now
// the storage NIC is not re-created, an uplink that now holds an address isn't
// re-claimed, and every vSwitch gets VLAN filtering with its port groups' VIDs.
func TestReensureVSwitches(t *testing.T) {
	h := mgmtHost()
	h.ifs = append(h.ifs,
		hostinfo.Iface{Name: "vxa", Type: "physical"}, hostinfo.Iface{Name: "vxb", Type: "physical"},
		hostinfo.Iface{Name: "vxc", Type: "physical"}, hostinfo.Iface{Name: "vxst", Type: "physical"},
		hostinfo.Iface{Name: "vxeno9", Type: "physical", Addrs: []string{"10.50.0.2/24"}})
	s, dir, calls := lifecycleService(t, h)
	if err := os.WriteFile(filepath.Join(dir, "90-vdx-vswitch0.yaml"), []byte(mgmtNetplanYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`INSERT INTO settings(key,value) VALUES('storage_iface','vxst')`)
	mustExec(t, s, `INSERT INTO net_bonds(name,mode,members) VALUES('bond0','balance-alb','eno1,eno2'),
		('bond1','lacp/layer2','vxa,vxb'),('bond2','active-backup','vxc,vxst')`)
	mustExec(t, s, `INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vSwitch0','vSwitch0','bond0'),
		('prod','vdsprod','bond1'),('lab','vdslab','vxeno9')`)
	mustExec(t, s, `INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(1,'a','bridge','vdsprod',20),
		(1,'b','bridge','vdsprod',20),(1,'c','bridge','vdsprod',0),(2,'d','bridge','vSwitch0',30)`)

	s.ReensureVSwitches()
	if want := []string{`bond1 lacp "layer2" vxa,vxb`}; !slices.Equal(calls.bonds, want) {
		t.Fatalf("teams re-created: %q, want %q", calls.bonds, want)
	}
	if want := []string{"vdslab ", "vdsprod bond1"}; !slices.Equal(calls.vswitches, want) {
		t.Fatalf("vSwitches re-created: %q, want %q", calls.vswitches, want)
	}
	if want := []string{"vdslab  []", "vdsprod bond1 [20]", "vSwitch0 bond0 [30]"}; !slices.Equal(calls.vlans, want) {
		t.Fatalf("VLAN filtering: %q, want %q", calls.vlans, want)
	}

	// Run again (a vdxd restart, no reboot): nothing is re-created, filtering is
	// re-applied.
	*calls = hostCalls{}
	s.ReensureVSwitches()
	if len(calls.bonds) != 0 || len(calls.vswitches) != 0 || len(calls.vlans) != 3 {
		t.Fatalf("second run must only re-apply filtering: %+v", calls)
	}

	// Management unknown: no NIC is claimed (the lost bridge comes back bare).
	h.ifs = slices.DeleteFunc(h.ifs, func(it hostinfo.Iface) bool { return it.Name == "bond1" || it.Name == "vdsprod" })
	h.defaults = nil
	*calls = hostCalls{}
	s.ReensureVSwitches()
	if len(calls.bonds) != 0 || !slices.Equal(calls.vswitches, []string{"vdsprod "}) {
		t.Fatalf("unknown management must not claim NICs: %+v", calls)
	}

	// Boot links-up: every physical NIC except netplan's (eno1/eno2); the one
	// vdxd doesn't manage (eno3) gets IPv6 autoconfiguration turned off first.
	h.defaults = []string{"vSwitch0"}
	for i := range h.ifs {
		h.ifs[i].State = "down"
	}
	*calls = hostCalls{}
	var quiet []string
	oldQuiet := noIPv6Autoconf
	noIPv6Autoconf = func(n string) error { quiet = append(quiet, n); return nil }
	defer func() { noIPv6Autoconf = oldQuiet }()
	s.EnsurePhysicalLinksUp()
	slices.Sort(calls.linksUp)
	if want := []string{"eno3", "vxa", "vxb", "vxc", "vxeno9", "vxst"}; !slices.Equal(calls.linksUp, want) {
		t.Fatalf("links brought up: %q, want %q", calls.linksUp, want)
	}
	if !slices.Equal(quiet, []string{"eno3"}) {
		t.Fatalf("IPv6 autoconfiguration turned off on %q, want only the unmanaged eno3", quiet)
	}

	// Even with no netplan file to recognise them by, the management bridge and
	// its bond are never re-created with ip link (vdxd didn't make them).
	os.Remove(filepath.Join(dir, "90-vdx-vswitch0.yaml"))
	h.ifs = slices.DeleteFunc(h.ifs, func(it hostinfo.Iface) bool { return it.Name == "bond0" || it.Name == "vSwitch0" })
	*calls = hostCalls{}
	s.ReensureVSwitches()
	for _, c := range append(calls.bonds, calls.vswitches...) {
		if strings.HasPrefix(c, "bond0") || strings.HasPrefix(c, "vSwitch0") {
			t.Fatalf("management devices must never be re-created by vdxd: %+v", calls)
		}
	}
}

// TestEnsureVSwitchVlansFor: a tagged port group on an admin vSwitch re-applies
// its filtering; the uplink is only trunked when it's really the bridge's port;
// non-vSwitch bridges are left alone.
func TestEnsureVSwitchVlansFor(t *testing.T) {
	h := mgmtHost()
	s, _, calls := lifecycleService(t, h)
	mustExec(t, s, `INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vSwitch0','vSwitch0','bond0'),('lab','vdslab','vxgone')`)
	h.ifs = append(h.ifs, hostinfo.Iface{Name: "vdslab", Type: "bridge"})
	mustExec(t, s, `INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(1,'a','bridge','vSwitch0',20)`)
	s.ensureVSwitchVlansFor("vSwitch0")
	s.ensureVSwitchVlansFor("vdslab")
	s.ensureVSwitchVlansFor("vdxt7") // a tenant bridge: not ours to filter here
	if want := []string{"vSwitch0 bond0 [20]", "vdslab  []"}; !slices.Equal(calls.vlans, want) {
		t.Fatalf("filtering: %q, want %q", calls.vlans, want)
	}
}

// TestEnsureDefaultPortGroup: the management bridge is registered with its real
// uplink (never a container veth), the default port group is seeded once and
// never resurrected after an admin deletes it, and the recorded uplink follows
// netplan.
func TestEnsureDefaultPortGroup(t *testing.T) {
	h := mgmtHost()
	h.ifs = append([]hostinfo.Iface{{Name: "aveth1", Type: "veth", Master: "vSwitch0"}}, h.ifs...)
	s, _, _ := lifecycleService(t, h)
	if err := s.EnsureDefaultPortGroup(); err != nil {
		t.Fatal(err)
	}
	v, err := s.net.VSwitchByBridge("vSwitch0")
	if err != nil || v.Uplink != "bond0" {
		t.Fatalf("registered %+v (%v), want uplink bond0", v, err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM networks WHERE bridge='vSwitch0' AND name='VM Network'`).Scan(&n)
	if n != 1 {
		t.Fatalf("the default port group must be seeded")
	}
	s.db.Exec(`DELETE FROM networks`)
	for i := range h.ifs {
		if h.ifs[i].Name == "bond0" {
			h.ifs[i].Name = "bond7"
		}
	}
	if err := s.EnsureDefaultPortGroup(); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM networks`).Scan(&n)
	if n != 0 {
		t.Fatalf("a deleted default port group must stay deleted")
	}
	if v, _ := s.net.VSwitchByBridge("vSwitch0"); v.Uplink != "bond7" {
		t.Fatalf("the recorded uplink must follow the kernel, got %q", v.Uplink)
	}
}

// TestReensureWaitsForMgmt: the boot re-ensure gives a late default route a
// moment before deciding management is unknown.
func TestReensureWaitsForMgmt(t *testing.T) {
	h := mgmtHost()
	h.defaults = nil
	s, _, _ := lifecycleService(t, h)
	mgmtWait = 500 * time.Millisecond
	start := time.Now()
	s.ReensureVSwitches()
	if time.Since(start) < 500*time.Millisecond {
		t.Fatalf("must wait for management to appear")
	}
}
