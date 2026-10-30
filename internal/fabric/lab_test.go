package fabric

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vdxclone/internal/routing"
)

// A two-host fabric in network namespaces on one machine (root, FRR installed):
// fxu is the underlay switch, fh1/fh2 are hosts (each runs its own FRR in an
// -N pathspace), vm* are guests. The hosts run exactly the production code:
// Realize, routing.RenderFRR with a Fabric section, DNSMasqConfig, BridgeGuard.
//
//	VX_FABRIC_LAB=1 go test ./internal/fabric -run TestLab -v   (VX_FABRIC_LAB_KEEP=1 leaves it up)
//
// VX_FABRIC_LAB_WG=1 runs the same lab over management: fxu is then the
// management network, each host's TEP sits on the WireGuard device EnsureWG
// builds (wireguard-tools needed), and the tunnel's own filters are checked.

var ex Exec

type nsRunner struct{ ns string }

func (n nsRunner) Run(args ...string) (string, error) {
	return ex.Run(append([]string{"ip", "netns", "exec", n.ns}, args...)...)
}

const (
	labASN    = 65100
	labSecret = "labsecret1"
	labMTU    = 1450
)

var labNS = []string{"fxu", "fh1", "fh2", "vm1", "vm2", "vm3", "vm4", "vm5", "vm6", "vm7", "vm8"}

func labCleanup() {
	for _, h := range []string{"fh1", "fh2"} {
		_ = exec.Command("sh", "-c", "for p in /run/frr/"+h+"/*.pid /run/vxflab-"+h+"/*.pid; do [ -f \"$p\" ] && kill $(cat \"$p\") 2>/dev/null; done; true").Run()
	}
	time.Sleep(300 * time.Millisecond)
	for _, ns := range labNS {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
	for _, h := range []string{"fh1", "fh2"} {
		_ = os.RemoveAll("/etc/frr/" + h)
		_ = os.RemoveAll("/run/frr/" + h)
		_ = os.RemoveAll("/run/vxflab-" + h)
	}
}

func must(t *testing.T, args ...string) string {
	t.Helper()
	out, err := ex.Run(args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func in(ns string, args ...string) []string {
	return append([]string{"ip", "netns", "exec", ns}, args...)
}

// guest is one VM stand-in.
type guest struct {
	ns, host string
	vni      int
	mac, ip  string // ip "" = DHCP
	gw       string
}

func TestLab(t *testing.T) {
	if os.Getenv("VX_FABRIC_LAB") != "1" {
		t.Skip("lab only (root, FRR)")
	}
	labCleanup()
	if os.Getenv("VX_FABRIC_LAB_KEEP") != "1" {
		t.Cleanup(labCleanup)
	}
	for _, ns := range labNS {
		must(t, "ip", "netns", "add", ns)
		must(t, in(ns, "ip", "link", "set", "lo", "up")...)
	}
	must(t, in("fxu", "ip", "link", "add", "ubr", "type", "bridge")...)
	must(t, in("fxu", "ip", "link", "set", "ubr", "up")...)

	teps := map[string]string{"fh1": "10.250.0.1", "fh2": "10.250.0.2"}
	const labFab = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	wgLab := os.Getenv("VX_FABRIC_LAB_WG") == "1"
	mgmt := map[string]string{"fh1": "172.31.0.11", "fh2": "172.31.0.12"}
	wgKey, wgPub := map[string]string{}, map[string]string{}
	labSpec := Spec{UUID: labFab, Name: "lab", ASN: labASN, MTU: labMTU + 50}
	for _, h := range []string{"fh1", "fh2"} {
		x := Host{Node: h, Iface: "u0", TEP: teps[h] + "/24"}
		if wgLab {
			k, err := NewWGKey()
			if err != nil {
				t.Fatal(err)
			}
			wgKey[h] = k
			wgPub[h], _ = WGPublic(k)
			x.Endpoint, x.WGPub = mgmt[h], wgPub[h]
			labSpec.Underlay = UnderlayMgmt
		}
		labSpec.Hosts = append(labSpec.Hosts, x)
	}
	anycast := AnycastMAC("lab-fabric")
	plan := func(h string) HostPlan {
		return HostPlan{TEP: teps[h], AnycastMAC: anycast, GuestMTU: labMTU,
			VRFs: []VRFPlan{{Org: 1, L3VNI: 4000001}, {Org: 2, L3VNI: 4000002}},
			Segments: []SegmentPlan{
				{VNI: 100, Org: 1, Gateway: "10.10.1.1/24"},
				{VNI: 200, Org: 1, Gateway: "10.10.2.1/24"},
				{VNI: 300, Org: 1},                          // L2-only
				{VNI: 400, Org: 2, Gateway: "10.10.1.1/24"}, // org 2 reuses org 1's subnet
			}}
	}
	leases := []DHCPSegment{
		{VNI: 100, Gateway: "10.10.1.1/24", MTU: labMTU, DNS: []string{"10.10.1.1"}},
		{VNI: 200, Gateway: "10.10.2.1/24", MTU: labMTU, Leases: []DHCPLease{{MAC: "52:54:00:00:00:04", IP: "10.10.2.40"}}},
	}

	// The bridge guard: every guest's lease on the routed segments (vm4's is
	// its DHCP lease); 300 is L2-only.
	labGuard := []GuardSegment{
		{VNI: 100, Routed: true, Leases: []DHCPLease{{MAC: "52:54:00:00:00:01", IP: "10.10.1.10"}, {MAC: "52:54:00:00:00:02", IP: "10.10.1.20"}}},
		{VNI: 200, Routed: true, Leases: []DHCPLease{{MAC: "52:54:00:00:00:03", IP: "10.10.2.30"}, {MAC: "52:54:00:00:00:04", IP: "10.10.2.40"}}},
		{VNI: 300},
		{VNI: 400, Routed: true, Leases: []DHCPLease{{MAC: "52:54:00:00:00:07", IP: "10.10.1.10"}, {MAC: "52:54:00:00:00:08", IP: "10.10.1.20"}}},
	}
	for h, tep := range teps {
		r := nsRunner{h}
		must(t, "ip", "link", "add", h+"-u", "type", "veth", "peer", "name", "u0", "netns", h)
		must(t, "ip", "link", "set", h+"-u", "netns", "fxu")
		if wgLab {
			// The management network carries a full tunnel packet: fabric MTU + 60.
			must(t, in("fxu", "ip", "link", "set", h+"-u", "mtu", fmt.Sprint(labMTU+50+WGOverhead))...)
			must(t, in(h, "ip", "link", "set", "u0", "mtu", fmt.Sprint(labMTU+50+WGOverhead))...)
		}
		must(t, in("fxu", "ip", "link", "set", h+"-u", "master", "ubr", "up")...)
		if wgLab {
			must(t, in(h, "ip", "addr", "add", mgmt[h]+"/24", "dev", "u0")...)
			must(t, in(h, "ip", "link", "set", "u0", "up")...)
			li := Intent{Fabrics: []Spec{labSpec}}
			if err := EnsureWG(r, WGConfDir, wgKey[h], li.WGPeers(h), tep+"/24", labMTU+50); err != nil {
				t.Fatalf("%s wireguard: %v", h, err)
			}
			if err := EnsureWG(r, WGConfDir, wgKey[h], li.WGPeers(h), tep+"/24", labMTU+50); err != nil {
				t.Fatalf("%s wireguard again: %v", h, err)
			}
		} else {
			must(t, in(h, "ip", "addr", "add", tep+"/24", "dev", "u0")...)
			must(t, in(h, "ip", "link", "set", "u0", "up")...)
		}
		must(t, in(h, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)

		if err := Realize(r, plan(h)); err != nil {
			t.Fatalf("%s realize: %v", h, err)
		}
		if err := Realize(r, plan(h)); err != nil { // idempotent
			t.Fatalf("%s realize again: %v", h, err)
		}
		guard, err := BridgeGuard(labGuard)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("ip", "netns", "exec", h, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(guard)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s bridge guard: %v %s\n%s", h, err, out, guard)
		}

		// FRR in a pathspace, configured by the production renderer.
		peer := teps["fh1"]
		if h == "fh1" {
			peer = teps["fh2"]
		}
		conf, err := routing.RenderFRR(routing.Config{Hostname: h, Fabric: &routing.Fabric{
			ASN: labASN, TEP: tep, Peers: []string{peer}, Password: labSecret, BFD: true,
			VRFs: []routing.FabricVRF{{Name: VRFName(1), VNI: 4000001}, {Name: VRFName(2), VNI: 4000002}}}})
		if err != nil {
			t.Fatal(err)
		}
		dir := "/etc/frr/" + h
		_ = os.MkdirAll(dir, 0o755)
		_ = os.MkdirAll("/run/frr/"+h, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "frr.conf"), []byte(conf), 0o640)
		_ = os.WriteFile(filepath.Join(dir, "vtysh.conf"), []byte("service integrated-vtysh-config\n"), 0o640)
		_ = os.WriteFile(filepath.Join(dir, "daemons"), []byte("zebra=yes\nbgpd=yes\nbfdd=yes\nstaticd=yes\nvtysh_enable=yes\n"), 0o640)
		must(t, "chown", "-R", "frr:frr", dir, "/run/frr/"+h)
		for _, dmn := range []string{"zebra", "mgmtd", "staticd", "bfdd", "bgpd"} {
			bin := "/usr/lib/frr/" + dmn
			if _, err := os.Stat(bin); err != nil {
				continue
			}
			must(t, "sh", "-c", "exec ip netns exec "+h+" "+bin+" -N "+h+" -d </dev/null >/dev/null 2>&1")
			if dmn == "zebra" {
				time.Sleep(500 * time.Millisecond)
			}
		}
		time.Sleep(500 * time.Millisecond)
		if out, err := ex.Run(in(h, "/usr/lib/frr/frr-reload.py", "-N", h, "--reload", filepath.Join(dir, "frr.conf"))...); err != nil {
			t.Fatalf("%s frr-reload: %v\n%s", h, err, out)
		}

		// Org 1's DHCP inside its VRF.
		run := "/run/vxflab-" + h
		_ = os.MkdirAll(run, 0o755)
		dc, err := DNSMasqConfig(1, leases, run)
		if err != nil {
			t.Fatal(err)
		}
		cp := filepath.Join(run, "dnsmasq-vxfvrf1.conf")
		_ = os.WriteFile(cp, []byte(dc), 0o644)
		must(t, in(h, DNSMasqArgs(1, cp)...)...)
	}

	guests := []guest{
		{"vm1", "fh1", 100, "52:54:00:00:00:01", "10.10.1.10", "10.10.1.1"},
		{"vm2", "fh2", 100, "52:54:00:00:00:02", "10.10.1.20", "10.10.1.1"},
		{"vm3", "fh2", 200, "52:54:00:00:00:03", "10.10.2.30", "10.10.2.1"},
		{"vm4", "fh1", 200, "52:54:00:00:00:04", "", ""}, // DHCP → 10.10.2.40
		{"vm5", "fh1", 300, "52:54:00:00:00:05", "10.30.0.5", ""},
		{"vm6", "fh2", 300, "52:54:00:00:00:06", "10.30.0.6", ""},
		{"vm7", "fh1", 400, "52:54:00:00:00:07", "10.10.1.10", "10.10.1.1"}, // org 2, same IP as vm1
		{"vm8", "fh2", 400, "52:54:00:00:00:08", "10.10.1.20", "10.10.1.1"},
	}
	for _, g := range guests {
		port := g.ns + "-p"
		must(t, "ip", "link", "add", port, "type", "veth", "peer", "name", "eth0", "netns", g.ns)
		must(t, "ip", "link", "set", port, "netns", g.host)
		must(t, in(g.host, "ip", "link", "set", port, "mtu", fmt.Sprint(labMTU), "master", SegBridge(g.vni), "up")...)
		must(t, in(g.ns, "ip", "link", "set", "eth0", "address", g.mac, "mtu", fmt.Sprint(labMTU), "up")...)
		if g.ip != "" {
			must(t, in(g.ns, "ip", "addr", "add", g.ip+"/24", "dev", "eth0")...)
			if g.gw != "" {
				must(t, in(g.ns, "ip", "route", "add", "default", "via", g.gw)...)
			}
		}
	}

	// BGP EVPN up between the TEPs.
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, _ := ex.Run(in("fh1", "vtysh", "-N", "fh1", "-c", "show bgp l2vpn evpn summary")...)
		if strings.Contains(out, "10.250.0.2") && !strings.Contains(out, "Active") && !strings.Contains(out, "Connect") && !strings.Contains(out, "Idle") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("EVPN session never came up:\n%s", out)
		}
		time.Sleep(2 * time.Second)
	}

	ping := func(ns, dst string) error {
		var err error
		for i := 0; i < 15; i++ {
			if _, err = ex.Run(in(ns, "ping", "-c", "1", "-W", "1", dst)...); err == nil {
				return nil
			}
			time.Sleep(time.Second)
		}
		return err
	}
	noPing := func(ns, dst string) bool {
		_, err := ex.Run(in(ns, "ping", "-c", "2", "-W", "1", dst)...)
		return err != nil
	}

	// DHCP: the static lease, router and MTU from this host's own dnsmasq.
	out, err := ex.Run(in("vm4", "busybox", "udhcpc", "-i", "eth0", "-n", "-q", "-t", "5", "-s", "/bin/true", "-O", "mtu")...)
	if err != nil || !strings.Contains(out, "10.10.2.40") {
		t.Fatalf("DHCP on a routed port group: %v\n%s", err, out)
	}
	must(t, in("vm4", "ip", "addr", "add", "10.10.2.40/24", "dev", "eth0")...)
	must(t, in("vm4", "ip", "route", "add", "default", "via", "10.10.2.1")...)

	checks := []struct {
		name, ns, dst string
	}{
		{"anycast gateway is local", "vm1", "10.10.1.1"},
		{"anycast gateway on the other host", "vm2", "10.10.1.1"},
		{"L2 across hosts", "vm1", "10.10.1.20"},
		{"routed across hosts (symmetric IRB)", "vm1", "10.10.2.30"},
		{"routed back", "vm3", "10.10.1.10"},
		{"routed, same host", "vm1", "10.10.2.40"},
		{"DHCP guest routed across hosts", "vm4", "10.10.1.20"},
		{"L2-only across hosts", "vm5", "10.30.0.6"},
		{"org 2, overlapping subnet, across hosts", "vm7", "10.10.1.20"},
	}
	for _, c := range checks {
		if err := ping(c.ns, c.dst); err != nil {
			t.Errorf("%s (%s → %s): %v", c.name, c.ns, c.dst, err)
		}
	}
	// vm7 (org 2, 10.10.1.10) and vm8 reach each other, never org 1's 10.10.2.0/24.
	if !noPing("vm7", "10.10.2.30") {
		t.Errorf("org 2 reached org 1's routed port group")
	}
	// vm8's 10.10.1.20 answered vm7 above; vm1 (org 1) must reach org 1's vm2, not vm8:
	// check by MAC in vm1's neighbour table.
	nb, _ := ex.Run(in("vm1", "ip", "neigh", "show", "10.10.1.20")...)
	if !strings.Contains(nb, "52:54:00:00:00:02") {
		t.Errorf("org 1's 10.10.1.20 resolved to %q, want vm2's MAC", nb)
	}
	// An L2-only segment has no gateway on the host.
	if !noPing("vm5", "10.30.0.1") {
		t.Errorf("something answered as a gateway on the L2-only segment")
	}

	evpn, _ := ex.Run(in("fh1", "vtysh", "-N", "fh1", "-c", "show evpn vni")...)
	for _, v := range []string{"100", "200", "300", "400"} {
		if !strings.Contains(evpn, v) {
			t.Errorf("fh1 EVPN VNIs lack %s:\n%s", v, evpn)
		}
	}
	bfd, _ := ex.Run(in("fh1", "vtysh", "-N", "fh1", "-c", "show bfd peers brief")...)
	t.Logf("fh1 BFD:\n%s", bfd)
	t.Logf("fh1 EVPN:\n%s", evpn)

	// ---- distributed firewall, rendered from an intent describing this lab ----
	pg := func(n int) string { return fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", n) }
	intent := Intent{
		Fabrics: []Spec{labSpec},
		PGs: []PortGroup{
			{UUID: pg(100), Fabric: labFab, Org: 1, Name: "a", VNI: 100, CIDR: "10.10.1.0/24", Gateway: "10.10.1.1"},
			{UUID: pg(200), Fabric: labFab, Org: 1, Name: "b", VNI: 200, CIDR: "10.10.2.0/24", Gateway: "10.10.2.1"},
			{UUID: pg(300), Fabric: labFab, Org: 1, Name: "l2", VNI: 300},
			{UUID: pg(400), Fabric: labFab, Org: 2, Name: "a", VNI: 400, CIDR: "10.10.1.0/24", Gateway: "10.10.1.1"},
		},
		VRFs: []VRF{{Fabric: labFab, Org: 1, L3VNI: 4000001}, {Fabric: labFab, Org: 2, L3VNI: 4000002}},
	}
	loadFW := func() {
		t.Helper()
		if err := intent.Validate(); err != nil {
			t.Fatal(err)
		}
		for h := range teps {
			fw, err := Firewall(&intent, h)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("ip", "netns", "exec", h, "nft", "-f", "-")
			cmd.Stdin = strings.NewReader(fw)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s firewall: %v %s\n%s", h, err, out, fw)
			}
		}
	}
	// A TCP service inside org 1's VRF on fh1, reachable before the firewall.
	listen := exec.Command("ip", "netns", "exec", "fh1", "ip", "vrf", "exec", VRFName(1), "python3", "-c",
		"import socket\ns=socket.socket()\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind(('0.0.0.0',9999))\ns.listen(8)\nwhile True: s.accept()[0].close()")
	if err := listen.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listen.Process.Kill(); _ = listen.Wait() }()
	time.Sleep(time.Second)
	tcp := func(ns, dst string) error {
		_, err := ex.Run(in(ns, "python3", "-c", "import socket,sys\nsocket.create_connection((sys.argv[1],9999),timeout=2)", dst)...)
		return err
	}
	if err := tcp("vm1", "10.10.1.1"); err != nil {
		t.Fatalf("lab precondition: the VRF service isn't reachable without the firewall: %v", err)
	}

	loadFW() // no rules: deny between port groups
	for _, c := range []struct{ name, ns, dst string }{
		{"FW: inside a port group, across hosts", "vm1", "10.10.1.20"},
		{"FW: gateway ping", "vm1", "10.10.1.1"},
		{"FW: org 2 inside its port group", "vm7", "10.10.1.20"},
		{"FW: L2-only", "vm5", "10.30.0.6"},
	} {
		if err := ping(c.ns, c.dst); err != nil {
			t.Errorf("%s (%s → %s): %v", c.name, c.ns, c.dst, err)
		}
	}
	if !noPing("vm1", "10.10.2.30") || !noPing("vm1", "10.10.2.40") {
		t.Errorf("FW: port group a reached b with no rule")
	}
	if tcp("vm1", "10.10.1.1") == nil {
		t.Errorf("FW: a guest reached a host TCP service in its VRF")
	}
	if wgLab {
		wgLabChecks(t, wgPub, ping)
	}
	if out, err := ex.Run(in("vm4", "busybox", "udhcpc", "-i", "eth0", "-n", "-q", "-t", "5", "-s", "/bin/true")...); err != nil ||
		!strings.Contains(out, "10.10.2.40") {
		t.Errorf("FW: DHCP blocked: %v\n%s", err, out)
	}

	intent.Rules = []Rule{{UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Fabric: labFab, Org: 1, Src: pg(100), Dst: pg(200), Proto: "icmp"}}
	loadFW() // a → b ping, one way
	if err := ping("vm1", "10.10.2.30"); err != nil {
		t.Errorf("FW: rule a→b icmp, across hosts: %v", err)
	}
	if err := ping("vm1", "10.10.2.40"); err != nil {
		t.Errorf("FW: rule a→b icmp, same host: %v", err)
	}
	if !noPing("vm3", "10.10.1.10") {
		t.Errorf("FW: one-way rule allowed b → a")
	}
	if !noPing("vm7", "10.10.2.30") {
		t.Errorf("FW: org 2 used org 1's rule")
	}
	intent.Rules[0].Both = true
	loadFW()
	if err := ping("vm3", "10.10.1.10"); err != nil {
		t.Errorf("FW: two-way rule b → a: %v", err)
	}
	if fw, _ := ex.Run(in("fh1", "nft", "list", "chain", "inet", FirewallTable, "org1")...); !strings.Contains(fw, "packets") {
		t.Errorf("FW: no counters:\n%s", fw)
	}

	// ---- egress: the VRF default route via a gateway on a port group survives
	// reconcile re-asserting the kernel's unreachable default (AD 0 vs static) ----
	egressConf := func(egress string) {
		t.Helper()
		conf, err := routing.RenderFRR(routing.Config{Hostname: "fh1", Fabric: &routing.Fabric{
			ASN: labASN, TEP: teps["fh1"], Peers: []string{teps["fh2"]}, Password: labSecret, BFD: true,
			VRFs: []routing.FabricVRF{{Name: VRFName(1), VNI: 4000001, Egress: egress}, {Name: VRFName(2), VNI: 4000002}}}})
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile("/etc/frr/fh1/frr.conf", []byte(conf), 0o640)
		if out, err := ex.Run(in("fh1", "/usr/lib/frr/frr-reload.py", "-N", "fh1", "--reload", "/etc/frr/fh1/frr.conf")...); err != nil {
			t.Fatalf("egress frr-reload: %v\n%s", err, out)
		}
	}
	vrfDefault := func() string {
		out, _ := ex.Run(in("fh1", "ip", "route", "show", "vrf", VRFName(1), "default")...)
		return out
	}
	waitRoute := func(what string, want bool) {
		t.Helper()
		for i := 0; i < 20; i++ {
			// vm2 is on fh2: zebra resolves the egress through the L3VNI (symmetric IRB).
			if strings.Contains(vrfDefault(), "proto static") == want {
				t.Logf("egress: %s", what)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Errorf("egress: %s: VRF default is\n%s", what, vrfDefault())
	}
	egressConf("10.10.1.20")
	waitRoute("installed", true)
	if err := Realize(nsRunner{"fh1"}, plan("fh1")); err != nil { // reconcile re-asserts the unreachable default
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	waitRoute("still installed after Realize", true)
	if err := ping("vm1", "10.10.1.1"); err != nil {
		t.Errorf("egress: %v", err)
	}
	egressConf("")
	waitRoute("removed", false)
	if !strings.Contains(vrfDefault(), "unreachable") {
		t.Errorf("egress: the unreachable default is gone:\n%s", vrfDefault())
	}

	// ---- bridge guard: a guest may only use its leased MAC and address ----
	if err := ping("vm1", "10.10.1.20"); err != nil {
		t.Errorf("guard: leased guest blocked: %v", err)
	}
	must(t, in("vm1", "ip", "addr", "add", "10.10.1.99/24", "dev", "eth0")...)
	if _, err := ex.Run(in("vm1", "ping", "-c", "2", "-W", "1", "-I", "10.10.1.99", "10.10.1.20")...); err == nil {
		t.Errorf("guard: a spoofed source address got through")
	}
	if _, err := ex.Run(in("vm1", "ping", "-c", "2", "-W", "1", "-I", "10.10.1.99", "10.10.1.1")...); err == nil {
		t.Errorf("guard: a spoofed source address reached the anycast gateway (input hook)")
	}
	must(t, in("vm1", "ip", "addr", "del", "10.10.1.99/24", "dev", "eth0")...)
	must(t, in("vm1", "ip", "link", "set", "eth0", "address", "52:54:00:00:00:99")...)
	if !noPing("vm1", "10.10.1.20") {
		t.Errorf("guard: a spoofed MAC got through")
	}
	must(t, in("vm1", "ip", "link", "set", "eth0", "address", "52:54:00:00:00:01")...)
	if err := ping("vm1", "10.10.1.20"); err != nil {
		t.Errorf("guard: guest blocked after restoring its MAC: %v", err)
	}
	// vm5 is on the L2-only segment: any address goes.
	must(t, in("vm5", "ip", "addr", "add", "10.30.0.55/24", "dev", "eth0")...)
	if _, err := ex.Run(in("vm5", "ping", "-c", "1", "-W", "2", "-I", "10.30.0.55", "10.30.0.6")...); err != nil {
		t.Errorf("guard: L2-only segment filtered addresses: %v", err)
	}
	if g, _ := ex.Run(in("fh1", "nft", "list", "chain", "bridge", "vdxfabric", "port")...); !strings.Contains(g, "packets") || strings.Contains(g, "counter packets 0 bytes 0 drop\n    ether type ip ip saddr") {
		t.Logf("guard port chain:\n%s", g)
	}

	// Prune: dropping the L2-only segment removes exactly its two devices.
	p := plan("fh1")
	p.Segments = p.Segments[:2]
	p.Segments = append(p.Segments, SegmentPlan{VNI: 400, Org: 2, Gateway: "10.10.1.1/24"})
	gone, err := Prune(nsRunner{"fh1"}, p)
	if err != nil || strings.Join(gone, ",") != "vxfv300,vxfb300" {
		t.Errorf("prune: %v %v", gone, err)
	}
}

// wgLabChecks covers what only a fabric over management has: live tunnel
// sessions, the CS1 mark on the tunnel's packets, and the input filter — no one
// on the management network may reach the tunnel port, or pass for a TEP.
func wgLabChecks(t *testing.T, pub map[string]string, ping func(ns, dst string) error) {
	t.Helper()
	hs, err := WGHandshakes(nsRunner{"fh1"})
	if err != nil || hs[pub["fh2"]] == 0 {
		t.Errorf("WG: no handshake fh1 → fh2: %v %v", hs, err)
	}
	// The receiving side sees the tunnel's packets marked CS1.
	must(t, "sh", "-c", `ip netns exec fh2 nft -f - <<'E'
table inet vxflabdscp {
  chain in { type filter hook input priority raw; policy accept;
    udp dport 51871 ip dscp cs1 counter
  }
}
E`)
	if err := ping("vm1", "10.10.1.20"); err != nil {
		t.Errorf("WG: overlay ping: %v", err)
	}
	if out, _ := ex.Run(in("fh2", "nft", "list", "table", "inet", "vxflabdscp")...); strings.Contains(out, "counter packets 0 ") || !strings.Contains(out, "counter packets") {
		t.Errorf("WG: tunnel packets not marked CS1:\n%s", out)
	}
	_, _ = ex.Run(in("fh2", "nft", "delete", "table", "inet", "vxflabdscp")...)

	// Someone else on the management network (fxu): the tunnel port is shut to
	// them, and a TEP source arriving outside the tunnel is dropped.
	must(t, in("fxu", "ip", "addr", "add", "172.31.0.99/24", "dev", "ubr")...)
	must(t, in("fxu", "ip", "addr", "add", "10.250.0.2/32", "dev", "ubr")...)
	send := func(src, dst string, port int) {
		_, _ = ex.Run(in("fxu", "python3", "-c", "import socket,sys\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind((sys.argv[1],0))\n[s.sendto(b'x'*64,(sys.argv[2],int(sys.argv[3]))) for _ in range(5)]",
			src, dst, fmt.Sprint(port))...)
	}
	counter := func(match string) string {
		out, _ := ex.Run(in("fh1", "nft", "list", "chain", "inet", FirewallTable, "input")...)
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, match) {
				return l
			}
		}
		return "(no rule " + match + ")"
	}
	send("172.31.0.99", "172.31.0.11", WGPort)
	if l := counter("udp dport 51871 ip saddr != "); !strings.Contains(l, "counter packets 5 ") {
		t.Errorf("WG: the tunnel port took packets from a stranger: %s", l)
	}
	send("10.250.0.2", "172.31.0.11", VXLANPort)
	if l := counter("ip saddr 10.250.0.0/24 iifname"); !strings.Contains(l, "counter packets 5 ") {
		t.Errorf("WG: a spoofed TEP source got in from the management side: %s", l)
	}
	if hs, _ := WGHandshakes(nsRunner{"fh1"}); hs[pub["fh2"]] == 0 {
		t.Errorf("WG: the tunnel dropped")
	}
	if err := ping("vm1", "10.10.1.20"); err != nil {
		t.Errorf("WG: overlay ping after the probes: %v", err)
	}
}
