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

	for h, tep := range teps {
		r := nsRunner{h}
		must(t, "ip", "link", "add", h+"-u", "type", "veth", "peer", "name", "u0", "netns", h)
		must(t, "ip", "link", "set", h+"-u", "netns", "fxu")
		must(t, in("fxu", "ip", "link", "set", h+"-u", "master", "ubr", "up")...)
		must(t, in(h, "ip", "addr", "add", tep+"/24", "dev", "u0")...)
		must(t, in(h, "ip", "link", "set", "u0", "up")...)
		must(t, in(h, "sysctl", "-qw", "net.ipv4.ip_forward=1")...)

		if err := Realize(r, plan(h)); err != nil {
			t.Fatalf("%s realize: %v", h, err)
		}
		if err := Realize(r, plan(h)); err != nil { // idempotent
			t.Fatalf("%s realize again: %v", h, err)
		}
		cmd := exec.Command("ip", "netns", "exec", h, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(BridgeGuard())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s bridge guard: %v %s", h, err, out)
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

	// Prune: dropping the L2-only segment removes exactly its two devices.
	p := plan("fh1")
	p.Segments = p.Segments[:2]
	p.Segments = append(p.Segments, SegmentPlan{VNI: 400, Org: 2, Gateway: "10.10.1.1/24"})
	gone, err := Prune(nsRunner{"fh1"}, p)
	if err != nil || strings.Join(gone, ",") != "vxfv300,vxfb300" {
		t.Errorf("prune: %v %v", gone, err)
	}
}
