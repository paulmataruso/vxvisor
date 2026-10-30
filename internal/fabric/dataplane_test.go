package fabric

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// fake records commands; "ip link show dev X" succeeds only for devices it has
// seen created (or listed in have), and "ip -o link show" lists them.
type fake struct {
	cmds []string
	have map[string]bool
}

func newFake(have ...string) *fake {
	f := &fake{have: map[string]bool{}}
	for _, h := range have {
		f.have[h] = true
	}
	return f
}

func (f *fake) Run(args ...string) (string, error) {
	c := strings.Join(args, " ")
	f.cmds = append(f.cmds, c)
	switch {
	case strings.HasPrefix(c, "ip link show dev "):
		if !f.have[args[4]] {
			return "", errors.New("does not exist")
		}
	case strings.HasPrefix(c, "ip link add "):
		f.have[args[3]] = true
	case strings.HasPrefix(c, "ip link del "):
		delete(f.have, args[3])
	case c == "ip -o link show":
		var b strings.Builder
		i := 1
		for n := range f.have {
			b.WriteString(strconv.Itoa(i) + ": " + n + "@if9: <UP> mtu 1500\n")
			i++
		}
		return b.String(), nil
	}
	return "", nil
}

func (f *fake) ran(sub string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func testPlan() HostPlan {
	return HostPlan{TEP: "10.250.0.1", AnycastMAC: AnycastMAC("f1"), GuestMTU: 1450,
		VRFs: []VRFPlan{{Org: 7, L3VNI: 4000007}},
		Segments: []SegmentPlan{
			{VNI: 100, Org: 7, Gateway: "10.10.1.1/24"},
			{VNI: 300, Org: 7},
		}}
}

func TestRealizeCommands(t *testing.T) {
	f := newFake()
	if err := Realize(f, testPlan()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip link add vxfvrf7 type vrf table 4000007",
		"ip route replace unreachable default metric 4278198272 vrf vxfvrf7",
		"ip link add vxfr4000007 type bridge stp_state 0 vlan_filtering 0 mcast_snooping 0",
		"ip link set vxfr4000007 address " + RouterMAC("10.250.0.1"),
		"ip link add vxfl4000007 type vxlan id 4000007 local 10.250.0.1 dstport 4789 nolearning",
		"bridge link set dev vxfl4000007 learning off neigh_suppress on",
		"ip link set vxfb100 master vxfvrf7",
		"ip link set vxfb100 address " + AnycastMAC("f1"),
		"net.ipv4.conf.vxfb100.arp_accept=1",
		"ip addr add 10.10.1.1/24 dev vxfb100",
		"ip link add vxfv100 type vxlan id 100 local 10.250.0.1 dstport 4789 nolearning",
		"ip link set vxfb300 nomaster",
		"net.ipv4.conf.vxfb300.forwarding=0",
		"ip link set vxfv300 mtu 1450",
	} {
		if !f.ran(want) {
			t.Errorf("Realize didn't run %q", want)
		}
	}
	if f.ran("ip link set vxfb300 master") || f.ran("set vxfb300 address") {
		t.Errorf("L2-only segment was routed")
	}
	// A second run adds nothing.
	g := &fake{have: f.have}
	if err := Realize(g, testPlan()); err != nil {
		t.Fatal(err)
	}
	if g.ran("ip link add ") {
		t.Errorf("second Realize created devices again")
	}
}

func TestRouterMACStableAndUnique(t *testing.T) {
	a, b := RouterMAC("10.250.0.1"), RouterMAC("10.250.0.2")
	if a == b || a != RouterMAC("10.250.0.1") || !strings.HasPrefix(a, "02:") {
		t.Fatalf("router MACs %s %s", a, b)
	}
	if AnycastMAC("f1") == AnycastMAC("f2") || AnycastMAC("f1") == a {
		t.Fatalf("anycast MAC not per fabric")
	}
}

func TestPlanValidate(t *testing.T) {
	bad := map[string]func(*HostPlan){
		"TEP":               func(p *HostPlan) { p.TEP = "10.250.0.1; reboot" },
		"v6 TEP":            func(p *HostPlan) { p.TEP = "fd00::1" },
		"MAC":               func(p *HostPlan) { p.AnycastMAC = "02:00:00:00:00" },
		"MTU":               func(p *HostPlan) { p.GuestMTU = 576 },
		"VRF twice":         func(p *HostPlan) { p.VRFs = append(p.VRFs, VRFPlan{Org: 7, L3VNI: 4000008}) },
		"L3VNI reused":      func(p *HostPlan) { p.Segments = append(p.Segments, SegmentPlan{VNI: 4000007}) },
		"VNI range":         func(p *HostPlan) { p.Segments[1].VNI = 1 << 24 },
		"gateway network":   func(p *HostPlan) { p.Segments[0].Gateway = "10.10.1.0/24" },
		"gateway no prefix": func(p *HostPlan) { p.Segments[0].Gateway = "10.10.1.1" },
		"routed, no VRF":    func(p *HostPlan) { p.Segments[0].Org = 8 },
	}
	for name, mut := range bad {
		p := testPlan()
		mut(&p)
		if err := Realize(newFake(), p); err == nil {
			t.Errorf("%s: realized", name)
		}
	}
}

func TestPruneOnlyFabricDevices(t *testing.T) {
	f := newFake("vxfv100", "vxfb100", "vxfv300", "vxfb300", "vxfvrf9", "vxfr4000009", "vxfl4000009",
		"vxfvrf7", "vxfr4000007", "vxfl4000007",
		"vxlan100", "vxfoo", "vxfb12a", "vdxt5", "vSwitch0", "bond0")
	gone, err := Prune(f, testPlan())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for i, n := range gone {
		got[n] = i
	}
	// testPlan keeps 100 and 300; only the org-9 VRF stack is stale.
	if len(gone) != 3 || got["vxfvrf9"] != 2 {
		t.Fatalf("pruned %v, want the org-9 VRF stack with the VRF last", gone)
	}
	for _, keep := range []string{"vxlan100", "vxfoo", "vxfb12a", "vdxt5", "vSwitch0", "bond0", "vxfb100", "vxfvrf7"} {
		if !f.have[keep] {
			t.Errorf("pruned %s", keep)
		}
	}
	if !IsFabricDevice("vxfvrf12") || IsFabricDevice("vxfvrf") || IsFabricDevice("vxlan4") || IsFabricDevice("vxfx1") {
		t.Errorf("IsFabricDevice shape")
	}
}

func TestDNSMasqConfig(t *testing.T) {
	conf, err := DNSMasqConfig(7, []DHCPSegment{{VNI: 100, Gateway: "10.10.1.1/24", MTU: 1450, DNS: []string{"1.1.1.1"},
		Leases: []DHCPLease{{MAC: "52:54:00:00:00:01", IP: "10.10.1.10"}}}}, "/run/vdxfabric")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"port=0\n", "bind-interfaces\n", "interface=vxfb100\n",
		"dhcp-range=set:vxfb100,10.10.1.0,static,255.255.255.0,12h\n", "option:router,10.10.1.1\n",
		"option:mtu,1450\n", "option:dns-server,1.1.1.1\n", "dhcp-host=52:54:00:00:00:01,set:vxfb100,10.10.1.10\n",
		"pid-file=/run/vdxfabric/dnsmasq-vxfvrf7.pid\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q:\n%s", want, conf)
		}
	}
	for name, s := range map[string]DHCPSegment{
		"lease outside":    {VNI: 1, Gateway: "10.10.1.1/24", MTU: 1450, Leases: []DHCPLease{{MAC: "52:54:00:00:00:01", IP: "10.9.9.9"}}},
		"lease is gateway": {VNI: 1, Gateway: "10.10.1.1/24", MTU: 1450, Leases: []DHCPLease{{MAC: "52:54:00:00:00:01", IP: "10.10.1.1"}}},
		"injected MAC":     {VNI: 1, Gateway: "10.10.1.1/24", MTU: 1450, Leases: []DHCPLease{{MAC: "52:54:00:00:00:01\ndhcp-script=/x", IP: "10.10.1.5"}}},
		"injected DNS":     {VNI: 1, Gateway: "10.10.1.1/24", MTU: 1450, DNS: []string{"1.1.1.1\nconf-file=/x"}},
		"bad gateway":      {VNI: 1, Gateway: "nope", MTU: 1450},
		"MTU out of range": {VNI: 1, Gateway: "10.10.1.1/24", MTU: 100},
	} {
		if _, err := DNSMasqConfig(7, []DHCPSegment{s}, "/run/x"); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if a := strings.Join(DNSMasqArgs(7, "/run/x.conf"), " "); a != "ip vrf exec vxfvrf7 dnsmasq --conf-file=/run/x.conf" {
		t.Errorf("args %q", a)
	}
}
