package netdrv

import (
	"strconv"
	"strings"
	"testing"
)

// Nothing in this file touches a device: only the pure validators/renderers,
// and AddTrunkVlan's refusals (which return before running anything).

func TestVXLANParamsValidate(t *testing.T) {
	ok := VXLANParams{VNI: 100, DstPort: 4789, MTU: 1450, Underlay: "eth0", Local: "10.0.0.1", Peers: []string{"10.0.0.2"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid params refused: %v", err)
	}
	for name, mut := range map[string]func(*VXLANParams){
		"vni 0":            func(v *VXLANParams) { v.VNI = 0 },
		"vni too big":      func(v *VXLANParams) { v.VNI = 16777216 },
		"low port":         func(v *VXLANParams) { v.DstPort = 53 },
		"port too big":     func(v *VXLANParams) { v.DstPort = 70000 },
		"mtu too small":    func(v *VXLANParams) { v.MTU = 500 },
		"mtu too big":      func(v *VXLANParams) { v.MTU = 65000 },
		"underlay newline": func(v *VXLANParams) { v.Underlay = "eth0\nExecStart=/bin/sh" },
		"underlay space":   func(v *VXLANParams) { v.Underlay = "eth0 x" },
		"underlay dash":    func(v *VXLANParams) { v.Underlay = "-batch" },
		"local newline":    func(v *VXLANParams) { v.Local = "10.0.0.1\nExecStart=/bin/sh" },
		"local multicast":  func(v *VXLANParams) { v.Local = "239.1.1.1" },
		"peer injection":   func(v *VXLANParams) { v.Peers = []string{"10.0.0.2\nExecStart=/bin/sh -c id"} },
		"peer loopback":    func(v *VXLANParams) { v.Peers = []string{"127.0.0.1"} },
		"peer family":      func(v *VXLANParams) { v.Peers = []string{"fd00::2"} },
		"peer is local":    func(v *VXLANParams) { v.Peers = []string{"10.0.0.1"} },
	} {
		v := ok
		v.Peers = append([]string{}, ok.Peers...)
		mut(&v)
		if err := v.Validate(); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	many := ok
	many.Peers = nil
	for i := 0; i < MaxVXLANPeers+1; i++ {
		many.Peers = append(many.Peers, "10.1.0."+strconv.Itoa(i+1))
	}
	if err := many.Validate(); err == nil {
		t.Errorf("more than %d peers must be refused", MaxVXLANPeers)
	}
}

func TestParsePeerCSV(t *testing.T) {
	got, err := ParsePeerCSV(" 10.0.0.2, ,10.0.0.3,10.0.0.2,fd00:0::5 ")
	if err != nil || strings.Join(got, ",") != "10.0.0.2,10.0.0.3,fd00::5" {
		t.Fatalf("peers = %v err=%v, want deduped canonical list", got, err)
	}
	if _, err := ParsePeerCSV("10.0.0.2,evil\nExecStart=x"); err == nil {
		t.Fatalf("a non-IP peer must be refused")
	}
}

func TestValidIfName(t *testing.T) {
	for _, n := range []string{"eth0", "bond0", "enp0s31f6", "eth1.20", "br_lan", "vxlan-stor"} {
		if !ValidIfName(n) {
			t.Errorf("%q must be valid", n)
		}
	}
	for _, n := range []string{"", ".", "..", "-x", "a/b", "a b", "a\nb", "abcdefghijklmnop", "eth0%i"} {
		if ValidIfName(n) {
			t.Errorf("%q must be invalid", n)
		}
	}
}

// TestRenderVNINetworkUnit: the boot unit loads the ingress guard first and
// carries the validated values; any value that could add a unit line is refused.
func TestRenderVNINetworkUnit(t *testing.T) {
	unit, err := RenderVNINetworkUnit(7, "eth0", "10.0.0.1", 100, 4789, 1450, []string{"10.0.0.2", "10.0.0.3"}, "10.100.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	pre := strings.Index(unit, "ExecStartPre=-")
	first := strings.Index(unit, "ExecStart=")
	if pre < 0 || first < pre || !strings.Contains(unit, " -f "+VXLANGuardFile+"\n") {
		t.Fatalf("the unit must load the VXLAN guard before bringing the device up:\n%s", unit)
	}
	for _, want := range []string{
		"type vxlan id 100 dev eth0 dstport 4789 local 10.0.0.1",
		"fdb append 00:00:00:00:00:00 dev vdxuvx7 dst 10.0.0.3",
		"/sbin/ip addr add 10.100.0.1/24 dev vdxubr7",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing %q", want)
		}
	}
	for name, args := range map[string][]any{
		"underlay": {"eth0\nExecStart=/bin/sh -c id", "", []string(nil), ""},
		"local":    {"eth0", "10.0.0.1\nExecStart=/bin/sh", []string(nil), ""},
		"peer":     {"eth0", "", []string{"10.0.0.2\nExecStart=/bin/sh"}, ""},
		"gateway":  {"eth0", "", []string(nil), "10.100.0.1/24\nExecStart=/bin/sh"},
	} {
		if _, err := RenderVNINetworkUnit(7, args[0].(string), args[1].(string), 100, 4789, 1450, args[2].([]string), args[3].(string)); err == nil {
			t.Errorf("%s injection must be refused", name)
		}
	}
	if err := EnsureVNINetwork(7, "eth0\nx", "", 100, 4789, 1450, nil, ""); err == nil {
		t.Errorf("EnsureVNINetwork must refuse an invalid underlay before touching the host")
	}
	if err := EnsureOverlay(OverlayConfig{Bridge: "vdxbr0", VNI: 0, Underlay: "eth0"}); err == nil {
		t.Errorf("EnsureOverlay must refuse VNI 0 before touching the host")
	}
}

// TestRenderVXLANGuard: per port, each VNI accepts only its own peers (v4 and
// v6), an open VNI accepts anyone, and everything else on the port is dropped.
func TestRenderVXLANGuard(t *testing.T) {
	rs := RenderVXLANGuard([]VXLANListener{
		{Port: 4789, VNI: 100, Peers: []string{"10.0.0.3", "10.0.0.2", "fd00::2"}},
		{Port: 4789, VNI: 100, Peers: []string{"10.0.0.2"}}, // merged + deduped
		{Port: 4789, VNI: 42, Open: true},
		{Port: 8472, VNI: 5, Peers: []string{"192.0.2.1", "not-an-ip"}},
		{Port: 8472, VNI: 6}, // no peers: drop all
		{Port: 0, VNI: 9, Peers: []string{"10.9.9.9"}},
		{Port: 4789, VNI: 0, Peers: []string{"10.9.9.9"}},
	})
	for _, want := range []string{
		"table inet vdxvxlan {}\ndelete table inet vdxvxlan\ntable inet vdxvxlan {",
		"type filter hook input priority filter - 10; policy accept;",
		"udp dport 4789 @th,96,24 42 accept\n",
		"udp dport 4789 @th,96,24 100 ip saddr { 10.0.0.2, 10.0.0.3 } accept\n",
		"udp dport 4789 @th,96,24 100 ip6 saddr { fd00::2 } accept\n",
		"udp dport 4789 counter drop\n",
		"udp dport 8472 @th,96,24 5 ip saddr { 192.0.2.1 } accept\n",
		"udp dport 8472 counter drop\n",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("guard missing %q\n%s", want, rs)
		}
	}
	for _, bad := range []string{"not-an-ip", "10.9.9.9", "@th,96,24 6 "} {
		if strings.Contains(rs, bad) {
			t.Errorf("guard must not contain %q\n%s", bad, rs)
		}
	}
	if strings.Index(rs, "udp dport 4789 counter drop") < strings.Index(rs, "@th,96,24 100 ip6") {
		t.Errorf("the port's drop must come after its accepts\n%s", rs)
	}
	if empty := RenderVXLANGuard(nil); strings.Contains(empty, "udp") {
		t.Errorf("no listeners = nothing filtered:\n%s", empty)
	}
	// Bound to an interface (a fabric over management): only out of the tunnel.
	wg := RenderVXLANGuard([]VXLANListener{{Port: 4789, VNI: 2000000, Peers: []string{"10.250.0.2"}, Iface: "vxfwg0"},
		{Port: 4789, VNI: 2000001, Peers: []string{"10.250.0.2"}, Iface: "bad name!"}})
	for _, want := range []string{`iifname "vxfwg0" udp dport 4789 @th,96,24 2000000 ip saddr { 10.250.0.2 } accept`,
		"\n    udp dport 4789 @th,96,24 2000001 ip saddr { 10.250.0.2 } accept"} {
		if !strings.Contains(wg, want) {
			t.Errorf("guard missing %q\n%s", want, wg)
		}
	}
}

// TestRenderBondEditPlan: a mode change releases every member, switches mode
// and re-enslaves; member changes add before they remove; a hash change alone
// is one live command.
func TestRenderBondEditPlan(t *testing.T) {
	join := func(p [][]string) string {
		var out []string
		for _, c := range p {
			out = append(out, strings.Join(c, " "))
		}
		return strings.Join(out, "\n")
	}
	cur := BondState{Mode: "balance-alb", Hash: "layer2", Members: []string{"eno1", "eno2"}}
	got := join(RenderBondEditPlan("bond1", cur, BondState{Mode: "802.3ad", Hash: "layer2+3", Members: []string{"eno1", "eno3"}}))
	want := strings.Join([]string{
		"ip link set bond1 down",
		"ip link set eno1 nomaster",
		"ip link set eno2 nomaster",
		"ip link set bond1 type bond mode 802.3ad lacp_rate fast xmit_hash_policy layer2+3",
		"ip addr flush dev eno1", "ip link set eno1 down", "ip link set eno1 master bond1",
		"ip addr flush dev eno3", "ip link set eno3 down", "ip link set eno3 master bond1",
		"ip link set bond1 up",
	}, "\n")
	if got != want {
		t.Fatalf("mode-change plan:\n%s\nwant:\n%s", got, want)
	}
	got = join(RenderBondEditPlan("bond1", cur, BondState{Mode: "balance-alb", Hash: "layer2", Members: []string{"eno2", "eno3"}}))
	want = strings.Join([]string{
		"ip addr flush dev eno3", "ip link set eno3 down", "ip link set eno3 master bond1",
		"ip link set eno1 nomaster",
	}, "\n")
	if got != want {
		t.Fatalf("member plan (add before remove):\n%s\nwant:\n%s", got, want)
	}
	lacp := BondState{Mode: "802.3ad", Hash: "layer3+4", Members: []string{"eno1", "eno2"}}
	got = join(RenderBondEditPlan("bond1", lacp, BondState{Mode: "802.3ad", Hash: "layer2+3", Members: []string{"eno2", "eno1"}}))
	if got != "ip link set bond1 type bond xmit_hash_policy layer2+3" {
		t.Fatalf("hash-only plan = %q", got)
	}
	if p := RenderBondEditPlan("bond1", lacp, lacp); len(p) != 0 {
		t.Fatalf("no change = empty plan, got %v", p)
	}
}

func TestRenderMTUPlan(t *testing.T) {
	join := func(p [][]string) string {
		var out []string
		for _, c := range p {
			out = append(out, c[3])
		}
		return strings.Join(out, ",")
	}
	if got := join(RenderMTUPlan("vdsA", "bond1", []string{"bond1", "vdxt1"}, 1500, 9000)); got != "bond1,vdxt1,vdsA" {
		t.Fatalf("raise order = %s, want adapter + ports before the bridge", got)
	}
	if got := join(RenderMTUPlan("vdsA", "bond1", []string{"bond1", "vdxt1"}, 9000, 1500)); got != "vdsA,bond1,vdxt1" {
		t.Fatalf("lower order = %s, want the bridge first", got)
	}
	if err := SetVSwitchMTU("vdsA", "eth0", 100); err == nil {
		t.Fatalf("an out-of-range MTU must be refused")
	}
	if err := SetVSwitchMTU("vds A", "", 9000); err == nil {
		t.Fatalf("an invalid bridge name must be refused")
	}
}

// TestAddTrunkVlanRange: VLAN 1 (the untagged default) and out-of-range VLANs
// are refused at the sink, before any bridge command runs.
func TestAddTrunkVlanRange(t *testing.T) {
	for _, v := range []int{1, 4095, 9999} {
		if err := AddTrunkVlan("vxnosuchdev0", v); err == nil {
			t.Errorf("VLAN %d must be refused", v)
		}
	}
	if err := AddTrunkVlan("", 10); err != nil {
		t.Errorf("no uplink = nothing to do, got %v", err)
	}
}
