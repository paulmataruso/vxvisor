package fabric

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

const (
	fabA = "11111111-1111-4111-8111-111111111111"
	pgW  = "22222222-2222-4222-8222-222222222222"
	pgD  = "33333333-3333-4333-8333-333333333333"
	pgL2 = "44444444-4444-4444-8444-444444444444"
	pgO2 = "55555555-5555-4555-8555-555555555555"
	rul1 = "66666666-6666-4666-8666-666666666666"
)

func sample() Intent {
	in := Intent{
		Fabrics: []Spec{{UUID: fabA, Name: "prod", ASN: 65100, MTU: 1600, Hosts: []Host{
			{Node: "h1", Iface: "eno3", TEP: "10.250.0.1/24"},
			{Node: "h2", Iface: "eno3", VLAN: 30, TEP: "10.250.0.2/24"},
		}}},
		PGs: []PortGroup{
			{UUID: pgW, Fabric: fabA, Org: 1, Name: "web", VNI: 2000000, CIDR: "10.10.1.0/24", Gateway: "10.10.1.1"},
			{UUID: pgD, Fabric: fabA, Org: 1, Name: "db", VNI: 2000001, CIDR: "10.10.2.0/24", Gateway: "10.10.2.1",
				PoolStart: "10.10.2.100", PoolEnd: "10.10.2.101", Span: []string{"h2"}},
			{UUID: pgL2, Fabric: fabA, Org: 1, Name: "appliance", VNI: 2000002},
			// Another org may reuse a subnet: its own VRF.
			{UUID: pgO2, Fabric: fabA, Org: 2, Name: "web", VNI: 2000003, CIDR: "10.10.1.0/24", Gateway: "10.10.1.1"},
		},
	}
	if err := in.Normalize(nil); err != nil {
		panic(err)
	}
	return in
}

func TestIntentValid(t *testing.T) {
	in := sample()
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(in.VRFs) != 2 || in.VRFs[0].L3VNI != L3VNIMin || in.VRFs[1].L3VNI != L3VNIMin+1 {
		t.Fatalf("VRFs %+v", in.VRFs)
	}
	// Normalize is stable.
	again := in.Clone()
	_ = again.Normalize(nil)
	if fmt.Sprint(again.VRFs) != fmt.Sprint(in.VRFs) {
		t.Fatalf("Normalize moved VRFs: %+v", again.VRFs)
	}
}

func TestIntentRejects(t *testing.T) {
	for name, mut := range map[string]func(*Intent){
		"host in two fabrics": func(in *Intent) {
			in.Fabrics = append(in.Fabrics, Spec{UUID: NewUUID(), Name: "b", ASN: 65101, MTU: 1500,
				Hosts: []Host{{Node: "h1", Iface: "eno4", TEP: "10.251.0.1/24"}}})
		},
		"dup TEP":            func(in *Intent) { in.Fabrics[0].Hosts[1].TEP = "10.250.0.1/24" },
		"TEP is network":     func(in *Intent) { in.Fabrics[0].Hosts[1].TEP = "10.250.0.0/24" },
		"TEP subnets differ": func(in *Intent) { in.Fabrics[0].Hosts[1].TEP = "10.250.1.2/24" },
		"iface injection":    func(in *Intent) { in.Fabrics[0].Hosts[0].Iface = "eno3 up; reboot" },
		"fabric device":      func(in *Intent) { in.Fabrics[0].Hosts[0].Iface = "vxfb7" },
		"VLAN 1":             func(in *Intent) { in.Fabrics[0].Hosts[0].VLAN = 1 },
		"long vlan dev":      func(in *Intent) { in.Fabrics[0].Hosts[0].Iface, in.Fabrics[0].Hosts[0].VLAN = "enp129s0f1np1", 300 },
		"MTU":                func(in *Intent) { in.Fabrics[0].MTU = 1300 },
		"ASN":                func(in *Intent) { in.Fabrics[0].ASN = 0 },
		"dup VNI":            func(in *Intent) { in.PGs[1].VNI = in.PGs[0].VNI },
		"VNI = L3VNI":        func(in *Intent) { in.PGs[2].VNI = in.VRFs[0].L3VNI },
		"dup name in org":    func(in *Intent) { in.PGs[1].Name = "WEB" },
		"overlap in org": func(in *Intent) {
			in.PGs[1].CIDR, in.PGs[1].Gateway, in.PGs[1].PoolStart, in.PGs[1].PoolEnd = "10.10.0.0/16", "10.10.9.1", "", ""
		},
		"gateway outside":    func(in *Intent) { in.PGs[0].Gateway = "10.10.9.1" },
		"gateway broadcast":  func(in *Intent) { in.PGs[0].Gateway = "10.10.1.255" },
		"pool reversed":      func(in *Intent) { in.PGs[1].PoolStart, in.PGs[1].PoolEnd = "10.10.2.101", "10.10.2.100" },
		"L2 with gateway":    func(in *Intent) { in.PGs[2].Gateway = "10.0.0.1" },
		"span stranger":      func(in *Intent) { in.PGs[0].Span = []string{"h9"} },
		"DNS injection":      func(in *Intent) { in.PGs[0].DNS = []string{"1.1.1.1\nconf-file=/x"} },
		"routed without VRF": func(in *Intent) { in.VRFs = in.VRFs[:1] },
		"egress off-net":     func(in *Intent) { in.VRFs[0].Egress = "192.0.2.1" },
		"egress = gateway":   func(in *Intent) { in.VRFs[0].Egress = "10.10.1.1" },
		"lease outside": func(in *Intent) {
			in.Leases = []Lease{{PG: pgW, IP: "10.10.9.9", MAC: "52:54:00:00:00:01", Session: "a"}}
		},
		"lease on L2": func(in *Intent) {
			in.Leases = []Lease{{PG: pgL2, IP: "10.10.1.9", MAC: "52:54:00:00:00:01", Session: "a"}}
		},
		"lease twice": func(in *Intent) {
			l := Lease{PG: pgW, IP: "10.10.1.9", MAC: "52:54:00:00:00:01", Session: "a"}
			l2 := l
			l2.Session = "b"
			in.Leases = []Lease{l, l2}
		},
		"rule across orgs": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgO2, Proto: "any"}}
		},
		"rule to L2": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgL2, Proto: "any"}}
		},
		"rule to self": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgW, Proto: "any"}}
		},
		"rule ports": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgD, Proto: "tcp", Ports: "22; drop"}}
		},
		"rule port range": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgD, Proto: "tcp", Ports: "90-80"}}
		},
		"rule external, no egress": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: External, Proto: "any"}}
		},
		"rule note quote": func(in *Intent) {
			in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgD, Proto: "any", Note: `x" accept`}}
		},
	} {
		in := sample()
		mut(&in)
		if err := in.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLeases(t *testing.T) {
	in := sample()
	a, err := in.AllocLease(pgD, "vm1", "52:54:00:AA:00:01")
	if err != nil || a.IP != "10.10.2.100" || a.MAC != "52:54:00:aa:00:01" {
		t.Fatalf("first lease %+v %v", a, err)
	}
	if again, _ := in.AllocLease(pgD, "vm1", "52:54:00:aa:00:01"); again != a {
		t.Fatalf("not idempotent: %+v", again)
	}
	if b, _ := in.AllocLease(pgD, "vm2", "52:54:00:aa:00:02"); b.IP != "10.10.2.101" {
		t.Fatalf("second lease %+v", b)
	}
	if _, err := in.AllocLease(pgD, "vm3", "52:54:00:aa:00:03"); err == nil {
		t.Fatal("pool of two gave a third address")
	}
	if _, err := in.AllocLease(pgL2, "vm3", "52:54:00:aa:00:03"); err == nil {
		t.Fatal("leased on an L2-only port group")
	}
	// The gateway and the egress address are never handed out.
	in.VRFs[0].Egress = "10.10.1.2"
	if c, _ := in.AllocLease(pgW, "vm4", "52:54:00:aa:00:04"); c.IP != "10.10.1.3" {
		t.Fatalf("lease %+v skipped neither gateway nor egress", c)
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if !in.ReleaseLeases("vm1") || in.ReleaseLeases("vm1") {
		t.Fatal("release")
	}
	// Deleting a port group drops its leases, rules and (last routed PG) VRF.
	in.Rules = []Rule{{UUID: rul1, Fabric: fabA, Org: 2, Src: pgO2, Dst: External, Proto: "any"}}
	in.PGs = in.PGs[:3]
	_ = in.Normalize(nil)
	if len(in.VRFs) != 1 || len(in.Rules) != 0 {
		t.Fatalf("after delete: VRFs %+v rules %+v", in.VRFs, in.Rules)
	}
}

func TestHostShare(t *testing.T) {
	in := sample()
	p1, ok := in.HostPlan("h1")
	if !ok || p1.TEP != "10.250.0.1" || p1.GuestMTU != 1550 || p1.AnycastMAC != AnycastMAC(fabA) {
		t.Fatalf("h1 plan %+v", p1)
	}
	// h1 is outside db's span.
	var vnis []int
	for _, s := range p1.Segments {
		vnis = append(vnis, s.VNI)
	}
	if fmt.Sprint(vnis) != "[2000000 2000002 2000003]" || len(p1.VRFs) != 2 {
		t.Fatalf("h1 segments %v VRFs %+v", vnis, p1.VRFs)
	}
	if err := Realize(newFake(), p1); err != nil {
		t.Fatal(err)
	}
	if _, ok := in.HostPlan("h9"); ok {
		t.Fatal("stranger has a plan")
	}
	r := in.Routing("h2", "abc123")
	if r == nil || r.TEP != "10.250.0.2" || fmt.Sprint(r.Peers) != "[10.250.0.1]" || len(r.VRFs) != 2 || r.Password != "abc123" {
		t.Fatalf("h2 routing %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	// An org's egress becomes its VRF's default route next hop, on every host.
	in.VRFs[0].Egress = "10.10.1.254"
	got := map[string]string{}
	for _, v := range in.Routing("h2", "abc123").VRFs {
		got[v.Name] = v.Egress
	}
	if len(got) != 2 || got[VRFName(in.VRFs[0].Org)] != "10.10.1.254" || got[VRFName(in.VRFs[1].Org)] != "" {
		t.Fatalf("VRF egress %v", got)
	}
	in.VRFs[0].Egress = ""
	in.Leases = []Lease{{PG: pgD, IP: "10.10.2.100", MAC: "52:54:00:00:00:09", Session: "vm9"}}
	d := in.DHCP("h2")
	if len(d[1]) != 2 || len(d[2]) != 1 {
		t.Fatalf("h2 DHCP %+v", d)
	}
	for _, s := range d[1] {
		if s.VNI == 2000001 && (len(s.Leases) != 1 || s.MTU != 1550 || s.Gateway != "10.10.2.1/24") {
			t.Fatalf("db DHCP %+v", s)
		}
		if _, err := DNSMasqConfig(1, d[1], "/run/x"); err != nil {
			t.Fatal(err)
		}
	}
	if u := in.UnderlayOf("h2"); u != "eno3.30" {
		t.Fatalf("underlay %q", u)
	}
}

func TestFirewallRender(t *testing.T) {
	in := sample()
	in.VRFs[0].Egress = "10.10.1.254"
	in.Rules = []Rule{
		{UUID: rul1, Fabric: fabA, Org: 1, Src: pgW, Dst: pgD, Proto: "tcp", Ports: "5432,6000-6010"},
		{UUID: NewUUID(), Fabric: fabA, Org: 1, Src: pgW, Dst: External, Proto: "any", Both: true},
		{UUID: NewUUID(), Fabric: fabA, Org: 1, Src: pgD, Dst: pgW, Proto: "icmp", Off: true},
	}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	fw, err := Firewall(&in, "h1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "vxfvrf1" jump org1`,
		`iifname "vxfvrf2" jump org2`,
		"ip saddr 10.10.1.0/24 ip daddr 10.10.2.0/24 meta l4proto tcp tcp dport { 5432, 6000-6010 } counter accept",
		"ip saddr 10.10.1.0/24 ip daddr != { 10.10.1.0/24, 10.10.2.0/24 } counter accept",
		"ip saddr != { 10.10.1.0/24, 10.10.2.0/24 } ip daddr 10.10.1.0/24 counter accept",
		`iifname "vxfb*" counter drop`,
		`iifname "vxfvrf*" tcp flags syn tcp option maxseg size set rt mtu`,
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("missing %q in\n%s", want, fw)
		}
	}
	if os.Getenv("VX_NFT_CHECK") == "1" {
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(fw)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -c: %v %s\n%s", err, out, fw)
		}
	}
	if strings.Contains(fw, "meta l4proto icmp") {
		t.Errorf("a disabled rule was rendered")
	}
	if !Allowed(&in, pgW, pgD, "tcp", 6005) || Allowed(&in, pgW, pgD, "tcp", 22) || Allowed(&in, pgD, pgW, "icmp", 0) ||
		!Allowed(&in, External, pgW, "udp", 53) || !Allowed(&in, pgD, pgD, "tcp", 1) {
		t.Errorf("Allowed")
	}
	if empty, _ := Firewall(&in, "h9"); strings.Contains(empty, "chain") {
		t.Errorf("a non-member got rules")
	}
}

// ---- replication --------------------------------------------------------------

type memStore struct {
	mu sync.Mutex
	in Intent
}

func (s *memStore) Load() (Intent, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.in.Clone(), nil }
func (s *memStore) Save(base int64, next Intent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.in.Version != base {
		return fmt.Errorf("version moved")
	}
	s.in = next.Clone()
	return nil
}

type memNet struct {
	nodes map[string]*Member
	down  map[string]bool
	// dropCommit makes Commit to a node fail after it prepared.
	dropCommit map[string]bool
}

func (n *memNet) get(node string) (*Member, error) {
	if n.down[node] || n.nodes[node] == nil {
		return nil, errors.New("unreachable")
	}
	return n.nodes[node], nil
}
func (n *memNet) Fetch(node string) (Intent, error) {
	m, err := n.get(node)
	if err != nil {
		return Intent{}, err
	}
	return m.Current()
}
func (n *memNet) Prepare(node string, p Proposal) error {
	m, err := n.get(node)
	if err != nil {
		return err
	}
	return m.Prepare(p)
}
func (n *memNet) Commit(node, id string) error {
	if n.dropCommit[node] {
		return errors.New("lost")
	}
	m, err := n.get(node)
	if err != nil {
		return err
	}
	return m.Commit(id)
}
func (n *memNet) Abort(node, id string) {
	if m, err := n.get(node); err == nil {
		m.Abort(id)
	}
}

func cluster(names ...string) (*memNet, map[string]*Coordinator) {
	net := &memNet{nodes: map[string]*Member{}, down: map[string]bool{}, dropCommit: map[string]bool{}}
	co := map[string]*Coordinator{}
	for _, n := range names {
		net.nodes[n] = &Member{Store: &memStore{}}
	}
	for _, n := range names {
		co[n] = &Coordinator{Self: n, Local: net.nodes[n], Net: net, Alive: func() map[string]bool {
			a := map[string]bool{}
			for _, o := range names {
				a[o] = !net.down[o]
			}
			return a
		}}
	}
	return net, co
}

func addFabric(hosts ...string) func(*Intent) error {
	return func(in *Intent) error {
		f := Spec{UUID: fabA, Name: "prod", ASN: 65100, MTU: 1500}
		for i, h := range hosts {
			f.Hosts = append(f.Hosts, Host{Node: h, Iface: "eno3", TEP: fmt.Sprintf("10.250.0.%d/24", i+1)})
		}
		in.Fabrics = []Spec{f}
		return nil
	}
}

func TestCommitUnanimous(t *testing.T) {
	net, co := cluster("h1", "h2", "h3")
	in, lag, err := co["h1"].Change(nil, addFabric("h1", "h2", "h3"))
	if err != nil || len(lag) != 0 || in.Version != 1 {
		t.Fatalf("create: %v %v %+v", err, lag, in)
	}
	for n, m := range net.nodes {
		if c, _ := m.Current(); c.Version != 1 || len(c.Fabrics) != 1 {
			t.Fatalf("%s at %+v", n, c)
		}
	}
	// Any node can coordinate the next change.
	if _, _, err := co["h3"].Change(nil, func(in *Intent) error { in.Fabrics[0].Name = "prod2"; return nil }); err != nil {
		t.Fatal(err)
	}
	// A down member blocks the write, and nothing changes anywhere.
	net.down["h2"] = true
	if _, _, err := co["h1"].Change(nil, func(in *Intent) error { in.Fabrics[0].Name = "x"; return nil }); err == nil ||
		!strings.Contains(err.Error(), "h2") {
		t.Fatalf("write with a member down: %v", err)
	}
	for _, n := range []string{"h1", "h3"} {
		if c, _ := net.nodes[n].Current(); c.Version != 2 || c.Fabrics[0].Name != "prod2" {
			t.Fatalf("%s changed: %+v", n, c)
		}
	}
	// Evict: the dead host is excluded and removed.
	if _, _, err := co["h1"].Change([]string{"h2"}, func(in *Intent) error {
		in.Fabrics[0].Hosts = []Host{in.Fabrics[0].Hosts[0], in.Fabrics[0].Hosts[2]}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// h2 comes back behind and catches up on the next coordinated change.
	net.down["h2"] = false
	if _, _, err := co["h2"].Change(nil, func(in *Intent) error { in.Fabrics[0].MTU = 1600; return nil }); err != nil {
		t.Fatal(err)
	}
	for n, m := range net.nodes {
		if c, _ := m.Current(); c.Version != 4 || c.Fabrics[0].MTU != 1600 || len(c.Fabrics[0].Hosts) != 2 {
			t.Fatalf("%s at %+v", n, c)
		}
	}
}

func TestCommitVetoAndLostCommit(t *testing.T) {
	net, co := cluster("h1", "h2")
	if _, _, err := co["h1"].Change(nil, addFabric("h1", "h2")); err != nil {
		t.Fatal(err)
	}
	// A node-local veto aborts everywhere; the coordinator keeps no pending change.
	net.nodes["h2"].Check = func(cur, next Intent) error {
		if next.Fabrics[0].MTU == 9000 {
			return errors.New("eno3 can't do 9000")
		}
		return nil
	}
	if _, _, err := co["h1"].Change(nil, func(in *Intent) error { in.Fabrics[0].MTU = 9000; return nil }); err == nil ||
		!strings.Contains(err.Error(), "h2 refused") {
		t.Fatalf("veto: %v", err)
	}
	if _, _, err := co["h1"].Change(nil, func(in *Intent) error { in.Fabrics[0].MTU = 1600; return nil }); err != nil {
		t.Fatalf("change after a veto: %v", err)
	}
	// A commit lost on the way to h2: h1 is ahead, h2 lags (never divergent),
	// and h2 adopts on its next change.
	net.dropCommit["h2"] = true
	_, lag, err := co["h1"].Change(nil, func(in *Intent) error { in.Fabrics[0].Name = "lost"; return nil })
	if err != nil || fmt.Sprint(lag) != "[h2]" {
		t.Fatalf("lost commit: %v %v", err, lag)
	}
	net.dropCommit["h2"] = false
	if c, _ := net.nodes["h2"].Current(); c.Version != 2 {
		t.Fatalf("h2 at %d", c.Version)
	}
	// h2's own stale-based proposal can't win: it syncs first.
	if _, _, err := co["h2"].Change(nil, func(in *Intent) error { in.Fabrics[0].ASN = 65200; return nil }); err != nil {
		t.Fatal(err)
	}
	for n, m := range net.nodes {
		if c, _ := m.Current(); c.Version != 4 || c.Fabrics[0].Name != "lost" || c.Fabrics[0].ASN != 65200 {
			t.Fatalf("%s at %+v", n, c.Fabrics)
		}
	}
	// A member holding another proposal refuses a second; a stale base is refused.
	m := net.nodes["h1"]
	cur, _ := m.Current()
	next := cur.Clone()
	next.Version++
	if err := m.Prepare(Proposal{ID: "a", Base: cur.Version, Intent: next}); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(Proposal{ID: "b", Base: cur.Version, Intent: next}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second proposal: %v", err)
	}
	m.Abort("a")
	if err := m.Commit("a"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("commit after abort: %v", err)
	}
	old := cur.Clone()
	old.Version = cur.Version
	if err := m.Prepare(Proposal{ID: "c", Base: cur.Version - 1, Intent: old}); !errors.As(err, new(StaleError)) {
		t.Fatalf("stale base: %v", err)
	}
}

func TestSingleHost(t *testing.T) {
	m := &Member{Store: &memStore{}}
	c := &Coordinator{Self: "solo", Local: m, Net: &memNet{}}
	if _, _, err := c.Change(nil, addFabric("solo")); err != nil {
		t.Fatal(err)
	}
	// Adding another host on a standalone node is refused before anything changes.
	if _, _, err := c.Change(nil, addFabric("solo", "other")); err == nil {
		t.Fatal("standalone node added a peer")
	}
	if cur, _ := m.Current(); cur.Version != 1 {
		t.Fatalf("version %d", cur.Version)
	}
}

func TestBridgeGuardRender(t *testing.T) {
	in := sample()
	in.Leases = []Lease{{PG: pgD, IP: "10.10.2.100", MAC: "52:54:00:00:00:09", Session: "vm9"}}
	segs := in.Guard("h2")
	g, err := BridgeGuard(segs)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"vxfb2000001" . 52:54:00:00:00:09 . 10.10.2.100`,
		"meta ibrname . ether saddr != @macs counter drop",
		"chain input {\n    type filter hook input priority -10; policy accept;\n    iifname != \"vxfv*\" meta ibrname @segs jump port",
		`iifname "vrh*" return`,
		"limit rate over 1000/second",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("guard lacks %q:\n%s", want, g)
		}
	}
	l2 := false
	for _, sg := range segs {
		if sg.VNI == 2000002 {
			l2 = !sg.Routed && len(sg.Leases) == 0
		}
	}
	if !l2 || strings.Contains(g, `"vxfb2000002" .`) {
		t.Errorf("L2-only segment %+v treated as routed", segs)
	}
	if _, err := BridgeGuard([]GuardSegment{{VNI: 1, Routed: true, Leases: []DHCPLease{{MAC: "52:54:00:00:00:01 } drop", IP: "10.0.0.1"}}}}); err == nil {
		t.Error("an injected MAC rendered")
	}
	if _, err := BridgeGuard([]GuardSegment{{VNI: 1, Routed: true, Leases: []DHCPLease{{MAC: "52:54:00:00:00:01", IP: "10.0.0.1 . x"}}}}); err == nil {
		t.Error("an injected address rendered")
	}
	if _, err := BridgeGuard(nil); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("VX_NFT_CHECK") == "1" { // root + nft: the kernel's parser accepts it
		for _, rs := range []string{g, func() string { e, _ := BridgeGuard(nil); return e }()} {
			cmd := exec.Command("nft", "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(rs)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("nft -c: %v %s\n%s", err, out, rs)
			}
		}
	}
}
