package service

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/db"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/routing"
	"vdxclone/internal/store"
	"vdxclone/internal/vrouter"
)

// l3TestService opens a fresh control-plane DB (no host access anywhere: the
// host-routing and vRouter backends are replaced by fakes in each test).
func l3TestService(t *testing.T) *Service {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return &Service{db: d, store: store.New(d), net: netdrv.New(d)}
}

func mustID(t *testing.T, s *Service, q string, args ...any) int64 {
	t.Helper()
	res, err := s.db.Exec(q, args...)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// ---- host management guard -------------------------------------------------

func cidrNet(s string) hostNet {
	ip, n, _ := net.ParseCIDR(s)
	return hostNet{IP: ip.To4(), Net: n}
}

// A host whose management is eno1 (192.168.0.163/24, default via 192.168.0.1),
// with a spare routed port eno2 (10.50.0.1/30); the admin is at 192.168.5.20
// (reached through the default gateway).
func mgmtL3Host() hostL3 {
	m, s := cidrNet("192.168.0.163/24"), cidrNet("10.50.0.1/30")
	m.Iface, s.Iface = "eno1", "eno2"
	return hostL3{Nets: []hostNet{m, s}, MgmtIface: "eno1", DefaultVia: net.ParseIP("192.168.0.1").To4(), DefaultDev: "eno1",
		Client: net.ParseIP("192.168.5.20").To4(), ClientVia: net.ParseIP("192.168.0.1").To4(), ClientDev: "eno1"}
}

func TestHostL3Guard(t *testing.T) {
	h := mgmtL3Host()
	for _, tc := range []struct {
		dest, nh string
		ok       bool
	}{
		{"0.0.0.0/0", "192.168.0.1", true},     // default via the management gateway
		{"0.0.0.0/0", "10.50.0.2", false},     // default moved off the management interface
		{"0.0.0.0/0", "192.0.2.1", false},     // next hop not on a connected subnet
		{"0.0.0.0/0", "eno2", false},          // interface default route
		{"10.60.0.0/24", "10.50.0.2", true},   // ordinary route via the routed port
		{"192.168.0.0/25", "10.50.0.2", false}, // inside the management subnet
		{"192.168.5.0/24", "10.50.0.2", false}, // covers the admin's own address
		{"192.168.5.0/24", "192.168.0.254", true},
	} {
		r, err := staticRoute(tc.dest, tc.nh)
		if err == nil {
			err = h.checkStaticAdd(r)
		}
		if (err == nil) != tc.ok {
			t.Errorf("route %s via %s: err=%v, want ok=%v", tc.dest, tc.nh, err, tc.ok)
		}
	}
	// Removing the route that carries the admin's session is refused.
	if h.checkStaticDelete(routing.Route{Dest: "192.168.5.0/24", NextHop: "192.168.0.1"}) == nil {
		t.Error("deleting the session route must be refused")
	}
	if h.checkStaticDelete(routing.Route{Dest: "10.60.0.0/24", NextHop: "10.50.0.2"}) != nil {
		t.Error("an unrelated delete must pass")
	}
	if h.checkOSPFNet("192.168.0.0/16") == nil || h.checkOSPFNet("10.50.0.0/30") != nil {
		t.Error("OSPF must stay off the management LAN, and be allowed elsewhere")
	}
	if h.checkIfPrefixAdd("eno1", "10.9.0.1/24") == nil || h.checkIfPrefixAdd("eno2", "192.168.0.200/24") == nil ||
		h.checkIfPrefixAdd("eno2", "10.9.0.1/24") != nil {
		t.Error("interface address guard")
	}
	// An admin on the management LAN itself: deleting its on-link address is refused.
	h2 := mgmtL3Host()
	h2.Client, h2.ClientVia = net.ParseIP("192.168.0.50").To4(), nil
	if h2.checkIfPrefixDelete(routing.IfPrefix{Iface: "eno1", CIDR: "192.168.0.163/24"}) == nil {
		t.Error("removing the address the session arrives on must be refused")
	}
	// With no management interface known and no default route, a default route
	// just needs a connected next hop.
	h3 := hostL3{Nets: h.Nets}
	if r, _ := staticRoute("default", "10.50.0.2"); h3.checkStaticAdd(r) != nil {
		t.Error("default route via a connected next hop must pass when nothing is at stake")
	}
}

func TestParseIPRouteJSON(t *testing.T) {
	gw, dev := parseIPRouteJSON([]byte(`[{"dst":"default","gateway":"10.0.0.1","dev":"eno2","metric":200},{"dst":"default","gateway":"192.168.0.1","dev":"eno1","metric":100}]`))
	if gw.String() != "192.168.0.1" || dev != "eno1" {
		t.Errorf("got %v %s", gw, dev)
	}
	if gw, dev := parseIPRouteJSON([]byte(`[{"dst":"192.168.0.50","dev":"eno1"}]`)); gw != nil || dev != "eno1" {
		t.Errorf("on-link: %v %s", gw, dev)
	}
	if gw, dev := parseIPRouteJSON(nil); gw != nil || dev != "" {
		t.Error("empty output")
	}
}

// ---- host routing: apply first, save after, roll back on failure -----------

func storedHostRouting(t *testing.T, s *Service) routing.Config {
	t.Helper()
	var raw string
	s.db.QueryRow(`SELECT config_json FROM routing_config WHERE id=1`).Scan(&raw)
	var c routing.Config
	_ = json.Unmarshal([]byte(raw), &c)
	return c
}

func TestMutateRoutingRollsBack(t *testing.T) {
	s := l3TestService(t)
	admin := &Principal{User: &auth.User{ID: 1, Username: "root"}, IsAdmin: true, OrgRole: "owner"}
	var applied []routing.Config
	fail := false
	oldApply, oldSnap := applyHostRoutingFn, hostL3Snapshot
	t.Cleanup(func() { applyHostRoutingFn, hostL3Snapshot = oldApply, oldSnap })
	applyHostRoutingFn = func(_ *Service, c routing.Config) error {
		applied = append(applied, c)
		if fail {
			fail = false // the rollback apply succeeds
			return errors.New("frr-reload failed")
		}
		return nil
	}
	hostL3Snapshot = func(*Service, string) (hostL3, error) { return mgmtL3Host(), nil }

	if err := s.AddFirewallRule(admin, "accept", "tcp", "443", "10.0.0.0/8", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if got := storedHostRouting(t, s); len(got.Firewall) != 1 {
		t.Fatalf("applied change not saved: %+v", got)
	}
	fail, applied = true, nil
	err := s.AddStaticRoute(admin, "10.60.0.0/24", "10.50.0.2", "1.2.3.4")
	if err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("want a not-saved error, got %v", err)
	}
	if len(applied) != 2 || len(applied[0].Static) != 1 || len(applied[1].Static) != 0 || len(applied[1].Firewall) != 1 {
		t.Fatalf("expected apply(new) then apply(previous), got %+v", applied)
	}
	if got := storedHostRouting(t, s); len(got.Static) != 0 || len(got.Firewall) != 1 {
		t.Fatalf("a failed change must not be saved: %+v", got)
	}

	// Validation and the management guard refuse before anything is applied.
	applied = nil
	for _, bad := range []func() error{
		func() error { return s.AddStaticRoute(admin, "10.60.0.0/24\nline vty", "10.50.0.2", "") },
		func() error { return s.AddStaticRoute(admin, "default", "10.50.0.2", "") }, // moves the default off eno1
		func() error { return s.AddFirewallRule(admin, "accept", "tcp", "443 }", "", "") },
		func() error { return s.SetBGP(admin, true, 0, "", "") },
		func() error { return s.AddOSPFNetwork(admin, "192.168.0.0/16", "0", "") }, // management LAN
		func() error { return s.SetRoutingUplink(admin, `eth0" accept`, "") },
		func() error { return s.DeleteStaticRoute(admin, 7, "") },
	} {
		if bad() == nil {
			t.Error("expected a refusal")
		}
	}
	if len(applied) != 0 {
		t.Errorf("refused changes must never be applied, got %d applies", len(applied))
	}
	if err := s.AddStaticRoute(&Principal{OrgRole: "owner"}, "10.60.0.0/24", "10.50.0.2", ""); err != ErrUnauthorized {
		t.Errorf("non-instance-admin: %v", err)
	}
}

// ---- vRouters: tenant policy, rollback ------------------------------------

type fakeBackend struct {
	vrouter.Backend
	pushed  []string
	failFRR int // fail this many PushFRR calls
	removed []vrouter.Leg
}

func (f *fakeBackend) PushFRR(_ vrouter.VRouter, conf string) error {
	f.pushed = append(f.pushed, conf)
	if f.failFRR > 0 {
		f.failFRR--
		return errors.New("frr-reload rejected the config")
	}
	return nil
}
func (f *fakeBackend) ApplyLegs(vrouter.VRouter, []vrouter.Leg) error { return nil }
func (f *fakeBackend) PushFirewall(vrouter.VRouter, string) error     { return nil }
func (f *fakeBackend) SetDHCP(vrouter.VRouter, vrouter.Leg) error     { return nil }
func (f *fakeBackend) RemoveLeg(_ vrouter.VRouter, l vrouter.Leg) error {
	f.removed = append(f.removed, l)
	return nil
}
func (f *fakeBackend) Status(vrouter.VRouter) (vrouter.LiveStatus, error) {
	return vrouter.LiveStatus{State: "running"}, nil
}

func withFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	fb := &fakeBackend{}
	old := vrouterBackend
	vrouterBackend = func(string) (vrouter.Backend, error) { return fb, nil }
	t.Cleanup(func() { vrouterBackend = old })
	return fb
}

// tenantRouter makes a running netns router in a tenant org with a downlink on
// 10.60.0.0/24 and an external interface on 203.0.113.8/29.
func tenantRouter(t *testing.T, s *Service) (org, vr, downNet int64) {
	org = mustID(t, s, `INSERT INTO orgs(name,slug) VALUES('acme','acme')`)
	vr = mustID(t, s, `INSERT INTO vrouters(org_id,name,runtime,status) VALUES(?,'edge','netns','running')`, org)
	downNet = mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge,cidr) VALUES(?,'app','bridge','vdxt1','10.60.0.0/24')`, org)
	extNet := mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge,cidr) VALUES(?,'wan','bridge','vdxt2','203.0.113.8/29')`, org)
	mustID(t, s, `INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr) VALUES(?,1,'internal','',?,'eth1','10.60.0.1/24')`, vr, downNet)
	mustID(t, s, `INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,upstream_gw) VALUES(?,2,'uplink','vdxt2',?,'eth2','203.0.113.10/29','203.0.113.9')`, vr, extNet)
	return org, vr, downNet
}

func TestTenantVRouterPolicy(t *testing.T) {
	s := l3TestService(t)
	fb := withFakeBackend(t)
	org, vr, _ := tenantRouter(t, s)
	p := &Principal{User: &auth.User{ID: 1, Username: "tenant"}, OrgID: org, OrgRole: "owner"}

	if err := s.VRSetBGP(p, vr, true, 65010, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.VRAddBGPNeighbor(p, vr, "203.0.113.9", 65000, ""); err != nil {
		t.Fatalf("connected neighbor refused: %v", err)
	}
	for name, err := range map[string]error{
		"remote neighbor":     s.VRAddBGPNeighbor(p, vr, "198.51.100.1", 65000, ""),
		"own address":         s.VRAddBGPNeighbor(p, vr, "203.0.113.10", 65000, ""),
		"foreign network":     s.VRAddBGPNetwork(p, vr, "8.8.8.0/24", ""),
		"default network":     s.VRAddBGPNetwork(p, vr, "0.0.0.0/0", ""),
		"external as network": s.VRAddBGPNetwork(p, vr, "203.0.113.8/29", ""),
		"ospf elsewhere":      s.VRAddOSPFNet(p, vr, "192.168.0.0/16", "0", ""),
		"eigrp":               s.VRSetEIGRP(p, vr, true, 100, "", ""),
		"eigrp network":       s.VRAddEIGRPNet(p, vr, "10.60.0.0/24", ""),
		"injected neighbor":   s.VRAddBGPNeighbor(p, vr, "203.0.113.9\n neighbor 1.1.1.1 remote-as 1", 65000, ""),
		"injected static":     s.VRAddStaticRoute(p, vr, "10.0.0.0/8 blackhole", "10.60.0.2", ""),
		"bad asn":             s.VRSetBGP(p, vr, true, 0, "", ""),
		"bad index":           s.VRDelBGPNetwork(p, vr, 5, ""),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := s.VRAddBGPNetwork(p, vr, "10.60.0.0/24", ""); err != nil {
		t.Fatalf("own downlink network refused: %v", err)
	}
	if err := s.VRSetOSPF(p, vr, true, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.VRAddOSPFNet(p, vr, "10.60.0.0/24", "0", ""); err != nil {
		t.Fatalf("own OSPF network refused: %v", err)
	}
	last := fb.pushed[len(fb.pushed)-1]
	for _, want := range []string{"neighbor 203.0.113.9 prefix-list VDX-TENANT-EXPORT out", "ip prefix-list VDX-TENANT-EXPORT seq 5 permit 10.60.0.0/24 le 32",
		"network 10.60.0.0/24 area 0", "interface eth1\n ip address 10.60.0.1/24\n ip ospf passive"} {
		if !strings.Contains(last, want) {
			t.Errorf("pushed config missing %q:\n%s", want, last)
		}
	}

	// A legacy entry stored outside the policy is shown as ignored and never pushed.
	var raw string
	s.db.QueryRow(`SELECT frr_json FROM vrouters WHERE id=?`, vr).Scan(&raw)
	var c routing.Config
	_ = json.Unmarshal([]byte(raw), &c)
	c.BGP.Neighbors = append(c.BGP.Neighbors, routing.Neighbor{Addr: "198.51.100.1", RemoteAS: 1})
	blob, _ := json.Marshal(c)
	s.db.Exec(`UPDATE vrouters SET frr_json=? WHERE id=?`, string(blob), vr)
	view, err := s.GetVRouterView(p, vr)
	if err != nil {
		t.Fatal(err)
	}
	if !view.Tenant || view.Tier() != "Tier-1" || len(view.Ignored) != 1 || !strings.Contains(view.Ignored[0], "198.51.100.1") {
		t.Errorf("view: tenant=%v tier=%s ignored=%v", view.Tenant, view.Tier(), view.Ignored)
	}
	if conf, _ := s.renderVRouterFRR(view.VRouter, view.Legs); strings.Contains(conf, "198.51.100.1") {
		t.Errorf("an ignored neighbor was rendered:\n%s", conf)
	}

	// A push the router rejects is rolled back and not saved.
	before := raw
	s.db.QueryRow(`SELECT frr_json FROM vrouters WHERE id=?`, vr).Scan(&before)
	fb.failFRR, fb.pushed = 1, nil
	err = s.VRAddStaticRoute(p, vr, "10.99.0.0/24", "10.60.0.2", "")
	if err == nil || !strings.Contains(err.Error(), "not saved") {
		t.Fatalf("want a not-saved error, got %v", err)
	}
	if len(fb.pushed) != 2 || !strings.Contains(fb.pushed[0], "10.99.0.0/24") || strings.Contains(fb.pushed[1], "10.99.0.0/24") {
		t.Errorf("expected push(new) then push(previous): %d pushes", len(fb.pushed))
	}
	var after string
	s.db.QueryRow(`SELECT frr_json FROM vrouters WHERE id=?`, vr).Scan(&after)
	if after != before {
		t.Errorf("a rejected change must not be saved:\n%s\n%s", before, after)
	}

	// The provider (Default org) gateway stays unrestricted.
	def, _ := s.store.DefaultOrgID()
	pvr := mustID(t, s, `INSERT INTO vrouters(org_id,name,runtime,status) VALUES(?,'core','lxc','running')`, def)
	admin := &Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: def, IsAdmin: true, OrgRole: "owner"}
	if err := s.VRSetBGP(admin, pvr, true, 65000, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.VRAddBGPNeighbor(admin, pvr, "198.51.100.1", 65001, ""); err != nil {
		t.Errorf("provider gateway neighbor refused: %v", err)
	}
	if err := s.VRSetEIGRP(admin, pvr, true, 100, "", ""); err != nil {
		t.Errorf("provider gateway EIGRP refused: %v", err)
	}
	if strings.Contains(fb.pushed[len(fb.pushed)-1], "VDX-TENANT-EXPORT") {
		t.Error("the tenant export filter must not apply to a provider gateway")
	}
	// A tenant can't create a host-bridge internal port group.
	if err := s.AttachInternalNetwork(p, vr, "x", "10.80.0.0/24", "10.80.0.1/24", false, "", "", ""); err != ErrUnauthorized {
		t.Errorf("tenant AttachInternalNetwork: %v", err)
	}
}

// Detaching a downlink the router created deletes its port group (refused
// while a VM is on it); an attached tenant port group is only detached.
func TestDetachOwnedDownlink(t *testing.T) {
	s := l3TestService(t)
	fb := withFakeBackend(t)
	org, vr, downNet := tenantRouter(t, s)
	p := &Principal{User: &auth.User{ID: 1, Username: "tenant"}, OrgID: org, OrgRole: "owner"}
	uid := mustID(t, s, `INSERT INTO users(username,password_hash) VALUES('u','x')`)
	mustID(t, s, `INSERT INTO images(name,path) VALUES('img','/x')`)
	mustID(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,org_id,network_id) VALUES('vm1','vm1',?,'img','/x',?,?)`, uid, org, downNet)
	if err := s.DetachSegment(p, vr, downNet, ""); err == nil || !strings.Contains(err.Error(), "instance") {
		t.Fatalf("detach with a VM on it: %v", err)
	}
	// In Trash it still points at the port group (a restore would need it).
	s.db.Exec(`UPDATE sessions SET deleted_at=datetime('now') WHERE id='vm1'`)
	if err := s.DetachSegment(p, vr, downNet, ""); err == nil || !strings.Contains(err.Error(), "Trash") {
		t.Fatalf("detach with a VM in Trash on it: %v", err)
	}
	if len(fb.removed) != 0 {
		t.Fatalf("a refused detach must not remove the leg: %v", fb.removed)
	}
	s.db.Exec(`DELETE FROM sessions WHERE id='vm1'`)
	if err := s.DetachSegment(p, vr, downNet, ""); err != nil {
		t.Fatalf("detach owned downlink: %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM networks WHERE id=?`, downNet).Scan(&n)
	if n != 0 || len(fb.removed) != 1 || fb.removed[0].IfaceName != "eth1" {
		t.Errorf("owned port group not deleted (%d) / leg not removed (%v)", n, fb.removed)
	}
	if s.routerLegOn(downNet) != "" {
		t.Error("leg row survived")
	}
}

// ---- leg addressing ----------------------------------------------------------

func TestUplinkLegAddr(t *testing.T) {
	taken := []string{"203.0.113.11/29"}
	for _, tc := range []struct {
		cidr, pg, gw string
		ok           bool
	}{
		{"203.0.113.10/29", "203.0.113.8/29", "203.0.113.9", true},
		{"203.0.113.10", "203.0.113.8/29", "203.0.113.9", true}, // sized from the port group
		{"198.51.100.10/29", "203.0.113.8/29", "", false},       // outside the port group
		{"203.0.113.9/29", "203.0.113.8/29", "203.0.113.9", false},
		{"203.0.113.8/29", "203.0.113.8/29", "", false},  // network address
		{"203.0.113.15/29", "203.0.113.8/29", "", false}, // broadcast
		{"203.0.113.11/29", "203.0.113.8/29", "", false}, // another leg has it
		{"203.0.113.10/24", "203.0.113.8/29", "", false}, // wider than the port group
		{"203.0.113.10/29", "203.0.113.8/29", "203.0.113.15", false},
		{"203.0.113.10/29", "203.0.113.8/29", "198.51.100.1", false},
		{"10.0.0.1/1", "", "", false}, // absurdly wide
		{"203.0.113.10/29", "", "", true},
	} {
		if _, err := checkUplinkLegAddr(tc.cidr, tc.pg, tc.gw, taken); (err == nil) != tc.ok {
			t.Errorf("checkUplinkLegAddr(%q, %q, %q) = %v, want ok=%v", tc.cidr, tc.pg, tc.gw, err, tc.ok)
		}
	}
	// /31 point-to-point: both addresses are usable.
	if _, err := checkUplinkLegAddr("192.0.2.0/31", "192.0.2.0/31", "192.0.2.1", nil); err != nil {
		t.Errorf("/31: %v", err)
	}
}

func TestLegDHCP(t *testing.T) {
	if r, d, err := legDHCP(true, "10.60.0.100-200", "1.1.1.1 8.8.8.8", "10.60.0.1/24"); err != nil || r != "10.60.0.100,10.60.0.200" || d != "1.1.1.1,8.8.8.8" {
		t.Errorf("legDHCP = %q %q %v", r, d, err)
	}
	for name, args := range map[string][3]string{
		"outside subnet":  {"10.61.0.100,10.61.0.200", "", "10.60.0.1/24"},
		"covers gateway":  {"10.60.0.1,10.60.0.50", "", "10.60.0.1/24"},
		"dns injection":   {"10.60.0.100,10.60.0.200", "1.1.1.1\ndhcp-script=/x", "10.60.0.1/24"},
		"range injection": {"10.60.0.100,10.60.0.200\nx", "", "10.60.0.1/24"},
		"missing range":   {"", "", "10.60.0.1/24"},
		"no leg address":  {"10.60.0.100,10.60.0.200", "", ""},
		"backwards range": {"10.60.0.200,10.60.0.100", "", "10.60.0.1/24"},
	} {
		if _, _, err := legDHCP(true, args[0], args[1], args[2]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if r, _, err := legDHCP(false, "", "", ""); err != nil || r != "" {
		t.Errorf("DHCP off with nothing set: %q %v", r, err)
	}
}

// ---- firewall compile: leases are scoped to the org -------------------------

// TestFWMapsLeasesScopedToOrg: another org's lease (even one with the same MAC
// as ours) and a stale lease from a VM's earlier network never reach the
// compiled maps.
func TestFWMapsLeasesScopedToOrg(t *testing.T) {
	s := l3TestService(t)
	ours := mustID(t, s, `INSERT INTO orgs(name,slug) VALUES('a','a')`)
	theirs := mustID(t, s, `INSERT INTO orgs(name,slug) VALUES('b','b')`)
	uid := mustID(t, s, `INSERT INTO users(username,password_hash) VALUES('u','x')`)
	mustID(t, s, `INSERT INTO images(name,path) VALUES('img','/x')`)
	netA := mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge,cidr) VALUES(?,'a','bridge','vdxt1','10.1.0.0/24')`, ours)
	oldA := mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge,cidr) VALUES(?,'old','bridge','vdxt3','10.3.0.0/24')`, ours)
	netB := mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge,cidr) VALUES(?,'b','bridge','vdxt2','10.1.0.0/24')`, theirs)
	const mac = "52:54:00:aa:bb:01"
	mustID(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,org_id,network_id,mac) VALUES('a1','a1',?,'img','/x',?,?,?)`, uid, ours, netA, mac)
	mustID(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,org_id,network_id,mac) VALUES('b1','b1',?,'img','/x',?,?,?)`, uid, theirs, netB, mac)
	mustID(t, s, `INSERT INTO sessions(id,name,owner_id,image_name,disk_path,org_id,network_id,mac) VALUES('b2','b2',?,'img','/x',?,?,'52:54:00:aa:bb:02')`, uid, theirs, netB)
	mustID(t, s, `INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,'a1','10.1.0.10',?)`, netA, mac)
	mustID(t, s, `INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,'a1','10.3.0.77',?)`, oldA, mac) // stale
	mustID(t, s, `INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,'b1','10.1.0.99',?)`, netB, mac)
	mustID(t, s, `INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,'b2','10.1.0.98','52:54:00:aa:bb:02')`, netB)

	m := s.buildFWMaps(ours)
	if got := m.macToIP[mac]; got != "10.1.0.10" {
		t.Errorf("our VM's address = %q, want 10.1.0.10", got)
	}
	if len(m.macToIP) != 1 {
		t.Errorf("another org's or a stale lease leaked into the maps: %v", m.macToIP)
	}
}
