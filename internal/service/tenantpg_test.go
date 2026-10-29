package service

import (
	"reflect"
	"strings"
	"testing"

	"vdxclone/internal/routing"
	"vdxclone/internal/vrouter"
)

func TestCarriedOutAndUplinkPortVlans(t *testing.T) {
	pgs := []int{10, 20, 30}
	for _, tc := range []struct {
		mode       string
		native     int
		wantPVID   int
		wantTagged []int
		carried    map[int]bool // vlan (0 = untagged default) -> carried
	}{
		{"", 0, 1, []int{10, 20, 30}, map[int]bool{0: false, 10: false}},
		{"access", 0, 1, nil, map[int]bool{0: true, 10: false, 20: false}},
		{"access", 20, 20, nil, map[int]bool{0: false, 10: false, 20: true}},
		{"qinq", 0, 1, []int{10, 20, 30}, map[int]bool{0: true, 10: true, 30: true}},
		{"dedicated", 20, 20, []int{10, 30}, map[int]bool{0: false, 10: true, 20: true}},
	} {
		if tc.mode != "" {
			pvid, tagged := uplinkPortVlans(tc.mode, tc.native, pgs)
			if pvid != tc.wantPVID || !reflect.DeepEqual(tagged, tc.wantTagged) {
				t.Errorf("%s/native %d: port pvid=%d tagged=%v, want %d %v", tc.mode, tc.native, pvid, tagged, tc.wantPVID, tc.wantTagged)
			}
		}
		for vlan, want := range tc.carried {
			if got := carriedOut(tc.mode, tc.native, vlan); got != want {
				t.Errorf("carriedOut(%q, native %d, vlan %d) = %v, want %v", tc.mode, tc.native, vlan, got, want)
			}
		}
	}
}

func TestLegAddr(t *testing.T) {
	for _, tc := range []struct {
		in, subnet, ip, cidr string
		ok                   bool
	}{
		{"10.60.0.1/24", "10.60.0.0/24", "10.60.0.1", "10.60.0.1/24", true},
		{"10.60.0.1", "10.60.0.0/24", "10.60.0.1", "10.60.0.1/24", true}, // sized from the subnet
		{"10.61.0.1/24", "10.60.0.0/24", "", "", false},                  // outside
		{"10.60.0.1", "", "", "", false},                                 // no prefix anywhere
		{"nope", "10.60.0.0/24", "", "", false},
	} {
		ip, cidr, err := legAddr(tc.in, tc.subnet)
		if (err == nil) != tc.ok || ip != tc.ip || cidr != tc.cidr {
			t.Errorf("legAddr(%q,%q) = %q,%q,%v", tc.in, tc.subnet, ip, cidr, err)
		}
	}
	if gatewayInCIDR("10.60.0.1", "10.60.0.0/24") != nil || gatewayInCIDR("10.7.0.1", "10.60.0.0/24") == nil {
		t.Fatal("gatewayInCIDR")
	}
}

func TestEdgeRender(t *testing.T) {
	legs := []vrouter.Leg{
		{Kind: vrouter.LegInternal, IfaceName: "eth1", CIDR: "10.60.0.1/24"},
		{Kind: vrouter.LegUplink, IfaceName: "eth2", CIDR: "203.0.113.10/29", UpstreamGW: "203.0.113.9", SNAT: true},
	}
	nat := vrouter.RenderEdgeNAT(legs)
	if !strings.Contains(nat, `oifname "eth2" masquerade`) || strings.Contains(nat, "eth1") {
		t.Fatalf("SNAT render:\n%s", nat)
	}
	if off := vrouter.RenderEdgeNAT(legs[:1]); strings.Contains(off, "chain") {
		t.Fatalf("no SNAT legs must only remove the table:\n%s", off)
	}
	vr := vrouter.VRouter{Name: "edge"}
	conf, err := vrouter.RenderForVRouter(vr, legs, routing.Config{})
	if err != nil || !strings.Contains(conf, "ip route 0.0.0.0/0 203.0.113.9") {
		t.Fatalf("uplink default route missing (%v):\n%s", err, conf)
	}
	own := routing.Config{Static: []routing.Route{{Dest: "0.0.0.0/0", NextHop: "10.60.0.254"}}}
	conf, _ = vrouter.RenderForVRouter(vr, legs, own)
	if strings.Contains(conf, "203.0.113.9") || len(own.Static) != 1 {
		t.Fatalf("an operator default route must win and the caller's config stay untouched:\n%s", conf)
	}
}

// TestTenantPortGroupGuards covers the refusals that happen before any host
// change: bad VLAN/gateway input, a native VLAN that isn't a port group, and an
// uplink that would carry a router-gatewayed port group onto the wire.
func TestTenantPortGroupGuards(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	p := &Principal{OrgID: orgID, OrgRole: "admin"}
	mustExec := func(q string, args ...any) int64 {
		t.Helper()
		res, err := s.db.Exec(q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	vsNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'default','bridge','vdxt1')`, orgID)
	tnet := mustExec(`INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'default',?)`, orgID, vsNet)

	for _, tc := range []struct {
		vlan              int
		cidr, gw, wantErr string
		dhcp              bool
	}{
		{1, "", "", "VLAN must be 2-4094", false},
		{4095, "", "", "VLAN must be 2-4094", false},
		{10, "", "10.60.0.1", "needs the subnet", false},
		{10, "10.60.0.0/24", "10.61.0.1", "not an IPv4 address inside", false},
		{10, "10.60.0.0/24", "", "DHCP needs a gateway", true},
	} {
		_, err := s.CreateTenantPortGroup(p, tnet, "web", tc.vlan, tc.cidr, tc.gw, tc.dhcp, "10.60.0.100-200", "", "")
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("vlan %d gw %q: err=%v, want %q", tc.vlan, tc.gw, err, tc.wantErr)
		}
	}
	if _, err := s.CreateTenantPortGroup(&Principal{OrgID: orgID, OrgRole: "member"}, tnet, "web", 10, "", "", false, "", "", ""); err != ErrUnauthorized {
		t.Fatalf("a member must not create port groups: %v", err)
	}
	if _, err := s.CreateTenantPortGroup(&Principal{OrgID: orgID + 99, OrgRole: "admin"}, tnet, "web", 10, "", "", false, "", "", ""); err == nil {
		t.Fatalf("another org must not reach this vSwitch")
	}
	if err := s.SetVSwitchNative(p, tnet, 33, ""); err == nil || !strings.Contains(err.Error(), "not a port group") {
		t.Fatalf("native VLAN must be one of the vSwitch's port groups: %v", err)
	}

	// A port group routed by a router (gatewayed by its leg) must never be
	// carried out an uplink.
	pgNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'default/db','bridge','vdxt1',20)`, orgID)
	mustExec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id,vrouter_id) VALUES(?,?,'db',20,?,7)`, orgID, tnet, pgNet)
	if err := s.checkCarry(tnet, "access", 0); err != nil {
		t.Fatalf("access uplink carrying only the untagged PG is fine: %v", err)
	}
	if err := s.checkCarry(tnet, "access", 20); err == nil {
		t.Fatalf("access uplink with the routed PG as native must be refused")
	}
	if err := s.checkCarry(tnet, "qinq", 0); err == nil {
		t.Fatalf("a QinQ uplink carries every PG — must be refused while one is routed")
	}
	u := mkUplink(t, s, orgID, trunkID, "wan")
	mustExec(`UPDATE tenant_uplinks SET mode='qinq', outer_vid=100 WHERE id=?`, u)
	if err := s.connectUplink(tnet, vsNet, u); err == nil {
		t.Fatalf("connecting a QinQ uplink over a routed port group must be refused")
	}
	var up any
	_ = s.db.QueryRow(`SELECT uplink_id FROM tenant_networks WHERE id=?`, tnet).Scan(&up)
	if up != nil {
		t.Fatalf("refused connect must leave the vSwitch unconnected, got uplink %v", up)
	}
}
