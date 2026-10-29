package service

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTenantTopologyScope: a tenant's diagram holds only its own vSwitches,
// port groups, VMs and routers — never another org's (not even a same-named
// router) and never a host device name — and a routed port group is drawn on
// its router, with the router's uplink leg as its way out.
func TestTenantTopologyScope(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	mustExec := func(q string, args ...any) int64 {
		t.Helper()
		res, err := s.db.Exec(q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	other := mustExec(`INSERT INTO orgs(name,slug) VALUES('o','o')`)
	uid := mustExec(`INSERT INTO users(username,password_hash) VALUES('u','x')`)
	mustExec(`INSERT INTO images(name,path) VALUES('img','/x')`)
	vm := func(id, name string, org, netID int64) {
		mustExec(`INSERT INTO sessions(id,name,owner_id,image_name,disk_path,org_id,network_id) VALUES(?,?,?,'img','/x',?,?)`, id, name, uid, org, netID)
	}

	// Ours: vSwitch "default" (vdxt1) on uplink "wan", PG web (VLAN 10), PG db
	// (VLAN 20) routed by router "edge", which also has an uplink leg.
	vsNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge,cidr) VALUES(?,'default','bridge','vdxt1','10.3.0.0/24')`, orgID)
	u := mkUplink(t, s, orgID, trunkID, "wan")
	tnet := mustExec(`INSERT INTO tenant_networks(org_id,name,network_id,uplink_id) VALUES(?,'default',?,?)`, orgID, vsNet, u)
	webNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr) VALUES(?,'default/web','bridge','vdxt1',10,'10.60.0.0/24')`, orgID)
	mustExec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'web',10,?)`, orgID, tnet, webNet)
	vr := mustExec(`INSERT INTO vrouters(org_id,name,runtime,status) VALUES(?,'edge','netns','running')`, orgID)
	dbNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr) VALUES(?,'default/db','bridge','vdxt1',20,'10.70.0.0/24')`, orgID)
	mustExec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id,vrouter_id) VALUES(?,?,'db',20,?,?)`, orgID, tnet, dbNet, vr)
	mustExec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,vlan_id) VALUES(?,1,'internal','vdxt1',?,'eth1','10.70.0.1/24',20)`, vr, dbNet)
	mustExec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,vlan_id) VALUES(?,2,'uplink','vdxt1',?,'eth2','203.0.113.10/29',0)`, vr, vsNet)
	vm("a1", "web-1", orgID, webNet)
	vm("a2", "db-1", orgID, dbNet)
	vm("a3", "loose-1", orgID, 0)

	// Theirs: a vSwitch, a VM and a router with the SAME name.
	theirNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'theirs','bridge','vdxt9')`, other)
	mustExec(`INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'theirs',?)`, other, theirNet)
	vm("b1", "their-vm", other, theirNet)
	theirVR := mustExec(`INSERT INTO vrouters(org_id,name,runtime,status) VALUES(?,'edge','netns','running')`, other)
	mustExec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr) VALUES(?,1,'internal','vdxt9',?,'eth1','10.9.0.1/24')`, theirVR, theirNet)

	for _, p := range []*Principal{{OrgID: 0, OrgRole: "owner"}, {OrgID: orgID}} {
		if _, err := s.NetworkTopology(p); err != ErrUnauthorized {
			t.Fatalf("no org / no role must be refused, got %v", err)
		}
	}
	topo, err := s.NetworkTopology(&Principal{OrgID: orgID, OrgRole: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(topo)
	js := string(b)
	for _, leak := range []string{"theirs", "their-vm", "vdxt", "10.9.0", "bond0"} {
		if strings.Contains(js, leak) {
			t.Errorf("tenant topology leaks %q:\n%s", leak, js)
		}
	}

	var vs *TopoSwitch
	for i := range topo.Switches {
		if topo.Switches[i].Name == "default" {
			vs = &topo.Switches[i]
		}
	}
	if vs == nil || len(vs.PortGroups) != 2 || vs.PortGroups[0].Name != "default" || vs.PortGroups[1].VLAN != 10 {
		t.Fatalf("vSwitch must keep the untagged + web port groups (db is routed):\n%s", js)
	}
	if len(vs.PortGroups[1].VMs) != 1 || vs.PortGroups[1].VMs[0].Name != "web-1" {
		t.Fatalf("web-1 must sit on the web port group:\n%s", js)
	}
	if len(vs.Uplinks) != 1 || vs.Uplinks[0].Name != "wan · access" || vs.Uplinks[0].State != "down" {
		t.Fatalf("an unbound uplink shows by its tenant name, down:\n%s", js)
	}
	if len(topo.VRouters) != 1 {
		t.Fatalf("exactly our router, got %d:\n%s", len(topo.VRouters), js)
	}
	r := topo.VRouters[0]
	if len(r.Internal) != 1 || r.Internal[0].Name != "db" || r.Internal[0].GW != "10.70.0.1/24" ||
		r.Internal[0].Bridge != "default · VLAN 20" || len(r.Internal[0].VMs) != 1 || r.Internal[0].VMs[0].Name != "db-1" {
		t.Fatalf("router must carry the routed db port group:\n%s", js)
	}
	if r.Transit == nil || r.Transit.CIDR != "203.0.113.8/29" || r.Transit.Phys != "wan · access" || r.Transit.Bridge != "default" {
		t.Fatalf("router's way out is its uplink leg:\n%s", js)
	}
	var natOK bool
	for _, sw := range topo.Switches {
		natOK = natOK || (sw.Kind == "user-mode" && len(sw.PortGroups[0].VMs) == 1 && sw.PortGroups[0].VMs[0].Name == "loose-1")
	}
	if !natOK {
		t.Fatalf("a VM on no port group shows on the NAT switch:\n%s", js)
	}
}

// TestMergeVRoutersPerPortGroup: on the host diagram a router leg on a tenant
// VLAN port group takes only that port group (the vSwitch, its other port groups
// and its uplink stay), while a legacy dedicated segment bridge and a transit
// bridge still collapse into the router as before. Same-named routers of two
// orgs stay two routers.
func TestMergeVRoutersPerPortGroup(t *testing.T) {
	s, orgID, _ := allocTestService(t)
	defer s.db.Close()
	topo := &Topology{Switches: []TopoSwitch{
		{Name: "vdxt1", bridge: "vdxt1", Uplinks: []TopoUplink{{Name: "bond0.500"}}, PortGroups: []TopoPortGroup{
			{Name: "default", netID: 1}, {Name: "web", VLAN: 10, netID: 2}, {Name: "db", VLAN: 20, netID: 3}}},
		{Name: "vr4-lan", bridge: "vr4-lan", PortGroups: []TopoPortGroup{{Name: "lan", netID: 5}}},
		{Name: "vr4-wan", bridge: "vr4-wan", Uplinks: []TopoUplink{{Name: "enp9s0"}}, PortGroups: []TopoPortGroup{{Name: "VM Network"}}},
	}}
	legs := []topoLeg{
		{vrID: 1, vr: "edge", kind: "internal", bridge: "vdxt1", cidr: "10.70.0.1/24", iface: "eth1", netID: 3, vlan: 20},
		{vrID: 1, vr: "edge", kind: "uplink", bridge: "vdxt1", cidr: "203.0.113.10/29", iface: "eth2", netID: 1},
		{vrID: 2, vr: "edge", kind: "internal", bridge: "vr4-lan", cidr: "10.5.0.1/24", iface: "eth1", netID: 5},
		{vrID: 2, vr: "edge", kind: "transit", bridge: "vr4-wan", cidr: "192.0.2.2/30", iface: "eth0"},
	}
	s.mergeVRouters(topo, legs, orgID, nil, false)
	if len(topo.Switches) != 1 || topo.Switches[0].Name != "vdxt1" || len(topo.Switches[0].PortGroups) != 2 {
		t.Fatalf("only the tenant vSwitch (minus db) must remain: %+v", topo.Switches)
	}
	if len(topo.VRouters) != 2 {
		t.Fatalf("two routers named edge must stay two: %+v", topo.VRouters)
	}
	a, b := topo.VRouters[0], topo.VRouters[1]
	if len(a.Internal) != 1 || a.Internal[0].Name != "db" || a.Transit == nil || a.Transit.Phys != "bond0.500" || a.Transit.Bridge != "vdxt1" {
		t.Fatalf("PG router: %+v / %+v", a.Internal, a.Transit)
	}
	if len(b.Internal) != 1 || b.Internal[0].Name != "lan" || b.Transit == nil || b.Transit.Phys != "enp9s0" || b.Transit.CIDR != "192.0.2.0/30" {
		t.Fatalf("legacy router: %+v / %+v", b.Internal, b.Transit)
	}
}
