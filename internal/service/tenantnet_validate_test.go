package service

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/db"
	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/store"
)

// stubTenantHost stands in for the machine the tests run on: the host's subnets (the
// overlap guard), a trunk's kernel VLAN subinterfaces and its master. Nothing in
// these tests reads, let alone changes, a real interface.
func stubTenantHost(t *testing.T, subnets []string) {
	t.Helper()
	oldSub, oldVlans, oldMaster := hostSubnets, trunkVlanSubs, trunkMaster
	t.Cleanup(func() { hostSubnets, trunkVlanSubs, trunkMaster = oldSub, oldVlans, oldMaster })
	var hs []hostSubnet
	for _, c := range subnets {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("stub subnet %q: %v", c, err)
		}
		hs = append(hs, hostSubnet{Dev: "eth9", Net: n})
	}
	hostSubnets = func() ([]hostSubnet, error) { return hs, nil }
	trunkVlanSubs = func(string) (map[int]string, error) { return nil, nil }
	trunkMaster = func(string) string { return "" }
}

// tenantTestService: a DB with one org whose admin is returned, and no host.
func tenantTestService(t *testing.T) (*Service, *Principal, func(string, ...any) int64) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	s := &Service{db: d, store: store.New(d)}
	stubTenantHost(t, []string{"192.168.1.0/24"})
	ins := func(q string, args ...any) int64 {
		t.Helper()
		res, err := d.Exec(q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	org := ins(`INSERT INTO orgs(name,slug) VALUES('acme','acme')`)
	return s, &Principal{User: &auth.User{ID: 1, Username: "ann"}, OrgID: org, OrgRole: "admin"}, ins
}

// mkVSwitch inserts a vSwitch (bridge vdxt<network id>) without touching the host.
func mkVSwitch(ins func(string, ...any) int64, org int64, name, cidr, gw string, def int) (tnet, netID int64) {
	netID = ins(`INSERT INTO networks(org_id,name,mode,bridge,cidr,gateway) VALUES(?,?,'bridge','',?,?)`, org, name, cidr, gw)
	ins(`UPDATE networks SET bridge='vdxt'||id WHERE id=?`, netID)
	tnet = ins(`INSERT INTO tenant_networks(org_id,name,network_id,is_default) VALUES(?,?,?,?)`, org, name, netID, def)
	return
}

// TestParseTenantL3: valid input comes back normalized; anything that isn't
// exactly an IPv4 subnet / host address / range / resolver list — above all a
// newline carrying a dnsmasq directive — is refused with a message that says
// what to type.
func TestParseTenantL3(t *testing.T) {
	l, err := parseTenantL3(" 10.50.0.7/24 ", "10.50.0.1", true, "10.50.0.100-200", "")
	if err != nil {
		t.Fatal(err)
	}
	if l != (tenantL3{CIDR: "10.50.0.0/24", Gateway: "10.50.0.1", DHCP: true, Range: "10.50.0.100,10.50.0.200", DNS: defaultTenantDNS}) {
		t.Fatalf("normalized: %+v", l)
	}
	if l, err = parseTenantL3("10.50.0.0/24", "", false, "junk", "junk"); err != nil || l.Gateway != "" || l.DHCP || l.Range != "" {
		t.Fatalf("gatewayless, DHCP off: %+v %v (range/DNS are ignored when DHCP is off)", l, err)
	}
	if l, err = parseTenantL3("", "", false, "", ""); err != nil || l != (tenantL3{}) {
		t.Fatalf("no addressing (L2 only): %+v %v", l, err)
	}
	if l, err = parseTenantL3("10.9.0.0/30", "10.9.0.1", true, "10.9.0.2,10.9.0.2", "9.9.9.9 1.1.1.1"); err != nil || l.DNS != "9.9.9.9,1.1.1.1" {
		t.Fatalf("/30 with a one-address range: %+v %v", l, err)
	}
	const inj = "\ndhcp-script=/tmp/x"
	for _, tc := range []struct {
		cidr, gw   string
		dhcp       bool
		rng, dns   string
		wantErrHas string
	}{
		{"10.50.0.0/24" + inj, "", false, "", "", "isn't an IPv4 CIDR"},
		{"10.50.0.0/24", "10.50.0.1" + inj, false, "", "", "not an IPv4 address"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.100-200" + inj, "", "not an IPv4 address"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.100-200", "1.1.1.1" + inj, "isn't an IPv4 address"},
		{"fd00::/64", "", false, "", "", "isn't an IPv4 CIDR"},
		{"127.0.0.0/8", "", false, "", "", "reserved"},
		{"", "10.50.0.1", false, "", "", "needs the subnet"},
		{"10.50.0.0/24", "10.51.0.1", false, "", "", "inside 10.50.0.0/24"},
		{"10.50.0.0/24", "10.50.0.0", false, "", "", "network or broadcast"},
		{"10.50.0.0/24", "10.50.0.255", false, "", "", "network or broadcast"},
		{"10.50.0.0/31", "10.50.0.1", false, "", "", "no room for a gateway"},
		{"10.50.0.0/24", "", true, "10.50.0.100-200", "", "DHCP needs a gateway"},
		{"10.50.0.0/24", "10.50.0.1", true, "", "", "range is required"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.200-100", "", "starts after it ends"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.1-50", "", "includes the gateway"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.100,10.50.1.10", "", "inside 10.50.0.0/24"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.100-200", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5", "at most 4"},
		{"10.50.0.0/24", "10.50.0.1", true, "10.50.0.100-200", "dns.example", "isn't an IPv4 address"},
	} {
		if _, err := parseTenantL3(tc.cidr, tc.gw, tc.dhcp, tc.rng, tc.dns); err == nil || !strings.Contains(err.Error(), tc.wantErrHas) {
			t.Errorf("%+v: err=%v, want %q", tc, err, tc.wantErrHas)
		}
	}
}

func TestDefaultDHCPRange(t *testing.T) {
	for _, tc := range []struct{ cidr, gw, want string }{
		{"10.50.0.0/24", "10.50.0.1", "10.50.0.100,10.50.0.200"},
		{"10.50.0.0/24", "10.50.0.150", "10.50.0.1,10.50.0.127"}, // gateway in .100-.200 and the upper half
		{"10.50.0.0/28", "10.50.0.1", "10.50.0.8,10.50.0.14"},
		{"10.50.0.0/28", "10.50.0.9", "10.50.0.1,10.50.0.7"},
		{"10.50.0.0/31", "", ""},
		{"fd00::/64", "", ""},
	} {
		if got := defaultDHCPRange(tc.cidr, tc.gw); got != tc.want {
			t.Errorf("defaultDHCPRange(%s, %s) = %q, want %q", tc.cidr, tc.gw, got, tc.want)
		}
		if tc.want != "" {
			if _, err := parseTenantL3(tc.cidr, tc.gw, true, tc.want, ""); err != nil {
				t.Errorf("the default range %s must itself validate: %v", tc.want, err)
			}
		}
	}
	// A row saved before DHCP settings were: the old defaults.
	if l := storedL3("10.3.0.0/24", "10.3.0.1", true, "", ""); !l.DHCP || l.Range != "10.3.0.100,10.3.0.200" || l.DNS != defaultTenantDNS {
		t.Fatalf("legacy row: %+v", l)
	}
	if l := storedL3("10.3.0.0/24", "", true, "", ""); l.DHCP {
		t.Fatalf("no gateway, no DHCP: %+v", l)
	}
}

// TestHostOverlap: a tenant subnet may not overlap a host interface subnet or
// route (either containing the other); only an instance admin is told which.
func TestHostOverlap(t *testing.T) {
	stubTenantHost(t, []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.5.4/32"})
	for _, c := range []string{"192.168.1.128/25", "192.168.0.0/16", "10.200.0.0/24", "172.16.5.0/24"} {
		if err := checkHostOverlap(c, false); err == nil {
			t.Errorf("%s overlaps a host network and must be refused", c)
		} else if strings.Contains(err.Error(), "eth9") || strings.Contains(err.Error(), "192.168.1.0") {
			t.Errorf("a tenant must not be told the host's addressing: %v", err)
		}
	}
	if err := checkHostOverlap("192.168.1.0/24", true); err == nil || !strings.Contains(err.Error(), "192.168.1.0/24 (on eth9)") {
		t.Fatalf("an instance admin is told the host network: %v", err)
	}
	for _, c := range []string{"172.20.0.0/24", "192.168.2.0/24", ""} {
		if err := checkHostOverlap(c, false); err != nil {
			t.Errorf("%s doesn't overlap: %v", c, err)
		}
	}
	// A new org's default subnet skips what the host uses.
	if got := defaultOrgSubnet(3); got != "172.16.4.0/24" {
		t.Fatalf("default org subnet with 10/8 taken = %q", got)
	}
	stubTenantHost(t, nil)
	if got := defaultOrgSubnet(3); got != "10.4.0.0/24" {
		t.Fatalf("default org subnet = %q", got)
	}
}

// TestTenantNetworkCreateRefusals: create refuses bad addressing, a host
// overlap and a duplicate name before anything is built.
func TestTenantNetworkCreateRefusals(t *testing.T) {
	s, p, ins := tenantTestService(t)
	mkVSwitch(ins, p.OrgID, "app", "10.50.0.0/24", "10.50.0.1", 1)
	for _, tc := range []struct{ name, cidr, gw, want string }{
		{"lab", "192.168.1.0/24", "192.168.1.1", "overlaps a network the host itself uses"},
		{"app", "10.60.0.0/24", "10.60.0.1", "already has a vSwitch named"},
		{"lab", "10.60.0.0/24", "10.60.0.1\nport=53", "not an IPv4 address"},
		{"a/b", "10.60.0.0/24", "10.60.0.1", "no '/'"},
	} {
		if _, err := s.CreateTenantNetwork(p, tc.name, tc.cidr, tc.gw, false, "", "", ""); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err=%v, want %q", tc, err, tc.want)
		}
	}
	var tnet int64
	s.db.QueryRow(`SELECT id FROM tenant_networks WHERE name='app'`).Scan(&tnet)
	if _, err := s.CreateTenantPortGroup(p, tnet, "web", 10, "192.168.1.0/25", "192.168.1.1", false, "", "", ""); err == nil ||
		!strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("a port group overlapping the host must be refused: %v", err)
	}
}

// TestDefaultVSwitch: the default vSwitch can't be deleted; Make default moves
// the flag (exactly one default per org).
func TestDefaultVSwitch(t *testing.T) {
	s, p, ins := tenantTestService(t)
	a, _ := mkVSwitch(ins, p.OrgID, "default", "10.3.0.0/24", "10.3.0.1", 1)
	b, bNet := mkVSwitch(ins, p.OrgID, "lab", "", "", 0)
	if err := s.DeleteTenantNetwork(p, a, ""); err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("deleting the default vSwitch must be refused: %v", err)
	}
	if err := s.SetDefaultTenantNetwork(&Principal{User: p.User, OrgID: p.OrgID, OrgRole: "member"}, b, ""); err != ErrUnauthorized {
		t.Fatalf("a member can't change the default: %v", err)
	}
	if err := s.SetDefaultTenantNetwork(&Principal{User: p.User, OrgID: p.OrgID + 9, OrgRole: "admin"}, b, ""); err == nil {
		t.Fatalf("another org can't reach this vSwitch")
	}
	if err := s.SetDefaultTenantNetwork(p, b, ""); err != nil {
		t.Fatal(err)
	}
	if got := s.defaultTenantNetworkFor(p.OrgID); got != bNet {
		t.Fatalf("default network = %d, want %d", got, bNet)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM tenant_networks WHERE org_id=? AND is_default=1`, p.OrgID).Scan(&n)
	if n != 1 {
		t.Fatalf("%d defaults", n)
	}
	if err := s.DeleteTenantNetwork(p, b, ""); err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("the new default is protected too: %v", err)
	}
}

// TestTenantEdits: renames (vSwitch + port group) touch only the DB; a subnet
// change is refused while something is attached; a routed port group's
// addressing belongs to its router.
func TestTenantEdits(t *testing.T) {
	s, p, ins := tenantTestService(t)
	tnet, netID := mkVSwitch(ins, p.OrgID, "default", "10.3.0.0/24", "10.3.0.1", 1)
	pgNet := ins(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr,gateway) VALUES(?,'default/web','bridge','vdxt1',10,'10.60.0.0/24','10.60.0.1')`, p.OrgID)
	pg := ins(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id,dhcp,dhcp_range,dhcp_dns) VALUES(?,?,'web',10,?,1,'10.60.0.100-200','')`, p.OrgID, tnet, pgNet)
	dbNet := ins(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr) VALUES(?,'default/db','bridge','vdxt1',20,'10.70.0.0/24')`, p.OrgID)
	dbPG := ins(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id,vrouter_id) VALUES(?,?,'db',20,?,7)`, p.OrgID, tnet, dbNet)

	if err := s.UpdateTenantNetwork(p, tnet, PortGroupEdit{Name: "main"}, ""); err != nil {
		t.Fatalf("rename: %v", err)
	}
	var vsName, defName, pgName string
	s.db.QueryRow(`SELECT name FROM tenant_networks WHERE id=?`, tnet).Scan(&vsName)
	s.db.QueryRow(`SELECT name FROM networks WHERE id=?`, netID).Scan(&defName)
	s.db.QueryRow(`SELECT name FROM networks WHERE id=?`, pgNet).Scan(&pgName)
	if vsName != "main" || defName != "main" || pgName != "main/web" {
		t.Fatalf("rename: vSwitch %q, untagged PG %q, port group %q", vsName, defName, pgName)
	}
	if err := s.UpdateTenantPortGroup(p, pg, PortGroupEdit{Name: "frontend"}, ""); err != nil {
		t.Fatalf("port group rename: %v", err)
	}
	s.db.QueryRow(`SELECT name FROM networks WHERE id=?`, pgNet).Scan(&pgName)
	if pgName != "main/frontend" {
		t.Fatalf("port group backing name %q", pgName)
	}
	if err := s.UpdateTenantPortGroup(p, pg, PortGroupEdit{Name: "db"}, ""); err == nil || !strings.Contains(err.Error(), "already has a port group named") {
		t.Fatalf("duplicate port group name: %v", err)
	}
	// The same addressing posted back, written differently, isn't a change.
	if !sameAddr(tenantL3{CIDR: "10.60.0.0/24", Gateway: "10.60.0.1"}, tenantL3{CIDR: "10.60.0.9/24", Gateway: " 10.60.0.1"}) {
		t.Fatalf("sameAddr must compare canonical forms")
	}

	// A router's external interface on the web port group locks its subnet.
	vr := ins(`INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge','netns')`, p.OrgID)
	ins(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,vlan_id) VALUES(?,1,'uplink',?,10)`, vr, tenantBridgeName(netID))
	err := s.UpdateTenantPortGroup(p, pg, PortGroupEdit{Name: "frontend", L3: true, CIDR: "10.61.0.0/24", Gateway: "10.61.0.1"}, "")
	if err == nil || !strings.Contains(err.Error(), "edge's external interface") {
		t.Fatalf("subnet change under a router's external interface: %v", err)
	}
	err = s.UpdateTenantPortGroup(p, dbPG, PortGroupEdit{Name: "db", L3: true, CIDR: "10.71.0.0/24"}, "")
	if err == nil || !strings.Contains(err.Error(), "on the router") {
		t.Fatalf("a routed port group's addressing belongs to its router: %v", err)
	}
	if err := s.UpdateTenantPortGroup(p, pg, PortGroupEdit{Name: "frontend", L3: true, CIDR: "10.60.0.0/24", Gateway: "10.60.0.1",
		DHCP: true, DHCPRange: "10.60.0.100-200", DNS: "1.1.1.1\nport=53"}, ""); err == nil {
		t.Fatalf("an injected DNS server must be refused")
	}
	tnets, _ := s.ListTenantNetworks(p)
	for _, x := range tnets[0].PortGroups {
		if x.ID == pg && (x.ExtRouter != "edge" || !x.AddrLocked) {
			t.Fatalf("listing: %+v", x)
		}
	}
}

// TestUplinkLegGuards: a router's external interface pins what the vSwitch's
// external network must carry — disconnect, delete, a mode / native change, and
// deleting the port group it sits on are refused while it is there.
func TestUplinkLegGuards(t *testing.T) {
	s, p, ins := tenantTestService(t)
	tnet, netID := mkVSwitch(ins, p.OrgID, "default", "", "", 1)
	trunk := ins(`INSERT INTO ext_trunks(iface,kind) VALUES('vxtest0','nic')`)
	up := ins(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan',?,'qinq',100)`, p.OrgID, trunk)
	ins(`UPDATE tenant_networks SET uplink_id=? WHERE id=?`, up, tnet)
	pgNet := ins(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'default/wan','bridge',?,10)`, p.OrgID, tenantBridgeName(netID))
	pg := ins(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'wan',10,?)`, p.OrgID, tnet, pgNet)
	vr := ins(`INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge','netns')`, p.OrgID)
	ins(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,vlan_id) VALUES(?,1,'uplink',?,10)`, vr, tenantBridgeName(netID))

	if err := s.checkUplinkLegs(tnet, "qinq", 0); err != nil {
		t.Fatalf("QinQ carries VLAN 10: %v", err)
	}
	if err := s.checkUplinkLegs(tnet, "access", 10); err != nil {
		t.Fatalf("access with VLAN 10 native carries it: %v", err)
	}
	if err := s.checkUplinkLegs(tnet, "access", 0); err == nil {
		t.Fatalf("access with the untagged PG native doesn't carry VLAN 10")
	}
	if err := s.DisconnectNetworkUplink(p, tnet, ""); err == nil || !strings.Contains(err.Error(), "external interface") {
		t.Fatalf("disconnect under a router external interface: %v", err)
	}
	if err := s.DeleteUplink(egressAdmin, up, ""); err == nil || !strings.Contains(err.Error(), "external interface") {
		t.Fatalf("deleting the external network under a router external interface: %v", err)
	}
	if err := s.DeleteTenantPortGroup(p, pg, ""); err == nil || !strings.Contains(err.Error(), "external interface") {
		t.Fatalf("deleting the port group a router external interface is on: %v", err)
	}
	var still int
	s.db.QueryRow(`SELECT COUNT(*) FROM tenant_networks WHERE uplink_id=?`, up).Scan(&still)
	if still != 1 {
		t.Fatalf("refusals must leave the vSwitch connected")
	}
}

// TestDeleteNativePortGroup: deleting the native port group makes the untagged
// one native — refused when that one is routed (it would be carried out).
func TestDeleteNativePortGroup(t *testing.T) {
	s, p, ins := tenantTestService(t)
	tnet, netID := mkVSwitch(ins, p.OrgID, "default", "", "", 1)
	ins(`UPDATE tenant_networks SET vrouter_id=7, native_vlan=10 WHERE id=?`, tnet)
	trunk := ins(`INSERT INTO ext_trunks(iface,kind) VALUES('vxtest0','nic')`)
	up := ins(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan',?,'access',100)`, p.OrgID, trunk)
	ins(`UPDATE tenant_networks SET uplink_id=? WHERE id=?`, up, tnet)
	pgNet := ins(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'default/out','bridge',?,10)`, p.OrgID, tenantBridgeName(netID))
	pg := ins(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'out',10,?)`, p.OrgID, tnet, pgNet)
	err := s.DeleteTenantPortGroup(p, pg, "")
	if err == nil || !strings.Contains(err.Error(), "native port group") || !strings.Contains(err.Error(), "routed") {
		t.Fatalf("deleting the native PG over a routed untagged PG must be refused: %v", err)
	}
	var native int
	s.db.QueryRow(`SELECT native_vlan FROM tenant_networks WHERE id=?`, tnet).Scan(&native)
	if native != 10 {
		t.Fatalf("a refused delete must leave the native VLAN alone, got %d", native)
	}
}

// TestConnectRefusesSecondUplink: a vSwitch has one external network.
func TestConnectRefusesSecondUplink(t *testing.T) {
	s, p, ins := tenantTestService(t)
	tnet, _ := mkVSwitch(ins, p.OrgID, "default", "", "", 1)
	trunk := ins(`INSERT INTO ext_trunks(iface,kind) VALUES('vxtest0','nic')`)
	u1 := ins(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan',?,'access',100)`, p.OrgID, trunk)
	u2 := ins(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan2',?,'access',101)`, p.OrgID, trunk)
	ins(`UPDATE tenant_networks SET uplink_id=? WHERE id=?`, u1, tnet)
	if err := s.ConnectNetworkUplink(p, tnet, u2, ""); err == nil || !strings.Contains(err.Error(), "already connected") {
		t.Fatalf("a second external network on one vSwitch must be refused: %v", err)
	}
}

// TestTrunkReservedVIDs: the allocator never hands a tenant a tag the host uses
// on the trunk — the admin's port groups on the bridge the trunk is the uplink
// of, or a VLAN interface already on it — and an explicit tag says why not.
func TestTrunkReservedVIDs(t *testing.T) {
	s, a, _, trunk := egressTestService(t)
	trunkMaster = func(iface string) string {
		if iface == "vxtest0" {
			return "vxbr0"
		}
		return ""
	}
	trunkVlanSubs = func(iface string) (map[int]string, error) {
		return map[int]string{102: "vxtest0.102", 103: "vxtest0.103"}, nil
	}
	s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(1,'storage','bridge','vxbr0',100)`)
	if err := s.SetVlanPool(egressAdmin, a, trunk, 100, 104, ""); err != nil {
		t.Fatal(err)
	}
	// 103 is the device of a's own (connected) uplink: not reserved.
	if _, err := s.db.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'own',?,'access',103)`, a, trunk); err != nil {
		t.Fatal(err)
	}
	res := s.trunkReservedVIDs(trunk)
	if len(res) != 2 || !strings.Contains(res[100], "storage") || !strings.Contains(res[102], "vxtest0.102") {
		t.Fatalf("reserved: %v", res)
	}
	id, err := s.CreateUplink(egressAdmin, a, "wan", "access", trunk, 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, vid := uplinkVID(t, s, id); vid != 104 && vid != 101 {
		t.Fatalf("allocated VLAN %d, want a free one (101 or 104)", vid)
	}
	for vid, want := range map[int]string{100: "storage", 102: "vxtest0.102"} {
		if _, err := s.CreateUplink(egressAdmin, a, "x", "access", trunk, vid, "", ""); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("explicit VLAN %d: %v", vid, err)
		}
	}
}

// TestCheckTenantClaims: an admin port group can't take a VLAN a tenant's
// external network holds on the same uplink, nor a VNI reserved for a tenant
// segment; a tenant bridge's own VLANs are private.
func TestCheckTenantClaims(t *testing.T) {
	s, a, _, trunk := egressTestService(t)
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vs1','vxbr9','vxtest0')`)
	if _, err := s.db.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan',?,'access',150)`, a, trunk); err != nil {
		t.Fatal(err)
	}
	if err := s.checkTenantClaims(netdrv.Network{Bridge: "vxbr9", VLANID: 150}); err == nil || !strings.Contains(err.Error(), `external network "wan"`) {
		t.Fatalf("VLAN held by a tenant: %v", err)
	}
	for _, n := range []netdrv.Network{{Bridge: "vxbr9", VLANID: 151}, {Bridge: "vdxt5", VLANID: 150}, {Bridge: "vxbr9"}} {
		if err := s.checkTenantClaims(n); err != nil {
			t.Fatalf("%+v: %v", n, err)
		}
	}
	s.db.Exec(`INSERT INTO net_segments(seg_type,seg_id,org_id,net_id) VALUES('vxlan',200001,?,77)`, a)
	if err := s.checkTenantClaims(netdrv.Network{Mode: "vxlan", VNI: 200001}); err == nil || !strings.Contains(err.Error(), "VNI 200001") {
		t.Fatalf("reserved VNI: %v", err)
	}
}

// TestReconcileSegmentIdentities: orphans are released; tenant vSwitches and
// port groups without an identity get one.
func TestReconcileSegmentIdentities(t *testing.T) {
	s, p, ins := tenantTestService(t)
	tnet, netID := mkVSwitch(ins, p.OrgID, "default", "", "", 1)
	pgNet := ins(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'default/web','bridge','vdxt1',10)`, p.OrgID)
	ins(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'web',10,?)`, p.OrgID, tnet, pgNet)
	ins(`INSERT INTO net_segments(seg_type,seg_id,org_id,net_id) VALUES('vxlan',200500,?,9999)`, p.OrgID)
	s.reconcileSegmentIdentities()
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM net_segments WHERE net_id=9999`).Scan(&n)
	if n != 0 {
		t.Fatalf("orphan identity kept")
	}
	for _, id := range []int64{netID, pgNet} {
		s.db.QueryRow(`SELECT COUNT(*) FROM net_segments WHERE net_id=?`, id).Scan(&n)
		if n != 1 {
			t.Fatalf("network %d has %d identities, want 1", id, n)
		}
	}
	s.reconcileSegmentIdentities() // idempotent
	s.db.QueryRow(`SELECT COUNT(*) FROM net_segments`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d identities after a second run, want 2", n)
	}
}

// TestSharedTrunkCandidate: only a physical NIC or bond on the management
// bridge — never a tap / veth / VLAN / VXLAN that merely sits on it, nor the
// storage interface, nor a name too long for its VLAN interfaces.
func TestSharedTrunkCandidate(t *testing.T) {
	for _, tc := range []struct {
		it   hostinfo.Iface
		want bool
	}{
		{hostinfo.Iface{Name: "bond0", Type: "bond", Master: "br0"}, true},
		{hostinfo.Iface{Name: "eno1", Type: "physical", Master: "br0"}, true},
		{hostinfo.Iface{Name: "eno2", Type: "physical", Master: "br1"}, false},
		{hostinfo.Iface{Name: "vdxt1a2b3c4d5e6", Type: "tap", Master: "br0"}, false},
		{hostinfo.Iface{Name: "vrh3e1", Type: "other", Master: "br0"}, false},
		{hostinfo.Iface{Name: "bond0.50", Type: "vlan", Master: "br0"}, false},
		{hostinfo.Iface{Name: "vx100", Type: "vxlan", Master: "br0"}, false},
		{hostinfo.Iface{Name: "enp3s0f1", Type: "physical", Master: "br0"}, false}, // storage
		{hostinfo.Iface{Name: "enx0123456789ab", Type: "physical", Master: "br0"}, false},
	} {
		if got := sharedTrunkCandidate(tc.it, "br0", "enp3s0f1"); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc.it, got, tc.want)
		}
	}
}

// TestTeardownResume: a resumed teardown only takes down external networks on
// trunks already marked for it, and removes such a trunk once nothing rides it.
func TestTeardownResume(t *testing.T) {
	s, a, b, _ := egressTestService(t)
	// Shared trunks: their parent is never modified, so nothing here runs a
	// command against an interface.
	pend, _ := s.db.Exec(`INSERT INTO ext_trunks(iface,kind,shared,teardown_pending) VALUES('vxtest1','bond',1,1)`)
	pendID, _ := pend.LastInsertId()
	live, _ := s.db.Exec(`INSERT INTO ext_trunks(iface,kind,shared) VALUES('vxtest2','bond',1)`)
	liveID, _ := live.LastInsertId()
	s.db.Exec(`INSERT INTO tenant_vlan_pools(org_id,trunk_id,vid_min,vid_max) VALUES(?,?,100,109)`, a, pendID)
	s.db.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan',?,'access',100)`, a, pendID)
	s.db.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,'wan',?,'access',100)`, b, liveID)
	if err := s.teardownTenantEgress(true); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE trunk_id=?`, pendID).Scan(&n)
	if n != 0 {
		t.Fatalf("the pending trunk's external network must be gone")
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM ext_trunks WHERE id=?`, pendID).Scan(&n)
	if n != 0 {
		t.Fatalf("the emptied pending trunk must be removed")
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE trunk_id=?`, liveID).Scan(&n)
	if n != 1 {
		t.Fatalf("a resume must not touch a trunk that isn't being torn down")
	}
}

func TestCheckTrunkName(t *testing.T) {
	if err := netdrv.CheckTrunkName("bond0"); err != nil {
		t.Fatal(err)
	}
	if err := netdrv.CheckTrunkName("enx0123456789ab"); err == nil || !strings.Contains(err.Error(), "10 characters") {
		t.Fatalf("a name whose .4094 subinterface can't exist: %v", err)
	}
}
