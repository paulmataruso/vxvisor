package service

import (
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/db"
	"vdxclone/internal/store"
)

// egressTestService: a DB with two tenants ("a", "b") and one dedicated trunk on
// an interface that doesn't exist, so nothing here touches a host device (every
// uplink stays unbound: no subinterface is ever created).
func egressTestService(t *testing.T) (s *Service, a, b, trunk int64) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	s = &Service{db: d, store: store.New(d)}
	stubTenantHost(t, nil)
	ins := func(q string, args ...any) int64 {
		t.Helper()
		res, err := d.Exec(q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	a = ins(`INSERT INTO orgs(name,slug) VALUES('a','a')`)
	b = ins(`INSERT INTO orgs(name,slug) VALUES('b','b')`)
	trunk = ins(`INSERT INTO ext_trunks(iface,kind,qinq_capable) VALUES('vxtest0','nic',0)`)
	return
}

var egressAdmin = &Principal{User: &auth.User{ID: 1, Username: "root"}, IsAdmin: true, OrgID: 1, OrgRole: "owner"}

func uplinkVID(t *testing.T, s *Service, id int64) (string, int) {
	t.Helper()
	var name string
	var vid int
	if err := s.db.QueryRow(`SELECT name,outer_vid FROM tenant_uplinks WHERE id=?`, id).Scan(&name, &vid); err != nil {
		t.Fatalf("uplink %d: %v", id, err)
	}
	return name, vid
}

// TestPoolRangeEdits: a pool can't overlap another tenant's pool or tag on the
// trunk, and can't shrink past a tag one of its own uplinks holds.
func TestPoolRangeEdits(t *testing.T) {
	s, a, b, trunk := egressTestService(t)
	if err := s.SetVlanPool(egressAdmin, a, trunk, 100, 109, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVlanPool(egressAdmin, b, trunk, 105, 120, ""); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping a's pool must be refused, got %v", err)
	}
	u, err := s.createUplink(egressAdmin, a, "wan", "access", trunk, 108, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetVlanPool(egressAdmin, a, trunk, 100, 104, ""); err == nil || !strings.Contains(err.Error(), "leaves out") {
		t.Fatalf("shrinking past wan's VLAN 108 must be refused, got %v", err)
	}
	if err := s.SetVlanPool(egressAdmin, a, trunk, 106, 115, ""); err != nil {
		t.Fatalf("a range that still holds 108 is fine: %v", err)
	}
	// b's explicit tag outside every pool still blocks a's pool from covering it.
	if err := s.SetVlanPool(egressAdmin, b, trunk, 200, 209, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.createUplink(egressAdmin, b, "wan", "access", trunk, 205, "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVlanPool(egressAdmin, a, trunk, 106, 205, ""); err == nil {
		t.Fatalf("covering b's pool / tag 205 must be refused")
	}
	if _, vid := uplinkVID(t, s, u); vid != 108 {
		t.Fatalf("a refused pool edit must not touch the uplink, vid=%d", vid)
	}
}

// TestUpdateUplinkUnbound: rename and retag an unconnected uplink; a clash
// leaves the old wiring in place; QinQ needs a QinQ-capable trunk.
func TestUpdateUplinkUnbound(t *testing.T) {
	s, a, b, trunk := egressTestService(t)
	_ = s.SetVlanPool(egressAdmin, a, trunk, 100, 109, "")
	_ = s.SetVlanPool(egressAdmin, b, trunk, 200, 209, "")
	u, _ := s.createUplink(egressAdmin, a, "wan", "access", trunk, 0, "", "", false)
	other, _ := s.createUplink(egressAdmin, a, "wan2", "access", trunk, 0, "", "", false)
	if _, vid := uplinkVID(t, s, u); vid != 100 {
		t.Fatalf("first auto tag = %d, want 100", vid)
	}
	if err := s.UpdateUplink(egressAdmin, u, "internet", "access", trunk, 105, "", ""); err != nil {
		t.Fatal(err)
	}
	if name, vid := uplinkVID(t, s, u); name != "internet" || vid != 105 {
		t.Fatalf("got %s/%d, want internet/105", name, vid)
	}
	_, otherVID := uplinkVID(t, s, other)
	if err := s.UpdateUplink(egressAdmin, u, "internet", "access", trunk, otherVID, "", ""); err == nil {
		t.Fatalf("retag onto wan2's VLAN %d must be refused", otherVID)
	}
	if name, vid := uplinkVID(t, s, u); name != "internet" || vid != 105 {
		t.Fatalf("a failed retag must restore the old wiring, got %s/%d", name, vid)
	}
	if err := s.UpdateUplink(egressAdmin, u, "wan2", "access", trunk, 105, "", ""); err == nil {
		t.Fatalf("renaming onto wan2 must be refused")
	}
	if err := s.UpdateUplink(egressAdmin, u, "internet", "qinq", trunk, 105, "", ""); err == nil {
		t.Fatalf("QinQ on a non-QinQ trunk must be refused")
	}
	if err := s.UpdateUplink(egressAdmin, u, "internet", "access", trunk, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, vid := uplinkVID(t, s, u); vid < 100 || vid > 109 || vid == otherVID {
		t.Fatalf("tag 0 = next free from the pool, got %d", vid)
	}
	if err := s.UpdateUplink(&Principal{OrgID: a, OrgRole: "owner"}, u, "x", "access", trunk, 0, "", ""); err != ErrUnauthorized {
		t.Fatalf("org admins can't edit uplinks, got %v", err)
	}
}

// TestSetUplinkConnectionOrgGuard: an uplink only ever connects to its own
// tenant's vSwitch, and one that already has an uplink is refused.
func TestSetUplinkConnectionOrgGuard(t *testing.T) {
	s, a, b, trunk := egressTestService(t)
	_ = s.SetVlanPool(egressAdmin, a, trunk, 100, 109, "")
	u, _ := s.createUplink(egressAdmin, a, "wan", "access", trunk, 0, "", "", false)
	u2, _ := s.createUplink(egressAdmin, a, "wan2", "access", trunk, 0, "", "", false)
	theirNet, _ := s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'theirs','bridge','vdxt90')`, b)
	nid, _ := theirNet.LastInsertId()
	res, _ := s.db.Exec(`INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'theirs',?)`, b, nid)
	theirs, _ := res.LastInsertId()
	if err := s.SetUplinkConnection(egressAdmin, u, theirs, ""); err == nil || !strings.Contains(err.Error(), "doesn't belong") {
		t.Fatalf("connecting to another tenant's vSwitch must be refused, got %v", err)
	}
	ourNet, _ := s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'ours','bridge','vdxt91')`, a)
	nid, _ = ourNet.LastInsertId()
	res, _ = s.db.Exec(`INSERT INTO tenant_networks(org_id,name,network_id,uplink_id) VALUES(?,'ours',?,?)`, a, nid, u2)
	ours, _ := res.LastInsertId()
	if err := s.SetUplinkConnection(egressAdmin, u, ours, ""); err == nil || !strings.Contains(err.Error(), "already has an uplink") {
		t.Fatalf("a vSwitch with an uplink must be refused, got %v", err)
	}
	if err := s.SetUplinkConnection(egressAdmin, u2, ours, ""); err != nil {
		t.Fatalf("re-selecting the current vSwitch is a no-op, got %v", err)
	}
}

// TestEgressWizard: the wizard reserves the pool and creates the uplink; when a
// later step fails, the steps it already did are undone.
func TestEgressWizard(t *testing.T) {
	s, a, b, trunk := egressTestService(t)
	res, err := s.ProvisionTenantEgress(egressAdmin, EgressWizard{
		OrgID: a, TrunkID: trunk, PoolMin: 100, PoolMax: 109, UplinkName: "wan", Mode: "access",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Org != "a" || res.Trunk != "vxtest0" || res.Pool != "100-109" || res.Uplink != "wan (VLAN 100)" || res.VSwitch != "" {
		t.Fatalf("result %+v", res)
	}

	// b: its uplink's explicit tag is outside the pool it asked for → the
	// uplink step fails and the new pool is removed again.
	_, err = s.ProvisionTenantEgress(egressAdmin, EgressWizard{
		OrgID: b, TrunkID: trunk, PoolMin: 200, PoolMax: 209, UplinkName: "wan", Mode: "access", VID: 300,
	}, "")
	if err == nil || !strings.Contains(err.Error(), "undone") {
		t.Fatalf("want an undone failure, got %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM tenant_vlan_pools WHERE org_id=?`, b).Scan(&n)
	if n != 0 {
		t.Fatalf("b's pool must be rolled back")
	}

	// a again, widening its pool, then pointing at b's vSwitch → refused; the
	// new uplink is deleted and the pool goes back to 100-109.
	theirNet, _ := s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'theirs','bridge','vdxt90')`, b)
	nid, _ := theirNet.LastInsertId()
	r, _ := s.db.Exec(`INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'theirs',?)`, b, nid)
	theirs, _ := r.LastInsertId()
	_, err = s.ProvisionTenantEgress(egressAdmin, EgressWizard{
		OrgID: a, TrunkID: trunk, PoolMin: 100, PoolMax: 119, UplinkName: "wan2", Mode: "access", VSwitchID: theirs,
	}, "")
	if err == nil || !strings.Contains(err.Error(), "doesn't belong") {
		t.Fatalf("another tenant's vSwitch must be refused, got %v", err)
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE org_id=?`, a).Scan(&n)
	lo, hi, _ := s.poolRange(a, trunk)
	if n != 1 || lo != 100 || hi != 109 {
		t.Fatalf("rollback: %d uplinks, pool %d-%d (want 1, 100-109)", n, lo, hi)
	}

	// An existing uplink of another tenant is refused; a non-admin is refused.
	var wan int64
	s.db.QueryRow(`SELECT id FROM tenant_uplinks WHERE org_id=? AND name='wan'`, a).Scan(&wan)
	if _, err := s.ProvisionTenantEgress(egressAdmin, EgressWizard{OrgID: b, TrunkID: trunk, UplinkID: wan}, ""); err == nil {
		t.Fatalf("b can't take a's uplink")
	}
	if _, err := s.ProvisionTenantEgress(&Principal{OrgID: a, OrgRole: "owner"}, EgressWizard{OrgID: a}, ""); err != ErrUnauthorized {
		t.Fatalf("org admins can't run the wizard, got %v", err)
	}
}
