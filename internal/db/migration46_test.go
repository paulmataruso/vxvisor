package db

import (
	"path/filepath"
	"testing"
)

// TestMigration46 validates tenant-net-v3 (migration 46) against the real
// modernc driver: that every statement applies cleanly on a fresh DB (the gating
// check — a bad statement would quarantine the live DB via OpenResilient), that
// the standalone partial unique index behaves (many outer_vid=0 rows coexist, a
// duplicate non-zero tag on the same trunk is rejected), that the uplink_id
// column exists on tenant_networks, and that org cascade / trunk restrict hold.
func TestMigration46(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 46 must apply clean): %v", err)
	}
	defer d.Close()

	// New objects exist.
	for _, tbl := range []string{"ext_trunks", "tenant_vlan_pools", "tenant_uplinks"} {
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing (n=%d err=%v)", tbl, n, err)
		}
	}
	// uplink_id column on tenant_networks.
	if _, err := d.Exec(`SELECT uplink_id FROM tenant_networks LIMIT 0`); err != nil {
		t.Fatalf("tenant_networks.uplink_id missing: %v", err)
	}

	// Seed an org + a trunk.
	if _, err := d.Exec(`INSERT INTO orgs(name,slug) VALUES('t','t')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	var orgID int64
	d.QueryRow(`SELECT id FROM orgs WHERE slug='t'`).Scan(&orgID)
	res, err := d.Exec(`INSERT INTO ext_trunks(iface,kind) VALUES('bond0','bond')`)
	if err != nil {
		t.Fatalf("insert trunk: %v", err)
	}
	trunkID, _ := res.LastInsertId()

	// Partial unique index: multiple outer_vid=0 rows coexist on the same trunk.
	for _, nm := range []string{"u-ded-a", "u-ded-b", "u-unbound"} {
		if _, err := d.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,?,?,?,0)`, orgID, nm, trunkID, "dedicated"); err != nil {
			t.Fatalf("outer_vid=0 row %s should be allowed: %v", nm, err)
		}
	}
	// A non-zero tag is accepted once...
	if _, err := d.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,?,?,?,100)`, orgID, "u-100", trunkID, "access"); err != nil {
		t.Fatalf("first vid 100 should be allowed: %v", err)
	}
	// ...and a duplicate non-zero tag on the same trunk is rejected.
	if _, err := d.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,?,?,?,100)`, orgID, "u-100-dup", trunkID, "access"); err == nil {
		t.Fatalf("duplicate vid 100 on the same trunk must be rejected by the partial unique index")
	}

	// trunk RESTRICT: a trunk with uplinks can't be deleted.
	if _, err := d.Exec(`DELETE FROM ext_trunks WHERE id=?`, trunkID); err == nil {
		t.Fatalf("deleting a trunk with uplinks must be FK-restricted")
	}

	// org CASCADE: deleting the org removes its uplinks (and pools).
	if _, err := d.Exec(`INSERT INTO tenant_vlan_pools(org_id,trunk_id,vid_min,vid_max) VALUES(?,?,100,199)`, orgID, trunkID); err != nil {
		t.Fatalf("insert pool: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM orgs WHERE id=?`, orgID); err != nil {
		t.Fatalf("delete org (should cascade uplinks/pools): %v", err)
	}
	var left int
	d.QueryRow(`SELECT count(*) FROM tenant_uplinks`).Scan(&left)
	if left != 0 {
		t.Fatalf("org cascade left %d uplinks", left)
	}
	d.QueryRow(`SELECT count(*) FROM tenant_vlan_pools`).Scan(&left)
	if left != 0 {
		t.Fatalf("org cascade left %d pools", left)
	}
}
