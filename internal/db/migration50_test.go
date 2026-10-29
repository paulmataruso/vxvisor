package db

import (
	"path/filepath"
	"strconv"
	"testing"
)

// TestMigration50 validates the vSwitch uniqueness indexes (migration 50)
// through the real modernc driver: on a fresh DB they apply and hold (one
// vSwitch per uplink, one default per org, many unconnected / non-default rows);
// and on a DB that already has the duplicates a race could leave behind, the
// migration resolves them instead of failing (a failed migration quarantines the
// live DB) — the uplink stays with the vSwitch it is wired into, the oldest
// default stays the default.
func TestMigration50(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.db")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("open (migrations through 50 must apply clean): %v", err)
	}
	mustExec := func(q string, args ...any) int64 {
		t.Helper()
		res, err := d.Exec(q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	org := mustExec(`INSERT INTO orgs(name,slug) VALUES('acme','acme')`)
	vswitch := func(name string, def int) (int64, int64) {
		n := mustExec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,?,'bridge','')`, org, name)
		mustExec(`UPDATE networks SET bridge='vdxt'||id WHERE id=?`, n)
		return mustExec(`INSERT INTO tenant_networks(org_id,name,network_id,is_default) VALUES(?,?,?,?)`, org, name, n, def), n
	}
	a, _ := vswitch("a", 1)
	b, bNet := vswitch("b", 0)
	vswitch("c", 0) // unconnected, not default: many may coexist
	up := mustExec(`INSERT INTO tenant_uplinks(org_id,name,mode) VALUES(?,'wan','access')`, org)

	mustExec(`UPDATE tenant_networks SET uplink_id=? WHERE id=?`, up, a)
	if _, err := d.Exec(`UPDATE tenant_networks SET uplink_id=? WHERE id=?`, up, b); err == nil {
		t.Fatalf("one uplink on two vSwitches must be rejected")
	}
	if _, err := d.Exec(`UPDATE tenant_networks SET is_default=1 WHERE id=?`, b); err == nil {
		t.Fatalf("a second default vSwitch in one org must be rejected")
	}

	// Duplicates from before the index: drop the indexes, make both kinds of
	// duplicate, and run migration 50 again.
	mustExec(`DROP INDEX ux_tnet_uplink`)
	mustExec(`DROP INDEX ux_tnet_org_default`)
	mustExec(`UPDATE tenant_networks SET uplink_id=?, is_default=1 WHERE id=?`, up, b)
	mustExec(`UPDATE tenant_uplinks SET status='bound', egress_bridge=? WHERE id=?`, "vdxt"+strconv.FormatInt(bNet, 10), up)
	mustExec(`DELETE FROM schema_migrations WHERE version=50`)
	d.Close()
	if d, err = Open(path); err != nil {
		t.Fatalf("reopen (migration 50 must resolve duplicates, not fail): %v", err)
	}
	defer d.Close()
	var holder int64
	if err := d.QueryRow(`SELECT id FROM tenant_networks WHERE uplink_id=?`, up).Scan(&holder); err != nil || holder != b {
		t.Fatalf("uplink kept by vSwitch %d (err=%v), want %d — the one it is wired into", holder, err, b)
	}
	var def int64
	if err := d.QueryRow(`SELECT id FROM tenant_networks WHERE org_id=? AND is_default=1`, org).Scan(&def); err != nil || def != a {
		t.Fatalf("default kept by vSwitch %d (err=%v), want %d — the oldest", def, err, a)
	}
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('ux_tnet_uplink','ux_tnet_org_default')`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d of the 2 indexes present after the re-run", n)
	}
}
