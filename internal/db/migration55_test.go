package db

import (
	"path/filepath"
	"testing"
)

// TestMigrations55to57 runs the snapshot migrations (policies, snapshots-v2,
// snapshot clones) through the real modernc driver on a fresh DB and checks the
// constraints the snapshot code relies on: the immutable⇒keep_days CHECK, the
// per-org unique policy name, policy delete detaching (not deleting) its
// snapshots, and the RESTRICT that stops a purge from dropping a snapshot an
// instant clone still depends on.
func TestMigrations55to57(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 57 must apply clean): %v", err)
	}
	defer d.Close()

	var org int64
	if err := d.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&org); err != nil {
		t.Fatalf("default org: %v", err)
	}
	res, err := d.Exec(`INSERT INTO orgs(name,slug) VALUES('Acme','acme')`)
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	acme, _ := res.LastInsertId()

	// ---- snapshot_policies ----
	if _, err := d.Exec(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule,immutable,keep_days)
		VALUES(?,?,?,?,1,0)`, org, "bad", "org", "daily"); err == nil {
		t.Fatalf("immutable policy without keep_days was accepted")
	}
	if _, err := d.Exec(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule) VALUES(?,?,?,?)`,
		org, "x", "datacenter", "daily"); err == nil {
		t.Fatalf("unknown target_kind was accepted")
	}
	res, err = d.Exec(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule,immutable,keep_days,keep_last)
		VALUES(?,?,?,?,1,7,24)`, org, "nightly", "org", "daily")
	if err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	pol, _ := res.LastInsertId()
	if _, err := d.Exec(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule) VALUES(?,?,?,?)`,
		org, "nightly", "org", "hourly"); err == nil {
		t.Fatalf("duplicate policy name in one org was accepted")
	}
	if _, err := d.Exec(`INSERT INTO snapshot_policies(org_id,name,target_kind,schedule) VALUES(?,?,?,?)`,
		acme, "nightly", "org", "hourly"); err != nil {
		t.Fatalf("same name in another org should be fine: %v", err)
	}

	// ---- snapshots-v2 + snapshot_clones ----
	if _, err := d.Exec(`INSERT INTO users(username,password_hash) VALUES('u','x')`); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO images(name,path) VALUES('img','/x')`); err != nil {
		t.Fatalf("image: %v", err)
	}
	for _, id := range []string{"origin", "clone"} {
		if _, err := d.Exec(`INSERT INTO sessions(id,name,owner_id,image_name,disk_path,org_id) VALUES(?,?,1,'img','/d',?)`, id, id, org); err != nil {
			t.Fatalf("session %s: %v", id, err)
		}
	}
	res, err = d.Exec(`INSERT INTO snapshots(session_id,name,tag,backend,ref,consistency,policy_id,locked_until)
		VALUES('origin','n1','snap-1','zvol','tank/vdx-1@snap-1','app',?,'2099-01-01T00:00:00Z')`, pol)
	if err != nil {
		t.Fatalf("insert v2 snapshot: %v", err)
	}
	snap, _ := res.LastInsertId()
	var cons, backend string
	var transient int
	if err := d.QueryRow(`SELECT consistency,backend,transient FROM snapshots WHERE id=?`, snap).Scan(&cons, &backend, &transient); err != nil ||
		cons != "app" || backend != "zvol" || transient != 0 {
		t.Fatalf("snapshot row = %q %q %d err=%v", cons, backend, transient, err)
	}
	// A legacy-style insert (old binary) still works and gets the defaults.
	if _, err := d.Exec(`INSERT INTO snapshots(session_id,name,tag,online) VALUES('origin','legacy','snap-2',1)`); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}

	// Deleting the policy detaches its snapshots (policy_id → NULL); the lock stays.
	if _, err := d.Exec(`DELETE FROM snapshot_policies WHERE id=?`, pol); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	var polRef *int64
	var locked *string
	if err := d.QueryRow(`SELECT policy_id, locked_until FROM snapshots WHERE id=?`, snap).Scan(&polRef, &locked); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if polRef != nil || locked == nil {
		t.Fatalf("after policy delete: policy_id=%v locked_until=%v (want NULL, kept)", polRef, locked)
	}

	// A dependent clone pins its base snapshot: purging the origin (cascade to
	// its snapshots) must fail while the dependency is recorded.
	if _, err := d.Exec(`INSERT INTO snapshot_clones(clone_id,origin_id,origin_name,snapshot_id,snapshot_name,backend,method)
		VALUES('clone','origin','origin',?,'n1','zvol','zfs-clone')`, snap); err != nil {
		t.Fatalf("insert clone link: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM snapshots WHERE id=?`, snap); err == nil {
		t.Fatalf("deleted a snapshot a clone depends on")
	}
	if _, err := d.Exec(`DELETE FROM sessions WHERE id='origin'`); err == nil {
		t.Fatalf("purged an origin whose snapshot a clone depends on")
	}
	// Once detached (promote/flatten), the origin can go and the link survives.
	if _, err := d.Exec(`UPDATE snapshot_clones SET snapshot_id=NULL WHERE clone_id='clone'`); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM sessions WHERE id='origin'`); err != nil {
		t.Fatalf("purge origin after detach: %v", err)
	}
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM snapshot_clones WHERE clone_id='clone'`).Scan(&n)
	if n != 1 {
		t.Fatalf("clone link lost with the origin (n=%d)", n)
	}
	// Purging the clone itself cascades its link away.
	if _, err := d.Exec(`DELETE FROM sessions WHERE id='clone'`); err != nil {
		t.Fatalf("purge clone: %v", err)
	}
	_ = d.QueryRow(`SELECT COUNT(*) FROM snapshot_clones`).Scan(&n)
	if n != 0 {
		t.Fatalf("clone link survived its clone (n=%d)", n)
	}
}
