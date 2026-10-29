package db

import (
	"path/filepath"
	"testing"
)

// TestMigration53And54 validates the CBT warm-import tables (53) and their
// unique indexes (54) through the real modernc driver on a fresh DB: they apply
// cleanly (a bad statement here would quarantine the live control plane), a
// second ACTIVE import of the same source VM is refused while a finished one is
// not, and snapshot names are unique.
func TestMigration53And54(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 54 must apply clean): %v", err)
	}
	defer d.Close()
	exec := func(q string, args ...any) error {
		_, err := d.Exec(q, args...)
		return err
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	imp := `INSERT INTO vmware_cbt_imports(id,vc_url,vc_host,vc_user,moid,consent,state) VALUES(?,?,?,?,?,1,?)`
	mustExec(imp, "a", "https://vc/sdk", "vc", "u", "vm-1", "syncing")
	if err := exec(imp, "b", "https://vc/sdk", "vc", "u", "vm-1", "starting"); err == nil {
		t.Fatal("a second active warm import of the same VM must be refused")
	}
	mustExec(imp, "c", "https://vc/sdk", "vc", "u", "vm-2", "starting")  // other VM: fine
	mustExec(imp, "d", "https://vc2/sdk", "vc2", "u", "vm-1", "syncing") // same moid, other vCenter: fine
	mustExec(`UPDATE vmware_cbt_imports SET state='done' WHERE id='a'`)
	mustExec(imp, "e", "https://vc/sdk", "vc", "u", "vm-1", "starting") // once the first ended
	mustExec(imp, "f", "https://vc/sdk", "vc", "u", "vm-9", "cancelled")
	mustExec(imp, "g", "https://vc/sdk", "vc", "u", "vm-9", "error")

	var cbtOrig, interval int
	var state string
	if err := d.QueryRow(`SELECT cbt_orig, interval_sec, state FROM vmware_cbt_imports WHERE id='c'`).Scan(&cbtOrig, &interval, &state); err != nil {
		t.Fatal(err)
	}
	if cbtOrig != -1 || interval != 1800 || state != "starting" {
		t.Fatalf("defaults: cbt_orig=%d interval=%d state=%s", cbtOrig, interval, state)
	}

	mustExec(`INSERT INTO vmware_cbt_disks(import_id,device_key,idx,capacity,staging) VALUES('c',2000,0,1024,'/x')`)
	if err := exec(`INSERT INTO vmware_cbt_disks(import_id,device_key,idx,capacity,staging) VALUES('nope',2000,0,1024,'/x')`); err == nil {
		t.Fatal("a disk row must reference an import")
	}
	snap := `INSERT INTO vmware_cbt_snapshots(import_id,moid,name) VALUES(?,?,?)`
	mustExec(snap, "c", "vm-2", "vxvisor-cbt-c-1")
	if err := exec(snap, "c", "vm-2", "vxvisor-cbt-c-1"); err == nil {
		t.Fatal("snapshot names must be unique")
	}
	var pending int
	d.QueryRow(`SELECT COUNT(*) FROM vmware_cbt_snapshots WHERE import_id='c' AND removed_at=0`).Scan(&pending)
	if pending != 1 {
		t.Fatalf("pending snapshots = %d, want 1", pending)
	}
	mustExec(`INSERT INTO vmware_cbt_passes(import_id,pass,kind,bytes) VALUES('c',1,'base',4096)`)
}
