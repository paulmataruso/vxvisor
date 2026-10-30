package db

import (
	"path/filepath"
	"testing"
)

// TestMigration58_59 validates the oVirt backup-API tables (migrations 58 and
// 59) on a fresh DB through the real modernc driver: they apply clean, the
// partial unique index allows many staged disks but one disk per VM, and
// purging a VM cascades its checkpoints, its attached API disk and its
// ovirt_vms row while leaving staged disks alone.
func TestMigration58_59(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 59 must apply clean): %v", err)
	}
	defer d.Close()

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := d.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	mustExec(`INSERT INTO users(username,password_hash) VALUES('u','x')`)
	mustExec(`INSERT INTO images(name,path) VALUES('img','/x')`)
	mustExec(`INSERT INTO sessions(id,name,owner_id,image_name,disk_path) VALUES('vm1','vm1',1,'img','/d/vm1.qcow2')`)

	mustExec(`INSERT INTO ovirt_checkpoints(id,vm_id) VALUES('c1','vm1')`)
	mustExec(`INSERT INTO ovirt_checkpoints(id,vm_id,parent_id,description) VALUES('c2','vm1','c1','{"x":1}')`)
	if _, err := d.Exec(`INSERT INTO ovirt_checkpoints(id,vm_id) VALUES('c3','nope')`); err == nil {
		t.Fatal("a checkpoint for a missing VM must violate the foreign key")
	}
	var created string
	if err := d.QueryRow(`SELECT created_at FROM ovirt_checkpoints WHERE id='c1'`).Scan(&created); err != nil || len(created) != 20 {
		t.Fatalf("created_at default = %q err=%v, want an RFC 3339 UTC stamp", created, err)
	}

	// Staged disks (vm_id NULL) are unconstrained; one attached disk per VM.
	mustExec(`INSERT INTO ovirt_disks(id,path,size) VALUES('s1','/d/s1.qcow2',1073741824)`)
	mustExec(`INSERT INTO ovirt_disks(id,path) VALUES('s2','/d/s2.qcow2')`)
	mustExec(`INSERT INTO ovirt_disks(id,vm_id,path) VALUES('a1','vm1','/d/a1.qcow2')`)
	if _, err := d.Exec(`INSERT INTO ovirt_disks(id,vm_id,path) VALUES('a2','vm1','/d/a2.qcow2')`); err == nil {
		t.Fatal("a second attached disk on one VM must hit ux_ovirt_disks_vm")
	}
	mustExec(`INSERT INTO ovirt_vms(vm_id,purpose) VALUES('vm1','worker')`)

	mustExec(`DELETE FROM sessions WHERE id='vm1'`)
	if n := count(`SELECT COUNT(*) FROM ovirt_checkpoints`); n != 0 {
		t.Errorf("checkpoints left after the VM was purged: %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM ovirt_vms`); n != 0 {
		t.Errorf("ovirt_vms rows left after the VM was purged: %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM ovirt_disks`); n != 2 {
		t.Errorf("ovirt_disks rows = %d, want the 2 staged disks only", n)
	}
}
