package db

import (
	"path/filepath"
	"testing"
)

// TestMigration55 validates the strictly-additive containers.network_id column
// (migration 55): it applies cleanly on a fresh DB through the real modernc
// driver, defaults to 0 for a row that doesn't set it, and stores a port group id.
func TestMigration55(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 55 must apply clean): %v", err)
	}
	defer d.Close()

	if _, err := d.Exec(`INSERT INTO containers(name,org_id,bridge) VALUES('legacy',1,'lxcbr0')`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	var nid int64
	if err := d.QueryRow(`SELECT network_id FROM containers WHERE name='legacy'`).Scan(&nid); err != nil || nid != 0 {
		t.Fatalf("network_id default = %d err=%v, want 0", nid, err)
	}
	if _, err := d.Exec(`INSERT INTO containers(name,org_id,bridge,network_id) VALUES('web1',2,'vdxt7',7)`); err != nil {
		t.Fatalf("insert bound row: %v", err)
	}
	if err := d.QueryRow(`SELECT network_id FROM containers WHERE name='web1'`).Scan(&nid); err != nil || nid != 7 {
		t.Fatalf("network_id = %d err=%v, want 7", nid, err)
	}
}
