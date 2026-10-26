package db

import (
	"path/filepath"
	"testing"
)

// TestMigration47 validates the strictly-additive ext_trunks.shared column
// (migration 47): it applies cleanly on a fresh DB through the real modernc
// driver, defaults to 0, and accepts an explicit shared=1 row.
func TestMigration47(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 47 must apply clean): %v", err)
	}
	defer d.Close()

	// Column exists and defaults to 0.
	if _, err := d.Exec(`INSERT INTO ext_trunks(iface,kind) VALUES('eth9','nic')`); err != nil {
		t.Fatalf("insert trunk: %v", err)
	}
	var shared int
	if err := d.QueryRow(`SELECT shared FROM ext_trunks WHERE iface='eth9'`).Scan(&shared); err != nil {
		t.Fatalf("read shared: %v", err)
	}
	if shared != 0 {
		t.Fatalf("shared default = %d, want 0", shared)
	}

	// A shared trunk row is accepted.
	if _, err := d.Exec(`INSERT INTO ext_trunks(iface,kind,shared) VALUES('bond0','bond',1)`); err != nil {
		t.Fatalf("insert shared trunk: %v", err)
	}
	if err := d.QueryRow(`SELECT shared FROM ext_trunks WHERE iface='bond0'`).Scan(&shared); err != nil || shared != 1 {
		t.Fatalf("shared row = %d err=%v, want 1", shared, err)
	}
}
