package db

import (
	"path/filepath"
	"testing"
)

// TestMigration51 validates the vSwitch MTU column (migration 51) through the
// real modernc driver: it applies on a fresh DB, existing-style inserts that
// don't name it still work, and it defaults to 0 (never set).
func TestMigration51(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 51 must apply clean): %v", err)
	}
	defer d.Close()
	if _, err := d.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vs1','vdsvs1','eth1')`); err != nil {
		t.Fatalf("insert without mtu: %v", err)
	}
	var mtu int
	if err := d.QueryRow(`SELECT mtu FROM net_vswitches WHERE name='vs1'`).Scan(&mtu); err != nil || mtu != 0 {
		t.Fatalf("mtu default = %d err=%v, want 0", mtu, err)
	}
	if _, err := d.Exec(`UPDATE net_vswitches SET mtu=9000 WHERE name='vs1'`); err != nil {
		t.Fatalf("set mtu: %v", err)
	}
	var v int
	if err := d.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&v); err != nil || v < 51 {
		t.Fatalf("schema version = %d err=%v, want >= 51", v, err)
	}
}
