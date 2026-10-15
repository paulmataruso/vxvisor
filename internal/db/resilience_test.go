package db

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenResilientRestoresFromBackup corrupts the live DB and verifies
// OpenResilient restores the newest verified backup (data intact) and
// quarantines the bad file.
func TestOpenResilientRestoresFromBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.db")
	bdir := filepath.Join(dir, "backups")

	d, err := OpenResilient(path, bdir)
	if err != nil {
		t.Fatalf("initial open: %v", err)
	}
	if _, err := d.Exec(`INSERT INTO users(username,password_hash) VALUES('alice','x')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := d.Backup(bdir); err != nil {
		t.Fatalf("backup: %v", err)
	}
	_ = d.Close()

	// Corrupt the live DB and drop its WAL/SHM so the garbage is authoritative.
	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database"), 0o640); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")

	d2, err := OpenResilient(path, bdir)
	if err != nil {
		t.Fatalf("resilient reopen: %v", err)
	}
	defer d2.Close()

	var n int
	if err := d2.QueryRow(`SELECT count(*) FROM users WHERE username='alice'`).Scan(&n); err != nil {
		t.Fatalf("query after restore: %v", err)
	}
	if n != 1 {
		t.Fatalf("restore did not bring back data: alice count=%d", n)
	}
	// The corrupt file must have been quarantined, not silently kept.
	globs, _ := filepath.Glob(path + ".corrupt-*")
	if len(globs) == 0 {
		t.Errorf("expected a quarantined .corrupt-* file")
	}
}

// TestOpenResilientFreshWhenNoBackup verifies that a corrupt DB with no usable
// backup yields a fresh, working database rather than a fatal error.
func TestOpenResilientFreshWhenNoBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cp.db")
	bdir := filepath.Join(dir, "backups")

	// Seed a corrupt file up front; no backups exist.
	if err := os.WriteFile(path, []byte("garbage"), 0o640); err != nil {
		t.Fatal(err)
	}
	d, err := OpenResilient(path, bdir)
	if err != nil {
		t.Fatalf("expected fresh DB, got error: %v", err)
	}
	defer d.Close()
	if err := d.quickCheck(); err != nil {
		t.Fatalf("fresh DB fails integrity: %v", err)
	}
	// Schema is present (migrations ran) and empty.
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("fresh DB missing schema: %v", err)
	}
}

// TestBackupVerifyAndPrune checks Backup produces a verifiable snapshot and
// PruneBackups keeps the newest N.
func TestBackupVerifyAndPrune(t *testing.T) {
	dir := t.TempDir()
	d, err := OpenResilient(filepath.Join(dir, "cp.db"), filepath.Join(dir, "b"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	bdir := filepath.Join(dir, "b")
	if err := os.MkdirAll(bdir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Make a few backups with distinct timestamps.
	for i := 0; i < 3; i++ {
		dest := filepath.Join(bdir, "controlplane-2026010"+string(rune('1'+i))+"T000000.db")
		if _, err := d.Exec(`VACUUM INTO ?`, dest); err != nil {
			t.Fatal(err)
		}
		if !verifyDBFile(dest) {
			t.Fatalf("backup %s failed verify", dest)
		}
	}
	PruneBackups(bdir, 2)
	left := listBackups(bdir)
	if len(left) != 2 {
		t.Fatalf("prune keep=2 left %d", len(left))
	}
}
