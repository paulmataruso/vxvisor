package db

import (
	"path/filepath"
	"testing"
)

// TestMigration60 validates the fabric tables on a fresh DB through the real
// modernc driver: the intent singleton exists at version 0 and can't be
// duplicated, and a networks row a fabric port group maps to can't be deleted
// out from under it (RESTRICT) until the mapping goes.
func TestMigration60(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 60 must apply clean): %v", err)
	}
	defer d.Close()
	var v int64
	var body string
	if err := d.QueryRow(`SELECT version, body FROM fabric_intent WHERE id=1`).Scan(&v, &body); err != nil || v != 0 || body != "{}" {
		t.Fatalf("intent singleton = %d %q %v", v, body, err)
	}
	if _, err := d.Exec(`INSERT INTO fabric_intent(id) VALUES(2)`); err == nil {
		t.Fatal("a second intent row must violate the CHECK")
	}
	res, err := d.Exec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(1,'web','fabric','vxfb2000000')`)
	if err != nil {
		t.Fatal(err)
	}
	nid, _ := res.LastInsertId()
	if _, err := d.Exec(`INSERT INTO fabric_pg_networks(pg_uuid,network_id) VALUES('p1',?)`, nid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO fabric_pg_networks(pg_uuid,network_id) VALUES('p2',?)`, nid); err == nil {
		t.Fatal("two port groups mapped to one networks row")
	}
	if _, err := d.Exec(`DELETE FROM networks WHERE id=?`, nid); err == nil {
		t.Fatal("deleting a fabric port group's networks row must be refused")
	}
	if _, err := d.Exec(`DELETE FROM fabric_pg_networks WHERE pg_uuid='p1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM networks WHERE id=?`, nid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO fabric_underlay(fabric_uuid,iface,dev,tep,made_vlan,orig_mtu) VALUES('f','eno3','eno3.30','10.250.0.1/24',1,1500)`); err != nil {
		t.Fatal(err)
	}
}
