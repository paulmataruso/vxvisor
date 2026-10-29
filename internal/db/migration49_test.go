package db

import (
	"path/filepath"
	"testing"
)

// TestMigration49 validates the vSwitch DHCP columns (migration 49) through the
// real modernc driver: they apply on a fresh DB, and a row inserted without them
// (an existing vSwitch) reads as DHCP on with empty range / DNS — what the
// service turns into the old boot-time defaults.
func TestMigration49(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 49 must apply clean): %v", err)
	}
	defer d.Close()

	res, err := d.Exec(`INSERT INTO orgs(name,slug) VALUES('acme','acme')`)
	if err != nil {
		t.Fatal(err)
	}
	org, _ := res.LastInsertId()
	res, err = d.Exec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'default','bridge','vdxt1')`, org)
	if err != nil {
		t.Fatal(err)
	}
	netID, _ := res.LastInsertId()
	if _, err := d.Exec(`INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'default',?)`, org, netID); err != nil {
		t.Fatal(err)
	}
	var dhcp int
	var rng, dns string
	if err := d.QueryRow(`SELECT dhcp,dhcp_range,dhcp_dns FROM tenant_networks`).Scan(&dhcp, &rng, &dns); err != nil {
		t.Fatalf("read DHCP columns: %v", err)
	}
	if dhcp != 1 || rng != "" || dns != "" {
		t.Fatalf("defaults dhcp=%d range=%q dns=%q, want 1,'',''", dhcp, rng, dns)
	}
	if _, err := d.Exec(`UPDATE tenant_networks SET dhcp=0,dhcp_range='10.0.0.10,10.0.0.20',dhcp_dns='9.9.9.9'`); err != nil {
		t.Fatalf("write DHCP columns: %v", err)
	}
}
