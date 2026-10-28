package db

import (
	"path/filepath"
	"testing"
)

// TestMigration48 validates tenant port groups (migration 48) through the real
// modernc driver: the table + standalone unique indexes apply on a fresh DB, the
// VLAN range CHECK and per-vSwitch uniqueness hold, the RESTRICT FKs protect the
// vSwitch and backing port group, and the new columns default sanely.
func TestMigration48(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open (migrations through 48 must apply clean): %v", err)
	}
	defer d.Close()

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
	vsNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'default','bridge','vdxt1')`, org)
	tnet := mustExec(`INSERT INTO tenant_networks(org_id,name,network_id) VALUES(?,'default',?)`, org, vsNet)
	pgNet := mustExec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'default/web','bridge','vdxt1',10)`, org)
	pg := mustExec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'web',10,?)`, org, tnet, pgNet)

	var native int
	if err := d.QueryRow(`SELECT native_vlan FROM tenant_networks WHERE id=?`, tnet).Scan(&native); err != nil || native != 0 {
		t.Fatalf("native_vlan default = %d err=%v, want 0", native, err)
	}
	other := mustExec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,'x','bridge','vdxt1',20)`, org)
	if _, err := d.Exec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'dup-vlan',10,?)`, org, tnet, other); err == nil {
		t.Fatalf("duplicate VLAN on one vSwitch must be rejected")
	}
	if _, err := d.Exec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,'web',20,?)`, org, tnet, other); err == nil {
		t.Fatalf("duplicate port-group name on one vSwitch must be rejected")
	}
	for _, bad := range []int{0, 1, 4095} {
		if _, err := d.Exec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id) VALUES(?,?,?,?,?)`, org, tnet, "v", bad, other); err == nil {
			t.Fatalf("VLAN %d must be rejected by the CHECK", bad)
		}
	}
	if _, err := d.Exec(`DELETE FROM tenant_networks WHERE id=?`, tnet); err == nil {
		t.Fatalf("a vSwitch with port groups must not be deletable (RESTRICT)")
	}
	if _, err := d.Exec(`DELETE FROM networks WHERE id=?`, pgNet); err == nil {
		t.Fatalf("a port group's backing network must not be deletable (RESTRICT)")
	}
	mustExec(`DELETE FROM tenant_portgroups WHERE id=?`, pg)

	vr := mustExec(`INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge','netns')`, org)
	mustExec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge) VALUES(?,1,'uplink','vdxt1')`, vr)
	var vlan, snat int
	var gw string
	if err := d.QueryRow(`SELECT vlan_id,upstream_gw,snat FROM vrouter_legs WHERE vrouter_id=?`, vr).Scan(&vlan, &gw, &snat); err != nil {
		t.Fatalf("read leg: %v", err)
	}
	if vlan != 0 || gw != "" || snat != 0 {
		t.Fatalf("leg defaults vlan=%d gw=%q snat=%d, want 0,'',0", vlan, gw, snat)
	}
}
