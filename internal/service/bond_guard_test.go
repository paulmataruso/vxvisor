package service

import (
	"strings"
	"testing"

	"vdxclone/internal/config"
	"vdxclone/internal/netdrv"
)

// TestDeleteBondInUse: a bond that anything uses is refused with the reason and
// stays recorded; an unused one is deleted. The bond name doesn't exist on the
// machine running the test, so only the DB-recorded uses are exercised here.
func TestDeleteBondInUse(t *testing.T) {
	s, a, _, trunk := egressTestService(t)
	s.cfg = &config.Config{}
	s.net = netdrv.New(s.db)
	const bond = "vxtestbond9"
	ins := func(q string, args ...any) int64 {
		t.Helper()
		res, err := s.db.Exec(q, args...)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	reset := func() {
		for _, q := range []string{`DELETE FROM net_vswitches`, `DELETE FROM tenant_uplinks`, `DELETE FROM vrouter_legs`,
			`DELETE FROM vrouters`, `DELETE FROM settings WHERE key='storage_iface'`, `UPDATE routing_config SET config_json='{}'`} {
			s.db.Exec(q)
		}
		s.db.Exec(`UPDATE ext_trunks SET iface='vxtest0' WHERE id=?`, trunk)
		s.db.Exec(`INSERT OR IGNORE INTO net_bonds(name,mode,members) VALUES(?,'balance-alb','vxa,vxb')`, bond)
	}
	cases := []struct {
		use, want string
		set       func()
	}{
		{"vSwitch uplink", `uplink of vSwitch "vs1"`, func() { ins(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('vs1','vdsvs1',?)`, bond) }},
		{"tenant trunk", "tenant egress trunk", func() { s.db.Exec(`UPDATE ext_trunks SET iface=? WHERE id=?`, bond, trunk) }},
		{"dedicated uplink", `tenant uplink "wan"`, func() {
			ins(`INSERT INTO tenant_uplinks(org_id,name,mode,dedicated_iface) VALUES(?,'wan','dedicated',?)`, a, bond)
		}},
		{"vRouter transit", `vRouter "edge"`, func() {
			vr := ins(`INSERT INTO vrouters(org_id,name,runtime) VALUES(?,'edge','netns')`, a)
			ins(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,phys_iface,iface_name,cidr) VALUES(?,0,'transit','vr1-wan',?,'eth0','192.0.2.2/30')`, vr, bond)
		}},
		{"storage", "storage interface", func() { ins(`INSERT INTO settings(key,value) VALUES('storage_iface',?)`, bond) }},
		{"routing uplink", "routing uplink", func() {
			s.db.Exec(`INSERT OR IGNORE INTO routing_config(id,config_json) VALUES(1,'{}')`)
			s.db.Exec(`UPDATE routing_config SET config_json=? WHERE id=1`, `{"uplink":"`+bond+`"}`)
		}},
	}
	for _, c := range cases {
		reset()
		c.set()
		err := s.DeleteBond(egressAdmin, bond, "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want a refusal mentioning %q, got %v", c.use, c.want, err)
		}
		if got := s.BondsInUse(egressAdmin)[bond]; got != err.Error() {
			t.Fatalf("%s: the page must show the same reason, got %q", c.use, got)
		}
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM net_bonds WHERE name=?`, bond).Scan(&n)
		if n != 1 {
			t.Fatalf("%s: a refused delete must keep the bond's record", c.use)
		}
	}
	reset()
	if err := s.DeleteBond(egressAdmin, bond, ""); err != nil {
		t.Fatalf("an unused bond must delete: %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM net_bonds WHERE name=?`, bond).Scan(&n)
	if n != 0 {
		t.Fatalf("the unused bond's record must be gone")
	}
	if err := s.DeleteBond(&Principal{OrgID: a, OrgRole: "owner"}, bond, ""); err != ErrUnauthorized {
		t.Fatalf("org admins can't delete bonds, got %v", err)
	}
}

// TestClaimGuards: creating a bond, a vSwitch or a team never claims an
// interface something else uses, never reuses an existing bond name (EnsureBond
// would add NICs to it — e.g. the management bond), and never lets two vSwitch
// names share one bridge. Every refusal happens before any kernel change.
func TestClaimGuards(t *testing.T) {
	s, a, _, _ := egressTestService(t)
	s.cfg = &config.Config{}
	s.net = netdrv.New(s.db)
	s.db.Exec(`INSERT INTO settings(key,value) VALUES('storage_iface','vxstor9')`)
	s.db.Exec(`INSERT INTO net_bonds(name,mode,members) VALUES('vxteam9','balance-alb','vxa,vxb')`)
	s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES('Prod-1','vdsProd1','vxteam9')`)

	if err := s.CreateBond(egressAdmin, "vxteam8", "active-backup", "", []string{"vxnic1", "vxstor9"}, ""); err == nil || !strings.Contains(err.Error(), "storage interface") {
		t.Fatalf("bonding the storage NIC must be refused, got %v", err)
	}
	if err := s.CreateBond(egressAdmin, "vxteam9", "active-backup", "", []string{"vxnic1", "vxnic2"}, ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("reusing an existing bond name must be refused, got %v", err)
	}
	if err := s.CreateBond(egressAdmin, "bad name", "active-backup", "", []string{"vxnic1"}, ""); err == nil || !strings.Contains(err.Error(), "invalid bond name") {
		t.Fatalf("an invalid bond name must be refused, got %v", err)
	}
	if err := s.CreateVSwitch(egressAdmin, "vs2", "vxteam9", ""); err == nil || !strings.Contains(err.Error(), `uplink of vSwitch "Prod-1"`) {
		t.Fatalf("taking another vSwitch's uplink must be refused, got %v", err)
	}
	if err := s.CreateVSwitch(egressAdmin, "Prod1", "", ""); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("a name mapping onto an existing bridge must be refused, got %v", err)
	}
	// A name equal to another vSwitch's bridge would make name-keyed lookups
	// (delete by name or bridge) hit the wrong vSwitch.
	if err := s.CreateVSwitch(egressAdmin, "vdsProd1", "", ""); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("a name equal to an existing bridge must be refused, got %v", err)
	}
	if err := s.CreateVSwitch(egressAdmin, "a/b", "", ""); err == nil {
		t.Fatalf("a vSwitch name with a slash must be refused")
	}
	if err := s.UpgradeVSwitchToBond(egressAdmin, "Prod-1", "", "active-backup", "", []string{"vxnic3"}, ""); err == nil || !strings.Contains(err.Error(), "already a NIC team") {
		t.Fatalf("teaming an uplink that is already a team must be refused, got %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM net_bonds`).Scan(&n)
	if n != 1 {
		t.Fatalf("refused creates must not record anything, %d bonds", n)
	}
	if err := s.CreateBond(&Principal{OrgID: a, OrgRole: "owner"}, "vxteam7", "active-backup", "", []string{"vxnic1"}, ""); err != ErrUnauthorized {
		t.Fatalf("org admins can't create bonds, got %v", err)
	}
}
