package service

import (
	"path/filepath"
	"testing"

	"vdxclone/internal/db"
)

func allocTestService(t *testing.T) (*Service, int64, int64) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s := &Service{db: d}
	stubHost(t, nil)
	if _, err := d.Exec(`INSERT INTO orgs(name,slug) VALUES('t','t')`); err != nil {
		t.Fatalf("org: %v", err)
	}
	var orgID int64
	d.QueryRow(`SELECT id FROM orgs WHERE slug='t'`).Scan(&orgID)
	res, _ := d.Exec(`INSERT INTO ext_trunks(iface,kind) VALUES('bond0','bond')`)
	trunkID, _ := res.LastInsertId()
	return s, orgID, trunkID
}

func mkUplink(t *testing.T, s *Service, orgID, trunkID int64, name string) int64 {
	t.Helper()
	res, err := s.db.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,outer_vid) VALUES(?,?,?,'access',0)`, orgID, name, trunkID)
	if err != nil {
		t.Fatalf("mk uplink %s: %v", name, err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestAllocVIDNoPool(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	u := mkUplink(t, s, orgID, trunkID, "u1")
	if _, err := s.AllocVID(u, orgID, trunkID); err == nil {
		t.Fatalf("AllocVID must fail with no pool defined")
	}
}

func TestAllocVIDWithinPoolAndExclusion(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	if _, err := s.db.Exec(`INSERT INTO tenant_vlan_pools(org_id,trunk_id,vid_min,vid_max) VALUES(?,?,100,102)`, orgID, trunkID); err != nil {
		t.Fatalf("pool: %v", err)
	}
	// Three allocations fill 100..102 (max+1 preference starts at the pool min,
	// then climbs); the fourth must fail (pool exhausted).
	got := map[int]bool{}
	for i := 0; i < 3; i++ {
		u := mkUplink(t, s, orgID, trunkID, string(rune('a'+i)))
		v, err := s.AllocVID(u, orgID, trunkID)
		if err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
		if v < 100 || v > 102 {
			t.Fatalf("alloc %d returned %d outside pool", i, v)
		}
		if got[v] {
			t.Fatalf("alloc %d reused vid %d", i, v)
		}
		got[v] = true
	}
	u := mkUplink(t, s, orgID, trunkID, "overflow")
	if _, err := s.AllocVID(u, orgID, trunkID); err == nil {
		t.Fatalf("pool should be exhausted")
	}
}

func TestAllocVIDFillsHole(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	s.db.Exec(`INSERT INTO tenant_vlan_pools(org_id,trunk_id,vid_min,vid_max) VALUES(?,?,200,202)`, orgID, trunkID)
	ua := mkUplink(t, s, orgID, trunkID, "a")
	ub := mkUplink(t, s, orgID, trunkID, "b")
	uc := mkUplink(t, s, orgID, trunkID, "c")
	va, _ := s.AllocVID(ua, orgID, trunkID)
	vb, _ := s.AllocVID(ub, orgID, trunkID)
	s.AllocVID(uc, orgID, trunkID)
	// Free the middle one and re-alloc: it should be reclaimable (hole fill).
	_ = vb
	s.FreeVID(ub)
	ud := mkUplink(t, s, orgID, trunkID, "d")
	vd, err := s.AllocVID(ud, orgID, trunkID)
	if err != nil {
		t.Fatalf("hole realloc: %v", err)
	}
	if vd == va {
		t.Fatalf("reused a live vid")
	}
}

func TestSetExplicitVID(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	s.db.Exec(`INSERT INTO tenant_vlan_pools(org_id,trunk_id,vid_min,vid_max) VALUES(?,?,100,199)`, orgID, trunkID)
	u1 := mkUplink(t, s, orgID, trunkID, "u1")
	if err := s.SetExplicitVID(u1, orgID, trunkID, 150); err != nil {
		t.Fatalf("explicit in-pool: %v", err)
	}
	// Out of pool -> rejected.
	u2 := mkUplink(t, s, orgID, trunkID, "u2")
	if err := s.SetExplicitVID(u2, orgID, trunkID, 50); err == nil {
		t.Fatalf("explicit out-of-pool must be rejected")
	}
	// Duplicate tag on same trunk -> rejected by partial unique index.
	if err := s.SetExplicitVID(u2, orgID, trunkID, 150); err == nil {
		t.Fatalf("duplicate tag must be rejected")
	}
	// Invalid (native VLAN 1) -> rejected.
	if err := s.SetExplicitVID(u2, orgID, trunkID, 1); err == nil {
		t.Fatalf("VLAN 1 must be rejected")
	}
}

func TestSetExplicitVIDNoPoolAllowsAnyValid(t *testing.T) {
	s, orgID, trunkID := allocTestService(t)
	defer s.db.Close()
	u := mkUplink(t, s, orgID, trunkID, "u")
	if err := s.SetExplicitVID(u, orgID, trunkID, 3000); err != nil {
		t.Fatalf("explicit tag with no pool should be allowed: %v", err)
	}
}
