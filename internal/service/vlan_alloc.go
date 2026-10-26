package service

import "fmt"

// Transactional outer-VLAN (S-tag / 802.1q tag) allocator for tenant networking
// v3. Mirrors segment_alloc.go: the single-connection DB pool serializes callers,
// and the standalone partial unique index ux_uplink_trunk_vid(trunk_id,outer_vid)
// WHERE outer_vid>0 turns any residual race into a constraint error, which the
// allocator retries on the next id. NO device operation happens inside the
// allocator; EnsureVlanSub runs after it returns, with a compensating FreeVID on
// failure.
//
// Unlike the VNI allocator (a separate net_segments identity table), the outer
// VID lives directly on the tenant_uplinks row, so "allocate" is an UPDATE of an
// unbound (outer_vid=0) uplink to a free tag. The tenant's PRIVATE inner VLAN
// numbering is a different namespace entirely and is never excluded here.

const (
	vidAllocMin = 2    // VLAN 1 is the native/default VLAN — never hand it out
	vidAllocMax = 4094 // 802.1q ceiling
)

func validVID(v int) bool { return v >= vidAllocMin && v <= vidAllocMax }

// poolRange returns the admin-reserved [min,max] outer-VID range for (org,trunk),
// and whether a pool is defined. A pool is required for auto-allocation; an
// explicit admin-typed tag is allowed without one (the admin owns the tag space).
func (s *Service) poolRange(orgID, trunkID int64) (lo, hi int, ok bool) {
	err := s.db.QueryRow(`SELECT vid_min,vid_max FROM tenant_vlan_pools WHERE org_id=? AND trunk_id=?`,
		orgID, trunkID).Scan(&lo, &hi)
	if err != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

// AllocVID claims a free outer VID for an UNBOUND uplink (outer_vid=0) from the
// tenant's pool on that trunk, writing it onto the uplink row. It prefers max+1
// within the pool (so a just-freed tag isn't reused while teardown settles) and
// falls back to filling holes. Excludes only tenant_uplinks.outer_vid already on
// the same trunk (enforced for real by the partial unique index). Returns an
// error if no pool is defined or the pool is exhausted.
func (s *Service) AllocVID(uplinkID, orgID, trunkID int64) (int, error) {
	lo, hi, ok := s.poolRange(orgID, trunkID)
	if !ok {
		return 0, fmt.Errorf("no VLAN pool defined for this tenant on this trunk")
	}
	if lo < vidAllocMin {
		lo = vidAllocMin
	}
	if hi > vidAllocMax {
		hi = vidAllocMax
	}
	if lo > hi {
		return 0, fmt.Errorf("invalid VLAN pool range %d-%d", lo, hi)
	}

	taken := map[int]bool{}
	rows, err := s.db.Query(`SELECT outer_vid FROM tenant_uplinks WHERE trunk_id=? AND outer_vid>0`, trunkID)
	if err == nil {
		for rows.Next() {
			var v int
			if rows.Scan(&v) == nil {
				taken[v] = true
			}
		}
		rows.Close()
	}

	start := lo
	var maxVid int
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(outer_vid),0) FROM tenant_uplinks WHERE trunk_id=? AND outer_vid BETWEEN ? AND ?`,
		trunkID, lo, hi).Scan(&maxVid)
	if maxVid >= lo && maxVid < hi {
		start = maxVid + 1
	}

	try := func(a, b int) (int, bool) {
		for v := a; v <= b; v++ {
			if taken[v] {
				continue
			}
			res, err := s.db.Exec(`UPDATE tenant_uplinks SET outer_vid=? WHERE id=? AND outer_vid=0`, v, uplinkID)
			if err != nil {
				taken[v] = true // lost the unique-index race on this id
				continue
			}
			if n, _ := res.RowsAffected(); n == 1 {
				return v, true
			}
			// 0 rows: the uplink is not in the unbound state we require.
			return 0, false
		}
		return 0, false
	}
	if v, ok := try(start, hi); ok {
		return v, nil
	}
	if v, ok := try(lo, start-1); ok {
		return v, nil
	}
	return 0, fmt.Errorf("no free VLAN id available in pool %d-%d", lo, hi)
}

// SetExplicitVID binds an admin-typed outer VID to an unbound uplink. If a pool
// is defined for (org,trunk) the tag must fall within it; otherwise any valid VID
// is allowed (the admin owns the tag space). The partial unique index rejects a
// tag already in use on that trunk.
func (s *Service) SetExplicitVID(uplinkID, orgID, trunkID int64, vid int) error {
	if !validVID(vid) {
		return fmt.Errorf("VLAN %d out of range (%d-%d)", vid, vidAllocMin, vidAllocMax)
	}
	if lo, hi, ok := s.poolRange(orgID, trunkID); ok && (vid < lo || vid > hi) {
		return fmt.Errorf("VLAN %d is outside this tenant's pool %d-%d", vid, lo, hi)
	}
	res, err := s.db.Exec(`UPDATE tenant_uplinks SET outer_vid=? WHERE id=? AND outer_vid=0`, vid, uplinkID)
	if err != nil {
		return fmt.Errorf("VLAN %d is already in use on this trunk", vid)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("uplink is not in an unbound state")
	}
	return nil
}

// FreeVID releases the outer VID of an uplink (sets it back to 0 and marks the
// uplink unbound). The caller MUST tear down the VLAN subinterface device FIRST
// and confirm it is gone, so a concurrent AllocVID cannot reuse the tag while a
// device still lingers (mirrors the FreeVNI contract).
func (s *Service) FreeVID(uplinkID int64) {
	_, _ = s.db.Exec(`UPDATE tenant_uplinks SET outer_vid=0, status='unbound', egress_bridge='' WHERE id=?`, uplinkID)
}
