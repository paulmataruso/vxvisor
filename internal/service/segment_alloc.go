package service

import "fmt"

// Transactional VXLAN segment-identity allocator for tenant networking v2.
//
// A tenant segment's backing networks row is given a globally-unique VXLAN VNI
// as its IDENTITY. In v2 this is an identity only: NO vxlan device is created
// from it — segments realize as plain uplink-less bridges, which is stronger
// isolation on a single host than a peerless vxlan (that would open a host-wide
// UDP:4789 ingress demuxed by VNI). The reserved VNI, a cluster-wide allocator,
// and actual device materialization are the v3 multi-host growth path.
//
// Correctness rests on two things: the single-connection DB pool serializes
// callers, and the composite PRIMARY KEY on net_segments(seg_type,seg_id) turns
// any residual race into a constraint error, which AllocVNI simply retries on
// the next id. NO device operation ever happens inside the allocator; realize
// (if any) runs after it returns, with a compensating FreeVNI on failure.

const (
	vniAllocMin = 200000  // above hand-entered VNIs and the cluster overlay's low range
	vniAllocMax = 1048575 // 0xFFFFF — well under the 24-bit VXLAN ceiling (16777215)
)

// AllocVNI reserves a free VNI for a backing networks row (netID) owned by orgID
// and records it in net_segments. It prefers max+1 within the range (so a just
// freed id is not immediately reused while any teardown settles) and falls back
// to filling freed holes. It excludes VNIs already used by prior allocations,
// per-network VXLAN port groups, and storage overlays (which share the VXLAN
// id-space). Returns an error only if the whole range is exhausted.
func (s *Service) AllocVNI(orgID, netID int64) (int, error) {
	taken := map[int]bool{}
	collect := func(q string) {
		rows, err := s.db.Query(q)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var v int
			if rows.Scan(&v) == nil {
				taken[v] = true
			}
		}
	}
	collect(`SELECT seg_id FROM net_segments WHERE seg_type='vxlan'`)
	collect(`SELECT vni FROM networks WHERE vni>0`)
	collect(`SELECT vni FROM storage_overlays WHERE vni>0`)

	start := vniAllocMin
	var maxSeg int
	_ = s.db.QueryRow(`SELECT COALESCE(MAX(seg_id),0) FROM net_segments WHERE seg_type='vxlan' AND seg_id BETWEEN ? AND ?`,
		vniAllocMin, vniAllocMax).Scan(&maxSeg)
	if maxSeg >= vniAllocMin && maxSeg < vniAllocMax {
		start = maxSeg + 1
	}

	try := func(lo, hi int) (int, bool) {
		for v := lo; v <= hi; v++ {
			if taken[v] {
				continue
			}
			if _, err := s.db.Exec(`INSERT INTO net_segments(seg_type,seg_id,org_id,net_id) VALUES('vxlan',?,?,?)`,
				v, orgID, netID); err == nil {
				return v, true
			}
			// Lost a race on this id (PK constraint) — note it and move on.
			taken[v] = true
		}
		return 0, false
	}
	if v, ok := try(start, vniAllocMax); ok {
		return v, nil
	}
	if v, ok := try(vniAllocMin, start-1); ok {
		return v, nil
	}
	return 0, fmt.Errorf("no free VXLAN segment id available")
}

// FreeVNI releases the segment identity for a backing networks row. The caller
// MUST tear down any device using the id first (v2 creates none), then free, so
// a concurrent AllocVNI cannot reuse the id while a device still lingers.
func (s *Service) FreeVNI(netID int64) {
	_, _ = s.db.Exec(`DELETE FROM net_segments WHERE net_id=?`, netID)
}
