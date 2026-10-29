package service

import (
	"fmt"
	"sort"
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// Transactional outer-VLAN (S-tag / 802.1q tag) allocator for tenant networking
// v3. Mirrors segment_alloc.go: the single-connection DB pool serializes callers,
// and the standalone partial unique index ux_uplink_trunk_vid(trunk_id,outer_vid)
// WHERE outer_vid>0 turns any residual race into a constraint error, which the
// allocator retries on the next id. NO device operation happens inside the
// allocator; ClaimVlanSub runs after it returns (when the uplink is connected),
// with a compensating FreeVID on failure.
//
// Unlike the VNI allocator (a separate net_segments identity table), the outer
// VID lives directly on the tenant_uplinks row, so "allocate" is an UPDATE of an
// unbound (outer_vid=0) uplink to a free tag. The tenant's PRIVATE inner VLAN
// numbering is a different namespace entirely and is never excluded here.
//
// The tag space on a trunk is shared with the host: on a shared (management)
// trunk the admin's own port groups ride the same wire as tagged VLANs, and any
// trunk may carry host VLAN subinterfaces (a storage VLAN, say). A tenant
// subinterface on such a VLAN would take its traffic away from the host —
// trunkReservedVIDs lists them, the allocator skips them, an explicit tag is
// refused, and checkTenantClaims refuses the reverse (an admin port group on a
// VLAN a tenant already holds).

// trunkVlanSubs / trunkMaster read the host (VLAN subinterfaces of a device; the
// bridge or bond it is enslaved to). Variables so tests can stand in for the
// machine they run on.
var (
	trunkVlanSubs = netdrv.VlanSubsOf
	trunkMaster   = func(iface string) string {
		ifs, err := hostinfo.Interfaces()
		if err != nil {
			return ""
		}
		for _, it := range ifs {
			if it.Name == iface {
				return it.Master
			}
		}
		return ""
	}
)

// trunkReservedVIDs lists the outer tags a trunk can't hand a tenant, with why:
// VLANs of the admin's port groups on a vSwitch the trunk is the uplink of, and
// VLAN subinterfaces already on the trunk that no tenant uplink owns.
func (s *Service) trunkReservedVIDs(trunkID int64) map[int]string {
	out := map[int]string{}
	var iface string
	if err := s.db.QueryRow(`SELECT iface FROM ext_trunks WHERE id=?`, trunkID).Scan(&iface); err != nil {
		return out
	}
	bridges := map[string]bool{}
	if m := trunkMaster(iface); m != "" {
		bridges[m] = true
	}
	if rows, err := s.db.Query(`SELECT bridge FROM net_vswitches WHERE uplink=?`, iface); err == nil {
		for rows.Next() {
			var b string
			if rows.Scan(&b) == nil && b != "" {
				bridges[b] = true
			}
		}
		rows.Close()
	}
	for b := range bridges {
		rows, err := s.db.Query(`SELECT name,vlan_id FROM networks WHERE bridge=? AND vlan_id>0`, b)
		if err != nil {
			continue
		}
		for rows.Next() {
			var name string
			var v int
			if rows.Scan(&name, &v) == nil {
				out[v] = fmt.Sprintf("the host's port group %q uses VLAN %d on this trunk", name, v)
			}
		}
		rows.Close()
	}
	if subs, err := trunkVlanSubs(iface); err == nil && len(subs) > 0 {
		owned := map[int]bool{}
		if rows, err := s.db.Query(`SELECT outer_vid FROM tenant_uplinks WHERE trunk_id=? AND outer_vid>0`, trunkID); err == nil {
			for rows.Next() {
				var v int
				if rows.Scan(&v) == nil {
					owned[v] = true
				}
			}
			rows.Close()
		}
		for v, dev := range subs {
			if !owned[v] {
				if _, ok := out[v]; !ok {
					out[v] = fmt.Sprintf("the host already has VLAN interface %s on this trunk", dev)
				}
			}
		}
	}
	return out
}

// checkTenantClaims refuses an admin (non-tenant) port group that would collide
// with what a tenant already holds: a tagged VLAN that a tenant's external
// network rides on the same uplink, or a VXLAN VNI reserved as a tenant
// segment's identity. Called from CreateNetwork.
func (s *Service) checkTenantClaims(n netdrv.Network) error {
	if n.VNI > 0 {
		if owner := s.vniReserved(n.VNI); owner != 0 {
			return fmt.Errorf("VNI %d is reserved for a tenant network's segment — pick another VNI", n.VNI)
		}
	}
	if n.VLANID <= 0 || n.Bridge == "" || strings.HasPrefix(n.Bridge, "vdxt") {
		return nil // untagged, or a tenant port group (its VLANs are private)
	}
	ifaces := map[string]bool{}
	var up string
	if err := s.db.QueryRow(`SELECT uplink FROM net_vswitches WHERE bridge=?`, n.Bridge).Scan(&up); err == nil && up != "" {
		ifaces[up] = true
	}
	for _, it := range s.bridgePorts(n.Bridge) {
		ifaces[it] = true
	}
	for iface := range ifaces {
		var uname, org string
		err := s.db.QueryRow(`SELECT u.name,COALESCE(o.name,'') FROM tenant_uplinks u JOIN ext_trunks t ON t.id=u.trunk_id
			LEFT JOIN orgs o ON o.id=u.org_id WHERE t.iface=? AND u.outer_vid=?`, iface, n.VLANID).Scan(&uname, &org)
		if err == nil {
			return fmt.Errorf("VLAN %d on %s is held by external network %q of tenant %q — pick another VLAN, or move that external network to another tag first",
				n.VLANID, iface, uname, org)
		}
	}
	return nil
}

// bridgePorts lists the devices enslaved to a bridge (its uplink NIC/bond
// among them), sorted.
func (s *Service) bridgePorts(bridge string) []string {
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, it := range ifs {
		if it.Master == bridge && (it.Type == "physical" || it.Type == "bond") {
			out = append(out, it.Name)
		}
	}
	sort.Strings(out)
	return out
}

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
// falls back to filling holes. Excludes tenant_uplinks.outer_vid already on the
// same trunk (enforced for real by the partial unique index) and the tags the
// host itself uses on the trunk (trunkReservedVIDs). Returns an error if no pool
// is defined or the pool is exhausted.
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
	for v := range s.trunkReservedVIDs(trunkID) {
		taken[v] = true
	}
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
	return 0, fmt.Errorf("no free VLAN id available in VLAN range %d-%d (tags the host uses on this trunk are skipped) — widen the range", lo, hi)
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
		return fmt.Errorf("VLAN %d is outside this tenant's VLAN range %d-%d", vid, lo, hi)
	}
	if why, ok := s.trunkReservedVIDs(trunkID)[vid]; ok {
		return fmt.Errorf("VLAN %d can't be used: %s — pick another tag", vid, why)
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
