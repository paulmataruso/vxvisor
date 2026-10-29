package service

import (
	"database/sql"
	"fmt"
	"strings"
)

// EgressWizard is the Tenant Egress console's "+ Add tenant egress" wizard: one
// tenant, the trunk its traffic leaves on (an existing one, or a NIC/bond to
// designate), the tenant's VLAN pool on that trunk, its uplink (new, or one of
// its unconnected ones) and the vSwitch that uplink connects (new, existing, or
// none yet).
type EgressWizard struct {
	OrgID int64

	TrunkID  int64 // existing trunk, or 0 to designate NewIface
	NewIface string
	NewMTU   int
	NewQinQ  bool

	PoolMin, PoolMax int // 0 = leave the tenant's pool on the trunk as it is

	UplinkID   int64 // the tenant's existing unconnected uplink, or 0 to create one
	UplinkName string
	Mode       string // access | qinq
	VID        int    // 0 = next free tag from the pool

	VSwitchID   int64  // existing vSwitch to connect, or 0
	VSwitchName string // else create this vSwitch ("" = connect nothing now)
	VSwitchCIDR string
	MakeDefault bool // the new vSwitch becomes the tenant's default (only if it has none)
}

// EgressResult is what the wizard set up, for the confirmation message.
type EgressResult struct{ Org, Trunk, Pool, Uplink, VSwitch string }

// ProvisionTenantEgress runs the wizard: trunk → VLAN pool → uplink → vSwitch,
// each step through the same guarded paths as the single-item forms. If a step
// fails, the steps before it are undone, so a tenant is never left half set up.
func (s *Service) ProvisionTenantEgress(p *Principal, w EgressWizard, ip string) (*EgressResult, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	res := &EgressResult{}
	if err := s.db.QueryRow(`SELECT name FROM orgs WHERE id=?`, w.OrgID).Scan(&res.Org); err != nil {
		return nil, fmt.Errorf("pick a tenant")
	}
	var undo []func()
	fail := func(step string, err error) (*EgressResult, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		if len(undo) > 0 {
			return nil, fmt.Errorf("%s: %w (the earlier steps were undone)", step, err)
		}
		return nil, fmt.Errorf("%s: %w", step, err)
	}

	// 1. Trunk.
	trunkID := w.TrunkID
	if trunkID == 0 {
		iface := strings.TrimSpace(w.NewIface)
		if iface == "" {
			return fail("trunk", fmt.Errorf("pick a trunk, or an interface to designate"))
		}
		if err := s.DesignateTrunk(p, iface, w.NewQinQ, w.NewMTU, ip); err != nil {
			return fail("designate "+iface, err)
		}
		_ = s.db.QueryRow(`SELECT id FROM ext_trunks WHERE iface=?`, iface).Scan(&trunkID)
		undo = append(undo, func() { _ = s.UndesignateTrunk(p, trunkID, ip) })
	}
	if err := s.db.QueryRow(`SELECT iface FROM ext_trunks WHERE id=?`, trunkID).Scan(&res.Trunk); err != nil {
		return fail("trunk", fmt.Errorf("trunk not found"))
	}

	// 2. The tenant's VLAN pool on it.
	oldLo, oldHi, hadPool := s.poolRange(w.OrgID, trunkID)
	if (w.PoolMin > 0 || w.PoolMax > 0) && !(hadPool && w.PoolMin == oldLo && w.PoolMax == oldHi) {
		if err := s.SetVlanPool(p, w.OrgID, trunkID, w.PoolMin, w.PoolMax, ip); err != nil {
			return fail("VLAN pool", err)
		}
		undo = append(undo, func() {
			if hadPool {
				_, _ = s.db.Exec(`UPDATE tenant_vlan_pools SET vid_min=?, vid_max=? WHERE org_id=? AND trunk_id=?`, oldLo, oldHi, w.OrgID, trunkID)
			} else {
				_, _ = s.db.Exec(`DELETE FROM tenant_vlan_pools WHERE org_id=? AND trunk_id=?`, w.OrgID, trunkID)
			}
		})
	}
	if lo, hi, ok := s.poolRange(w.OrgID, trunkID); ok {
		res.Pool = fmt.Sprintf("%d-%d", lo, hi)
	}

	// 3. Uplink.
	uplinkID := w.UplinkID
	if uplinkID != 0 {
		var uOrg, uTrunk, uTnet int64
		if err := s.db.QueryRow(`SELECT org_id,COALESCE(trunk_id,0),COALESCE((SELECT id FROM tenant_networks WHERE uplink_id=u.id),0)
			FROM tenant_uplinks u WHERE id=?`, uplinkID).Scan(&uOrg, &uTrunk, &uTnet); err != nil || uOrg != w.OrgID {
			return fail("uplink", fmt.Errorf("that uplink doesn't belong to %s", res.Org))
		}
		if uTrunk != trunkID {
			return fail("uplink", fmt.Errorf("that uplink is on another trunk"))
		}
		if uTnet != 0 && (w.VSwitchID != 0 || strings.TrimSpace(w.VSwitchName) != "") {
			return fail("uplink", fmt.Errorf("that uplink is already connected to a vSwitch"))
		}
	} else {
		mode := w.Mode
		if mode != "qinq" {
			mode = "access"
		}
		id, err := s.createUplink(p, w.OrgID, w.UplinkName, mode, trunkID, w.VID, "", ip, false)
		if err != nil {
			return fail("create uplink", err)
		}
		uplinkID = id
		undo = append(undo, func() { _ = s.DeleteUplink(p, uplinkID, ip) })
	}
	var vid int
	_ = s.db.QueryRow(`SELECT name,outer_vid FROM tenant_uplinks WHERE id=?`, uplinkID).Scan(&res.Uplink, &vid)
	if vid > 0 {
		res.Uplink += fmt.Sprintf(" (VLAN %d)", vid)
	}

	// 4. The vSwitch it connects.
	switch name := strings.TrimSpace(w.VSwitchName); {
	case w.VSwitchID != 0:
		var tOrg, netID int64
		var up sql.NullInt64
		if err := s.db.QueryRow(`SELECT org_id,network_id,name,uplink_id FROM tenant_networks WHERE id=?`, w.VSwitchID).
			Scan(&tOrg, &netID, &res.VSwitch, &up); err != nil || tOrg != w.OrgID {
			return fail("vSwitch", fmt.Errorf("that vSwitch doesn't belong to %s", res.Org))
		}
		if up.Valid {
			return fail("vSwitch", fmt.Errorf("vSwitch %s already has an uplink", res.VSwitch))
		}
		if err := s.connectUplink(w.VSwitchID, netID, uplinkID); err != nil {
			return fail("connect "+res.VSwitch, err)
		}
		s.audit(p, w.OrgID, "uplink.connect", "tenant_network", fmt.Sprint(w.VSwitchID), ip, map[string]any{"uplink": uplinkID})
	case name != "":
		isDefault := w.MakeDefault && s.defaultTenantNetworkFor(w.OrgID) == 0
		tnID, err := s.createTenantNetwork(w.OrgID, name, strings.TrimSpace(w.VSwitchCIDR), "", false, "", "", isDefault, true)
		if err != nil {
			return fail("create vSwitch", err)
		}
		// Undo even a vSwitch this run made the default (a tenant can't delete
		// its default, but this one only just appeared).
		undo = append(undo, func() { _, _ = s.deleteTenantNetwork(w.OrgID, tnID, true) })
		var netID int64
		_ = s.db.QueryRow(`SELECT network_id FROM tenant_networks WHERE id=?`, tnID).Scan(&netID)
		if err := s.connectUplink(tnID, netID, uplinkID); err != nil {
			return fail("connect "+name, err)
		}
		s.audit(p, w.OrgID, "tenantnet.create", "tenant_network", fmt.Sprint(tnID), ip,
			map[string]any{"name": name, "cidr": w.VSwitchCIDR, "default": isDefault, "uplink": uplinkID})
		res.VSwitch = name
	}
	s.audit(p, w.OrgID, "egress.wizard", "uplink", res.Uplink, ip,
		map[string]any{"trunk": res.Trunk, "pool": res.Pool, "vswitch": res.VSwitch})
	return res, nil
}
