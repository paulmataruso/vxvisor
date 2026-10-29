package service

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"vdxclone/internal/netdrv"
)

// Editing what the Tenant Egress console created: a trunk's MTU / QinQ setting,
// a VLAN pool's range (SetVlanPool + checkPoolRange), an uplink's name / wiring /
// tag, and which vSwitch an uplink is connected to. A connected uplink is
// re-wired live; if the new wiring fails its old wiring is put back.

// UpdateTrunk changes a dedicated trunk's MTU and QinQ capability. A shared
// (management) trunk is never modified.
func (s *Service) UpdateTrunk(p *Principal, id int64, mtu int, qinq bool, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var iface, origOffload string
	var curMTU, curQ, shared int
	if err := s.db.QueryRow(`SELECT iface,mtu,qinq_capable,shared,orig_offload FROM ext_trunks WHERE id=?`, id).
		Scan(&iface, &curMTU, &curQ, &shared, &origOffload); err != nil {
		return fmt.Errorf("trunk not found")
	}
	if shared == 1 {
		return fmt.Errorf("%s is shared with management: its MTU and offloads are never changed, and it stays access-only", iface)
	}
	if mtu < 1500 || mtu > 9000 {
		return fmt.Errorf("MTU must be 1500-9000")
	}
	if !qinq && curQ == 1 {
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE trunk_id=? AND mode='qinq'`, id).Scan(&n)
		if n > 0 {
			return fmt.Errorf("%d QinQ uplink(s) use %s — switch them to access mode first", n, iface)
		}
	}
	slaves := s.trunkSlaves(iface)
	if !qinq && curQ == 1 {
		// Offloads back to their pre-designation state (MTU 0 = leave it; set below).
		_ = netdrv.RestoreTrunk(iface, slaves, 0, origOffload)
	}
	if err := netdrv.EnsureTrunk(iface, slaves, mtu, qinq); err != nil {
		_ = netdrv.EnsureTrunk(iface, slaves, curMTU, curQ == 1)
		return fmt.Errorf("apply trunk settings: %w", err)
	}
	q := b2iDHCP(qinq)
	if _, err := s.db.Exec(`UPDATE ext_trunks SET mtu=?, qinq_capable=?, offload_disabled=? WHERE id=?`, mtu, q, q, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "trunk.update", "ext_trunk", iface, ip, map[string]any{"mtu": mtu, "qinq": qinq})
	return nil
}

// checkPoolRange refuses a pool range for (org, trunk) that overlaps another
// tenant's pool or in-use tag on the same trunk, or that would leave out a tag one
// of this tenant's uplinks holds from its current pool.
func (s *Service) checkPoolRange(orgID, trunkID int64, lo, hi int) error {
	var n int
	if _ = s.db.QueryRow(`SELECT COUNT(*) FROM ext_trunks WHERE id=?`, trunkID).Scan(&n); n == 0 {
		return fmt.Errorf("trunk not found")
	}
	if _ = s.db.QueryRow(`SELECT COUNT(*) FROM orgs WHERE id=?`, orgID).Scan(&n); n == 0 {
		return fmt.Errorf("organization not found")
	}
	var who string
	var olo, ohi, vid int
	if s.db.QueryRow(`SELECT o.name,p.vid_min,p.vid_max FROM tenant_vlan_pools p JOIN orgs o ON o.id=p.org_id
		WHERE p.trunk_id=? AND p.org_id!=? AND p.vid_min<=? AND p.vid_max>=? LIMIT 1`, trunkID, orgID, hi, lo).Scan(&who, &olo, &ohi) == nil {
		return fmt.Errorf("VLANs %d-%d overlap %s's pool %d-%d on this trunk", lo, hi, who, olo, ohi)
	}
	if s.db.QueryRow(`SELECT o.name||' / '||u.name, u.outer_vid FROM tenant_uplinks u JOIN orgs o ON o.id=u.org_id
		WHERE u.trunk_id=? AND u.org_id!=? AND u.outer_vid BETWEEN ? AND ? LIMIT 1`, trunkID, orgID, lo, hi).Scan(&who, &vid) == nil {
		return fmt.Errorf("VLAN %d on this trunk is in use by uplink %s", vid, who)
	}
	if olo, ohi, ok := s.poolRange(orgID, trunkID); ok {
		if s.db.QueryRow(`SELECT name, outer_vid FROM tenant_uplinks WHERE org_id=? AND trunk_id=?
			AND outer_vid BETWEEN ? AND ? AND (outer_vid<? OR outer_vid>?) LIMIT 1`, orgID, trunkID, olo, ohi, lo, hi).Scan(&who, &vid) == nil {
			return fmt.Errorf("uplink %s uses VLAN %d, which %d-%d leaves out — retag it first", who, vid, lo, hi)
		}
	}
	return nil
}

// validateUplinkWiring checks an uplink's mode against its trunk (QinQ needs a
// QinQ-capable trunk) or its dedicated NIC (never mgmt / storage / a trunk /
// another uplink's NIC). self is the uplink being edited (0 on create).
func (s *Service) validateUplinkWiring(mode string, trunkID int64, dedIface string, self int64) error {
	switch mode {
	case "access", "qinq":
		if trunkID == 0 {
			return fmt.Errorf("a trunk is required for %s mode", mode)
		}
		var qc int
		if err := s.db.QueryRow(`SELECT qinq_capable FROM ext_trunks WHERE id=?`, trunkID).Scan(&qc); err != nil {
			return fmt.Errorf("trunk not found: %w", err)
		}
		if mode == "qinq" && qc == 0 {
			return fmt.Errorf("this trunk isn't QinQ-capable (it may be a management-shared trunk, which is access-only) — edit the trunk to enable QinQ, or use access mode")
		}
	case "dedicated":
		if dedIface == "" {
			return fmt.Errorf("a dedicated interface is required")
		}
		if err := s.guardMgmt(dedIface); err != nil {
			return err
		}
		if err := s.guardTrunk(dedIface); err != nil {
			return err
		}
		if st := s.StorageIface(); st != "" && dedIface == st {
			return fmt.Errorf("refusing to assign the storage interface")
		}
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE dedicated_iface=? AND id!=?`, dedIface, self).Scan(&n)
		if n > 0 {
			return fmt.Errorf("%s is already another uplink's dedicated interface", dedIface)
		}
	default:
		return fmt.Errorf("unknown uplink mode %q", mode)
	}
	return nil
}

type uplinkWiring struct {
	mode, ded string
	trunkID   int64
	vid       int
}

// UpdateUplink renames an uplink and/or changes its wiring: mode, trunk, tag
// (vid 0 = next free tag from the tenant's pool) or dedicated NIC. A connected
// uplink is taken off the wire, re-tagged and put back (its tenant's external
// traffic pauses for a moment); if that fails the old wiring is restored.
func (s *Service) UpdateUplink(p *Principal, id int64, name, mode string, trunkID int64, vid int, dedIface, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var orgID int64
	var curName, egress string
	var cur uplinkWiring
	if err := s.db.QueryRow(`SELECT org_id,name,mode,COALESCE(trunk_id,0),outer_vid,dedicated_iface,egress_bridge
		FROM tenant_uplinks WHERE id=?`, id).Scan(&orgID, &curName, &cur.mode, &cur.trunkID, &cur.vid, &cur.ded, &egress); err != nil {
		return fmt.Errorf("uplink not found")
	}
	if name = strings.TrimSpace(name); name == "" {
		return fmt.Errorf("uplink name required")
	}
	if mode == "dedicated" {
		trunkID, vid = 0, 0
	} else {
		dedIface = ""
	}
	if err := s.validateUplinkWiring(mode, trunkID, dedIface, id); err != nil {
		return err
	}
	var dup int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE org_id=? AND name=? AND id!=?`, orgID, name, id).Scan(&dup)
	if dup > 0 {
		return fmt.Errorf("this tenant already has an uplink named %q", name)
	}
	rename := func() error {
		if name == curName {
			return nil
		}
		_, err := s.db.Exec(`UPDATE tenant_uplinks SET name=? WHERE id=?`, name, id)
		return err
	}
	next := uplinkWiring{mode: mode, ded: dedIface, trunkID: trunkID, vid: vid}
	if next == cur {
		if err := rename(); err != nil {
			return err
		}
		s.audit(p, orgID, "uplink.update", "uplink", name, ip, map[string]any{"renamed_from": curName})
		return nil
	}
	var tnetID int64
	_ = s.db.QueryRow(`SELECT id FROM tenant_networks WHERE uplink_id=?`, id).Scan(&tnetID)
	if tnetID != 0 {
		var native int
		_ = s.db.QueryRow(`SELECT native_vlan FROM tenant_networks WHERE id=?`, tnetID).Scan(&native)
		if err := s.checkCarry(tnetID, mode, native); err != nil {
			return err
		}
	}
	// Off the wire (keeps nothing: the tag is re-assigned below), then rewire.
	if egress != "" {
		if err := s.unrealizeUplink(id, false, false); err != nil {
			return err
		}
	}
	err := s.wireUplink(id, orgID, next, egress, tnetID)
	if err != nil {
		if egress != "" {
			_ = s.unrealizeUplink(id, false, false)
		}
		if rerr := s.wireUplink(id, orgID, cur, egress, tnetID); rerr != nil {
			log.Printf("uplink %d: restoring the old wiring after a failed edit: %v", id, rerr)
		}
		return err
	}
	if err := rename(); err != nil {
		return err
	}
	s.audit(p, orgID, "uplink.update", "uplink", name, ip, map[string]any{"mode": mode, "trunk": trunkID, "vid": vid, "iface": dedIface})
	return nil
}

// wireUplink writes w onto an uplink (unbound, its old tag released — the caller
// has taken any old device down), assigns the tag (w.vid, or the next free one
// from the pool when 0) and, when egress is set, puts it back on the wire.
func (s *Service) wireUplink(id, orgID int64, w uplinkWiring, egress string, tnetID int64) error {
	if _, err := s.db.Exec(`UPDATE tenant_uplinks SET mode=?, trunk_id=?, dedicated_iface=?, outer_vid=0,
		status='unbound', egress_bridge='', error='' WHERE id=?`, w.mode, nullIf(w.trunkID), w.ded, id); err != nil {
		return err
	}
	if w.mode != "dedicated" {
		if w.vid > 0 {
			if err := s.SetExplicitVID(id, orgID, w.trunkID, w.vid); err != nil {
				return err
			}
		} else if _, err := s.AllocVID(id, orgID, w.trunkID); err != nil {
			return err
		}
	}
	if egress == "" {
		return nil
	}
	if err := s.realizeUplink(id, egress); err != nil {
		return err
	}
	if tnetID != 0 {
		return s.resyncVSwitch(tnetID)
	}
	return nil
}

// SetUplinkConnection connects an uplink to one of its tenant's vSwitches, moves
// it to another, or (tnetID 0) disconnects it — the admin side of the tenant's
// Connect / Disconnect.
func (s *Service) SetUplinkConnection(p *Principal, uplinkID, tnetID int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var orgID, curT, netID int64
	if err := s.db.QueryRow(`SELECT org_id FROM tenant_uplinks WHERE id=?`, uplinkID).Scan(&orgID); err != nil {
		return fmt.Errorf("uplink not found")
	}
	_ = s.db.QueryRow(`SELECT id FROM tenant_networks WHERE uplink_id=?`, uplinkID).Scan(&curT)
	if tnetID == curT {
		return nil
	}
	if tnetID != 0 {
		var tOrg int64
		var name string
		var up sql.NullInt64
		if err := s.db.QueryRow(`SELECT org_id,network_id,name,uplink_id FROM tenant_networks WHERE id=?`, tnetID).
			Scan(&tOrg, &netID, &name, &up); err != nil || tOrg != orgID {
			return fmt.Errorf("that vSwitch doesn't belong to this uplink's organization")
		}
		if up.Valid {
			return fmt.Errorf("vSwitch %s already has an uplink — disconnect it first", name)
		}
	}
	if curT != 0 {
		if err := s.disconnectUplink(curT, uplinkID); err != nil {
			return err
		}
	}
	if tnetID != 0 {
		if err := s.connectUplink(tnetID, netID, uplinkID); err != nil {
			return err
		}
		s.audit(p, orgID, "uplink.connect", "tenant_network", fmt.Sprint(tnetID), ip, map[string]any{"uplink": uplinkID})
	} else {
		s.audit(p, orgID, "uplink.disconnect", "tenant_network", fmt.Sprint(curT), ip, nil)
	}
	return nil
}

// disconnectUplink takes an uplink off its vSwitch (refused while a VM is live on
// it). The uplink keeps its tag; port groups it carried get their host gateway /
// DHCP back.
func (s *Service) disconnectUplink(tnetID, uplinkID int64) error {
	if err := s.unrealizeUplink(uplinkID, true, false); err != nil {
		return err
	}
	_, _ = s.db.Exec(`UPDATE tenant_networks SET uplink_id=NULL WHERE id=?`, tnetID)
	if err := s.resyncVSwitch(tnetID); err != nil {
		log.Printf("tenant-net: resync vSwitch %d after disconnect: %v", tnetID, err)
	}
	return nil
}

// TenantNetLite is a tenant vSwitch as the egress console lists it.
type TenantNetLite struct {
	ID        int64  `json:"id"`
	OrgID     int64  `json:"org"`
	Name      string `json:"name"`
	IsDefault bool   `json:"default"`
	UplinkID  int64  `json:"uplink"`
}

// AllTenantNetworks lists every org's vSwitches (instance admin) — the egress
// console's connect pickers.
func (s *Service) AllTenantNetworks(p *Principal) ([]TenantNetLite, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,org_id,name,is_default,COALESCE(uplink_id,0) FROM tenant_networks ORDER BY org_id, is_default DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantNetLite
	for rows.Next() {
		var t TenantNetLite
		var def int
		if rows.Scan(&t.ID, &t.OrgID, &t.Name, &def, &t.UplinkID) == nil {
			t.IsDefault = def == 1
			out = append(out, t)
		}
	}
	return out, rows.Err()
}
