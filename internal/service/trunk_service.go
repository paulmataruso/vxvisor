package service

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// Tenant networking v3 — external trunks + per-tenant virtual uplinks.
//
// The INSTANCE admin owns this whole surface (physical egress). An ORG admin only
// chooses which of THEIR admin-provisioned uplinks a tenant network connects to
// (see tenantnet_service). A trunk is role-dedicated: guardTrunk refuses to let
// any other path (vSwitch uplink, bond member, transit NIC) steal a trunk device,
// and designation refuses mgmt/storage/in-use NICs.

// ---- views ---------------------------------------------------------------

type ExtTrunkView struct {
	ID              int64
	Iface           string
	Kind            string
	MTU             int
	QinQCapable     bool
	OffloadDisabled bool
	TeardownPending bool
	Shared          bool
	Slaves          []string
	UplinkCount     int
	QinQStatus      string // VerifyQinQ detail, populated on demand
}

type UplinkView struct {
	ID        int64
	OrgID     int64
	OrgName   string
	Name      string
	TrunkID   sql.NullInt64
	TrunkName string
	Mode      string
	OuterVID  int
	DedIface  string
	Bridge    string
	Status    string
	Error     string
	InUseBy   string // tenant network name using this uplink, if any
	InUseByID int64  // ... and its id (0 = not connected)
}

type VlanPoolView struct {
	ID        int64
	OrgID     int64
	OrgName   string
	TrunkID   int64
	TrunkName string
	VidMin    int
	VidMax    int
	Used      int
	Available int
}

// ---- trunk dedication guards ---------------------------------------------

// trunkSlaves returns the physical member NICs of a bond trunk (empty for a NIC
// trunk). Used to apply MTU/offload to every slave and to guard them.
func (s *Service) trunkSlaves(iface string) []string {
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, it := range ifs {
		if it.Master == iface && it.Type != "tap" && it.Type != "vxlan" {
			out = append(out, it.Name)
		}
	}
	return out
}

// extTrunkIfaces returns the set of iface names that are external trunks OR
// slaves of a bond trunk — the devices no other networking path may touch.
// SHARED trunks (shared=1, the mgmt-bond case) are deliberately EXCLUDED: a
// shared trunk is by definition also the management vSwitch's uplink, so it must
// NOT be guarded against that use — only truly dedicated trunks are protected.
func (s *Service) extTrunkIfaces() map[string]bool {
	set := map[string]bool{}
	rows, err := s.db.Query(`SELECT iface FROM ext_trunks WHERE shared=0`)
	if err != nil {
		return set
	}
	var trunks []string
	for rows.Next() {
		var i string
		if rows.Scan(&i) == nil {
			set[i] = true
			trunks = append(trunks, i)
		}
	}
	rows.Close()
	for _, t := range trunks {
		for _, sl := range s.trunkSlaves(t) {
			set[sl] = true
		}
	}
	return set
}

// guardTrunk refuses to let any of nics be used elsewhere (vSwitch uplink, bond
// member, transit NIC) if it is a designated external trunk or a slave of one.
// Wired into CreateVSwitch/CreateBond/UpgradeVSwitchToBond/AddTransitLink.
func (s *Service) guardTrunk(nics ...string) error {
	set := s.extTrunkIfaces()
	for _, n := range nics {
		if set[n] {
			return fmt.Errorf("interface %q is a designated external trunk (dedicated to tenant egress) — remove the trunk designation first", n)
		}
	}
	return nil
}

// isMgmtBridgeUplink reports whether iface is a NIC/bond enslaved to the
// management vSwitch (i.e. the uplink carrying host management). Such a device
// may be designated as a SHARED external trunk — tenant egress rides it as VLAN
// subinterfaces while the parent (and thus management) is never touched.
func (s *Service) isMgmtBridgeUplink(iface string) bool {
	mgmt := s.mgmtIface()
	if mgmt == "" {
		return false
	}
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return false
	}
	mgmtIsBridge := false
	for _, it := range ifs {
		if it.Name == mgmt && it.Type == "bridge" {
			mgmtIsBridge = true
		}
	}
	if !mgmtIsBridge {
		return false // bare mgmt NIC has no uplink to share
	}
	storage := s.StorageIface()
	for _, it := range ifs {
		if it.Name == iface && sharedTrunkCandidate(it, mgmt, storage) {
			return true
		}
	}
	return false
}

// sharedTrunkCandidate reports whether a host interface can be the management
// vSwitch's shared trunk: a physical NIC or bond enslaved to the management
// bridge — never a VM tap, a router or container veth, a VLAN or VXLAN device
// that merely sits on that bridge, nor the storage interface — whose name leaves
// room for a ".<vid>" subinterface.
func sharedTrunkCandidate(it hostinfo.Iface, mgmt, storage string) bool {
	if mgmt == "" || it.Master != mgmt || (storage != "" && it.Name == storage) {
		return false
	}
	if it.Type != "physical" && it.Type != "bond" {
		return false
	}
	return netdrv.CheckTrunkName(it.Name) == nil
}

// SharedTrunkCandidates lists the management vSwitch's uplink device(s) that are
// eligible to become a SHARED external trunk (not already designated). On a
// typical host this is the single management bond. Backs the designate modal's
// "shared with management" option group.
func (s *Service) SharedTrunkCandidates(p *Principal) ([]TransitIface, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	mgmt := s.mgmtIface()
	if mgmt == "" {
		return nil, nil
	}
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	mgmtIsBridge := false
	for _, it := range ifs {
		if it.Name == mgmt && it.Type == "bridge" {
			mgmtIsBridge = true
		}
	}
	if !mgmtIsBridge {
		return nil, nil
	}
	// Exclude any device already designated (shared or not).
	already := map[string]bool{}
	rows, err := s.db.Query(`SELECT iface FROM ext_trunks`)
	if err == nil {
		for rows.Next() {
			var i string
			if rows.Scan(&i) == nil {
				already[i] = true
			}
		}
		rows.Close()
	}
	storage := s.StorageIface()
	var out []TransitIface
	for _, it := range ifs {
		if !sharedTrunkCandidate(it, mgmt, storage) || already[it.Name] {
			continue
		}
		out = append(out, TransitIface{Name: it.Name, State: it.State, Carrier: it.Carrier, SpeedMbps: it.SpeedMbps, Addrs: it.Addrs})
	}
	return out, nil
}

// ---- trunk CRUD (instance admin) -----------------------------------------

func (s *Service) ListExtTrunks(p *Principal) ([]ExtTrunkView, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,iface,kind,mtu,qinq_capable,offload_disabled,teardown_pending,shared FROM ext_trunks ORDER BY iface`)
	if err != nil {
		return nil, err
	}
	var out []ExtTrunkView
	for rows.Next() {
		var t ExtTrunkView
		var qinq, off, tp, sh int
		if err := rows.Scan(&t.ID, &t.Iface, &t.Kind, &t.MTU, &qinq, &off, &tp, &sh); err != nil {
			rows.Close()
			return nil, err
		}
		t.QinQCapable, t.OffloadDisabled, t.TeardownPending, t.Shared = qinq == 1, off == 1, tp == 1, sh == 1
		out = append(out, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// Per-row enrichment runs AFTER the cursor is closed: the single-connection
	// pool (SetMaxOpenConns(1)) deadlocks if a nested query is issued while the
	// outer rows cursor still holds the only connection.
	for i := range out {
		out[i].Slaves = s.trunkSlaves(out[i].Iface)
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE trunk_id=?`, out[i].ID).Scan(&out[i].UplinkCount)
	}
	return out, nil
}

// DesignateTrunk marks a NIC/bond as an external trunk, recording its original
// MTU + offload state ONCE (never overwritten on re-apply) so teardown restores
// it exactly, and preps it (MTU up, offloads off if QinQ-capable).
//
// SHARED mode: the chosen device may instead be the management vSwitch's uplink
// (e.g. the mgmt bond). Then the trunk is SHARED — tenant egress rides the same
// physical link as management as VLAN subinterfaces, and the parent is NEVER
// modified (no MTU raise, no offload toggles) so the management path is never
// disturbed. A shared trunk is access-only; QinQ (which must change the parent's
// MTU/offload) is refused on it.
func (s *Service) DesignateTrunk(p *Principal, iface string, qinqCapable bool, mtu int, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	// C2: refuse mgmt (incl. the 0.0.0.0 case where mgmt can't be identified),
	// storage, and any in-use NIC.
	if s.mgmtIface() == "" {
		return fmt.Errorf("refusing to designate a trunk: the management interface can't be positively identified (admin listener binds 0.0.0.0) — set a specific listen address first so the mgmt NIC is protected")
	}
	// The management interface ITSELF (the bridge carrying the admin IP) is never a
	// trunk — only a NIC/bond enslaved to it can be shared.
	if err := s.guardMgmt(iface); err != nil {
		return err
	}
	if st := s.StorageIface(); st != "" && iface == st {
		return fmt.Errorf("refusing to designate the storage interface %q as a tenant trunk", st)
	}
	if err := netdrv.CheckTrunkName(iface); err != nil {
		return err
	}
	// Is this the management vSwitch's uplink? If so it's a SHARED trunk and the
	// normal "already enslaved / is a vSwitch uplink" refusals are expected and
	// must be bypassed — but only for THIS device and only in access mode.
	sharedMgmt := s.isMgmtBridgeUplink(iface)
	if sharedMgmt && qinqCapable {
		return fmt.Errorf("QinQ can't run on the management uplink %q: it would raise the bond's MTU and disable VLAN offload, disrupting host management — use access (single-tag) mode here, or dedicate a separate NIC/bond for QinQ", iface)
	}
	// Not already enslaved / a vSwitch uplink / a bond member (except the shared
	// mgmt-uplink case handled above).
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return err
	}
	kind := "nic"
	for _, it := range ifs {
		if it.Name == iface {
			if it.Master != "" && !sharedMgmt {
				return fmt.Errorf("interface %q is already enslaved to %q — free it first", iface, it.Master)
			}
			if it.Type == "bond" {
				kind = "bond"
			}
			if it.Type == "bridge" {
				return fmt.Errorf("interface %q is a bridge (vSwitch), not a trunk candidate", iface)
			}
		}
	}
	var usedBy string
	_ = s.db.QueryRow(`SELECT name FROM net_vswitches WHERE uplink=?`, iface).Scan(&usedBy)
	if usedBy != "" && !sharedMgmt {
		return fmt.Errorf("interface %q is the uplink of vSwitch %q — detach it first", iface, usedBy)
	}
	if mtu <= 0 {
		mtu = 1600
	}
	origMTU, origOffload := netdrv.ReadTrunkState(iface)
	q := 0
	if qinqCapable {
		q = 1
	}
	sh := 0
	if sharedMgmt {
		sh = 1
		mtu = origMTU // never change the mgmt uplink's MTU; show its real value
	}
	res, err := s.db.Exec(`INSERT INTO ext_trunks(iface,kind,mtu,qinq_capable,offload_disabled,orig_mtu,orig_offload,shared)
		VALUES(?,?,?,?,?,?,?,?)`, iface, kind, mtu, q, q, origMTU, origOffload, sh)
	if err != nil {
		return fmt.Errorf("designate trunk: %w", err)
	}
	id, _ := res.LastInsertId()
	// A shared trunk's parent is left untouched — only its subinterfaces (created
	// per uplink) carry tenant traffic, so there is nothing to prep here.
	if !sharedMgmt {
		if err := netdrv.EnsureTrunk(iface, s.trunkSlaves(iface), mtu, qinqCapable); err != nil {
			// Roll back the row so a failed prep doesn't leave a half-designated trunk.
			_, _ = s.db.Exec(`DELETE FROM ext_trunks WHERE id=?`, id)
			return fmt.Errorf("prep trunk: %w", err)
		}
	}
	s.audit(p, p.OrgID, "trunk.designate", "ext_trunk", iface, ip, map[string]any{"qinq": qinqCapable, "mtu": mtu, "shared": sharedMgmt})
	return nil
}

// UndesignateTrunk removes a trunk after restoring its original MTU/offload. It
// refuses while any uplink still references it (FK RESTRICT + a friendly error).
func (s *Service) UndesignateTrunk(p *Principal, id int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var iface string
	var origMTU, shared int
	var origOffload string
	if err := s.db.QueryRow(`SELECT iface,orig_mtu,orig_offload,shared FROM ext_trunks WHERE id=?`, id).Scan(&iface, &origMTU, &origOffload, &shared); err != nil {
		return err
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE trunk_id=?`, id).Scan(&n)
	if n > 0 {
		return fmt.Errorf("trunk still has %d uplink(s) — remove them first", n)
	}
	var np int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_vlan_pools WHERE trunk_id=?`, id).Scan(&np)
	if np > 0 {
		return fmt.Errorf("trunk still has %d VLAN pool(s) — remove them first", np)
	}
	if shared == 0 {
		// A shared trunk's parent was never modified, so there is nothing to
		// restore (and we must not touch the live mgmt bond).
		_ = netdrv.RestoreTrunk(iface, s.trunkSlaves(iface), origMTU, origOffload)
	}
	if _, err := s.db.Exec(`DELETE FROM ext_trunks WHERE id=?`, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "trunk.undesignate", "ext_trunk", iface, ip, nil)
	return nil
}

// VerifyTrunkQinQ reports whether a QinQ trunk looks correctly configured on this
// host's NIC (offloads off, MTU high enough) — a pre-trust check for the admin.
func (s *Service) VerifyTrunkQinQ(p *Principal, id int64) (bool, string, error) {
	if !p.IsAdmin {
		return false, "", ErrUnauthorized
	}
	var iface string
	var mtu int
	if err := s.db.QueryRow(`SELECT iface,mtu FROM ext_trunks WHERE id=?`, id).Scan(&iface, &mtu); err != nil {
		return false, "", err
	}
	ok, detail := netdrv.VerifyQinQ(iface, mtu)
	return ok, detail, nil
}

// ---- VLAN pools (instance admin) -----------------------------------------

func (s *Service) SetVlanPool(p *Principal, orgID, trunkID int64, vidMin, vidMax int, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if vidMin < vidAllocMin || vidMax > vidAllocMax || vidMin > vidMax {
		return fmt.Errorf("invalid VLAN pool range %d-%d (must be within %d-%d)", vidMin, vidMax, vidAllocMin, vidAllocMax)
	}
	if err := s.checkPoolRange(orgID, trunkID, vidMin, vidMax); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO tenant_vlan_pools(org_id,trunk_id,vid_min,vid_max) VALUES(?,?,?,?)
		ON CONFLICT(org_id,trunk_id) DO UPDATE SET vid_min=excluded.vid_min, vid_max=excluded.vid_max`,
		orgID, trunkID, vidMin, vidMax); err != nil {
		return err
	}
	s.audit(p, orgID, "trunk.pool.set", "ext_trunk", fmt.Sprint(trunkID), ip, map[string]any{"min": vidMin, "max": vidMax})
	return nil
}

// DeleteVlanPool removes a per-tenant VLAN pool. Refuses while an uplink in that
// pool's range is still allocated from it (so a live tag isn't orphaned).
func (s *Service) DeleteVlanPool(p *Principal, id int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var orgID, trunkID int64
	var lo, hi int
	if err := s.db.QueryRow(`SELECT org_id,trunk_id,vid_min,vid_max FROM tenant_vlan_pools WHERE id=?`, id).Scan(&orgID, &trunkID, &lo, &hi); err != nil {
		return err
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE org_id=? AND trunk_id=? AND outer_vid BETWEEN ? AND ?`, orgID, trunkID, lo, hi).Scan(&n)
	if n > 0 {
		return fmt.Errorf("%d uplink(s) still use a tag from this pool — delete them first", n)
	}
	if _, err := s.db.Exec(`DELETE FROM tenant_vlan_pools WHERE id=?`, id); err != nil {
		return err
	}
	s.audit(p, orgID, "trunk.pool.delete", "ext_trunk", fmt.Sprint(trunkID), ip, nil)
	return nil
}

// ---- uplink CRUD (instance admin) ----------------------------------------

// CreateUplink defines a tenant uplink and allocates/assigns its outer tag. For
// access/qinq a trunk is required; the tag is either auto-allocated from the
// tenant's pool (vid<=0) or an explicit admin-typed tag. For dedicated mode a
// free, guarded physical NIC is assigned instead of a tag. The device isn't wired
// until a tenant network connects to the uplink (realizeUplink).
func (s *Service) CreateUplink(p *Principal, orgID int64, name, mode string, trunkID int64, vid int, dedIface, ip string) (int64, error) {
	return s.createUplink(p, orgID, name, mode, trunkID, vid, dedIface, ip, true)
}

// createUplink is CreateUplink; autoConnect connects the org's unconnected
// default vSwitch to it (the egress wizard connects the vSwitch it was told to).
func (s *Service) createUplink(p *Principal, orgID int64, name, mode string, trunkID int64, vid int, dedIface, ip string, autoConnect bool) (int64, error) {
	if !p.IsAdmin {
		return 0, ErrUnauthorized
	}
	if name = strings.TrimSpace(name); name == "" {
		return 0, fmt.Errorf("uplink name required")
	}
	if mode == "dedicated" {
		trunkID = 0
	}
	if err := s.validateUplinkWiring(mode, trunkID, dedIface, 0); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO tenant_uplinks(org_id,name,trunk_id,mode,dedicated_iface) VALUES(?,?,?,?,?)`,
		orgID, name, nullIf(trunkID), mode, dedIface)
	if err != nil {
		return 0, fmt.Errorf("create uplink (name must be unique within the org): %w", err)
	}
	id, _ := res.LastInsertId()
	if mode == "access" || mode == "qinq" {
		if vid > 0 {
			if err := s.SetExplicitVID(id, orgID, trunkID, vid); err != nil {
				_, _ = s.db.Exec(`DELETE FROM tenant_uplinks WHERE id=?`, id)
				return 0, err
			}
		} else {
			if _, err := s.AllocVID(id, orgID, trunkID); err != nil {
				_, _ = s.db.Exec(`DELETE FROM tenant_uplinks WHERE id=?`, id)
				return 0, err
			}
		}
	}
	s.audit(p, orgID, "uplink.create", "uplink", name, ip, map[string]any{"mode": mode})
	if autoConnect {
		s.autoConnectDefault(orgID, id)
	}
	return id, nil
}

// autoConnectDefault connects a new uplink to the org's default vSwitch when that
// vSwitch has no uplink yet, so a tenant sees its default network wired out with
// no extra step. Best effort: on failure the uplink is simply left unconnected
// (the tenant can connect it from Networks).
func (s *Service) autoConnectDefault(orgID, uplinkID int64) {
	var tnetID, netID int64
	if err := s.db.QueryRow(`SELECT id,network_id FROM tenant_networks WHERE org_id=? AND is_default=1 AND uplink_id IS NULL LIMIT 1`,
		orgID).Scan(&tnetID, &netID); err != nil {
		return
	}
	if err := s.connectUplink(tnetID, netID, uplinkID); err != nil {
		log.Printf("uplink %d: auto-connect to org %d default vSwitch: %v", uplinkID, orgID, err)
	}
}

// DeleteUplink removes an uplink after clearing any tenant-network reference and
// tearing its device down (free-after-device-gone). Refuses if a tenant VM is
// live on its egress bridge.
func (s *Service) DeleteUplink(p *Principal, id int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var tnetID int64
	_ = s.db.QueryRow(`SELECT id FROM tenant_networks WHERE uplink_id=?`, id).Scan(&tnetID)
	if tnetID != 0 {
		if err := s.checkUplinkLegs(tnetID, "", 0); err != nil {
			return err
		}
	}
	if err := s.unrealizeUplink(id, true, true); err != nil {
		return err
	}
	// Clear any network reference (the FK is RESTRICT), then delete.
	_, _ = s.db.Exec(`UPDATE tenant_networks SET uplink_id=NULL WHERE uplink_id=?`, id)
	if _, err := s.db.Exec(`DELETE FROM tenant_uplinks WHERE id=?`, id); err != nil {
		return err
	}
	if tnetID != 0 {
		// Port groups it carried get their host gateway / DHCP back.
		if err := s.resyncVSwitch(tnetID); err != nil {
			log.Printf("tenant-net: resync vSwitch %d after deleting its uplink: %v", tnetID, err)
		}
	}
	s.audit(p, p.OrgID, "uplink.delete", "uplink", fmt.Sprint(id), ip, nil)
	return nil
}

// realizeUplink wires the uplink's device into the given tenant egress bridge:
// a VLAN subinterface for access/qinq, or the whole dedicated NIC. The port is
// enslaved DOWN; syncVSwitch brings it up once its VLANs are set and the host is
// off everything it carries. Idempotent.
func (s *Service) realizeUplink(id int64, egressBridge string) error {
	if !strings.HasPrefix(egressBridge, "vdxt") {
		return fmt.Errorf("refusing to wire an uplink into %q: not a tenant vSwitch", egressBridge)
	}
	var mode, dedIface string
	var vid int
	var trunkID sql.NullInt64
	if err := s.db.QueryRow(`SELECT mode,outer_vid,dedicated_iface,trunk_id FROM tenant_uplinks WHERE id=?`, id).
		Scan(&mode, &vid, &dedIface, &trunkID); err != nil {
		return err
	}
	switch mode {
	case "access", "qinq":
		var trunk string
		if err := s.db.QueryRow(`SELECT iface FROM ext_trunks WHERE id=?`, trunkID.Int64).Scan(&trunk); err != nil {
			return fmt.Errorf("uplink trunk missing: %w", err)
		}
		proto := "802.1q"
		if mode == "qinq" {
			proto = "802.1ad"
		}
		if vid <= 0 {
			return fmt.Errorf("uplink has no tag assigned")
		}
		if _, err := netdrv.ClaimVlanSub(trunk, vid, proto, egressBridge); err != nil {
			s.markUplink(id, "error", err.Error())
			return err
		}
	case "dedicated":
		// Same guarded enslave contract as transit (free / no IP already checked
		// at create; re-guard mgmt/storage/trunk here defensively).
		if err := s.guardMgmt(dedIface); err != nil {
			return err
		}
		if err := netdrv.EnslavePortDown(dedIface, egressBridge); err != nil {
			s.markUplink(id, "error", err.Error())
			return err
		}
	}
	_, _ = s.db.Exec(`UPDATE tenant_uplinks SET status='bound', egress_bridge=?, error='' WHERE id=?`, egressBridge, id)
	return nil
}

// unrealizeUplink tears the uplink device down. For access/qinq it deletes the
// subinterface; with free it then (only after confirming the device is gone)
// releases the VID back to the pool. A tenant disconnect passes free=false: the
// uplink keeps its admin-assigned tag so it can be reconnected — only deleting
// the uplink (or the global teardown) gives the tag back. For dedicated it
// detaches the NIC. If guardLiveVMs, it refuses when a VM tap is still on the
// egress bridge.
func (s *Service) unrealizeUplink(id int64, guardLiveVMs, free bool) error {
	var mode, dedIface, egress string
	var vid int
	var trunkID sql.NullInt64
	if err := s.db.QueryRow(`SELECT mode,outer_vid,dedicated_iface,egress_bridge,trunk_id FROM tenant_uplinks WHERE id=?`, id).
		Scan(&mode, &vid, &dedIface, &egress, &trunkID); err != nil {
		return err
	}
	if guardLiveVMs && egress != "" && s.bridgeHasLiveTap(egress) {
		return fmt.Errorf("a VM is still connected to this uplink's network — stop/move it first")
	}
	switch mode {
	case "access", "qinq":
		if trunkID.Valid {
			var trunk string
			if s.db.QueryRow(`SELECT iface FROM ext_trunks WHERE id=?`, trunkID.Int64).Scan(&trunk) == nil && vid > 0 {
				// Only the uplink's own subinterface is removed — a host device
				// that a refused claim left alone is never touched.
				if err := netdrv.ReleaseVlanSub(trunk, vid); err != nil {
					// Device still present — do NOT free the VID (would risk reuse
					// while the device lingers). Surface the error.
					return fmt.Errorf("tear down subinterface %s: %w", netdrv.SubName(trunk, vid), err)
				}
			}
		}
		if free {
			s.FreeVID(id) // only reached after the device is confirmed gone
		} else {
			_, _ = s.db.Exec(`UPDATE tenant_uplinks SET status='unbound', egress_bridge='' WHERE id=?`, id)
		}
	case "dedicated":
		if dedIface != "" {
			_ = netdrv.DetachFromBridge(dedIface)
		}
		_, _ = s.db.Exec(`UPDATE tenant_uplinks SET status='unbound', egress_bridge='' WHERE id=?`, id)
	}
	return nil
}

func (s *Service) markUplink(id int64, status, errMsg string) {
	_, _ = s.db.Exec(`UPDATE tenant_uplinks SET status=?, error=? WHERE id=?`, status, errMsg, id)
}

// bridgeHasLiveTap reports whether any tap interface is enslaved to bridge.
func (s *Service) bridgeHasLiveTap(bridge string) bool {
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return false
	}
	for _, it := range ifs {
		if it.Master == bridge && it.Type == "tap" {
			return true
		}
	}
	return false
}

func nullIf(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// ---- boot reapply + feature teardown -------------------------------------

// ReensureExtTrunks re-applies trunk MTU/offload on boot (devices don't persist).
// It respects teardown_pending: a trunk mid-teardown is restored, not re-enabled.
// Runs BEFORE ReensureUplinks.
func (s *Service) ReensureExtTrunks() {
	rows, err := s.db.Query(`SELECT iface,mtu,qinq_capable,orig_mtu,orig_offload,teardown_pending,shared FROM ext_trunks`)
	if err != nil {
		return
	}
	type t struct {
		iface             string
		mtu, qinq, tp, sh int
		origMTU           int
		origOffload       string
	}
	var ts []t
	for rows.Next() {
		var x t
		if rows.Scan(&x.iface, &x.mtu, &x.qinq, &x.origMTU, &x.origOffload, &x.tp, &x.sh) == nil {
			ts = append(ts, x)
		}
	}
	rows.Close()
	pending := false
	for _, x := range ts {
		if x.tp == 1 {
			pending = true
		}
		if x.sh == 1 {
			continue // shared mgmt-uplink trunk: the parent is never prepped or restored
		}
		if x.tp == 1 {
			_ = netdrv.RestoreTrunk(x.iface, s.trunkSlaves(x.iface), x.origMTU, x.origOffload)
			continue
		}
		_ = netdrv.EnsureTrunk(x.iface, s.trunkSlaves(x.iface), x.mtu, x.qinq == 1)
	}
	if pending {
		// A "Disable tenant egress" that didn't finish (crash, or a device that
		// wouldn't go away): carry it on rather than re-wiring its uplinks.
		if err := s.teardownTenantEgress(true); err != nil {
			log.Printf("tenant egress teardown (resumed at boot): %v", err)
		}
	}
}

// ReensureUplinks re-wires bound uplinks' subinterfaces into their egress bridges
// on boot. Runs AFTER ReensureTenantNetworks (the egress bridges must exist).
// While a global teardown is pending, uplinks are left off the wire.
func (s *Service) ReensureUplinks() {
	rows, err := s.db.Query(`SELECT id,egress_bridge FROM tenant_uplinks WHERE status='bound' AND egress_bridge!=''
		AND NOT EXISTS (SELECT 1 FROM ext_trunks WHERE teardown_pending=1)`)
	if err != nil {
		return
	}
	type u struct {
		id     int64
		bridge string
	}
	var us []u
	for rows.Next() {
		var x u
		if rows.Scan(&x.id, &x.bridge) == nil {
			us = append(us, x)
		}
	}
	rows.Close()
	for _, x := range us {
		if netdrv.IfaceExists(x.bridge) {
			_ = s.realizeUplink(x.id, x.bridge)
		}
	}
	s.syncAllVSwitches() // re-enslaved ports start at VLAN 1 — set their port groups
}

// DisableTenantEgress is the global rollback hammer: tear down every uplink's
// device and restore every trunk, returning host networking to pre-feature state.
func (s *Service) DisableTenantEgress(p *Principal, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	err := s.teardownTenantEgress(false)
	s.audit(p, p.OrgID, "trunk.disable_all", "ext_trunk", "*", ip, map[string]any{"complete": err == nil})
	return err
}

// teardownTenantEgress takes every uplink off the wire and removes it (router
// external interfaces on its vSwitch are detached first; the port groups it
// carried get their host gateway / DHCP back), then restores and removes every
// trunk that no longer has an uplink. The DB only ever forgets what is really
// gone: an uplink whose device won't go away is kept (status error) along with
// its trunk, which stays teardown_pending — the next run, or the next boot,
// carries on from there. onlyPending (boot) resumes an earlier teardown: only
// uplinks on trunks already marked teardown_pending.
func (s *Service) teardownTenantEgress(onlyPending bool) error {
	q := `SELECT u.id,COALESCE(t.id,0) FROM tenant_uplinks u LEFT JOIN tenant_networks t ON t.uplink_id=u.id`
	if onlyPending {
		q += ` WHERE u.trunk_id IN (SELECT id FROM ext_trunks WHERE teardown_pending=1)`
	} else {
		// Mark every trunk first so a crash mid-teardown converges at boot.
		if _, err := s.db.Exec(`UPDATE ext_trunks SET teardown_pending=1`); err != nil {
			return err
		}
	}
	type up struct{ id, tnet int64 }
	var ups []up
	rows, err := s.db.Query(q)
	if err != nil {
		return err
	}
	for rows.Next() {
		var x up
		if rows.Scan(&x.id, &x.tnet) == nil {
			ups = append(ups, x)
		}
	}
	rows.Close()
	var failed []string
	for _, x := range ups {
		if x.tnet != 0 {
			s.detachUplinkLegs(x.tnet)
		}
		if err := s.unrealizeUplink(x.id, false, true); err != nil {
			s.markUplink(x.id, "error", "teardown: "+err.Error())
			failed = append(failed, err.Error())
			continue
		}
		_, _ = s.db.Exec(`UPDATE tenant_networks SET uplink_id=NULL WHERE uplink_id=?`, x.id)
		if _, err := s.db.Exec(`DELETE FROM tenant_uplinks WHERE id=?`, x.id); err != nil {
			failed = append(failed, err.Error())
			continue
		}
		if x.tnet != 0 {
			if err := s.resyncVSwitch(x.tnet); err != nil {
				log.Printf("tenant egress teardown: resync vSwitch %d: %v", x.tnet, err)
			}
		}
	}
	// Restore + remove each pending trunk nothing rides any more (shared trunks
	// never modified the parent, so skip the restore for them — don't touch the
	// live mgmt bond).
	trows, err := s.db.Query(`SELECT id,iface,orig_mtu,orig_offload,shared FROM ext_trunks WHERE teardown_pending=1
		AND id NOT IN (SELECT trunk_id FROM tenant_uplinks WHERE trunk_id IS NOT NULL)`)
	if err != nil {
		return err
	}
	type tr struct {
		id      int64
		iface   string
		origMTU int
		origOff string
		shared  int
	}
	var trs []tr
	for trows.Next() {
		var x tr
		if trows.Scan(&x.id, &x.iface, &x.origMTU, &x.origOff, &x.shared) == nil {
			trs = append(trs, x)
		}
	}
	trows.Close()
	for _, x := range trs {
		if x.shared == 0 {
			_ = netdrv.RestoreTrunk(x.iface, s.trunkSlaves(x.iface), x.origMTU, x.origOff)
		}
		_, _ = s.db.Exec(`DELETE FROM tenant_vlan_pools WHERE trunk_id=?`, x.id)
		_, _ = s.db.Exec(`DELETE FROM ext_trunks WHERE id=?`, x.id)
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d external network(s) couldn't be taken off the wire (first: %s) — they and their trunks are kept and marked; fix the cause and run Disable again (it also resumes at the next boot)",
			len(failed), failed[0])
	}
	return nil
}

// OrgLite is a minimal org row for admin-page dropdowns.
type OrgLite struct {
	ID   int64
	Name string
	Slug string
}

func (s *Service) ListOrgsLite(p *Principal) ([]OrgLite, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,name,slug FROM orgs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrgLite
	for rows.Next() {
		var o OrgLite
		if rows.Scan(&o.ID, &o.Name, &o.Slug) == nil {
			out = append(out, o)
		}
	}
	return out, rows.Err()
}

// ListAllUplinks returns every tenant uplink with its org + trunk name and which
// tenant network (if any) it's connected to — the admin console table.
func (s *Service) ListAllUplinks(p *Principal) ([]UplinkView, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT u.id,u.org_id,COALESCE(o.name,''),u.name,u.trunk_id,COALESCE(t.iface,''),
		u.mode,u.outer_vid,u.dedicated_iface,u.egress_bridge,u.status,u.error,
		COALESCE((SELECT tn.name FROM tenant_networks tn WHERE tn.uplink_id=u.id LIMIT 1),''),
		COALESCE((SELECT tn.id FROM tenant_networks tn WHERE tn.uplink_id=u.id LIMIT 1),0)
		FROM tenant_uplinks u
		LEFT JOIN orgs o ON o.id=u.org_id
		LEFT JOIN ext_trunks t ON t.id=u.trunk_id
		ORDER BY o.name, u.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UplinkView
	for rows.Next() {
		var u UplinkView
		if err := rows.Scan(&u.ID, &u.OrgID, &u.OrgName, &u.Name, &u.TrunkID, &u.TrunkName,
			&u.Mode, &u.OuterVID, &u.DedIface, &u.Bridge, &u.Status, &u.Error, &u.InUseBy, &u.InUseByID); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListVlanPools returns all per-tenant VLAN pools with live used/available counts.
func (s *Service) ListVlanPools(p *Principal) ([]VlanPoolView, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT p.id,p.org_id,COALESCE(o.name,''),p.trunk_id,COALESCE(t.iface,''),p.vid_min,p.vid_max
		FROM tenant_vlan_pools p LEFT JOIN orgs o ON o.id=p.org_id LEFT JOIN ext_trunks t ON t.id=p.trunk_id
		ORDER BY o.name, t.iface`)
	if err != nil {
		return nil, err
	}
	var out []VlanPoolView
	for rows.Next() {
		var v VlanPoolView
		if err := rows.Scan(&v.ID, &v.OrgID, &v.OrgName, &v.TrunkID, &v.TrunkName, &v.VidMin, &v.VidMax); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// Nested counts AFTER the cursor is closed (single-conn pool — see ListExtTrunks).
	for i := range out {
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_uplinks WHERE trunk_id=? AND org_id=? AND outer_vid BETWEEN ? AND ?`,
			out[i].TrunkID, out[i].OrgID, out[i].VidMin, out[i].VidMax).Scan(&out[i].Used)
		out[i].Available = (out[i].VidMax - out[i].VidMin + 1) - out[i].Used
	}
	return out, nil
}

// trunkNameByID is a small helper for views.
func (s *Service) trunkNameByID(id sql.NullInt64) string {
	if !id.Valid {
		return ""
	}
	var n string
	_ = s.db.QueryRow(`SELECT iface FROM ext_trunks WHERE id=?`, id.Int64).Scan(&n)
	return n
}

var _ = strings.TrimSpace
