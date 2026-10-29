package service

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"vdxclone/internal/lxc"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/vrouter"
)

// Tenant vSwitches + port groups. A tenant network IS the tenant's vSwitch: its
// bridge (vdxt<network_id>) and its backing networks row, which doubles as the
// vSwitch's untagged default port group. tenant_portgroups adds VLAN port groups
// (2-4094) on the same bridge, each with its own backing networks row (so VMs
// attach to a port group exactly like any other). The bridge turns on 802.1q
// filtering only once it has a tagged port group; until then it stays the plain
// bridge it always was.
//
// A port group is one of:
//   - standalone: a host gateway (VLAN interface <bridge>.<vid>) holding the
//     gateway IP and DHCP — local to the tenant, never routed by the host;
//   - routed: gatewayless, attached to the org's netns vRouter (its leg is the
//     gateway; see AttachPortGroup);
//   - L2-out: gatewayless, carried out the vSwitch's uplink and routed upstream.
//
// The uplink port carries the vSwitch's NATIVE port group untagged (native_vlan;
// 0 = the untagged default PG). An access uplink is one 802.1q tag on the wire,
// so it carries only that native port group; a QinQ or dedicated uplink also
// carries every other port group tagged with its own VLAN. A port group carried
// out the uplink belongs to the upstream network: its host gateway + DHCP are
// suspended while it is carried (the host must never answer DHCP or hold an
// address on the provider's wire), and it can't be routed by a tenant router
// (that would put a second gateway on the upstream L2) — the router joins it
// with an uplink leg (its external interface) instead. Every change that alters
// what the uplink carries (connect / disconnect / native / mode / deleting the
// native port group) re-checks both: no router-gatewayed port group may become
// carried, and no router external interface may be left on one that isn't.
//
// The host never routes for a tenant: every tenant bridge / port-group interface
// gets per-interface forwarding off + the vdxtenant nft guard (DHCP in, nothing
// else), and every tenant bridge the vdxtenantl2 segment guard (no rogue DHCP /
// RA / BPDU from a VM), re-applied after anything that could reset them.

// vswitchMu serializes host-side vSwitch syncs and the isolation guard reload.
var vswitchMu sync.Mutex

// TenantPortGroup is one VLAN port group on a tenant vSwitch.
type TenantPortGroup struct {
	ID          int64
	OrgID       int64
	TnetID      int64
	Name        string
	VLAN        int
	NetworkID   int64
	CIDR        string
	Gateway     string
	DHCP        bool
	DHCPRange   string
	DNS         string
	VRouterID   int64
	VRouterName string
	Native      bool   // carried untagged on the vSwitch's uplink
	Carried     bool   // leaves on the vSwitch's uplink (set by ListTenantNetworks)
	VMs         int    // live instances attached
	ExtRouter   string // router whose external interface is on it (set by ListTenantNetworks)
	AddrLocked  bool   // subnet / gateway can't change now (set by ListTenantNetworks)
}

// Kind is the port group's role for display: routed / uplink / standalone / l2.
func (pg TenantPortGroup) Kind() string {
	switch {
	case pg.VRouterID != 0:
		return "routed"
	case pg.Carried:
		return "uplink"
	case pg.Gateway != "":
		return "standalone"
	}
	return "l2"
}

// DHCPRangeText is the port group's DHCP range as a form shows it ("start-end").
func (pg TenantPortGroup) DHCPRangeText() string { return strings.Replace(pg.DHCPRange, ",", "-", 1) }

// carriedOut reports whether a vSwitch's port group (vlan; 0 = the untagged
// default) leaves on its uplink, given the uplink mode ("" = none) and the
// native VLAN. Mirrors uplinkPortVlans.
func carriedOut(mode string, native, vlan int) bool {
	if mode == "" {
		return false
	}
	if vlan == native {
		return true
	}
	return mode != "access" && vlan != 0
}

// vswitchEgress returns a vSwitch's uplink mode ("" = no uplink) and native VLAN.
func (s *Service) vswitchEgress(tnetID int64) (mode string, native int) {
	_ = s.db.QueryRow(`SELECT COALESCE(u.mode,''),t.native_vlan FROM tenant_networks t
		LEFT JOIN tenant_uplinks u ON u.id=t.uplink_id WHERE t.id=?`, tnetID).Scan(&mode, &native)
	return mode, native
}

// checkCarry refuses an uplink/native change that would carry a router-gatewayed
// port group out the uplink, or leave a router's external interface on a port
// group the uplink no longer carries.
func (s *Service) checkCarry(tnetID int64, mode string, native int) error {
	var vr int64
	_ = s.db.QueryRow(`SELECT vrouter_id FROM tenant_networks WHERE id=?`, tnetID).Scan(&vr)
	if vr != 0 && carriedOut(mode, native, 0) {
		return fmt.Errorf("the vSwitch's untagged port group is routed by a router, so it can't be carried out the uplink — detach it from the router first")
	}
	pgs, err := s.portGroupsWhere(`pg.tnet_id=?`, tnetID)
	if err != nil {
		return err
	}
	for _, pg := range pgs {
		if pg.VRouterID != 0 && carriedOut(mode, native, pg.VLAN) {
			return fmt.Errorf("port group %s (VLAN %d) is routed by %s, so it can't be carried out the uplink — detach it from the router first",
				pg.Name, pg.VLAN, pg.VRouterName)
		}
	}
	return s.checkUplinkLegs(tnetID, mode, native)
}

const tpgCols = `pg.id,pg.org_id,pg.tnet_id,pg.name,pg.vlan_id,pg.network_id,COALESCE(n.cidr,''),COALESCE(n.gateway,''),
	pg.dhcp,pg.dhcp_range,pg.dhcp_dns,pg.vrouter_id,COALESCE((SELECT v.name FROM vrouters v WHERE v.id=pg.vrouter_id),''),
	CASE WHEN t.native_vlan=pg.vlan_id THEN 1 ELSE 0 END,
	(SELECT COUNT(*) FROM sessions s WHERE s.network_id=pg.network_id AND s.deleted_at IS NULL)`

func scanTPG(sc interface{ Scan(...any) error }) (TenantPortGroup, error) {
	var pg TenantPortGroup
	var dhcp, native int
	err := sc.Scan(&pg.ID, &pg.OrgID, &pg.TnetID, &pg.Name, &pg.VLAN, &pg.NetworkID, &pg.CIDR, &pg.Gateway,
		&dhcp, &pg.DHCPRange, &pg.DNS, &pg.VRouterID, &pg.VRouterName, &native, &pg.VMs)
	pg.DHCP, pg.Native = dhcp == 1, native == 1
	return pg, err
}

// portGroupsWhere lists port groups matching a WHERE clause on pg/t.
func (s *Service) portGroupsWhere(where string, args ...any) ([]TenantPortGroup, error) {
	rows, err := s.db.Query(`SELECT `+tpgCols+` FROM tenant_portgroups pg
		JOIN tenant_networks t ON t.id=pg.tnet_id LEFT JOIN networks n ON n.id=pg.network_id
		WHERE `+where+` ORDER BY pg.vlan_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantPortGroup
	for rows.Next() {
		pg, err := scanTPG(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pg)
	}
	return out, rows.Err()
}

// ListTenantPortGroups returns the caller org's port groups (every vSwitch).
func (s *Service) ListTenantPortGroups(p *Principal) ([]TenantPortGroup, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.portGroupsWhere(`pg.org_id=?`, p.OrgID)
}

// CreateTenantPortGroup adds a VLAN port group to one of the org's vSwitches
// (org admin). A gateway makes it standalone (host gateway + optional DHCP,
// local only); without one it is routed (attach it to a router) or L2-out.
func (s *Service) CreateTenantPortGroup(p *Principal, tnetID int64, name string, vlan int, cidr, gateway string,
	dhcp bool, dhcpRange, dns, ip string) (int64, error) {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return 0, ErrUnauthorized
	}
	var vsName string
	var netID int64
	if err := s.db.QueryRow(`SELECT name,network_id FROM tenant_networks WHERE id=? AND org_id=?`, tnetID, p.OrgID).
		Scan(&vsName, &netID); err != nil {
		return 0, fmt.Errorf("vSwitch not found in this org")
	}
	name, err := validTenantName(name, "port group")
	if err != nil {
		return 0, err
	}
	if vlan < 2 || vlan > 4094 {
		return 0, fmt.Errorf("VLAN must be 2-4094 (VLAN 1 is the vSwitch's untagged default port group)")
	}
	bridge := tenantBridgeName(netID)
	if n := netdrv.BridgeVlanIfaceName(bridge, vlan); len(n) > 15 {
		return 0, fmt.Errorf("this vSwitch can't take VLAN %d: its gateway interface %s would exceed the kernel's 15-character interface-name limit — use a lower VLAN ID", vlan, n)
	}
	l3, err := parseTenantL3(cidr, gateway, dhcp, dhcpRange, dns)
	if err != nil {
		return 0, err
	}
	if err := checkHostOverlap(l3.CIDR, p.IsAdmin); err != nil {
		return 0, err
	}
	pgNet, err := s.net.CreateNetwork(netdrv.Network{
		OrgID: p.OrgID, Name: vsName + "/" + name, Mode: "bridge", Bridge: bridge, VLANID: vlan, CIDR: l3.CIDR, Gateway: l3.Gateway,
	})
	if err != nil {
		return 0, fmt.Errorf("create backing port group: %w", err)
	}
	res, err := s.db.Exec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id,dhcp,dhcp_range,dhcp_dns)
		VALUES(?,?,?,?,?,?,?,?)`, p.OrgID, tnetID, name, vlan, pgNet, b2iDHCP(l3.DHCP), l3.Range, l3.DNS)
	if err != nil {
		_ = s.net.DeleteNetwork(p.OrgID, pgNet)
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, fmt.Errorf("this vSwitch already has a port group with that name or VLAN")
		}
		return 0, err
	}
	id, _ := res.LastInsertId()
	// The port group's own segment identity, like its vSwitch's (best effort).
	if _, err := s.AllocVNI(p.OrgID, pgNet); err != nil {
		log.Printf("tenant-pg: VNI identity not allocated for net %d: %v", pgNet, err)
	}
	if err := s.resyncVSwitch(tnetID); err != nil {
		_, _ = s.db.Exec(`DELETE FROM tenant_portgroups WHERE id=?`, id)
		_ = s.net.DeleteNetwork(p.OrgID, pgNet)
		netdrv.StopTenantDHCP(netdrv.BridgeVlanIfaceName(bridge, vlan))
		netdrv.DelBridgeVlanIface(bridge, vlan)
		s.FreeVNI(pgNet)
		if rerr := s.resyncVSwitch(tnetID); rerr != nil {
			log.Printf("tenant-pg: resync %s after failed create: %v", bridge, rerr)
		}
		return 0, fmt.Errorf("realize port group: %w", err)
	}
	s.audit(p, p.OrgID, "tenantpg.create", "tenant_portgroup", fmt.Sprint(id), ip,
		map[string]any{"vswitch": vsName, "name": name, "vlan": vlan, "cidr": l3.CIDR, "gateway": l3.Gateway})
	return id, nil
}

// DeleteTenantPortGroup removes a port group (org admin). Refuses while an
// instance, a router or a router's external interface is attached to it, and
// when it is the uplink's native port group and the untagged port group that
// takes over as native can't be carried (it is router-gatewayed).
func (s *Service) DeleteTenantPortGroup(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	list, err := s.portGroupsWhere(`pg.id=? AND pg.org_id=?`, id, p.OrgID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return fmt.Errorf("port group not found in this org")
	}
	pg := list[0]
	if pg.VRouterID != 0 {
		return fmt.Errorf("this port group is attached to router %q — detach it first", pg.VRouterName)
	}
	if pg.VMs > 0 {
		return fmt.Errorf("%d instance(s) are still attached to this port group — move or delete them first", pg.VMs)
	}
	var netID int64
	if err := s.db.QueryRow(`SELECT network_id FROM tenant_networks WHERE id=?`, pg.TnetID).Scan(&netID); err != nil {
		return err
	}
	bridge := tenantBridgeName(netID)
	for _, l := range s.uplinkLegsOn(bridge) {
		if l.vlan == pg.VLAN {
			return fmt.Errorf("router %s's external interface is on this port group — detach it from the router first", l.router)
		}
	}
	if pg.Native {
		// The untagged port group becomes native in its place: the same check as
		// picking it as native by hand.
		if mode, _ := s.vswitchEgress(pg.TnetID); mode != "" {
			if err := s.checkCarry(pg.TnetID, mode, 0); err != nil {
				return fmt.Errorf("this is the uplink's native port group, and the untagged port group would take its place: %w", err)
			}
		}
		if _, err := s.db.Exec(`UPDATE tenant_networks SET native_vlan=0 WHERE id=? AND native_vlan=?`, pg.TnetID, pg.VLAN); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`DELETE FROM tenant_portgroups WHERE id=?`, id); err != nil {
		return err
	}
	if err := s.net.DeleteNetwork(p.OrgID, pg.NetworkID); err != nil {
		return err
	}
	iface := netdrv.BridgeVlanIfaceName(bridge, pg.VLAN)
	netdrv.StopTenantDHCP(iface)
	netdrv.DelBridgeVlanIface(bridge, pg.VLAN)
	if !netdrv.IfaceExists(iface) {
		s.FreeVNI(pg.NetworkID) // device gone: release the segment identity
	}
	if err := s.resyncVSwitch(pg.TnetID); err != nil {
		log.Printf("tenant-pg: resync %s after delete: %v", bridge, err)
	}
	s.audit(p, p.OrgID, "tenantpg.delete", "tenant_portgroup", fmt.Sprint(id), ip,
		map[string]any{"name": pg.Name, "vlan": pg.VLAN})
	return nil
}

// UpdateTenantPortGroup edits a VLAN port group (org admin): its name and DHCP
// settings any time; its subnet and gateway only while no instance, router or
// router external interface is attached. A routed port group's addressing and
// DHCP belong to its router. The VLAN can't change (delete and re-add).
func (s *Service) UpdateTenantPortGroup(p *Principal, id int64, e PortGroupEdit, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	tnets, err := s.ListTenantNetworks(p)
	if err != nil {
		return err
	}
	var pg *TenantPortGroup
	var vs *TenantNetwork
	for i := range tnets {
		for j := range tnets[i].PortGroups {
			if tnets[i].PortGroups[j].ID == id {
				vs, pg = &tnets[i], &tnets[i].PortGroups[j]
			}
		}
	}
	if pg == nil {
		return fmt.Errorf("port group not found in this org")
	}
	name, err := validTenantName(e.Name, "port group")
	if err != nil {
		return err
	}
	if name != pg.Name {
		var dup int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_portgroups WHERE tnet_id=? AND name=? AND id!=?`, pg.TnetID, name, id).Scan(&dup)
		if dup > 0 {
			return fmt.Errorf("vSwitch %s already has a port group named %q", vs.Name, name)
		}
	}
	old := pgL3(*pg)
	next := old
	if e.L3 {
		if pg.VRouterID != 0 {
			return fmt.Errorf("this port group is routed by %s — change its gateway and DHCP on the router", pg.VRouterName)
		}
		if next, err = parseTenantL3(e.CIDR, e.Gateway, e.DHCP, e.DHCPRange, e.DNS); err != nil {
			return err
		}
		if sameAddr(old, next) {
			next.CIDR, next.Gateway = old.CIDR, old.Gateway
		} else {
			if err := lockedAddr(pg.VMs, pg.VRouterID != 0, pg.ExtRouter); err != nil {
				return err
			}
			if next.CIDR != old.CIDR {
				if err := checkHostOverlap(next.CIDR, p.IsAdmin); err != nil {
					return err
				}
			}
		}
	}
	write := func(n string, l tenantL3) error {
		if _, err := s.db.Exec(`UPDATE tenant_portgroups SET name=?,dhcp=?,dhcp_range=?,dhcp_dns=? WHERE id=?`,
			n, b2iDHCP(l.DHCP), l.Range, l.DNS, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("vSwitch %s already has a port group named %q", vs.Name, n)
			}
			return err
		}
		_, err := s.db.Exec(`UPDATE networks SET name=?,cidr=?,gateway=? WHERE id=?`, vs.Name+"/"+n, l.CIDR, l.Gateway, pg.NetworkID)
		return err
	}
	if err := write(name, next); err != nil {
		return err
	}
	if next != old {
		// Take the old host gateway + DHCP down; the resync puts up whatever the
		// port group should have now.
		bridge := tenantBridgeName(vs.NetworkID)
		down := func() {
			netdrv.StopTenantDHCP(netdrv.BridgeVlanIfaceName(bridge, pg.VLAN))
			netdrv.DelBridgeVlanIface(bridge, pg.VLAN)
		}
		down()
		if err := s.resyncVSwitch(pg.TnetID); err != nil {
			_ = write(pg.Name, old)
			down()
			if rerr := s.resyncVSwitch(pg.TnetID); rerr != nil {
				log.Printf("tenant-pg: restoring port group %d after a failed edit: %v", id, rerr)
			}
			return fmt.Errorf("apply: %w (the old settings were put back)", err)
		}
	}
	s.audit(p, p.OrgID, "tenantpg.update", "tenant_portgroup", fmt.Sprint(id), ip,
		map[string]any{"name": name, "renamed_from": pg.Name, "vlan": pg.VLAN, "cidr": next.CIDR, "gateway": next.Gateway,
			"dhcp": next.DHCP, "range": next.Range, "dns": next.DNS})
	return nil
}

// pgL3 is a VLAN port group's saved addressing.
func pgL3(pg TenantPortGroup) tenantL3 {
	return storedL3(pg.CIDR, pg.Gateway, pg.DHCP, pg.DHCPRange, pg.DNS)
}

// SetVSwitchNative picks which port group the vSwitch's uplink carries untagged
// (org admin): 0 = the untagged default port group, else one of its port
// groups' VLANs.
func (s *Service) SetVSwitchNative(p *Principal, tnetID int64, vlan int, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	var cur int
	if err := s.db.QueryRow(`SELECT native_vlan FROM tenant_networks WHERE id=? AND org_id=?`, tnetID, p.OrgID).Scan(&cur); err != nil {
		return fmt.Errorf("vSwitch not found in this org")
	}
	if vlan != 0 {
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_portgroups WHERE tnet_id=? AND vlan_id=?`, tnetID, vlan).Scan(&n)
		if n == 0 {
			return fmt.Errorf("VLAN %d is not a port group on this vSwitch", vlan)
		}
	}
	if vlan == cur {
		return nil
	}
	if mode, _ := s.vswitchEgress(tnetID); mode != "" {
		if err := s.checkCarry(tnetID, mode, vlan); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`UPDATE tenant_networks SET native_vlan=? WHERE id=?`, vlan, tnetID); err != nil {
		return err
	}
	if err := s.resyncVSwitch(tnetID); err != nil {
		_, _ = s.db.Exec(`UPDATE tenant_networks SET native_vlan=? WHERE id=?`, cur, tnetID)
		_ = s.resyncVSwitch(tnetID)
		return err
	}
	s.audit(p, p.OrgID, "tenantpg.native", "tenant_network", fmt.Sprint(tnetID), ip, map[string]any{"vlan": vlan})
	return nil
}

// ---- host realization ------------------------------------------------------

// resyncVSwitch brings one vSwitch's host side in line with the DB, then
// reloads the host isolation guard.
func (s *Service) resyncVSwitch(tnetID int64) error {
	err := s.syncVSwitch(tnetID)
	if ierr := s.applyTenantIsolation(); ierr != nil && err == nil {
		err = fmt.Errorf("tenant isolation: %w", ierr)
	}
	return err
}

// uplinkPortVlans is what a vSwitch's uplink port carries: the native port
// group untagged (VLAN 1 inside the bridge = the untagged default PG), and —
// only on QinQ/dedicated uplinks, which can carry inner tags — every other port
// group tagged.
func uplinkPortVlans(mode string, native int, pgVlans []int) (pvid int, tagged []int) {
	pvid = native
	if pvid == 0 {
		pvid = 1
	}
	if mode == "access" {
		return pvid, nil
	}
	for _, v := range pgVlans {
		if v != pvid {
			tagged = append(tagged, v)
		}
	}
	sort.Ints(tagged)
	return pvid, tagged
}

// syncVSwitch reconciles one vSwitch's bridge, in an order that never puts the
// host on the provider's wire:
//  1. the host leaves every port group it must not be on (routed, carried out
//     the uplink, or without a gateway): gateway address + DHCP down;
//  2. the uplink port gets its VLAN memberships and only then comes up (it is
//     enslaved down — see realizeUplink);
//  3. the host gateway + DHCP of each standalone port group that isn't carried
//     (the untagged one on the bridge itself, VLAN ones on <bridge>.<vid>).
//
// Idempotent. A failure on one port group doesn't stop the others; the first
// error is returned.
func (s *Service) syncVSwitch(tnetID int64) error {
	vswitchMu.Lock()
	defer vswitchMu.Unlock()
	var netID, vrouterID int64
	var native, dhcp int
	var uplinkID sql.NullInt64
	var cidr, gateway, mode, rng, dns string
	if err := s.db.QueryRow(`SELECT t.network_id,t.native_vlan,t.uplink_id,t.vrouter_id,COALESCE(n.cidr,''),COALESCE(n.gateway,''),
		COALESCE(u.mode,''),t.dhcp,t.dhcp_range,t.dhcp_dns FROM tenant_networks t JOIN networks n ON n.id=t.network_id
		LEFT JOIN tenant_uplinks u ON u.id=t.uplink_id WHERE t.id=?`, tnetID).
		Scan(&netID, &native, &uplinkID, &vrouterID, &cidr, &gateway, &mode, &dhcp, &rng, &dns); err != nil {
		return err
	}
	bridge := tenantBridgeName(netID)
	if !netdrv.IfaceExists(bridge) {
		return fmt.Errorf("vSwitch bridge %s is not present", bridge)
	}
	pgs, err := s.portGroupsWhere(`pg.tnet_id=?`, tnetID)
	if err != nil {
		return err
	}
	if err := netdrv.SetBridgeVlanFiltering(bridge, len(pgs) > 0); err != nil {
		return err
	}

	// 1. Off everything the host must not be on.
	defHost := vrouterID == 0 && gateway != "" && !carriedOut(mode, native, 0)
	if !defHost {
		netdrv.StopTenantDHCP(bridge)
		if vrouterID == 0 { // with a router, the gateway on the row is the router's own
			hostGatewayDown(bridge, gateway, cidr)
		}
	}
	var vlans []int
	hostGW := map[int]bool{}
	for _, pg := range pgs {
		vlans = append(vlans, pg.VLAN)
		if pg.Gateway != "" && pg.VRouterID == 0 && !carriedOut(mode, native, pg.VLAN) {
			hostGW[pg.VLAN] = true
		}
	}
	for _, vid := range bridgeVlanIfaceVIDs(bridge) {
		if !hostGW[vid] {
			netdrv.StopTenantDHCP(netdrv.BridgeVlanIfaceName(bridge, vid))
			netdrv.DelBridgeVlanIface(bridge, vid)
		}
	}

	// 2. The uplink port: VLANs, then up.
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if uplinkID.Valid {
		if port, umode := s.uplinkPort(uplinkID.Int64); port != "" && netdrv.IfaceExists(port) {
			if len(pgs) > 0 {
				pvid, tagged := uplinkPortVlans(umode, native, vlans)
				if err := netdrv.SetPortVlans(port, pvid, tagged); err != nil {
					return fmt.Errorf("uplink port %s: %w", port, err) // leave it down
				}
			}
			keep(netdrv.LinkUp(port))
		}
	}

	// 3. Host gateways where the host belongs.
	if defHost {
		keep(hostGatewayUp(bridge, storedL3(cidr, gateway, dhcp == 1, rng, dns)))
	}
	for _, pg := range pgs {
		if !hostGW[pg.VLAN] {
			continue
		}
		iface, err := netdrv.EnsureBridgeVlanIface(bridge, pg.VLAN)
		if err != nil {
			keep(fmt.Errorf("port group %s: %w", pg.Name, err))
			continue
		}
		if err := hostGatewayUp(iface, pgL3(pg)); err != nil {
			keep(fmt.Errorf("port group %s: %w", pg.Name, err))
		}
	}
	return firstErr
}

// hostGatewayUp puts a standalone port group's host gateway on iface (the
// vSwitch bridge for its untagged port group, <bridge>.<vid> for a VLAN one) and
// serves its DHCP. Idempotent; a different address left from before an edit is
// replaced. An l3 without a gateway only stops DHCP.
func hostGatewayUp(iface string, l3 tenantL3) error {
	gwCIDR, mask := gatewayCIDRMask(l3.Gateway, l3.CIDR)
	if gwCIDR == "" {
		netdrv.StopTenantDHCP(iface)
		return nil
	}
	if !strings.HasPrefix(iface, "vdxt") {
		return fmt.Errorf("refusing to put a tenant gateway on %q", iface)
	}
	fresh := false
	if cur := netdrv.IfaceIPv4(iface); cur != l3.Gateway {
		if cur != "" {
			_ = netdrv.FlushAddrs(iface)
		}
		if err := netdrv.AddAddr(iface, gwCIDR); err != nil {
			return fmt.Errorf("gateway %s: %w", gwCIDR, err)
		}
		fresh = true
	}
	if !l3.DHCP || l3.Range == "" {
		netdrv.StopTenantDHCP(iface)
		return nil
	}
	if fresh || !netdrv.TenantDHCPRunning(iface) {
		if err := netdrv.StartTenantDHCP(iface, l3.Gateway, l3.Range, mask, l3.DNS); err != nil {
			return fmt.Errorf("DHCP: %w", err)
		}
	}
	return nil
}

// hostGatewayDown takes the host's DHCP and its gateway address (if it holds
// gateway) off iface.
func hostGatewayDown(iface, gateway, cidr string) {
	netdrv.StopTenantDHCP(iface)
	if gwCIDR, _ := gatewayCIDRMask(gateway, cidr); gwCIDR != "" && netdrv.IfaceIPv4(iface) != "" {
		netdrv.DelAddr(iface, gwCIDR)
	}
}

// syncAllVSwitches resyncs every tenant vSwitch (boot, after uplinks).
func (s *Service) syncAllVSwitches() {
	rows, err := s.db.Query(`SELECT id FROM tenant_networks`)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if err := s.syncVSwitch(id); err != nil {
			log.Printf("tenant-pg: sync vSwitch %d: %v", id, err)
		}
	}
	if err := s.applyTenantIsolation(); err != nil {
		log.Printf("tenant-pg: isolation: %v", err)
	}
}

// uplinkPort returns the bridge port device of a bound uplink (its VLAN
// subinterface, or the dedicated NIC) and its mode.
func (s *Service) uplinkPort(uplinkID int64) (port, mode string) {
	var vid int
	var ded, status, trunk string
	if err := s.db.QueryRow(`SELECT u.mode,u.outer_vid,u.dedicated_iface,u.status,COALESCE(t.iface,'')
		FROM tenant_uplinks u LEFT JOIN ext_trunks t ON t.id=u.trunk_id WHERE u.id=?`, uplinkID).
		Scan(&mode, &vid, &ded, &status, &trunk); err != nil || status != "bound" {
		return "", ""
	}
	if mode == "dedicated" {
		return ded, mode
	}
	if trunk == "" || vid <= 0 {
		return "", mode
	}
	return netdrv.SubName(trunk, vid), mode
}

// bridgeVlanIfaceVIDs lists the VIDs of existing <bridge>.<vid> host interfaces.
func bridgeVlanIfaceVIDs(bridge string) []int {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []int
	for _, it := range ifs {
		if rest, ok := strings.CutPrefix(it.Name, bridge+"."); ok {
			if v, err := strconv.Atoi(rest); err == nil {
				out = append(out, v)
			}
		}
	}
	return out
}

// applyTenantIsolation turns host forwarding off (and ARP replies for other
// addresses) on every tenant bridge and port-group interface and reloads the
// vdxtenant host guard over all of them, plus the vdxtenantl2 segment guard over
// every tenant bridge (its uplink port and router legs trusted). Safe to call
// any time; it is the single place both guards are (re)built.
func (s *Service) applyTenantIsolation() error {
	vswitchMu.Lock()
	defer vswitchMu.Unlock()
	rows, err := s.db.Query(`SELECT t.network_id,COALESCE(pg.vlan_id,0) FROM tenant_networks t
		LEFT JOIN tenant_portgroups pg ON pg.tnet_id=t.id`)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var devs, bridges []string
	for rows.Next() {
		var netID int64
		var vid int
		if rows.Scan(&netID, &vid) != nil {
			continue
		}
		br := tenantBridgeName(netID)
		if !seen[br] {
			seen[br] = true
			devs = append(devs, br)
			bridges = append(bridges, br)
		}
		if d := netdrv.BridgeVlanIfaceName(br, vid); vid > 0 && !seen[d] {
			seen[d] = true
			devs = append(devs, d)
		}
	}
	rows.Close()
	sort.Strings(devs)
	sort.Strings(bridges)
	for _, d := range devs {
		if netdrv.IfaceExists(d) {
			if err := netdrv.IsolateTenantIface(d); err != nil {
				log.Printf("tenant-pg: %v", err)
			}
		}
	}
	return netdrv.ApplyTenantGuard(devs, bridges, s.tenantTrustedPorts())
}

// tenantTrustedPorts lists the tenant-bridge ports that may legitimately send
// what the segment guard drops from VMs: each vSwitch's uplink port (the
// provider network's own DHCP / routers are on the other side) and every router
// leg on a tenant bridge (a routed port group's DHCP is the router's).
func (s *Service) tenantTrustedPorts() []string {
	var uplinks []int64
	rows, err := s.db.Query(`SELECT uplink_id FROM tenant_networks WHERE uplink_id IS NOT NULL`)
	if err == nil {
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				uplinks = append(uplinks, id)
			}
		}
		rows.Close()
	}
	set := map[string]bool{}
	for _, id := range uplinks {
		if port, _ := s.uplinkPort(id); port != "" {
			set[port] = true
		}
	}
	rows, err = s.db.Query(`SELECT v.id,v.runtime,v.container_name,l.idx FROM vrouter_legs l JOIN vrouters v ON v.id=l.vrouter_id
		WHERE l.bridge LIKE 'vdxt%'`)
	if err == nil {
		for rows.Next() {
			var id int64
			var rt, ctr string
			var idx int
			if rows.Scan(&id, &rt, &ctr, &idx) == nil {
				if port := routerLegPort(id, rt, ctr, idx); port != "" {
					set[port] = true
				}
			}
		}
		rows.Close()
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// routerLegPort is the host-side veth of a router leg — the names the backends
// give them (netns: vrouter backend_netns.go ApplyLegs; lxc: lxc.LegVethName).
func routerLegPort(vrID int64, runtime, container string, idx int) string {
	switch runtime {
	case vrouter.RuntimeNetns:
		return "vrh" + strconv.FormatInt(vrID, 10) + "e" + strconv.Itoa(idx)
	case vrouter.RuntimeLXC:
		if container != "" {
			return lxc.LegVethName(container, idx)
		}
	}
	return ""
}

// gatewayInCIDR checks that gw is a host address inside cidr.
func gatewayInCIDR(gw, cidr string) error {
	ip := net.ParseIP(gw)
	_, ipnet, err := net.ParseCIDR(cidr)
	if ip == nil || ip.To4() == nil || err != nil || !ipnet.Contains(ip) {
		return fmt.Errorf("gateway %q is not an IPv4 address inside %s", gw, cidr)
	}
	return nil
}
