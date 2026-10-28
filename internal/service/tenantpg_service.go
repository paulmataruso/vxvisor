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
// with an uplink leg instead.
//
// The host never routes for a tenant: every tenant bridge / port-group interface
// gets per-interface forwarding off + the vdxtenant nft guard (DHCP in, nothing
// else), re-applied after anything that could reset it.

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
	Native      bool // carried untagged on the vSwitch's uplink
	Carried     bool // leaves on the vSwitch's uplink (set by ListTenantNetworks)
	VMs         int  // live instances attached
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
// port group out the uplink.
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
	return nil
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
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\n\r") {
		return 0, fmt.Errorf("a port group name is required (no '/')")
	}
	if vlan < 2 || vlan > 4094 {
		return 0, fmt.Errorf("VLAN must be 2-4094 (VLAN 1 is the vSwitch's untagged default port group)")
	}
	bridge := tenantBridgeName(netID)
	if len(netdrv.BridgeVlanIfaceName(bridge, vlan)) > 15 {
		return 0, fmt.Errorf("VLAN interface name for %s.%d is too long", bridge, vlan)
	}
	cidr, gateway = strings.TrimSpace(cidr), strings.TrimSpace(gateway)
	if cidr != "" {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return 0, fmt.Errorf("invalid CIDR %q", cidr)
		}
	}
	if gateway != "" {
		if cidr == "" {
			return 0, fmt.Errorf("a gateway needs the port group's CIDR")
		}
		if err := gatewayInCIDR(gateway, cidr); err != nil {
			return 0, err
		}
	}
	if dhcp {
		if gateway == "" {
			return 0, fmt.Errorf("DHCP needs a gateway (the host serves DHCP from the gateway address)")
		}
		if err := validDHCPRange(dhcpRange); err != nil {
			return 0, err
		}
		if strings.TrimSpace(dns) == "" {
			dns = "1.1.1.1,8.8.8.8"
		}
	} else {
		dhcpRange, dns = "", ""
	}
	pgNet, err := s.net.CreateNetwork(netdrv.Network{
		OrgID: p.OrgID, Name: vsName + "/" + name, Mode: "bridge", Bridge: bridge, VLANID: vlan, CIDR: cidr, Gateway: gateway,
	})
	if err != nil {
		return 0, fmt.Errorf("create backing port group: %w", err)
	}
	res, err := s.db.Exec(`INSERT INTO tenant_portgroups(org_id,tnet_id,name,vlan_id,network_id,dhcp,dhcp_range,dhcp_dns)
		VALUES(?,?,?,?,?,?,?,?)`, p.OrgID, tnetID, name, vlan, pgNet, b2iDHCP(dhcp), dhcpRange, dns)
	if err != nil {
		_ = s.net.DeleteNetwork(p.OrgID, pgNet)
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, fmt.Errorf("this vSwitch already has a port group with that name or VLAN")
		}
		return 0, err
	}
	id, _ := res.LastInsertId()
	if err := s.resyncVSwitch(tnetID); err != nil {
		_, _ = s.db.Exec(`DELETE FROM tenant_portgroups WHERE id=?`, id)
		_ = s.net.DeleteNetwork(p.OrgID, pgNet)
		netdrv.StopTenantDHCP(netdrv.BridgeVlanIfaceName(bridge, vlan))
		netdrv.DelBridgeVlanIface(bridge, vlan)
		if rerr := s.resyncVSwitch(tnetID); rerr != nil {
			log.Printf("tenant-pg: resync %s after failed create: %v", bridge, rerr)
		}
		return 0, fmt.Errorf("realize port group: %w", err)
	}
	s.audit(p, p.OrgID, "tenantpg.create", "tenant_portgroup", fmt.Sprint(id), ip,
		map[string]any{"vswitch": vsName, "name": name, "vlan": vlan, "cidr": cidr, "gateway": gateway})
	return id, nil
}

// DeleteTenantPortGroup removes a port group (org admin). Refuses while an
// instance or a router is attached to it.
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
	if _, err := s.db.Exec(`UPDATE tenant_networks SET native_vlan=0 WHERE id=? AND native_vlan=?`, pg.TnetID, pg.VLAN); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM tenant_portgroups WHERE id=?`, id); err != nil {
		return err
	}
	if err := s.net.DeleteNetwork(p.OrgID, pg.NetworkID); err != nil {
		return err
	}
	bridge := tenantBridgeName(netID)
	netdrv.StopTenantDHCP(netdrv.BridgeVlanIfaceName(bridge, pg.VLAN))
	netdrv.DelBridgeVlanIface(bridge, pg.VLAN)
	if err := s.resyncVSwitch(pg.TnetID); err != nil {
		log.Printf("tenant-pg: resync %s after delete: %v", bridge, err)
	}
	s.audit(p, p.OrgID, "tenantpg.delete", "tenant_portgroup", fmt.Sprint(id), ip,
		map[string]any{"name": pg.Name, "vlan": pg.VLAN})
	return nil
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

// syncVSwitch reconciles one vSwitch's bridge: VLAN filtering, the host gateway
// + DHCP of each standalone port group that is not carried out the uplink
// (default PG on the bridge itself, VLAN PGs on <bridge>.<vid>; stale ones
// removed), and the uplink port's VLAN memberships. Idempotent.
func (s *Service) syncVSwitch(tnetID int64) error {
	vswitchMu.Lock()
	defer vswitchMu.Unlock()
	var netID, vrouterID int64
	var native int
	var uplinkID sql.NullInt64
	var cidr, gateway, mode string
	if err := s.db.QueryRow(`SELECT t.network_id,t.native_vlan,t.uplink_id,t.vrouter_id,COALESCE(n.cidr,''),COALESCE(n.gateway,''),
		COALESCE(u.mode,'') FROM tenant_networks t JOIN networks n ON n.id=t.network_id
		LEFT JOIN tenant_uplinks u ON u.id=t.uplink_id WHERE t.id=?`, tnetID).
		Scan(&netID, &native, &uplinkID, &vrouterID, &cidr, &gateway, &mode); err != nil {
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
	// The untagged default port group's host gateway lives on the bridge itself.
	if vrouterID == 0 && gateway != "" {
		gwCIDR, _ := gatewayCIDRMask(gateway, cidr)
		if carriedOut(mode, native, 0) {
			if gwCIDR != "" && netdrv.IfaceIPv4(bridge) != "" {
				netdrv.DelAddr(bridge, gwCIDR)
			}
			netdrv.StopTenantDHCP(bridge)
		} else if netdrv.IfaceIPv4(bridge) == "" {
			// Back from suspension: same derivation as ReensureTenantNetworks.
			rng := defaultDHCPRange(cidr)
			if err := s.provisionIsolated(bridge, cidr, gateway, rng != "", rng, "1.1.1.1,8.8.8.8"); err != nil {
				return fmt.Errorf("restore default port group gateway: %w", err)
			}
		}
	}
	var vlans []int
	hostGW := map[int]bool{}
	for _, pg := range pgs {
		vlans = append(vlans, pg.VLAN)
		if pg.Gateway == "" || pg.VRouterID != 0 || carriedOut(mode, native, pg.VLAN) {
			continue // routed / L2-out / upstream-owned: no host presence at all
		}
		hostGW[pg.VLAN] = true
		iface, err := netdrv.EnsureBridgeVlanIface(bridge, pg.VLAN)
		if err != nil {
			return fmt.Errorf("port group %s: %w", pg.Name, err)
		}
		gwCIDR, mask := gatewayCIDRMask(pg.Gateway, pg.CIDR)
		fresh := false
		if gwCIDR != "" && netdrv.IfaceIPv4(iface) == "" {
			if err := netdrv.AddAddr(iface, gwCIDR); err != nil {
				return fmt.Errorf("port group %s gateway: %w", pg.Name, err)
			}
			fresh = true
		}
		if pg.DHCP {
			if fresh || !netdrv.TenantDHCPRunning(iface) {
				if err := netdrv.StartTenantDHCP(iface, pg.Gateway, vrouter.NormalizeDHCPRange(pg.DHCPRange), mask, pg.DNS); err != nil {
					return fmt.Errorf("port group %s DHCP: %w", pg.Name, err)
				}
			}
		} else {
			netdrv.StopTenantDHCP(iface)
		}
	}
	for _, vid := range bridgeVlanIfaceVIDs(bridge) {
		if !hostGW[vid] {
			netdrv.StopTenantDHCP(netdrv.BridgeVlanIfaceName(bridge, vid))
			netdrv.DelBridgeVlanIface(bridge, vid)
		}
	}
	if uplinkID.Valid && len(pgs) > 0 {
		if port, mode := s.uplinkPort(uplinkID.Int64); port != "" && netdrv.IfaceExists(port) {
			pvid, tagged := uplinkPortVlans(mode, native, vlans)
			if err := netdrv.SetPortVlans(port, pvid, tagged); err != nil {
				return fmt.Errorf("uplink port %s: %w", port, err)
			}
		}
	}
	return nil
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

// applyTenantIsolation turns host forwarding off on every tenant bridge and
// port-group interface and reloads the vdxtenant guard over all of them. Safe
// to call any time; it is the single place the guard is (re)built.
func (s *Service) applyTenantIsolation() error {
	vswitchMu.Lock()
	defer vswitchMu.Unlock()
	rows, err := s.db.Query(`SELECT t.network_id,COALESCE(pg.vlan_id,0) FROM tenant_networks t
		LEFT JOIN tenant_portgroups pg ON pg.tnet_id=t.id`)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var devs []string
	for rows.Next() {
		var netID int64
		var vid int
		if rows.Scan(&netID, &vid) != nil {
			continue
		}
		br := tenantBridgeName(netID)
		for _, d := range []string{br, netdrv.BridgeVlanIfaceName(br, vid)} {
			if (d == br || vid > 0) && !seen[d] {
				seen[d] = true
				devs = append(devs, d)
			}
		}
	}
	rows.Close()
	sort.Strings(devs)
	for _, d := range devs {
		if netdrv.IfaceExists(d) {
			if err := netdrv.IsolateTenantIface(d); err != nil {
				log.Printf("tenant-pg: %v", err)
			}
		}
	}
	return netdrv.ApplyTenantGuard(devs)
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
