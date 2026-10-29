package service

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/vrouter"
)

// Tenant networks (v1: "isolated" mode). A tenant network is a first-class,
// per-org isolated L2 segment: a dedicated host bridge vdxt<network_id> with no
// uplink, so two orgs' VMs can never share a broadcast domain. It OWNS a backing
// 'networks' row (the normal port group VMs attach to), referenced via a RESTRICT
// FK so the raw /networks delete can't orphan it. External modes (routed/l2bridge/
// vrouter) are a later release; see docs/TENANT-NETWORKING.md.

type TenantNetwork struct {
	ID        int64
	OrgID     int64
	Name      string
	NetworkID int64
	ExtMode   string
	State     string
	Error     string
	IsDefault bool
	CreatedAt string
	// Joined from the backing networks row (for display).
	NetName string // the untagged default port group's name
	Bridge  string
	CIDR    string
	Gateway string
	// v3 egress: the connected uplink, if any (empty = internal/no egress).
	UplinkID   int64
	UplinkName string
	UplinkMode string
	// vSwitch view: the port group carried untagged on the uplink (0 = the
	// untagged default) and the VLAN port groups on this vSwitch.
	NativeVLAN     int
	PortGroups     []TenantPortGroup
	VMs            int  // live instances on the untagged default port group
	DefaultCarried bool // the untagged default port group leaves on the uplink
	VRouterID      int64
}

// DefaultKind is the untagged default port group's role, like TenantPortGroup.Kind.
func (t TenantNetwork) DefaultKind() string {
	switch {
	case t.VRouterID != 0:
		return "routed"
	case t.DefaultCarried:
		return "uplink"
	case t.Gateway != "":
		return "standalone"
	}
	return "l2"
}

func tenantBridgeName(networkID int64) string { return fmt.Sprintf("vdxt%d", networkID) }

// ListTenantNetworks returns the caller org's tenant networks.
func (s *Service) ListTenantNetworks(p *Principal) ([]TenantNetwork, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT t.id,t.org_id,t.name,t.network_id,t.ext_mode,t.state,t.error,t.is_default,t.created_at,
		COALESCE(n.name,''),COALESCE(n.bridge,''),COALESCE(n.cidr,''),COALESCE(n.gateway,''),
		COALESCE(t.uplink_id,0),COALESCE((SELECT u.name FROM tenant_uplinks u WHERE u.id=t.uplink_id),''),
		COALESCE((SELECT u.mode FROM tenant_uplinks u WHERE u.id=t.uplink_id),''),t.native_vlan,
		(SELECT COUNT(*) FROM sessions s WHERE s.network_id=t.network_id AND s.deleted_at IS NULL),t.vrouter_id
		FROM tenant_networks t LEFT JOIN networks n ON n.id=t.network_id
		WHERE t.org_id=? ORDER BY t.is_default DESC, t.name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantNetwork
	for rows.Next() {
		var t TenantNetwork
		var def int
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.NetworkID, &t.ExtMode, &t.State, &t.Error, &def,
			&t.CreatedAt, &t.NetName, &t.Bridge, &t.CIDR, &t.Gateway, &t.UplinkID, &t.UplinkName, &t.UplinkMode, &t.NativeVLAN, &t.VMs, &t.VRouterID); err != nil {
			return nil, err
		}
		t.IsDefault = def == 1
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	pgs, err := s.ListTenantPortGroups(p)
	if err != nil {
		return nil, err
	}
	for i := range out {
		t := &out[i]
		t.DefaultCarried = carriedOut(t.UplinkMode, t.NativeVLAN, 0)
		for _, pg := range pgs {
			if pg.TnetID == t.ID {
				pg.Carried = carriedOut(t.UplinkMode, t.NativeVLAN, pg.VLAN)
				t.PortGroups = append(t.PortGroups, pg)
			}
		}
	}
	return out, nil
}

// AttachableSegments returns the org's segments eligible to attach to a router:
// unattached (vrouter_id=0) and gatewayless (no host gateway), so the router leg
// can become their sole gateway without any live gateway-ownership handoff.
func (s *Service) AttachableSegments(p *Principal) ([]TenantNetwork, error) {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT t.id,t.org_id,t.name,t.network_id,COALESCE(n.bridge,''),COALESCE(n.cidr,'')
		FROM tenant_networks t JOIN networks n ON n.id=t.network_id
		WHERE t.org_id=? AND t.vrouter_id=0 AND COALESCE(n.gateway,'')='' ORDER BY t.name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantNetwork
	for rows.Next() {
		var t TenantNetwork
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.NetworkID, &t.Bridge, &t.CIDR); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AttachableUplinks returns the org's admin-provisioned uplinks not yet connected
// to any tenant network (an uplink is 1:1 with a network's egress). The org admin
// picks from these; they cannot create or alter the underlying egress mapping.
func (s *Service) AttachableUplinks(p *Principal) ([]UplinkView, error) {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT id,name,mode,outer_vid,status FROM tenant_uplinks
		WHERE org_id=? AND id NOT IN (SELECT uplink_id FROM tenant_networks WHERE uplink_id IS NOT NULL)
		ORDER BY name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UplinkView
	for rows.Next() {
		var u UplinkView
		if err := rows.Scan(&u.ID, &u.Name, &u.Mode, &u.OuterVID, &u.Status); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ConnectNetworkUplink connects one of the org's tenant networks to one of its
// admin-provisioned uplinks (org admin). It records the reference on
// tenant_networks and realizes the uplink device into the network's bridge. Both
// objects must belong to the caller's org.
func (s *Service) ConnectNetworkUplink(p *Principal, tnetID, uplinkID int64, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	var netID int64
	if err := s.db.QueryRow(`SELECT network_id FROM tenant_networks WHERE id=? AND org_id=?`, tnetID, p.OrgID).Scan(&netID); err != nil {
		return fmt.Errorf("tenant network not found in this org")
	}
	var uOrg int64
	if err := s.db.QueryRow(`SELECT org_id FROM tenant_uplinks WHERE id=?`, uplinkID).Scan(&uOrg); err != nil || uOrg != p.OrgID {
		return fmt.Errorf("uplink not found in this org")
	}
	// One uplink per network: refuse if the uplink is already connected elsewhere.
	var used int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_networks WHERE uplink_id=?`, uplinkID).Scan(&used)
	if used > 0 {
		return fmt.Errorf("that uplink is already connected to a network")
	}
	if err := s.connectUplink(tnetID, netID, uplinkID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "uplink.connect", "tenant_network", fmt.Sprint(tnetID), ip, map[string]any{"uplink": uplinkID})
	return nil
}

// connectUplink records the uplink on the vSwitch, wires its device into the
// bridge and sets the port's VLANs; on any failure it is fully undone.
func (s *Service) connectUplink(tnetID, netID, uplinkID int64) error {
	var mode string
	var native int
	if err := s.db.QueryRow(`SELECT mode FROM tenant_uplinks WHERE id=?`, uplinkID).Scan(&mode); err != nil {
		return err
	}
	_ = s.db.QueryRow(`SELECT native_vlan FROM tenant_networks WHERE id=?`, tnetID).Scan(&native)
	if err := s.checkCarry(tnetID, mode, native); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE tenant_networks SET uplink_id=? WHERE id=?`, uplinkID, tnetID); err != nil {
		return err
	}
	err := s.realizeUplink(uplinkID, tenantBridgeName(netID))
	if err == nil {
		if err = s.resyncVSwitch(tnetID); err != nil {
			_ = s.unrealizeUplink(uplinkID, false, false)
		}
	}
	if err != nil {
		_, _ = s.db.Exec(`UPDATE tenant_networks SET uplink_id=NULL WHERE id=?`, tnetID)
		return err
	}
	return nil
}

// DisconnectNetworkUplink detaches a tenant network from its uplink, tearing down
// the uplink device (refusing while a VM is live on the bridge).
func (s *Service) DisconnectNetworkUplink(p *Principal, tnetID int64, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	var uplinkID sql.NullInt64
	if err := s.db.QueryRow(`SELECT uplink_id FROM tenant_networks WHERE id=? AND org_id=?`, tnetID, p.OrgID).Scan(&uplinkID); err != nil {
		return fmt.Errorf("tenant network not found in this org")
	}
	if !uplinkID.Valid {
		return nil // already disconnected
	}
	if err := s.disconnectUplink(tnetID, uplinkID.Int64); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "uplink.disconnect", "tenant_network", fmt.Sprint(tnetID), ip, nil)
	return nil
}

// CreateTenantNetwork creates and realizes an isolated tenant network (admin).
func (s *Service) CreateTenantNetwork(p *Principal, name, cidr, gateway string, dhcp bool, dhcpRange, dns, ip string) (int64, error) {
	if !p.atLeast("admin") {
		return 0, ErrUnauthorized
	}
	if p.OrgID == 0 {
		return 0, fmt.Errorf("no organization selected")
	}
	id, err := s.createTenantNetwork(p.OrgID, name, cidr, gateway, dhcp, dhcpRange, dns, false)
	if err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "tenantnet.create", "tenant_network", fmt.Sprint(id), ip,
		map[string]any{"name": name, "cidr": cidr, "mode": "isolated"})
	return id, nil
}

// createTenantNetwork is the internal (principal-less) create used by both the
// handler path and org bootstrap. It creates the backing networks row, names and
// realizes the isolated bridge, and records the tenant_networks row. On any
// provisioning failure it rolls back cleanly (no half-built segment).
func (s *Service) createTenantNetwork(orgID int64, name, cidr, gateway string, dhcp bool, dhcpRange, dns string, isDefault bool) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0, fmt.Errorf("a name is required")
	}
	if cidr != "" {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return 0, fmt.Errorf("invalid CIDR %q", cidr)
		}
	}
	if dhcp {
		if err := validDHCPRange(dhcpRange); err != nil {
			return 0, err
		}
	}
	// Backing port group (mode=bridge). Created via the store directly (not the
	// guarded CreateNetwork) because we own the bridge name and there is no VLAN.
	netID, err := s.net.CreateNetwork(netdrv.Network{
		OrgID: orgID, Name: name, Mode: "bridge", VLANID: 0, CIDR: cidr, Gateway: gateway,
	})
	if err != nil {
		return 0, fmt.Errorf("create backing port group: %w", err)
	}
	bridge := tenantBridgeName(netID)
	if err := s.net.SetNetworkBridge(netID, bridge); err != nil {
		_ = s.net.DeleteNetwork(orgID, netID)
		return 0, err
	}
	// Reserve a globally-unique segment identity (a VXLAN VNI). v2 uses it as an
	// identity only — the segment realizes as a plain bridge below; the VNI
	// reserves the number for the future multi-host overlay. Best effort: if the
	// allocator is exhausted we still create a working single-host segment.
	if _, err := s.AllocVNI(orgID, netID); err != nil {
		log.Printf("tenant-net: VNI identity not allocated for net %d: %v", netID, err)
	}
	def := 0
	if isDefault {
		def = 1
	}
	res, err := s.db.Exec(`INSERT INTO tenant_networks(org_id,name,network_id,ext_mode,state,is_default)
		VALUES(?,?,?,?,?,?)`, orgID, name, netID, "isolated", "applied", def)
	if err != nil {
		s.FreeVNI(netID)
		_ = s.net.DeleteNetwork(orgID, netID)
		return 0, err
	}
	tnID, _ := res.LastInsertId()
	// Realize the host segment and fence it off from the host (fail closed: an
	// unguarded tenant bridge is never left behind). On failure, roll back.
	err = s.provisionIsolated(bridge, cidr, gateway, dhcp, dhcpRange, dns)
	if err == nil {
		err = s.applyTenantIsolation()
	}
	if err != nil {
		netdrv.StopTenantDHCP(bridge)
		netdrv.DelLink(bridge)
		_, _ = s.db.Exec(`DELETE FROM tenant_networks WHERE id=?`, tnID)
		s.FreeVNI(netID)
		_ = s.net.DeleteNetwork(orgID, netID)
		return 0, fmt.Errorf("realize isolated segment: %w", err)
	}
	return tnID, nil
}

// provisionIsolated (re)builds the host side of an isolated tenant network: a
// bridge with no uplink, an optional gateway IP, and optional DHCP bound strictly
// to that bridge. Idempotent — safe to call on create and at every boot.
func (s *Service) provisionIsolated(bridge, cidr, gateway string, dhcp bool, dhcpRange, dns string) error {
	// Hard guard: never operate on the management bridge/NIC.
	if bridge == "" || bridge == s.mgmtIface() {
		return fmt.Errorf("refusing to build an isolated segment on %q", bridge)
	}
	if err := netdrv.EnsureBridge(bridge); err != nil {
		return err
	}
	gwCIDR, mask := gatewayCIDRMask(gateway, cidr)
	if gwCIDR != "" && netdrv.IfaceIPv4(bridge) == "" {
		_ = netdrv.AddAddr(bridge, gwCIDR)
	}
	if dhcp {
		return netdrv.StartTenantDHCP(bridge, gateway, vrouter.NormalizeDHCPRange(dhcpRange), mask, dns)
	}
	netdrv.StopTenantDHCP(bridge)
	return nil
}

// DeleteTenantNetwork tears down an isolated tenant network (admin). It refuses
// while VMs are still attached (so a delete never silently re-homes a running VM
// to the shared default bridge), removes the tenant row first (releasing the
// RESTRICT FK), then the backing port group, then the host bridge + DHCP.
func (s *Service) DeleteTenantNetwork(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	var orgID, netID, vrouterID int64
	var name string
	err := s.db.QueryRow(`SELECT org_id,network_id,name,vrouter_id FROM tenant_networks WHERE id=? AND org_id=?`, id, p.OrgID).
		Scan(&orgID, &netID, &name, &vrouterID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("tenant network not found")
	}
	if err != nil {
		return err
	}
	if vrouterID != 0 {
		return fmt.Errorf("this segment is attached to a router — detach it from the router first")
	}
	var pgs int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_portgroups WHERE tnet_id=?`, id).Scan(&pgs)
	if pgs > 0 {
		return fmt.Errorf("this vSwitch still has %d port group(s) — delete them first", pgs)
	}
	var attached int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE network_id=? AND deleted_at IS NULL`, netID).Scan(&attached)
	if attached > 0 {
		return fmt.Errorf("%d instance(s) are still attached to this network — detach or delete them first", attached)
	}
	bridge := tenantBridgeName(netID)
	// Disconnect its uplink first (the uplink keeps its tag for reuse).
	var uplinkID sql.NullInt64
	_ = s.db.QueryRow(`SELECT uplink_id FROM tenant_networks WHERE id=?`, id).Scan(&uplinkID)
	if uplinkID.Valid {
		if err := s.unrealizeUplink(uplinkID.Int64, true, false); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`DELETE FROM tenant_networks WHERE id=?`, id); err != nil {
		return err
	}
	if err := s.net.DeleteNetwork(orgID, netID); err != nil {
		return err
	}
	netdrv.StopTenantDHCP(bridge)
	netdrv.DelLink(bridge)
	// Device is gone — now release the reserved segment identity (never before,
	// so a concurrent allocation can't reuse the VNI while the bridge lingers).
	s.FreeVNI(netID)
	if err := s.applyTenantIsolation(); err != nil {
		log.Printf("tenant-net: isolation after delete: %v", err)
	}
	if netdrv.IfaceExists(bridge) {
		// Row is gone but the device lingered (should not happen for an empty
		// bridge); surface it so the operator can clean up.
		return fmt.Errorf("deleted the tenant network but host bridge %s did not go away", bridge)
	}
	s.audit(p, p.OrgID, "tenantnet.delete", "tenant_network", fmt.Sprint(id), ip, map[string]any{"name": name})
	return nil
}

// defaultTenantNetworkFor returns the backing networks.id of an org's default
// tenant network, or 0 if it has none. Used to land a new org's VMs on their
// isolated bridge instead of the shared default (see session.Manager.Create).
func (s *Service) defaultTenantNetworkFor(orgID int64) int64 {
	var netID int64
	_ = s.db.QueryRow(`SELECT network_id FROM tenant_networks WHERE org_id=? AND is_default=1 LIMIT 1`, orgID).Scan(&netID)
	return netID
}

// provisionDefaultForOrg creates a per-org default isolated tenant network. Called
// from CreateOrg so a NEW org is isolated by default. Best-effort: a failure does
// not fail org creation (the org simply has no default network yet). Does nothing
// if the org already has one.
func (s *Service) provisionDefaultForOrg(orgID int64) {
	if s.defaultTenantNetworkFor(orgID) != 0 {
		return
	}
	// A distinct private /24 per org (overlapping would be fine for isolated
	// segments, but distinct keeps future routed/NAT modes simple). gw .1, DHCP
	// .100-.200.
	third := (orgID % 250) + 1
	cidr := fmt.Sprintf("10.%d.0.0/24", third)
	gw := fmt.Sprintf("10.%d.0.1", third)
	rng := fmt.Sprintf("10.%d.0.100-200", third)
	if _, err := s.createTenantNetwork(orgID, "default", cidr, gw, true, rng, "1.1.1.1,8.8.8.8", true); err != nil {
		log.Printf("tenant-net: default network for org %d not created: %v", orgID, err)
	}
}

// ReensureTenantNetworks rebuilds every isolated tenant network's host side at
// boot (the kernel loses bridges/addresses across a reboot). Runs after
// ReensureVRouters and before autostart so VMs find their bridge ready.
func (s *Service) ReensureTenantNetworks() {
	// Skip segments attached to a router (vrouter_id!=0): the router leg owns
	// their gateway + DHCP, so re-adding a host gateway IP here would create a
	// duplicate gateway on that L2. Standalone segments (vrouter_id=0) rebuild.
	rows, err := s.db.Query(`SELECT t.network_id,COALESCE(n.cidr,''),COALESCE(n.gateway,''),COALESCE(u.mode,''),t.native_vlan
		FROM tenant_networks t JOIN networks n ON n.id=t.network_id LEFT JOIN tenant_uplinks u ON u.id=t.uplink_id
		WHERE t.ext_mode='isolated' AND t.vrouter_id=0`)
	if err != nil {
		return
	}
	type row struct {
		netID         int64
		cidr, gateway string
	}
	var list []row
	for rows.Next() {
		var r row
		var mode string
		var native int
		if rows.Scan(&r.netID, &r.cidr, &r.gateway, &mode, &native) == nil {
			if carriedOut(mode, native, 0) {
				r.gateway = "" // upstream owns this L2: bridge only, no host gateway/DHCP
			}
			list = append(list, r)
		}
	}
	rows.Close()
	for _, r := range list {
		bridge := tenantBridgeName(r.netID)
		// DHCP state is re-derived from the leased range on the networks row's
		// gateway; v1 re-enables DHCP when a gateway is present (the common case).
		dhcp := r.gateway != ""
		rng := ""
		if dhcp && r.cidr != "" {
			rng = defaultDHCPRange(r.cidr)
		}
		if err := s.provisionIsolated(bridge, r.cidr, r.gateway, dhcp && rng != "", rng, "1.1.1.1,8.8.8.8"); err != nil {
			log.Printf("tenant-net: reensure %s: %v", bridge, err)
		}
	}
	// Port groups + host isolation for every vSwitch (uplink ports are set again
	// once ReensureUplinks has re-wired them).
	s.syncAllVSwitches()
}

// gatewayCIDRMask turns a gateway IP + a network CIDR into "gwip/prefix" and the
// dotted netmask. Returns ("","") if either is missing/invalid.
func gatewayCIDRMask(gateway, cidr string) (gwCIDR, mask string) {
	gateway = strings.TrimSpace(gateway)
	if gateway == "" || cidr == "" {
		return "", ""
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", ""
	}
	ones, _ := ipnet.Mask.Size()
	m := ipnet.Mask
	if len(m) == 4 {
		mask = fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	}
	return fmt.Sprintf("%s/%d", gateway, ones), mask
}

// defaultDHCPRange derives a ".100-200" range from a /24-ish CIDR's network base.
func defaultDHCPRange(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.100-200", ip[0], ip[1], ip[2])
}
