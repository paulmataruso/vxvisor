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
	Bridge  string
	CIDR    string
	Gateway string
}

func tenantBridgeName(networkID int64) string { return fmt.Sprintf("vdxt%d", networkID) }

// ListTenantNetworks returns the caller org's tenant networks.
func (s *Service) ListTenantNetworks(p *Principal) ([]TenantNetwork, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT t.id,t.org_id,t.name,t.network_id,t.ext_mode,t.state,t.error,t.is_default,t.created_at,
		COALESCE(n.bridge,''),COALESCE(n.cidr,''),COALESCE(n.gateway,'')
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
			&t.CreatedAt, &t.Bridge, &t.CIDR, &t.Gateway); err != nil {
			return nil, err
		}
		t.IsDefault = def == 1
		out = append(out, t)
	}
	return out, rows.Err()
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
	def := 0
	if isDefault {
		def = 1
	}
	res, err := s.db.Exec(`INSERT INTO tenant_networks(org_id,name,network_id,ext_mode,state,is_default)
		VALUES(?,?,?,?,?,?)`, orgID, name, netID, "isolated", "applied", def)
	if err != nil {
		_ = s.net.DeleteNetwork(orgID, netID)
		return 0, err
	}
	tnID, _ := res.LastInsertId()
	// Realize the host segment. On failure, roll the whole thing back.
	if err := s.provisionIsolated(bridge, cidr, gateway, dhcp, dhcpRange, dns); err != nil {
		netdrv.StopTenantDHCP(bridge)
		netdrv.DelLink(bridge)
		_, _ = s.db.Exec(`DELETE FROM tenant_networks WHERE id=?`, tnID)
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
	var orgID, netID int64
	var name string
	err := s.db.QueryRow(`SELECT org_id,network_id,name FROM tenant_networks WHERE id=? AND org_id=?`, id, p.OrgID).
		Scan(&orgID, &netID, &name)
	if err == sql.ErrNoRows {
		return fmt.Errorf("tenant network not found")
	}
	if err != nil {
		return err
	}
	var attached int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE network_id=? AND deleted_at IS NULL`, netID).Scan(&attached)
	if attached > 0 {
		return fmt.Errorf("%d instance(s) are still attached to this network — detach or delete them first", attached)
	}
	bridge := tenantBridgeName(netID)
	if _, err := s.db.Exec(`DELETE FROM tenant_networks WHERE id=?`, id); err != nil {
		return err
	}
	if err := s.net.DeleteNetwork(orgID, netID); err != nil {
		return err
	}
	netdrv.StopTenantDHCP(bridge)
	netdrv.DelLink(bridge)
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
	rows, err := s.db.Query(`SELECT t.network_id,COALESCE(n.cidr,''),COALESCE(n.gateway,'')
		FROM tenant_networks t JOIN networks n ON n.id=t.network_id WHERE t.ext_mode='isolated'`)
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
		if rows.Scan(&r.netID, &r.cidr, &r.gateway) == nil {
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
