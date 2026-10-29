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
	// The untagged default port group's host DHCP (used while it has a host
	// gateway; DHCPRange is "start,end").
	DHCP      bool
	DHCPRange string
	DNS       string
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
	ExtRouter      string // router whose external interface is on the untagged port group
	// AddrLocked: the untagged port group's subnet / gateway can't change now
	// (instances or a router are attached to it).
	AddrLocked bool
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

// DHCPRangeText is the untagged port group's DHCP range as a form shows it
// ("start-end").
func (t TenantNetwork) DHCPRangeText() string { return strings.Replace(t.DHCPRange, ",", "-", 1) }

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
		(SELECT COUNT(*) FROM sessions s WHERE s.network_id=t.network_id AND s.deleted_at IS NULL),t.vrouter_id,
		t.dhcp,t.dhcp_range,t.dhcp_dns
		FROM tenant_networks t LEFT JOIN networks n ON n.id=t.network_id
		WHERE t.org_id=? ORDER BY t.is_default DESC, t.name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantNetwork
	for rows.Next() {
		var t TenantNetwork
		var def, dhcp int
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.NetworkID, &t.ExtMode, &t.State, &t.Error, &def,
			&t.CreatedAt, &t.NetName, &t.Bridge, &t.CIDR, &t.Gateway, &t.UplinkID, &t.UplinkName, &t.UplinkMode, &t.NativeVLAN, &t.VMs, &t.VRouterID,
			&dhcp, &t.DHCPRange, &t.DNS); err != nil {
			return nil, err
		}
		t.IsDefault = def == 1
		l3 := storedL3(t.CIDR, t.Gateway, dhcp == 1, t.DHCPRange, t.DNS)
		t.DHCP, t.DHCPRange, t.DNS = l3.DHCP, l3.Range, l3.DNS
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
	legs := s.orgUplinkLegs(p.OrgID)
	for i := range out {
		t := &out[i]
		t.DefaultCarried = carriedOut(t.UplinkMode, t.NativeVLAN, 0)
		t.ExtRouter = legs[legKey{tenantBridgeName(t.NetworkID), 0}]
		t.AddrLocked = t.VMs > 0 || t.VRouterID != 0 || t.ExtRouter != ""
		for _, pg := range pgs {
			if pg.TnetID == t.ID {
				pg.Carried = carriedOut(t.UplinkMode, t.NativeVLAN, pg.VLAN)
				pg.ExtRouter = legs[legKey{tenantBridgeName(t.NetworkID), pg.VLAN}]
				pg.AddrLocked = pg.VMs > 0 || pg.VRouterID != 0 || pg.ExtRouter != ""
				t.PortGroups = append(t.PortGroups, pg)
			}
		}
	}
	return out, nil
}

// legKey is where a router's external interface (uplink leg) sits: a tenant
// vSwitch bridge and the port group's VLAN (0 = the untagged one).
type legKey struct {
	bridge string
	vlan   int
}

// orgUplinkLegs maps each tenant port group carrying a router's external
// interface (uplink leg) to that router's name.
func (s *Service) orgUplinkLegs(orgID int64) map[legKey]string {
	out := map[legKey]string{}
	rows, err := s.db.Query(`SELECT l.bridge,l.vlan_id,v.name FROM vrouter_legs l JOIN vrouters v ON v.id=l.vrouter_id
		WHERE l.kind=? AND v.org_id=?`, vrouter.LegUplink, orgID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k legKey
		var name string
		if rows.Scan(&k.bridge, &k.vlan, &name) == nil {
			out[k] = name
		}
	}
	return out
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
	var cur sql.NullInt64
	if err := s.db.QueryRow(`SELECT network_id,uplink_id FROM tenant_networks WHERE id=? AND org_id=?`, tnetID, p.OrgID).Scan(&netID, &cur); err != nil {
		return fmt.Errorf("tenant network not found in this org")
	}
	if cur.Valid {
		return fmt.Errorf("this vSwitch is already connected to an external network — disconnect it first")
	}
	var uOrg int64
	if err := s.db.QueryRow(`SELECT org_id FROM tenant_uplinks WHERE id=?`, uplinkID).Scan(&uOrg); err != nil || uOrg != p.OrgID {
		return fmt.Errorf("external network not found in this org")
	}
	// One uplink per network: refuse if the uplink is already connected elsewhere.
	var used int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_networks WHERE uplink_id=?`, uplinkID).Scan(&used)
	if used > 0 {
		return fmt.Errorf("that external network is already connected to a vSwitch")
	}
	if err := s.connectUplink(tnetID, netID, uplinkID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "uplink.connect", "tenant_network", fmt.Sprint(tnetID), ip, map[string]any{"uplink": uplinkID})
	return nil
}

// connectUplink records the uplink on the vSwitch, wires its device into the
// bridge and sets the port's VLANs; on any failure it is fully undone. The host
// leaves whatever the uplink is about to carry (gateway + DHCP suspended) BEFORE
// the device is enslaved, and the device is enslaved down and only brought up
// once its VLANs are set — so the host is never on the provider's wire, not even
// for a moment.
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
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("that external network is already connected to a vSwitch")
		}
		return err
	}
	err := s.syncVSwitch(tnetID) // uplink not bound yet: this only suspends the host
	if err == nil {
		if err = s.realizeUplink(uplinkID, tenantBridgeName(netID)); err == nil {
			if err = s.resyncVSwitch(tnetID); err != nil {
				_ = s.unrealizeUplink(uplinkID, false, false)
			}
		}
	}
	if err != nil {
		_, _ = s.db.Exec(`UPDATE tenant_networks SET uplink_id=NULL WHERE id=?`, tnetID)
		if rerr := s.resyncVSwitch(tnetID); rerr != nil {
			log.Printf("tenant-net: resync vSwitch %d after a failed connect: %v", tnetID, rerr)
		}
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
	id, err := s.createTenantNetwork(p.OrgID, name, cidr, gateway, dhcp, dhcpRange, dns, false, p.IsAdmin)
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
// provisioning failure it rolls back cleanly (no half-built segment). detail:
// the caller may be told which host network a subnet overlaps.
func (s *Service) createTenantNetwork(orgID int64, name, cidr, gateway string, dhcp bool, dhcpRange, dns string, isDefault, detail bool) (int64, error) {
	name, err := validTenantName(name, "vSwitch")
	if err != nil {
		return 0, err
	}
	l3, err := parseTenantL3(cidr, gateway, dhcp, dhcpRange, dns)
	if err != nil {
		return 0, err
	}
	if err := checkHostOverlap(l3.CIDR, detail); err != nil {
		return 0, err
	}
	var dup int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_networks WHERE org_id=? AND name=?`, orgID, name).Scan(&dup)
	if dup > 0 {
		return 0, fmt.Errorf("this organization already has a vSwitch named %q", name)
	}
	// Backing port group (mode=bridge). Created via the store directly (not the
	// guarded CreateNetwork) because we own the bridge name and there is no VLAN.
	netID, err := s.net.CreateNetwork(netdrv.Network{
		OrgID: orgID, Name: name, Mode: "bridge", VLANID: 0, CIDR: l3.CIDR, Gateway: l3.Gateway,
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
	res, err := s.db.Exec(`INSERT INTO tenant_networks(org_id,name,network_id,ext_mode,state,is_default,dhcp,dhcp_range,dhcp_dns)
		VALUES(?,?,?,?,?,?,?,?,?)`, orgID, name, netID, "isolated", "applied", def, b2iDHCP(l3.DHCP), l3.Range, l3.DNS)
	if err != nil {
		s.FreeVNI(netID)
		_ = s.net.DeleteNetwork(orgID, netID)
		return 0, err
	}
	tnID, _ := res.LastInsertId()
	// Realize the host segment and fence it off from the host (fail closed: an
	// unguarded tenant bridge is never left behind). On failure, roll back.
	err = s.provisionIsolated(bridge, l3)
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
// bridge with no uplink and, when l3 has a gateway, the host's gateway address
// and DHCP bound strictly to that bridge (pass an empty tenantL3 for a bridge
// the host must stay off). Idempotent — safe to call on create and at every boot.
func (s *Service) provisionIsolated(bridge string, l3 tenantL3) error {
	// Hard guard: never operate on the management bridge/NIC.
	if bridge == "" || !strings.HasPrefix(bridge, "vdxt") || bridge == s.mgmtIface() {
		return fmt.Errorf("refusing to build an isolated segment on %q", bridge)
	}
	if err := netdrv.EnsureBridge(bridge); err != nil {
		return err
	}
	return hostGatewayUp(bridge, l3)
}

// DeleteTenantNetwork tears down an isolated tenant network (admin). It refuses
// while VMs are still attached (so a delete never silently re-homes a running VM
// to the shared default bridge) and while it is the org's default vSwitch (new
// VMs would land with no network), removes the tenant row first (releasing the
// RESTRICT FK), then the backing port group, then the host bridge + DHCP.
func (s *Service) DeleteTenantNetwork(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	name, err := s.deleteTenantNetwork(p.OrgID, id, false)
	if err != nil {
		return err
	}
	s.audit(p, p.OrgID, "tenantnet.delete", "tenant_network", fmt.Sprint(id), ip, map[string]any{"name": name})
	return nil
}

// deleteTenantNetwork is DeleteTenantNetwork without the principal. allowDefault
// lets the egress wizard undo a default vSwitch it has just created itself.
func (s *Service) deleteTenantNetwork(orgID, id int64, allowDefault bool) (string, error) {
	var netID, vrouterID int64
	var name string
	var isDefault int
	err := s.db.QueryRow(`SELECT network_id,name,vrouter_id,is_default FROM tenant_networks WHERE id=? AND org_id=?`, id, orgID).
		Scan(&netID, &name, &vrouterID, &isDefault)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("tenant network not found")
	}
	if err != nil {
		return "", err
	}
	if isDefault == 1 && !allowDefault {
		return "", fmt.Errorf("vSwitch %s is this organization's default (new instances attach to it) — make another vSwitch the default first", name)
	}
	if vrouterID != 0 {
		return "", fmt.Errorf("this segment is attached to a router — detach it from the router first")
	}
	if vr := s.routerLegOn(netID); vr != "" {
		return fmt.Errorf("router %q has an interface on this vSwitch — detach it from the router first", vr)
	}
	var pgs int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_portgroups WHERE tnet_id=?`, id).Scan(&pgs)
	if pgs > 0 {
		return "", fmt.Errorf("this vSwitch still has %d port group(s) — delete them first", pgs)
	}
	var attached int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE network_id=? AND deleted_at IS NULL`, netID).Scan(&attached)
	if attached > 0 {
		return "", fmt.Errorf("%d instance(s) are still attached to this network — detach or delete them first", attached)
	}
	bridge := tenantBridgeName(netID)
	if err := s.checkUplinkLegs(id, "", 0); err != nil {
		return "", err
	}
	// Disconnect its uplink first (the uplink keeps its tag for reuse).
	var uplinkID sql.NullInt64
	_ = s.db.QueryRow(`SELECT uplink_id FROM tenant_networks WHERE id=?`, id).Scan(&uplinkID)
	if uplinkID.Valid {
		if err := s.unrealizeUplink(uplinkID.Int64, true, false); err != nil {
			return "", err
		}
	}
	if _, err := s.db.Exec(`DELETE FROM tenant_networks WHERE id=?`, id); err != nil {
		return "", err
	}
	if err := s.net.DeleteNetwork(orgID, netID); err != nil {
		return "", err
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
		return "", fmt.Errorf("deleted the tenant network but host bridge %s did not go away", bridge)
	}
	return name, nil
}

// SetDefaultTenantNetwork makes one of the org's vSwitches its default — the
// one new instances attach to when they don't name a network (org admin).
func (s *Service) SetDefaultTenantNetwork(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	var name string
	var isDefault int
	if err := s.db.QueryRow(`SELECT name,is_default FROM tenant_networks WHERE id=? AND org_id=?`, id, p.OrgID).Scan(&name, &isDefault); err != nil {
		return fmt.Errorf("vSwitch not found in this org")
	}
	if isDefault == 1 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE tenant_networks SET is_default=0 WHERE org_id=? AND is_default=1`, p.OrgID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`UPDATE tenant_networks SET is_default=1 WHERE id=? AND org_id=?`, id, p.OrgID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "tenantnet.default", "tenant_network", fmt.Sprint(id), ip, map[string]any{"name": name})
	return nil
}

// PortGroupEdit is an edit of a port group — a VLAN one, or a vSwitch's
// untagged one (with the vSwitch's name).
type PortGroupEdit struct {
	Name string
	// L3 = also change the addressing below (false: rename only — the form for
	// a router-gatewayed port group has no addressing fields).
	L3            bool
	CIDR, Gateway string
	DHCP          bool
	DHCPRange     string
	DNS           string
}

// UpdateTenantNetwork edits a vSwitch (org admin): its name (which is also its
// untagged port group's) and that port group's DHCP settings and — only while
// no instance, router or router external interface is attached to it — its
// subnet and gateway. A routed untagged port group's addressing and DHCP belong
// to its router.
func (s *Service) UpdateTenantNetwork(p *Principal, id int64, e PortGroupEdit, ip string) error {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return ErrUnauthorized
	}
	tnets, err := s.ListTenantNetworks(p)
	if err != nil {
		return err
	}
	var cur *TenantNetwork
	for i := range tnets {
		if tnets[i].ID == id {
			cur = &tnets[i]
		}
	}
	if cur == nil {
		return fmt.Errorf("vSwitch not found in this org")
	}
	name, err := validTenantName(e.Name, "vSwitch")
	if err != nil {
		return err
	}
	if name != cur.Name {
		var dup int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM tenant_networks WHERE org_id=? AND name=? AND id!=?`, p.OrgID, name, id).Scan(&dup)
		if dup > 0 {
			return fmt.Errorf("this organization already has a vSwitch named %q", name)
		}
	}
	old := tenantL3{CIDR: cur.CIDR, Gateway: cur.Gateway, DHCP: cur.DHCP, Range: cur.DHCPRange, DNS: cur.DNS}
	next := old
	if e.L3 {
		if cur.VRouterID != 0 {
			return fmt.Errorf("the untagged port group is routed by a router — change its gateway and DHCP on the router")
		}
		if next, err = parseTenantL3(e.CIDR, e.Gateway, e.DHCP, e.DHCPRange, e.DNS); err != nil {
			return err
		}
		if sameAddr(old, next) {
			next.CIDR, next.Gateway = old.CIDR, old.Gateway
		} else {
			if err := lockedAddr(cur.VMs, cur.VRouterID != 0, cur.ExtRouter); err != nil {
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
		if _, err := s.db.Exec(`UPDATE tenant_networks SET name=?,dhcp=?,dhcp_range=?,dhcp_dns=? WHERE id=?`,
			n, b2iDHCP(l.DHCP), l.Range, l.DNS, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("this organization already has a vSwitch named %q", n)
			}
			return err
		}
		if _, err := s.db.Exec(`UPDATE networks SET name=?,cidr=?,gateway=? WHERE id=?`, n, l.CIDR, l.Gateway, cur.NetworkID); err != nil {
			return err
		}
		// Port groups' backing networks are named "<vSwitch>/<port group>".
		_, err := s.db.Exec(`UPDATE networks SET name=?||'/'||(SELECT pg.name FROM tenant_portgroups pg WHERE pg.network_id=networks.id)
			WHERE id IN (SELECT network_id FROM tenant_portgroups WHERE tnet_id=?)`, n, id)
		return err
	}
	if err := write(name, next); err != nil {
		return err
	}
	if next != old {
		// Take the old host gateway + DHCP down; the resync puts up whatever the
		// port group should have now.
		bridge := tenantBridgeName(cur.NetworkID)
		hostGatewayDown(bridge, old.Gateway, old.CIDR)
		if err := s.resyncVSwitch(id); err != nil {
			_ = write(cur.Name, old)
			hostGatewayDown(bridge, next.Gateway, next.CIDR)
			if rerr := s.resyncVSwitch(id); rerr != nil {
				log.Printf("tenant-net: restoring vSwitch %d after a failed edit: %v", id, rerr)
			}
			return fmt.Errorf("apply: %w (the old settings were put back)", err)
		}
	}
	s.audit(p, p.OrgID, "tenantnet.update", "tenant_network", fmt.Sprint(id), ip,
		map[string]any{"name": name, "renamed_from": cur.Name, "cidr": next.CIDR, "gateway": next.Gateway, "dhcp": next.DHCP, "range": next.Range, "dns": next.DNS})
	return nil
}

// lockedAddr refuses a subnet / gateway change on a port group something is
// attached to: instances (their addresses), a router gatewaying it, or a
// router's external interface.
func lockedAddr(vms int, routed bool, extRouter string) error {
	switch {
	case vms > 0:
		return fmt.Errorf("the subnet and gateway can't change while %d instance(s) are attached — move them first (DHCP settings and the name can change any time)", vms)
	case routed:
		return fmt.Errorf("the subnet and gateway can't change while a router gateways this port group — detach it first")
	case extRouter != "":
		return fmt.Errorf("the subnet and gateway can't change while router %s's external interface is on this port group — detach it first", extRouter)
	}
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
	cidr := defaultOrgSubnet(orgID)
	if cidr == "" {
		log.Printf("tenant-net: default network for org %d not created: every candidate /24 overlaps a host network", orgID)
		return
	}
	// gw .1, DHCP .100-.200.
	_, sn, _ := net.ParseCIDR(cidr)
	gw := uintIPv4(ipv4Uint(sn.IP) + 1).String()
	rng := defaultDHCPRange(cidr, gw)
	if _, err := s.createTenantNetwork(orgID, "default", cidr, gw, true, rng, defaultTenantDNS, true, true); err != nil {
		log.Printf("tenant-net: default network for org %d not created: %v", orgID, err)
	}
}

// defaultOrgSubnet picks a new org's default subnet: a distinct private /24 per
// org (10.<org%250+1>.0.0/24 — overlapping would be fine for isolated segments,
// but distinct keeps routed/NAT setups simple), moving on to the next free one
// when that overlaps a host network. "" if none is free.
func defaultOrgSubnet(orgID int64) string {
	host, err := hostSubnets()
	if err != nil {
		return ""
	}
	var cands []string
	for k := int64(0); k < 250; k++ {
		cands = append(cands, fmt.Sprintf("10.%d.0.0/24", (orgID+k)%250+1))
	}
	for third := 16; third < 32; third++ {
		cands = append(cands, fmt.Sprintf("172.%d.%d.0/24", third, orgID%250+1))
	}
	for _, c := range cands {
		if overlapsHost(c, host) == nil {
			return c
		}
	}
	return ""
}

// ReensureTenantNetworks rebuilds every tenant network's host side at boot (the
// kernel loses bridges/addresses across a reboot). Runs after ReensureVRouters
// and before autostart so VMs find their bridge ready. Every vSwitch gets its
// bridge back; only a standalone untagged port group (not routed by a router —
// its leg is the gateway — and not carried out the uplink — the upstream owns
// that L2) gets the host's gateway and DHCP, with its saved settings.
func (s *Service) ReensureTenantNetworks() {
	s.reconcileSegmentIdentities()
	rows, err := s.db.Query(`SELECT t.network_id,t.vrouter_id,COALESCE(n.cidr,''),COALESCE(n.gateway,''),COALESCE(u.mode,''),t.native_vlan,
		t.dhcp,t.dhcp_range,t.dhcp_dns
		FROM tenant_networks t JOIN networks n ON n.id=t.network_id LEFT JOIN tenant_uplinks u ON u.id=t.uplink_id
		WHERE t.ext_mode='isolated'`)
	if err != nil {
		return
	}
	type row struct {
		netID int64
		l3    tenantL3
	}
	var list []row
	for rows.Next() {
		var r row
		var vr int64
		var cidr, gw, mode, rng, dns string
		var native, dhcp int
		if rows.Scan(&r.netID, &vr, &cidr, &gw, &mode, &native, &dhcp, &rng, &dns) == nil {
			if vr == 0 && !carriedOut(mode, native, 0) {
				r.l3 = storedL3(cidr, gw, dhcp == 1, rng, dns)
			}
			list = append(list, r)
		}
	}
	rows.Close()
	for _, r := range list {
		bridge := tenantBridgeName(r.netID)
		if err := s.provisionIsolated(bridge, r.l3); err != nil {
			log.Printf("tenant-net: reensure %s: %v", bridge, err)
		}
	}
	// Port groups + host isolation for every vSwitch (uplink ports are set again
	// once ReensureUplinks has re-wired them).
	s.syncAllVSwitches()
}

// storedL3 is a port group's addressing as saved. A row from before DHCP
// settings were saved has none: the long-standing defaults apply (DHCP on when
// there's a gateway, .100-.200, 1.1.1.1 + 8.8.8.8).
func storedL3(cidr, gateway string, dhcp bool, rng, dns string) tenantL3 {
	l := tenantL3{CIDR: cidr, Gateway: gateway}
	if !dhcp || gateway == "" {
		return l
	}
	if rng = vrouter.NormalizeDHCPRange(rng); rng == "" {
		rng = defaultDHCPRange(cidr, gateway)
	}
	if dns == "" {
		dns = defaultTenantDNS
	}
	if rng != "" {
		l.DHCP, l.Range, l.DNS = true, rng, dns
	}
	return l
}

// gatewayCIDRMask turns a gateway IP + a network CIDR into "gwip/prefix" and the
// dotted netmask. Returns ("","") if either is missing/invalid or the gateway
// isn't inside the network.
func gatewayCIDRMask(gateway, cidr string) (gwCIDR, mask string) {
	gw := parseIPv4(strings.TrimSpace(gateway))
	if gw == nil || cidr == "" {
		return "", ""
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil || !ipnet.Contains(gw) {
		return "", ""
	}
	ones, _ := ipnet.Mask.Size()
	m := ipnet.Mask
	if len(m) == 4 {
		mask = fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
	}
	return fmt.Sprintf("%s/%d", gw, ones), mask
}
