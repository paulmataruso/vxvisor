package service

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/vrouter"
)

// Tenant routers on vSwitches. A router can be the gateway of a gatewayless VLAN
// port group (AttachPortGroup — the "routed" kind), and can join the port group
// a vSwitch's uplink carries as its WAN (AttachUplinkLeg — L3 out: the upstream
// next hop becomes its default route, optionally with SNAT). Both are
// netns-only: the leg's host veth end must become a VLAN access port on the
// vSwitch, which only the netns backend does.

// UplinkLegChoice is a port group a router's uplink leg can join: one carried
// out its vSwitch's uplink.
type UplinkLegChoice struct {
	TnetID int64
	VLAN   int // 0 = the vSwitch's untagged default port group
	Label  string
}

// Value is the form value encoding of the choice ("<tnet>:<vlan>").
func (c UplinkLegChoice) Value() string { return fmt.Sprintf("%d:%d", c.TnetID, c.VLAN) }

// AttachablePortGroups lists the org's port groups a router can become the
// gateway of: gatewayless, not routed yet, and not carried out an uplink.
func (s *Service) AttachablePortGroups(p *Principal) ([]TenantPortGroup, error) {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return nil, nil
	}
	tnets, err := s.ListTenantNetworks(p)
	if err != nil {
		return nil, err
	}
	var out []TenantPortGroup
	for _, t := range tnets {
		for _, pg := range t.PortGroups {
			if pg.VRouterID == 0 && pg.Gateway == "" && !pg.Carried {
				out = append(out, pg)
			}
		}
	}
	return out, nil
}

// UplinkLegChoices lists the uplink-carried port groups of the org's vSwitches.
func (s *Service) UplinkLegChoices(p *Principal) ([]UplinkLegChoice, error) {
	if !p.atLeast("admin") || p.OrgID == 0 {
		return nil, nil
	}
	tnets, err := s.ListTenantNetworks(p)
	if err != nil {
		return nil, err
	}
	var out []UplinkLegChoice
	for _, t := range tnets {
		if t.UplinkMode == "" {
			continue
		}
		if t.DefaultCarried {
			out = append(out, UplinkLegChoice{TnetID: t.ID, Label: t.Name + " · untagged (uplink " + t.UplinkName + ")"})
		}
		for _, pg := range t.PortGroups {
			if pg.Carried {
				out = append(out, UplinkLegChoice{TnetID: t.ID, VLAN: pg.VLAN,
					Label: fmt.Sprintf("%s / %s · VLAN %d (uplink %s)", t.Name, pg.Name, pg.VLAN, t.UplinkName)})
			}
		}
	}
	return out, nil
}

// vswitchRouter loads a router the caller may wire onto a tenant vSwitch.
func (s *Service) vswitchRouter(p *Principal, vrID int64) (vrouter.VRouter, error) {
	if !p.atLeast("admin") {
		return vrouter.VRouter{}, ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return v, err
	}
	if v.Runtime != vrouter.RuntimeNetns {
		return v, fmt.Errorf("only netns routers can join a vSwitch's VLAN port groups or its uplink")
	}
	switch v.Status {
	case "creating":
		return v, fmt.Errorf("the router is still being created — wait a moment, then try again")
	case "error":
		return v, fmt.Errorf("the router is in an error state (%s) — fix or recreate it first", v.Error)
	}
	return v, nil
}

// legIndex is the next free leg index for a router (internal legs start at 1;
// 0 is the transit slot).
func (s *Service) legIndex(vrID int64) int {
	if idx := s.nextLegIdx(vrID); idx > 0 {
		return idx
	}
	return 1
}

// AttachPortGroup makes a router the gateway of one of the org's gatewayless
// VLAN port groups (org admin). The leg joins the port group's VLAN on the
// vSwitch; gatewayCIDR ("10.20.0.1/24", or a bare IP sized from the port
// group's subnet) must sit inside the port group's subnet.
func (s *Service) AttachPortGroup(p *Principal, vrID, pgID int64, gatewayCIDR string, dhcp bool, dhcpRange, dns, ip string) error {
	v, err := s.vswitchRouter(p, vrID)
	if err != nil {
		return err
	}
	list, err := s.portGroupsWhere(`pg.id=? AND pg.org_id=?`, pgID, p.OrgID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return fmt.Errorf("port group not found in this organization")
	}
	pg := list[0]
	if pg.VRouterID != 0 {
		return fmt.Errorf("that port group is already routed by %s", pg.VRouterName)
	}
	if pg.Gateway != "" {
		return fmt.Errorf("that port group has a host gateway — create it without one to route it")
	}
	if mode, native := s.vswitchEgress(pg.TnetID); carriedOut(mode, native, pg.VLAN) {
		return fmt.Errorf("that port group is carried out its vSwitch's uplink (the upstream network owns its gateway) — connect the router to the uplink instead")
	}
	gwIP, legCIDR, err := legAddr(gatewayCIDR, pg.CIDR)
	if err != nil {
		return err
	}
	if dhcp {
		if err := validDHCPRange(dhcpRange); err != nil {
			return err
		}
	}
	var vsNet int64
	if err := s.db.QueryRow(`SELECT network_id FROM tenant_networks WHERE id=?`, pg.TnetID).Scan(&vsNet); err != nil {
		return err
	}
	idx := s.legIndex(vrID)
	if _, err := s.db.Exec(`UPDATE networks SET gateway=? WHERE id=?`, gwIP, pg.NetworkID); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,dhcp,dhcp_range,dhcp_dns,vlan_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, vrID, idx, vrouter.LegInternal, tenantBridgeName(vsNet), pg.NetworkID,
		"eth"+strconv.Itoa(idx), legCIDR, b2iDHCP(dhcp), dhcpRange, dns, pg.VLAN); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE tenant_portgroups SET vrouter_id=? WHERE id=?`, vrID, pgID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.portgroup.attach", "vrouter", v.Name, ip,
		map[string]any{"portgroup": pg.Name, "vlan": pg.VLAN, "gateway": gwIP, "dhcp": dhcp})
	if err := s.applyAndPush(vrID); err != nil {
		return err
	}
	if dhcp {
		return s.applyDHCP(vrID, idx)
	}
	return nil
}

// AttachUplinkLeg gives a router its WAN leg on a port group carried out a
// vSwitch's uplink (org admin) — L3 out. cidr is the router's own address on
// the upstream network; upstreamGW (optional) becomes its default route; snat
// masquerades everything leaving the leg. One uplink leg per router.
func (s *Service) AttachUplinkLeg(p *Principal, vrID, tnetID int64, vlan int, cidr, upstreamGW string, snat bool, ip string) error {
	v, err := s.vswitchRouter(p, vrID)
	if err != nil {
		return err
	}
	if s.legCount(vrID, vrouter.LegUplink) > 0 {
		return fmt.Errorf("this router already has an uplink leg — detach it first")
	}
	var vsName string
	var vsNet int64
	if err := s.db.QueryRow(`SELECT name,network_id FROM tenant_networks WHERE id=? AND org_id=?`, tnetID, p.OrgID).
		Scan(&vsName, &vsNet); err != nil {
		return fmt.Errorf("vSwitch not found in this organization")
	}
	mode, native := s.vswitchEgress(tnetID)
	if mode == "" {
		return fmt.Errorf("vSwitch %s has no uplink — connect one first", vsName)
	}
	netID := vsNet
	if vlan != 0 {
		list, err := s.portGroupsWhere(`pg.tnet_id=? AND pg.vlan_id=?`, tnetID, vlan)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return fmt.Errorf("vSwitch %s has no port group on VLAN %d", vsName, vlan)
		}
		netID = list[0].NetworkID
	}
	if !carriedOut(mode, native, vlan) {
		return fmt.Errorf("the uplink doesn't carry that port group (an access uplink carries only the vSwitch's native port group)")
	}
	addr, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || addr.To4() == nil {
		return fmt.Errorf("the router's uplink address must be an IPv4 address with prefix (e.g. 203.0.113.10/29)")
	}
	upstreamGW = strings.TrimSpace(upstreamGW)
	if upstreamGW != "" {
		if gw := net.ParseIP(upstreamGW); gw == nil || gw.To4() == nil || !ipnet.Contains(gw) || gw.Equal(addr) {
			return fmt.Errorf("upstream gateway %q must be another IPv4 address inside %s", upstreamGW, ipnet)
		}
	}
	idx := s.legIndex(vrID)
	if _, err := s.db.Exec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,vlan_id,upstream_gw,snat)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, vrID, idx, vrouter.LegUplink, tenantBridgeName(vsNet), netID,
		"eth"+strconv.Itoa(idx), strings.TrimSpace(cidr), vlan, upstreamGW, b2iDHCP(snat)); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.uplink.attach", "vrouter", v.Name, ip,
		map[string]any{"vswitch": vsName, "vlan": vlan, "cidr": cidr, "upstream": upstreamGW, "snat": snat})
	return s.applyAndPush(vrID)
}

// DetachUplinkLeg removes a router's uplink leg (org admin), which also drops
// its default route and SNAT.
func (s *Service) DetachUplinkLeg(p *Principal, vrID int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	var idx int
	if err := s.db.QueryRow(`SELECT idx FROM vrouter_legs WHERE vrouter_id=? AND kind=?`, vrID, vrouter.LegUplink).Scan(&idx); err != nil {
		return fmt.Errorf("this router has no uplink leg")
	}
	if v.NetnsName != "" {
		netdrv.NetnsDelLink(v.NetnsName, "eth"+strconv.Itoa(idx))
	}
	if _, err := s.db.Exec(`DELETE FROM vrouter_legs WHERE vrouter_id=? AND kind=?`, vrID, vrouter.LegUplink); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.uplink.detach", "vrouter", v.Name, ip, nil)
	return s.applyAndPush(vrID)
}

// legAddr turns a router leg's gateway ("10.20.0.1/24", or a bare IP) into
// (bare IP, IP/prefix), checking it sits inside subnet (sizing a bare IP from
// it). subnet may be empty only when gatewayCIDR carries its own prefix.
func legAddr(gatewayCIDR, subnet string) (string, string, error) {
	gatewayCIDR = strings.TrimSpace(gatewayCIDR)
	var sn *net.IPNet
	if subnet != "" {
		if _, n, err := net.ParseCIDR(subnet); err == nil {
			sn = n
		}
	}
	gw, prefix := gatewayCIDR, ""
	if i := strings.IndexByte(gatewayCIDR, '/'); i >= 0 {
		gw, prefix = gatewayCIDR[:i], gatewayCIDR[i+1:]
	}
	ip := net.ParseIP(gw)
	if ip == nil || ip.To4() == nil {
		return "", "", fmt.Errorf("a gateway IP for the router leg is required (e.g. 10.20.0.1/24)")
	}
	if sn != nil && !sn.Contains(ip) {
		return "", "", fmt.Errorf("gateway %s is not inside the port group subnet %s", gw, sn)
	}
	if prefix == "" {
		if sn == nil {
			return "", "", fmt.Errorf("give the gateway with its prefix (e.g. %s/24)", gw)
		}
		ones, _ := sn.Mask.Size()
		prefix = strconv.Itoa(ones)
	}
	if _, _, err := net.ParseCIDR(gw + "/" + prefix); err != nil {
		return "", "", fmt.Errorf("invalid gateway %q", gatewayCIDR)
	}
	return gw, gw + "/" + prefix, nil
}
