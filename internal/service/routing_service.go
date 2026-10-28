package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/routing"
)

// RoutingAvailable reports whether FRR is installed (for conditional UI).
func (s *Service) RoutingAvailable(p *Principal) bool {
	return p != nil && p.IsAdmin && routing.FRRAvailable()
}

// GetRoutingConfig returns the stored managed L3 config (admin only).
func (s *Service) GetRoutingConfig(p *Principal) (routing.Config, error) {
	var c routing.Config
	if !p.IsAdmin {
		return c, ErrUnauthorized
	}
	var raw string
	if err := s.db.QueryRow(`SELECT config_json FROM routing_config WHERE id=1`).Scan(&raw); err != nil {
		return c, nil // empty default
	}
	if raw != "" && raw != "{}" {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	return c, nil
}

// natCIDRs collects CIDRs of networks flagged for NAT across all orgs — these
// are masqueraded out the uplink at the edge.
func (s *Service) natCIDRs() []string {
	var cidrs []string
	rows, err := s.db.Query(`SELECT cidr FROM networks WHERE nat=1 AND cidr<>''`)
	if err != nil {
		return cidrs
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if rows.Scan(&c) == nil && c != "" {
			cidrs = append(cidrs, c)
		}
	}
	return cidrs
}

// SaveRoutingConfig persists the L3 config and applies it (forwarding + nftables
// NAT/firewall + FRR static/OSPF/BGP). Admin only.
func (s *Service) SaveRoutingConfig(p *Principal, c routing.Config, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	// NAT target CIDRs are derived live from networks flagged for NAT.
	c.InternalCIDRs = s.natCIDRs()
	blob, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE routing_config SET config_json=?, updated_at=datetime('now') WHERE id=1`, string(blob)); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "routing.apply", "routing", "l3", ip, map[string]any{
		"uplink": c.Uplink, "ospf": c.OSPF.Enabled, "bgp": c.BGP.Enabled,
		"static_routes": len(c.Static), "firewall_rules": len(c.Firewall),
	})
	// Apply to the host. Surface errors but keep the saved config.
	return s.applyHostRouting(c)
}

// RoutingStatus returns the live FRR route table (admin only).
func (s *Service) RoutingStatus(p *Principal) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	return routing.FRRStatus()
}

// ---- button-driven L3 CRUD ------------------------------------------------
//
// Each operation loads the stored config, mutates one item, persists, and
// re-applies the whole managed FRR + nftables state (idempotent).

func delAt[T any](s []T, i int) []T {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

func (s *Service) mutateRouting(p *Principal, ip, action string, fn func(*routing.Config)) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	c, _ := s.GetRoutingConfig(p)
	fn(&c)
	c.InternalCIDRs = s.natCIDRs()
	blob, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE routing_config SET config_json=?, updated_at=datetime('now') WHERE id=1`, string(blob)); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "routing."+action, "routing", "l3", ip, nil)
	return s.applyHostRouting(c)
}

func (s *Service) SetRoutingUplink(p *Principal, uplink, ip string) error {
	return s.mutateRouting(p, ip, "uplink", func(c *routing.Config) { c.Uplink = uplink })
}

func (s *Service) AddStaticRoute(p *Principal, dest, nexthop, ip string) error {
	return s.mutateRouting(p, ip, "static.add", func(c *routing.Config) {
		c.Static = append(c.Static, routing.Route{Dest: dest, NextHop: nexthop})
	})
}
func (s *Service) DeleteStaticRoute(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "static.delete", func(c *routing.Config) { c.Static = delAt(c.Static, idx) })
}

func (s *Service) AddFirewallRule(p *Principal, action, proto, dport, source, ip string) error {
	return s.mutateRouting(p, ip, "firewall.add", func(c *routing.Config) {
		c.Firewall = append(c.Firewall, routing.FirewallRule{Action: action, Proto: proto, DPort: dport, Source: source})
	})
}
func (s *Service) DeleteFirewallRule(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "firewall.delete", func(c *routing.Config) { c.Firewall = delAt(c.Firewall, idx) })
}

func (s *Service) AddIfPrefix(p *Principal, iface, cidr, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if iface == "" || cidr == "" {
		return errors.New("interface and CIDR are required")
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR %q (use e.g. 10.50.0.1/30)", cidr)
	}
	// Never assign onto the management NIC (would cut host access) or an interface
	// already enslaved to a vSwitch/bond (its IPs belong to the bridge, not here).
	if err := s.guardMgmt(iface); err != nil {
		return err
	}
	if ifs, err := hostinfo.Interfaces(); err == nil {
		for _, it := range ifs {
			if it.Name == iface && it.Master != "" {
				return fmt.Errorf("%s is enslaved to %s — detach it first, or pick a free interface", iface, it.Master)
			}
		}
	}
	return s.mutateRouting(p, ip, "prefix.add", func(c *routing.Config) {
		c.Prefixes = append(c.Prefixes, routing.IfPrefix{Iface: iface, CIDR: cidr})
	})
}
func (s *Service) DeleteIfPrefix(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "prefix.delete", func(c *routing.Config) { c.Prefixes = delAt(c.Prefixes, idx) })
}

func (s *Service) AddPrefixList(p *Principal, pl routing.PrefixList, ip string) error {
	return s.mutateRouting(p, ip, "prefixlist.add", func(c *routing.Config) { c.PrefixLists = append(c.PrefixLists, pl) })
}
func (s *Service) DeletePrefixList(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "prefixlist.delete", func(c *routing.Config) { c.PrefixLists = delAt(c.PrefixLists, idx) })
}

func (s *Service) AddRouteMap(p *Principal, rm routing.RouteMapClause, ip string) error {
	return s.mutateRouting(p, ip, "routemap.add", func(c *routing.Config) { c.RouteMaps = append(c.RouteMaps, rm) })
}
func (s *Service) DeleteRouteMap(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "routemap.delete", func(c *routing.Config) { c.RouteMaps = delAt(c.RouteMaps, idx) })
}

func (s *Service) SetOSPF(p *Principal, enabled bool, routerID, ip string) error {
	return s.mutateRouting(p, ip, "ospf.set", func(c *routing.Config) {
		c.OSPF.Enabled = enabled
		c.OSPF.RouterID = routerID
	})
}
func (s *Service) AddOSPFNetwork(p *Principal, cidr, area, ip string) error {
	if area == "" {
		area = "0"
	}
	return s.mutateRouting(p, ip, "ospf.net.add", func(c *routing.Config) {
		c.OSPF.Networks = append(c.OSPF.Networks, routing.OSPFNet{CIDR: cidr, Area: area})
	})
}
func (s *Service) DeleteOSPFNetwork(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "ospf.net.delete", func(c *routing.Config) { c.OSPF.Networks = delAt(c.OSPF.Networks, idx) })
}

func (s *Service) SetBGP(p *Principal, enabled bool, asn int, routerID, ip string) error {
	return s.mutateRouting(p, ip, "bgp.set", func(c *routing.Config) {
		c.BGP.Enabled = enabled
		c.BGP.ASN = asn
		c.BGP.RouterID = routerID
	})
}
func (s *Service) AddBGPNeighbor(p *Principal, nb routing.Neighbor, ip string) error {
	return s.mutateRouting(p, ip, "bgp.neighbor.add", func(c *routing.Config) { c.BGP.Neighbors = append(c.BGP.Neighbors, nb) })
}
func (s *Service) DeleteBGPNeighbor(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "bgp.neighbor.delete", func(c *routing.Config) { c.BGP.Neighbors = delAt(c.BGP.Neighbors, idx) })
}
func (s *Service) AddBGPNetwork(p *Principal, cidr, ip string) error {
	return s.mutateRouting(p, ip, "bgp.network.add", func(c *routing.Config) { c.BGP.Networks = append(c.BGP.Networks, cidr) })
}
func (s *Service) DeleteBGPNetwork(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "bgp.network.delete", func(c *routing.Config) { c.BGP.Networks = delAt(c.BGP.Networks, idx) })
}

func (s *Service) SetEIGRP(p *Principal, enabled bool, asn int, routerID, ip string) error {
	if enabled && (asn < 1 || asn > 65535) {
		return fmt.Errorf("EIGRP AS number must be 1-65535")
	}
	return s.mutateRouting(p, ip, "eigrp.set", func(c *routing.Config) {
		c.EIGRP.Enabled = enabled
		c.EIGRP.ASN = asn
		c.EIGRP.RouterID = routerID
	})
}
func (s *Service) AddEIGRPNetwork(p *Principal, cidr, ip string) error {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid network %q (use e.g. 10.0.0.0/24)", cidr)
	}
	return s.mutateRouting(p, ip, "eigrp.network.add", func(c *routing.Config) { c.EIGRP.Networks = append(c.EIGRP.Networks, cidr) })
}
func (s *Service) DeleteEIGRPNetwork(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "eigrp.network.delete", func(c *routing.Config) { c.EIGRP.Networks = delAt(c.EIGRP.Networks, idx) })
}

// applyHostRouting applies the host routing config, then re-fences the tenant
// networks: rewriting the global ip_forward resets every interface's forwarding
// flag, including the ones that keep the host from routing for a tenant.
func (s *Service) applyHostRouting(c routing.Config) error {
	err := routing.Apply(c)
	if ierr := s.applyTenantIsolation(); ierr != nil {
		log.Printf("routing: re-apply tenant isolation: %v", ierr)
	}
	return err
}
