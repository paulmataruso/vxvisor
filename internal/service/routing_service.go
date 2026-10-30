package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/routing"
)

// hostRoutingMu serializes host routing changes: each one reads the stored
// config, applies the changed one, and only then saves it.
var hostRoutingMu sync.Mutex

// Seams for tests: applying host routing and snapshotting the host's L3 state
// both touch the live machine.
var (
	applyHostRoutingFn = (*Service).applyHostRouting
	hostL3Snapshot     = func(s *Service, clientIP string) (hostL3, error) {
		return snapshotHostL3(s.mgmtIface(), clientIP)
	}
)

// RoutingAvailable reports whether FRR is installed (for conditional UI).
func (s *Service) RoutingAvailable(p *Principal) bool {
	return p != nil && p.IsAdmin && routing.FRRAvailable()
}

// GetRoutingConfig returns the stored managed L3 config (admin only), cleaned
// of any entry the renderer would refuse (routing.Sanitize). The page lists and
// the index-based CRUD below both use this cleaned view, so an index always
// names the entry the admin saw.
func (s *Service) GetRoutingConfig(p *Principal) (routing.Config, error) {
	if !p.IsAdmin {
		return routing.Config{}, ErrUnauthorized
	}
	return s.loadHostRouting(), nil
}

// loadHostRouting reads and sanitizes the stored host config.
func (s *Service) loadHostRouting() routing.Config {
	var c routing.Config
	var raw string
	if err := s.db.QueryRow(`SELECT config_json FROM routing_config WHERE id=1`).Scan(&raw); err != nil {
		return c // empty default
	}
	if raw != "" && raw != "{}" {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	c, dropped := routing.Sanitize(c)
	if len(dropped) > 0 {
		log.Printf("routing: ignoring stored host routing entries that can't be rendered: %s", strings.Join(dropped, "; "))
	}
	return c
}

// natCIDRs collects CIDRs of networks flagged for NAT across all orgs — these
// are masqueraded out the uplink at the edge. A network whose CIDR isn't a
// valid IPv4 network is skipped (it would make the NAT table unrenderable).
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
			canon, err := routing.CanonPrefix(c)
			if err != nil || canon == "0.0.0.0/0" {
				log.Printf("routing: not NATing network CIDR %q: %v", c, err)
				continue
			}
			cidrs = append(cidrs, canon)
		}
	}
	return cidrs
}

// SaveRoutingConfig re-applies the L3 config (forwarding + nftables NAT/firewall
// + FRR static/OSPF/BGP) and saves it once it applied. Admin only.
func (s *Service) SaveRoutingConfig(p *Principal, c routing.Config, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	hostRoutingMu.Lock()
	defer hostRoutingMu.Unlock()
	prev := s.loadHostRouting()
	// NAT target CIDRs are derived live from networks flagged for NAT.
	c.InternalCIDRs = s.natCIDRs()
	if err := c.Validate(); err != nil {
		return err
	}
	if err := s.commitHostRouting(prev, c); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "routing.apply", "routing", "l3", ip, map[string]any{
		"uplink": c.Uplink, "ospf": c.OSPF.Enabled, "bgp": c.BGP.Enabled,
		"static_routes": len(c.Static), "firewall_rules": len(c.Firewall),
	})
	return nil
}

// commitHostRouting applies next and only then saves it. If the apply fails,
// the previous config is put back on the host and nothing is saved — so a
// config that failed to apply is never the stored one that the next change (or
// a reboot) builds on.
func (s *Service) commitHostRouting(prev, next routing.Config) error {
	if err := applyHostRoutingFn(s, next); err != nil {
		prev.InternalCIDRs = next.InternalCIDRs // roll back the routing change, not the NAT set
		if rerr := applyHostRoutingFn(s, prev); rerr != nil {
			return fmt.Errorf("apply routing: %v — restoring the previous routing config also failed (%v); check the host's FRR and nftables state", err, rerr)
		}
		return fmt.Errorf("apply routing: %v — the change was not saved and the previous routing config was restored", err)
	}
	blob, err := json.Marshal(next)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE routing_config SET config_json=?, updated_at=datetime('now') WHERE id=1`, string(blob))
	return err
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
// Each operation loads the stored config, mutates one item, applies the whole
// managed FRR + nftables state (idempotent), and saves it only once it applied.

func delAt[T any](s []T, i int) []T {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

// errNoEntry is returned by the delete CRUD for an index that isn't listed.
func errNoEntry(what string, i int) error {
	return fmt.Errorf("there is no %s #%d — reload the page", what, i+1)
}

func (s *Service) mutateRouting(p *Principal, ip, action string, detail map[string]any, fn func(*routing.Config) error) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	hostRoutingMu.Lock()
	defer hostRoutingMu.Unlock()
	prev := s.loadHostRouting()
	next := s.loadHostRouting() // an independent copy: fn may edit slices in place
	if err := fn(&next); err != nil {
		return err
	}
	next.InternalCIDRs = s.natCIDRs()
	if err := next.Validate(); err != nil {
		return err
	}
	if err := s.commitHostRouting(prev, next); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "routing."+action, "routing", "l3", ip, detail)
	return nil
}

func (s *Service) SetRoutingUplink(p *Principal, uplink, ip string) error {
	uplink = strings.TrimSpace(uplink)
	if uplink != "" {
		if err := routing.ValidIface(uplink); err != nil {
			return err
		}
	}
	return s.mutateRouting(p, ip, "uplink", map[string]any{"uplink": uplink}, func(c *routing.Config) error {
		c.Uplink = uplink
		return nil
	})
}

func (s *Service) AddStaticRoute(p *Principal, dest, nexthop, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	r, err := staticRoute(dest, nexthop)
	if err != nil {
		return err
	}
	h, err := hostL3Snapshot(s, ip)
	if err != nil {
		return fmt.Errorf("couldn't read the host's interfaces to check this route against the management network: %w", err)
	}
	if err := h.checkStaticAdd(r); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "static.add", map[string]any{"dest": r.Dest, "next_hop": r.NextHop}, func(c *routing.Config) error {
		c.Static = append(c.Static, r)
		return nil
	})
}

func (s *Service) DeleteStaticRoute(p *Principal, idx int, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	h, _ := hostL3Snapshot(s, ip) // best effort: without it only the session check is skipped
	return s.mutateRouting(p, ip, "static.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.Static) {
			return errNoEntry("static route", idx)
		}
		if err := h.checkStaticDelete(c.Static[idx]); err != nil {
			return err
		}
		c.Static = delAt(c.Static, idx)
		return nil
	})
}

// staticRoute validates and canonicalizes a static route from form input.
func staticRoute(dest, nexthop string) (routing.Route, error) {
	d, err := routing.CanonPrefix(dest)
	if err != nil {
		return routing.Route{}, fmt.Errorf("destination: %w (or \"default\")", err)
	}
	nexthop = strings.TrimSpace(nexthop)
	if err := routing.ValidNextHop(nexthop); err != nil {
		return routing.Route{}, err
	}
	return routing.Route{Dest: d, NextHop: nexthop}, nil
}

func (s *Service) AddFirewallRule(p *Principal, action, proto, dport, source, ip string) error {
	r := routing.FirewallRule{Action: strings.TrimSpace(action), Proto: strings.TrimSpace(proto),
		DPort: strings.TrimSpace(dport), Source: strings.TrimSpace(source)}
	if r.Proto == "any" {
		r.Proto = ""
	}
	if err := routing.ValidFirewallRule(r); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "firewall.add", map[string]any{"rule": r}, func(c *routing.Config) error {
		c.Firewall = append(c.Firewall, r)
		return nil
	})
}
func (s *Service) DeleteFirewallRule(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "firewall.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.Firewall) {
			return errNoEntry("firewall rule", idx)
		}
		c.Firewall = delAt(c.Firewall, idx)
		return nil
	})
}

func (s *Service) AddIfPrefix(p *Principal, iface, cidr, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	iface, cidr = strings.TrimSpace(iface), strings.TrimSpace(cidr)
	if iface == "" || cidr == "" {
		return errors.New("interface and CIDR are required")
	}
	if err := routing.ValidIface(iface); err != nil {
		return err
	}
	if err := routing.ValidIfaceAddr(cidr); err != nil {
		return fmt.Errorf("invalid CIDR %q (use e.g. 10.50.0.1/30)", cidr)
	}
	// Never assign onto the management NIC (would cut host access) or an interface
	// already enslaved to a vSwitch/bond (its IPs belong to the bridge, not here).
	if err := s.guardMgmt(iface); err != nil {
		return err
	}
	h, err := hostL3Snapshot(s, ip)
	if err != nil {
		return fmt.Errorf("couldn't read the host's interfaces to check this address against the management network: %w", err)
	}
	if err := h.checkIfPrefixAdd(iface, cidr); err != nil {
		return err
	}
	if ifs, err := hostinfo.Interfaces(); err == nil {
		for _, it := range ifs {
			if it.Name == iface && it.Master != "" {
				return fmt.Errorf("%s is enslaved to %s — detach it first, or pick a free interface", iface, it.Master)
			}
		}
	}
	return s.mutateRouting(p, ip, "prefix.add", map[string]any{"iface": iface, "cidr": cidr}, func(c *routing.Config) error {
		c.Prefixes = append(c.Prefixes, routing.IfPrefix{Iface: iface, CIDR: cidr})
		return nil
	})
}
func (s *Service) DeleteIfPrefix(p *Principal, idx int, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	h, _ := hostL3Snapshot(s, ip)
	return s.mutateRouting(p, ip, "prefix.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.Prefixes) {
			return errNoEntry("interface address", idx)
		}
		if err := h.checkIfPrefixDelete(c.Prefixes[idx]); err != nil {
			return err
		}
		c.Prefixes = delAt(c.Prefixes, idx)
		return nil
	})
}

func (s *Service) AddPrefixList(p *Principal, pl routing.PrefixList, ip string) error {
	pl.Name, pl.Action, pl.Prefix = strings.TrimSpace(pl.Name), strings.TrimSpace(pl.Action), strings.TrimSpace(pl.Prefix)
	if pl.Prefix != "any" {
		canon, err := routing.CanonPrefix(pl.Prefix)
		if err != nil {
			return fmt.Errorf("prefix: %w (or \"any\")", err)
		}
		pl.Prefix = canon
	}
	if err := routing.ValidPrefixListEntry(pl); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "prefixlist.add", map[string]any{"entry": pl}, func(c *routing.Config) error {
		c.PrefixLists = append(c.PrefixLists, pl)
		return nil
	})
}
func (s *Service) DeletePrefixList(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "prefixlist.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.PrefixLists) {
			return errNoEntry("prefix-list entry", idx)
		}
		c.PrefixLists = delAt(c.PrefixLists, idx)
		return nil
	})
}

func (s *Service) AddRouteMap(p *Principal, rm routing.RouteMapClause, ip string) error {
	rm.Name, rm.Action, rm.MatchPrefixList = strings.TrimSpace(rm.Name), strings.TrimSpace(rm.Action), strings.TrimSpace(rm.MatchPrefixList)
	if err := routing.ValidRouteMapClause(rm); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "routemap.add", map[string]any{"clause": rm}, func(c *routing.Config) error {
		c.RouteMaps = append(c.RouteMaps, rm)
		return nil
	})
}
func (s *Service) DeleteRouteMap(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "routemap.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.RouteMaps) {
			return errNoEntry("route-map clause", idx)
		}
		c.RouteMaps = delAt(c.RouteMaps, idx)
		return nil
	})
}

func (s *Service) SetOSPF(p *Principal, enabled bool, routerID, ip string) error {
	routerID = strings.TrimSpace(routerID)
	if err := routing.ValidRouterID(routerID); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "ospf.set", map[string]any{"enabled": enabled, "router_id": routerID}, func(c *routing.Config) error {
		c.OSPF.Enabled = enabled
		c.OSPF.RouterID = routerID
		return nil
	})
}
func (s *Service) AddOSPFNetwork(p *Principal, cidr, area, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	n, err := routing.CanonPrefix(cidr)
	if err != nil {
		return err
	}
	if area = strings.TrimSpace(area); area == "" {
		area = "0"
	}
	if err := routing.ValidArea(area); err != nil {
		return err
	}
	h, err := hostL3Snapshot(s, ip)
	if err != nil {
		return fmt.Errorf("couldn't read the host's interfaces to check this network against the management network: %w", err)
	}
	if err := h.checkOSPFNet(n); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "ospf.net.add", map[string]any{"cidr": n, "area": area}, func(c *routing.Config) error {
		c.OSPF.Networks = append(c.OSPF.Networks, routing.OSPFNet{CIDR: n, Area: area})
		return nil
	})
}
func (s *Service) DeleteOSPFNetwork(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "ospf.net.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.OSPF.Networks) {
			return errNoEntry("OSPF network", idx)
		}
		c.OSPF.Networks = delAt(c.OSPF.Networks, idx)
		return nil
	})
}

func (s *Service) SetBGP(p *Principal, enabled bool, asn int, routerID, ip string) error {
	routerID = strings.TrimSpace(routerID)
	if enabled {
		if err := routing.ValidASN(asn); err != nil {
			return fmt.Errorf("local %w", err)
		}
	}
	if err := routing.ValidRouterID(routerID); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "bgp.set", map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID}, func(c *routing.Config) error {
		c.BGP.Enabled = enabled
		c.BGP.ASN = asn
		c.BGP.RouterID = routerID
		return nil
	})
}
func (s *Service) AddBGPNeighbor(p *Principal, nb routing.Neighbor, ip string) error {
	nb.Addr = strings.TrimSpace(nb.Addr)
	nb.RouteMapIn, nb.RouteMapOut = strings.TrimSpace(nb.RouteMapIn), strings.TrimSpace(nb.RouteMapOut)
	nb.PrefixListOut = ""
	if err := routing.ValidPeer(nb.Addr); err != nil {
		return err
	}
	if err := routing.ValidASN(nb.RemoteAS); err != nil {
		return fmt.Errorf("remote %w", err)
	}
	for _, rm := range []string{nb.RouteMapIn, nb.RouteMapOut} {
		if rm != "" {
			if err := routing.ValidListName(rm); err != nil {
				return fmt.Errorf("route-map %w", err)
			}
		}
	}
	return s.mutateRouting(p, ip, "bgp.neighbor.add", map[string]any{"addr": nb.Addr, "remote_as": nb.RemoteAS}, func(c *routing.Config) error {
		c.BGP.Neighbors = append(c.BGP.Neighbors, nb)
		return nil
	})
}
func (s *Service) DeleteBGPNeighbor(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "bgp.neighbor.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.BGP.Neighbors) {
			return errNoEntry("BGP neighbor", idx)
		}
		c.BGP.Neighbors = delAt(c.BGP.Neighbors, idx)
		return nil
	})
}
func (s *Service) AddBGPNetwork(p *Principal, cidr, ip string) error {
	n, err := routing.CanonPrefix(cidr)
	if err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "bgp.network.add", map[string]any{"cidr": n}, func(c *routing.Config) error {
		c.BGP.Networks = append(c.BGP.Networks, n)
		return nil
	})
}
func (s *Service) DeleteBGPNetwork(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "bgp.network.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.BGP.Networks) {
			return errNoEntry("BGP network", idx)
		}
		c.BGP.Networks = delAt(c.BGP.Networks, idx)
		return nil
	})
}

func (s *Service) SetEIGRP(p *Principal, enabled bool, asn int, routerID, ip string) error {
	if enabled && (asn < 1 || asn > 65535) {
		return fmt.Errorf("EIGRP AS number must be 1-65535")
	}
	routerID = strings.TrimSpace(routerID)
	if err := routing.ValidRouterID(routerID); err != nil {
		return err
	}
	return s.mutateRouting(p, ip, "eigrp.set", map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID}, func(c *routing.Config) error {
		c.EIGRP.Enabled = enabled
		c.EIGRP.ASN = asn
		c.EIGRP.RouterID = routerID
		return nil
	})
}
func (s *Service) AddEIGRPNetwork(p *Principal, cidr, ip string) error {
	n, err := routing.CanonPrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid network %q (use e.g. 10.0.0.0/24)", cidr)
	}
	return s.mutateRouting(p, ip, "eigrp.network.add", map[string]any{"cidr": n}, func(c *routing.Config) error {
		c.EIGRP.Networks = append(c.EIGRP.Networks, n)
		return nil
	})
}
func (s *Service) DeleteEIGRPNetwork(p *Principal, idx int, ip string) error {
	return s.mutateRouting(p, ip, "eigrp.network.delete", map[string]any{"index": idx}, func(c *routing.Config) error {
		if idx < 0 || idx >= len(c.EIGRP.Networks) {
			return errNoEntry("EIGRP network", idx)
		}
		c.EIGRP.Networks = delAt(c.EIGRP.Networks, idx)
		return nil
	})
}

// ReensureBGPGuard reloads the host's TCP 179 peer guard at boot (the kernel
// drops nft tables on reboot; frr.service's drop-in reloads the saved copy
// before bgpd starts, and this brings an upgraded host up to date).
func (s *Service) ReensureBGPGuard() {
	if !routing.NFTAvailable() {
		return
	}
	if err := routing.ApplyBGPGuard(s.loadHostRouting()); err != nil {
		log.Printf("routing: BGP peer guard: %v", err)
	}
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

// ---- management guard ------------------------------------------------------
//
// A host route, interface address or OSPF network can take the management path
// away: a default route out another interface, a route that covers the admin's
// own address, a more-specific route inside the management subnet, or OSPF
// running on the management LAN. Each add/delete is checked against a snapshot
// of the host's L3 state first. "Management" is the interface carrying the
// admin listener (mgmtIface), or — when that can't be told — the interface the
// host reaches the requesting admin through. BGP is not checked: it only changes
// host routes through what peers send, which can't be known in advance.

// hostNet is one IPv4 address on a host interface.
type hostNet struct {
	Iface string
	IP    net.IP
	Net   *net.IPNet
}

// hostL3 is the snapshot a routing change is checked against.
type hostL3 struct {
	Nets       []hostNet
	MgmtIface  string // "" = unknown
	DefaultVia net.IP // the kernel's current default route (nil = none)
	DefaultDev string
	Client     net.IP // the requesting admin's address (nil = local/unknown)
	ClientVia  net.IP // the gateway the host reaches the admin through (nil = on-link)
	ClientDev  string
}

// snapshotHostL3 reads the host's addresses, its default route and its route
// back to the admin at clientIP.
func snapshotHostL3(mgmtIface, clientIP string) (hostL3, error) {
	var h hostL3
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return h, err
	}
	for _, it := range ifs {
		for _, a := range it.Addrs {
			ip, n, err := net.ParseCIDR(a)
			if err != nil || ip.To4() == nil || ip.IsLoopback() {
				continue
			}
			h.Nets = append(h.Nets, hostNet{Iface: it.Name, IP: ip.To4(), Net: n})
		}
	}
	h.DefaultVia, h.DefaultDev = parseIPRouteJSON(ipRouteJSON("show", "default"))
	if c := net.ParseIP(clientIP); c != nil && c.To4() != nil && !c.IsLoopback() {
		h.Client = c.To4()
		h.ClientVia, h.ClientDev = parseIPRouteJSON(ipRouteJSON("get", h.Client.String()))
	}
	h.MgmtIface = mgmtIface
	if h.MgmtIface == "" && h.ClientDev != "lo" {
		h.MgmtIface = h.ClientDev
	}
	return h, nil
}

func ipRouteJSON(args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ip", append([]string{"-4", "-j", "route"}, args...)...).Output()
	return out
}

// parseIPRouteJSON picks the preferred (lowest-metric) route from `ip -j route`
// output and returns its gateway (nil when on-link) and interface.
func parseIPRouteJSON(out []byte) (net.IP, string) {
	var rs []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
		Metric  int    `json:"metric"`
	}
	if json.Unmarshal(out, &rs) != nil || len(rs) == 0 {
		return nil, ""
	}
	best := 0
	for i, r := range rs {
		if r.Metric < rs[best].Metric {
			best = i
		}
	}
	var gw net.IP
	if ip := net.ParseIP(rs[best].Gateway); ip != nil {
		gw = ip.To4()
	}
	return gw, rs[best].Dev
}

// onLink returns the most specific host subnet containing ip.
func (h hostL3) onLink(ip net.IP) (hostNet, bool) {
	var best hostNet
	bestLen := -1
	for _, n := range h.Nets {
		if l, _ := n.Net.Mask.Size(); n.Net.Contains(ip) && l > bestLen {
			best, bestLen = n, l
		}
	}
	return best, bestLen >= 0
}

func (h hostL3) mgmtNets() []hostNet {
	var out []hostNet
	for _, n := range h.Nets {
		if h.MgmtIface != "" && n.Iface == h.MgmtIface {
			out = append(out, n)
		}
	}
	return out
}

// nextHopDev is the interface a next hop is reached through ("" = not on a
// connected subnet, so unknown).
func (h hostL3) nextHopDev(nh string) string {
	if routing.IsIPv4(nh) {
		if n, ok := h.onLink(net.ParseIP(nh)); ok {
			return n.Iface
		}
		return ""
	}
	return nh // an interface next hop
}

// within reports whether a lies inside b (equal or more specific).
func within(a, b *net.IPNet) bool {
	al, _ := a.Mask.Size()
	bl, _ := b.Mask.Size()
	return al >= bl && b.Contains(a.IP)
}

func (h hostL3) checkStaticAdd(r routing.Route) error {
	dst, err := routing.ParsePrefix(r.Dest)
	if err != nil {
		return err
	}
	ones, _ := dst.Mask.Size()
	dev := h.nextHopDev(r.NextHop)
	if ones == 0 {
		if !routing.IsIPv4(r.NextHop) {
			return fmt.Errorf("give the default route a gateway IP address, not an interface")
		}
		if dev == "" {
			return fmt.Errorf("the default route's next hop %s isn't on a directly connected subnet — use a gateway on one of the host's networks", r.NextHop)
		}
		if h.MgmtIface != "" && h.DefaultDev == h.MgmtIface && dev != h.MgmtIface {
			return fmt.Errorf("the host's default route goes out the management interface %s (via %s); a default route via %s on %s would move it off that interface and cut management access from other networks", h.MgmtIface, h.DefaultVia, r.NextHop, dev)
		}
	}
	for _, m := range h.mgmtNets() {
		if within(dst, m.Net) {
			return fmt.Errorf("%s is (part of) the management subnet %s on %s — a static route there would take management traffic off the management interface", dst, m.Net, m.Iface)
		}
	}
	if h.Client != nil && h.ClientDev != "" && h.ClientDev != "lo" && dst.Contains(h.Client) && dev != h.ClientDev {
		cur := 0 // the admin is reached through a gateway: the current route is at most as specific as a default
		if n, ok := h.onLink(h.Client); ok {
			cur, _ = n.Net.Mask.Size()
		}
		if ones >= cur {
			via := r.NextHop
			if dev != "" {
				via += " on " + dev
			}
			return fmt.Errorf("%s covers your own address %s, which the host reaches through %s — routing it via %s would cut your session", dst, h.Client, h.ClientDev, via)
		}
	}
	return nil
}

func (h hostL3) checkStaticDelete(r routing.Route) error {
	if h.Client == nil || h.ClientVia == nil || r.NextHop != h.ClientVia.String() {
		return nil
	}
	if dst, err := routing.ParsePrefix(r.Dest); err == nil && dst.Contains(h.Client) {
		return fmt.Errorf("the route to %s via %s carries your current session (from %s) — removing it would cut you off; add a replacement route first", dst, r.NextHop, h.Client)
	}
	return nil
}

func (h hostL3) checkOSPFNet(cidr string) error {
	n, err := routing.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	for _, m := range h.mgmtNets() {
		if n.Contains(m.IP) {
			return fmt.Errorf("OSPF network %s includes the management address %s on %s — OSPF would run on the management LAN and routes learned there could replace the management routes; use a network that leaves %s out", n, m.IP, m.Iface, m.Net)
		}
	}
	return nil
}

func (h hostL3) checkIfPrefixAdd(iface, cidr string) error {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if h.MgmtIface != "" && iface == h.MgmtIface {
		return fmt.Errorf("refusing to use the management interface %q (it carries the admin IP — using it here would cut host access)", iface)
	}
	for _, m := range h.mgmtNets() {
		if within(n, m.Net) || within(m.Net, n) {
			return fmt.Errorf("%s overlaps the management subnet %s on %s — a second route to it on %s would take management traffic off the management interface", n, m.Net, m.Iface, iface)
		}
	}
	if h.Client != nil && n.Contains(h.Client) && iface != h.ClientDev {
		return fmt.Errorf("%s contains your own address %s — the host would answer you on %s instead of %s and cut your session", n, h.Client, iface, h.ClientDev)
	}
	return nil
}

func (h hostL3) checkIfPrefixDelete(p routing.IfPrefix) error {
	if h.Client == nil || p.Iface != h.ClientDev || h.ClientVia != nil {
		return nil
	}
	if _, n, err := net.ParseCIDR(p.CIDR); err == nil && n.Contains(h.Client) {
		return fmt.Errorf("you are connected through %s on %s — removing it would cut your session", p.CIDR, p.Iface)
	}
	return nil
}
