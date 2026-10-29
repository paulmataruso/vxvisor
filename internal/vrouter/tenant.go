package vrouter

import (
	"fmt"
	"net"
	"strings"

	"vdxclone/internal/routing"
)

// Tenant routing policy. A gateway in a tenant org (any org but the provider's
// Default org) can sit on the provider's wire through its external interface
// (uplink leg), so what it may tell the provider is constrained here. The
// service runs ConstrainTenant on every render of a tenant router, so a stored
// config can never get past it:
//
//   - BGP: a neighbor must be on a subnet directly connected to one of the
//     router's legs (no sessions to arbitrary hosts), and EVERY neighbor gets
//     the outbound prefix-list TenantExportList, which permits only the
//     router's downlink networks (the segments / port groups attached to it) and
//     their subnets. `network` statements outside those networks are dropped.
//   - OSPF: `network` statements must fall inside a connected or downlink
//     network. While the router has an external interface every downlink is
//     passive: OSPF floods LSAs through an area with no per-neighbor filter, so
//     a VM forming an adjacency on a downlink could otherwise inject routes the
//     provider would learn. The model has no `redistribute`, so OSPF only ever
//     originates the connected networks it runs on.
//   - EIGRP is off (FRR's eigrpd is experimental and nothing here can filter it).
//   - Prefix-lists and route-maps are the policy's own; any others are dropped.
//
// Static routes are local to the router (never redistributed) and stay as-is.

// TenantExportList is the outbound prefix-list every BGP neighbor of a tenant
// router gets.
const TenantExportList = "VDX-TENANT-EXPORT"

// MinLegPrefix is the shortest prefix a leg address (and so a connected or
// exported network) may have. A /0-/7 interface would make "directly
// connected" and "the gateway's own networks" cover a large part of the
// address space; the service refuses such addresses and the policy here
// ignores any that are stored.
const MinLegPrefix = 8

// legNet returns the subnet a leg sits on (nil if its address is unset,
// invalid or shorter than MinLegPrefix).
func legNet(l Leg) *net.IPNet {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(l.CIDR))
	if err != nil || ip.To4() == nil {
		return nil
	}
	if ones, _ := n.Mask.Size(); ones < MinLegPrefix {
		return nil
	}
	return n
}

// ConnectedNets returns the subnet of every leg: the networks the router is
// directly attached to (downlinks, external interface, provider link).
func ConnectedNets(legs []Leg) []*net.IPNet {
	var out []*net.IPNet
	for _, l := range legs {
		if n := legNet(l); n != nil {
			out = appendNet(out, n)
		}
	}
	return out
}

// ExportNets returns what a tenant router may advertise: the networks of the
// segments / port groups attached to it as downlinks (the port group's own
// CIDR, else the leg's subnet). Never a default route.
func ExportNets(legs []Leg) []*net.IPNet {
	var out []*net.IPNet
	for _, l := range legs {
		if l.Kind != LegInternal {
			continue
		}
		n := legNet(l)
		if pg, err := routing.ParsePrefix(l.NetworkCIDR); err == nil && strings.TrimSpace(l.NetworkCIDR) != "default" {
			n = pg
		}
		if n == nil {
			continue
		}
		if ones, _ := n.Mask.Size(); ones < MinLegPrefix {
			continue
		}
		out = appendNet(out, n)
	}
	return out
}

func appendNet(nets []*net.IPNet, n *net.IPNet) []*net.IPNet {
	for _, x := range nets {
		if x.String() == n.String() {
			return nets
		}
	}
	return append(nets, n)
}

// OnConnected reports whether ip is a usable neighbor on one of the legs'
// subnets: inside the subnet, and not the router's own address there.
func OnConnected(legs []Leg, ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	for _, l := range legs {
		own, _, err := net.ParseCIDR(strings.TrimSpace(l.CIDR))
		n := legNet(l)
		if err != nil || n == nil {
			continue
		}
		if n.Contains(ip) && !own.Equal(ip) {
			return true
		}
	}
	return false
}

// NetWithin reports whether n lies inside one of nets (equal or more specific).
func NetWithin(n *net.IPNet, nets []*net.IPNet) bool {
	ones, _ := n.Mask.Size()
	for _, x := range nets {
		xo, _ := x.Mask.Size()
		if xo <= ones && x.Contains(n.IP) {
			return true
		}
	}
	return false
}

// hasExternal reports whether the router has a provider-facing leg.
func hasExternal(legs []Leg) bool {
	for _, l := range legs {
		if l.Kind == LegUplink || l.Kind == LegTransit {
			return true
		}
	}
	return false
}

// ConstrainTenant returns cfg limited to what a tenant router may run (see the
// policy above), plus a description of every entry it left out. cfg itself is
// not modified.
func ConstrainTenant(cfg routing.Config, legs []Leg) (routing.Config, []string) {
	var dropped []string
	out := cfg
	conn := ConnectedNets(legs)
	export := ExportNets(legs)

	if cfg.EIGRP.Enabled {
		dropped = append(dropped, "EIGRP (not available on tenant gateways)")
	}
	out.EIGRP.Enabled = false
	if len(cfg.PrefixLists) > 0 || len(cfg.RouteMaps) > 0 {
		dropped = append(dropped, "custom prefix-lists / route-maps")
	}
	out.PrefixLists, out.RouteMaps = nil, nil

	out.BGP.Neighbors = nil
	for _, nb := range cfg.BGP.Neighbors {
		ip := net.ParseIP(strings.TrimSpace(nb.Addr))
		if ip == nil || !OnConnected(legs, ip) {
			dropped = append(dropped, fmt.Sprintf("BGP neighbor %s (not on a connected network)", nb.Addr))
			continue
		}
		nb.RouteMapIn, nb.RouteMapOut = "", ""
		nb.PrefixListOut = TenantExportList
		out.BGP.Neighbors = append(out.BGP.Neighbors, nb)
	}
	out.BGP.Networks = nil
	for _, s := range cfg.BGP.Networks {
		n, err := routing.ParsePrefix(s)
		if err != nil || !NetWithin(n, export) {
			dropped = append(dropped, fmt.Sprintf("BGP network %s (not one of the gateway's downlink networks)", s))
			continue
		}
		out.BGP.Networks = append(out.BGP.Networks, s)
	}
	if out.BGP.Enabled {
		out.PrefixLists = TenantExportPrefixList(export)
	}

	ospfOK := append(append([]*net.IPNet(nil), conn...), export...)
	out.OSPF.Networks = nil
	for _, on := range cfg.OSPF.Networks {
		n, err := routing.ParsePrefix(on.CIDR)
		if err != nil || !NetWithin(n, ospfOK) {
			dropped = append(dropped, fmt.Sprintf("OSPF network %s (not one of the gateway's networks)", on.CIDR))
			continue
		}
		out.OSPF.Networks = append(out.OSPF.Networks, on)
	}
	out.OSPF.Passive = nil
	if hasExternal(legs) {
		for _, l := range legs {
			if l.Kind == LegInternal && l.IfaceName != "" {
				out.OSPF.Passive = append(out.OSPF.Passive, l.IfaceName)
			}
		}
	}
	return out, dropped
}

// TenantExportPrefixList builds the TenantExportList entries: permit each
// export network and its subnets, nothing else. With no downlinks it is a
// single deny-all, so the list always exists (and always filters).
func TenantExportPrefixList(export []*net.IPNet) []routing.PrefixList {
	if len(export) == 0 {
		return []routing.PrefixList{{Name: TenantExportList, Seq: 5, Action: "deny", Prefix: "any"}}
	}
	var out []routing.PrefixList
	for i, n := range export {
		pl := routing.PrefixList{Name: TenantExportList, Seq: 5 * (i + 1), Action: "permit", Prefix: n.String()}
		if ones, _ := n.Mask.Size(); ones < 32 {
			pl.Le = 32
		}
		out = append(out, pl)
	}
	return out
}
