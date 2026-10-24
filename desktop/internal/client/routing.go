package client

import "fmt"

// Host L3 routing (FRR + nftables) client — mirrors internal/routing.Config and
// its nested types, and the granular REST surface in internal/api/api_routing.go.
//
// GET /api/v1/routing returns routing.Config, which carries EXPLICIT snake_case
// json tags on the server (not the usual PascalCase), so these structs match
// those tags. Every mutation is a granular POST; the server loads the stored
// config, mutates one item, persists, and re-applies the whole managed state.

// StaticRoute is one static route (routing.Route).
type StaticRoute struct {
	Dest    string `json:"dest"`     // CIDR, or "default"
	NextHop string `json:"next_hop"` // gateway IP
}

// IfPrefix assigns an IP prefix (CIDR) to a host interface (routing.IfPrefix).
type IfPrefix struct {
	Iface string `json:"iface"`
	CIDR  string `json:"cidr"`
}

// RoutingFirewallRule is one host-edge nft forward-chain rule
// (routing.FirewallRule) — distinct from the unified vFirewall.
type RoutingFirewallRule struct {
	Action string `json:"action"` // accept | drop
	Proto  string `json:"proto"`  // tcp | udp | "" (any)
	DPort  string `json:"dport"`  // "" = any
	Source string `json:"source"` // CIDR or "" = any
}

// PrefixList is one ip prefix-list entry (routing.PrefixList).
type PrefixList struct {
	Name   string `json:"name"`
	Seq    int    `json:"seq"`
	Action string `json:"action"` // permit | deny
	Prefix string `json:"prefix"` // CIDR, or "any"
	Ge     int    `json:"ge"`     // 0 = unset
	Le     int    `json:"le"`     // 0 = unset
}

// RouteMapClause is one route-map clause (routing.RouteMapClause).
type RouteMapClause struct {
	Name            string `json:"name"`
	Seq             int    `json:"seq"`
	Action          string `json:"action"` // permit | deny
	MatchPrefixList string `json:"match_prefix_list"`
	SetMetric       int    `json:"set_metric"`     // 0 = unset
	SetLocalPref    int    `json:"set_local_pref"` // 0 = unset
}

// OSPFNet attaches a network to an OSPF area (routing.OSPFNet).
type OSPFNet struct {
	CIDR string `json:"cidr"`
	Area string `json:"area"`
}

// OSPFConfig is the OSPFv2 config (routing.OSPF).
type OSPFConfig struct {
	Enabled  bool      `json:"enabled"`
	RouterID string    `json:"router_id"`
	Networks []OSPFNet `json:"networks"`
}

// BGPNeighbor is a BGP peer (routing.Neighbor).
type BGPNeighbor struct {
	Addr        string `json:"addr"`
	RemoteAS    int    `json:"remote_as"`
	RouteMapIn  string `json:"route_map_in"`
	RouteMapOut string `json:"route_map_out"`
}

// BGPConfig is the BGP config (routing.BGP).
type BGPConfig struct {
	Enabled   bool          `json:"enabled"`
	ASN       int           `json:"asn"`
	RouterID  string        `json:"router_id"`
	Neighbors []BGPNeighbor `json:"neighbors"`
	Networks  []string      `json:"networks"` // CIDRs to advertise
}

// EIGRPConfig is the EIGRP config (routing.EIGRP).
type EIGRPConfig struct {
	Enabled  bool     `json:"enabled"`
	ASN      int      `json:"asn"`
	RouterID string   `json:"router_id"`
	Networks []string `json:"networks"`
}

// RoutingConfig is the whole managed host L3 state (routing.Config).
type RoutingConfig struct {
	Hostname      string                `json:"hostname"`
	Uplink        string                `json:"uplink"`         // edge NIC for SNAT
	InternalCIDRs []string              `json:"internal_cidrs"` // NAT'd networks (server-derived)
	Prefixes      []IfPrefix            `json:"prefixes"`
	Static        []StaticRoute         `json:"static"`
	Firewall      []RoutingFirewallRule `json:"firewall"`
	PrefixLists   []PrefixList          `json:"prefix_lists"`
	RouteMaps     []RouteMapClause      `json:"route_maps"`
	OSPF          OSPFConfig            `json:"ospf"`
	BGP           BGPConfig             `json:"bgp"`
	EIGRP         EIGRPConfig           `json:"eigrp"`
	FRRVersion    string                `json:"frr_version,omitempty"`
}

// Routing fetches the stored host L3 config (admin only on the server).
func (c *Client) Routing() (RoutingConfig, error) {
	var cfg RoutingConfig
	err := c.getJSON("/api/v1/routing", &cfg)
	return cfg, err
}

// ApplyRouting re-saves and re-applies the stored config (forwarding + nft + FRR).
func (c *Client) ApplyRouting() error {
	return c.apiPostJSON("/api/v1/routing/apply", nil)
}

// SetRoutingUplink sets the edge NIC used for SNAT/masquerade.
func (c *Client) SetRoutingUplink(uplink string) error {
	return c.apiPostJSON("/api/v1/routing/uplink", map[string]any{"uplink": uplink})
}

// AddStaticRoute adds a static route.
func (c *Client) AddStaticRoute(dest, nextHop string) error {
	return c.apiPostJSON("/api/v1/routing/static", map[string]any{"dest": dest, "next_hop": nextHop})
}

// DeleteStaticRoute removes the static route at index i.
func (c *Client) DeleteStaticRoute(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/static/%d/delete", i), nil)
}

// AddIfPrefix assigns an IP prefix (CIDR) to a host interface.
func (c *Client) AddIfPrefix(iface, cidr string) error {
	return c.apiPostJSON("/api/v1/routing/prefix", map[string]any{"iface": iface, "cidr": cidr})
}

// DeleteIfPrefix removes the interface prefix at index i.
func (c *Client) DeleteIfPrefix(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/prefix/%d/delete", i), nil)
}

// AddRoutingFirewallRule adds a host-edge nft forward rule.
func (c *Client) AddRoutingFirewallRule(action, proto, dport, source string) error {
	return c.apiPostJSON("/api/v1/routing/firewall", map[string]any{
		"action": action, "proto": proto, "dport": dport, "source": source,
	})
}

// DeleteRoutingFirewallRule removes the host-edge rule at index i.
func (c *Client) DeleteRoutingFirewallRule(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/firewall/%d/delete", i), nil)
}

// AddPrefixList adds one ip prefix-list entry.
func (c *Client) AddPrefixList(pl PrefixList) error {
	return c.apiPostJSON("/api/v1/routing/prefixlist", pl)
}

// DeletePrefixList removes the prefix-list entry at index i.
func (c *Client) DeletePrefixList(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/prefixlist/%d/delete", i), nil)
}

// AddRouteMap adds one route-map clause.
func (c *Client) AddRouteMap(rm RouteMapClause) error {
	return c.apiPostJSON("/api/v1/routing/routemap", rm)
}

// DeleteRouteMap removes the route-map clause at index i.
func (c *Client) DeleteRouteMap(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/routemap/%d/delete", i), nil)
}

// SetOSPF toggles OSPF and sets the router-id.
func (c *Client) SetOSPF(enabled bool, routerID string) error {
	return c.apiPostJSON("/api/v1/routing/ospf", map[string]any{"enabled": enabled, "router_id": routerID})
}

// AddOSPFNetwork attaches a network/area to OSPF (empty area → "0").
func (c *Client) AddOSPFNetwork(cidr, area string) error {
	return c.apiPostJSON("/api/v1/routing/ospf/net", map[string]any{"cidr": cidr, "area": area})
}

// DeleteOSPFNetwork removes the OSPF network at index i.
func (c *Client) DeleteOSPFNetwork(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/ospf/net/%d/delete", i), nil)
}

// SetBGP toggles BGP and sets the local ASN + router-id.
func (c *Client) SetBGP(enabled bool, asn int, routerID string) error {
	return c.apiPostJSON("/api/v1/routing/bgp", map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID})
}

// AddBGPNeighbor adds a BGP peer.
func (c *Client) AddBGPNeighbor(nb BGPNeighbor) error {
	return c.apiPostJSON("/api/v1/routing/bgp/neighbor", nb)
}

// DeleteBGPNeighbor removes the BGP neighbor at index i.
func (c *Client) DeleteBGPNeighbor(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/bgp/neighbor/%d/delete", i), nil)
}

// AddBGPNetwork advertises a CIDR via BGP.
func (c *Client) AddBGPNetwork(cidr string) error {
	return c.apiPostJSON("/api/v1/routing/bgp/network", map[string]any{"cidr": cidr})
}

// DeleteBGPNetwork removes the advertised BGP network at index i.
func (c *Client) DeleteBGPNetwork(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/bgp/network/%d/delete", i), nil)
}

// SetEIGRP toggles EIGRP and sets the AS number (1-65535) + router-id.
func (c *Client) SetEIGRP(enabled bool, asn int, routerID string) error {
	return c.apiPostJSON("/api/v1/routing/eigrp", map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID})
}

// AddEIGRPNetwork runs EIGRP on / advertises a CIDR.
func (c *Client) AddEIGRPNetwork(cidr string) error {
	return c.apiPostJSON("/api/v1/routing/eigrp/network", map[string]any{"cidr": cidr})
}

// DeleteEIGRPNetwork removes the EIGRP network at index i.
func (c *Client) DeleteEIGRPNetwork(i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/routing/eigrp/network/%d/delete", i), nil)
}
