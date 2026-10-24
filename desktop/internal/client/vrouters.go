package client

import "fmt"

// NSX-lite per-tenant vRouter client surface (FRR in LXC/netns). Mirrors the
// server's /api/v1/vrouters endpoints: GETs return service.VRouterView (the
// embedded vrouter.VRouter has no json tags → PascalCase keys, while the nested
// routing config carries snake_case json tags). POST bodies are snake_case.
//
// Types here are deliberately vRouter-prefixed (VRLeg, VRStaticRoute, …) so they
// never collide with a sibling routing.go in this package.

// VRouter is the core of a vRouter row (service.VRouterView's embedded
// vrouter.VRouter, flattened — no json tags server-side → PascalCase). LiveState
// and RouteTable come from the live backend status the view carries.
type VRouter struct {
	ID            int64  `json:"ID"`
	OrgID         int64  `json:"OrgID"`
	OwnerID       int64  `json:"OwnerID"`
	Name          string `json:"Name"`
	Runtime       string `json:"Runtime"`
	ContainerName string `json:"ContainerName"`
	NetnsName     string `json:"NetnsName"`
	VMSessionID   string `json:"VMSessionID"`
	Image         string `json:"Image"`
	Dist          string `json:"Dist"`
	Release       string `json:"Release"`
	CPUs          int    `json:"CPUs"`
	MemMB         int    `json:"MemMB"`
	Status        string `json:"Status"`
	Error         string `json:"Error"`
	LiveState     string `json:"LiveState"`
	RouteTable    string `json:"RouteTable"`
}

// VRouterView is the full view returned by both the list and get endpoints: the
// vRouter plus its legs and parsed routing config.
type VRouterView struct {
	VRouter
	Legs []VRLeg         `json:"Legs"`
	Cfg  VRRoutingConfig `json:"Cfg"`
}

// VRLeg mirrors vrouter.Leg (PascalCase; no json tags server-side). Idx 0 is the
// transit leg (eth0); idx 1.. are internal legs.
type VRLeg struct {
	ID          int64  `json:"ID"`
	VRouterID   int64  `json:"VRouterID"`
	Idx         int    `json:"Idx"`
	Kind        string `json:"Kind"` // transit | internal
	Bridge      string `json:"Bridge"`
	PhysIface   string `json:"PhysIface"`
	NetworkID   int64  `json:"NetworkID"`
	IfaceName   string `json:"IfaceName"`
	CIDR        string `json:"CIDR"`
	MAC         string `json:"MAC"`
	DHCP        bool   `json:"DHCP"`
	DHCPRange   string `json:"DHCPRange"`
	DHCPDNS     string `json:"DHCPDNS"`
	NetworkName string `json:"NetworkName"`
	NetworkCIDR string `json:"NetworkCIDR"`
}

// VRRoutingConfig is the vRouter's parsed FRR config (routing.Config, snake_case
// json tags). Only the fields the vRouter endpoints manage are surfaced.
type VRRoutingConfig struct {
	Hostname   string          `json:"hostname"`
	Prefixes   []VRIfPrefix    `json:"prefixes"`
	Static     []VRStaticRoute `json:"static"`
	OSPF       VROSPF          `json:"ospf"`
	BGP        VRBGP           `json:"bgp"`
	EIGRP      VREIGRP         `json:"eigrp"`
	FRRVersion string          `json:"frr_version,omitempty"`
}

// VRIfPrefix is an interface IP assignment (zebra-managed).
type VRIfPrefix struct {
	Iface string `json:"iface"`
	CIDR  string `json:"cidr"`
}

// VRStaticRoute is a static route.
type VRStaticRoute struct {
	Dest    string `json:"dest"`
	NextHop string `json:"next_hop"`
}

// VROSPFNet attaches a network to an OSPF area.
type VROSPFNet struct {
	CIDR string `json:"cidr"`
	Area string `json:"area"`
}

// VROSPF is the OSPFv2 config.
type VROSPF struct {
	Enabled  bool        `json:"enabled"`
	RouterID string      `json:"router_id"`
	Networks []VROSPFNet `json:"networks"`
}

// VRNeighbor is a BGP peer.
type VRNeighbor struct {
	Addr        string `json:"addr"`
	RemoteAS    int    `json:"remote_as"`
	RouteMapIn  string `json:"route_map_in"`
	RouteMapOut string `json:"route_map_out"`
}

// VRBGP is the BGP config.
type VRBGP struct {
	Enabled   bool         `json:"enabled"`
	ASN       int          `json:"asn"`
	RouterID  string       `json:"router_id"`
	Neighbors []VRNeighbor `json:"neighbors"`
	Networks  []string     `json:"networks"`
}

// VREIGRP is the EIGRP config.
type VREIGRP struct {
	Enabled  bool     `json:"enabled"`
	ASN      int      `json:"asn"`
	RouterID string   `json:"router_id"`
	Networks []string `json:"networks"`
}

// VRouterInput is the create body (POST /api/v1/vrouters, snake_case).
type VRouterInput struct {
	Name    string `json:"name"`
	Runtime string `json:"runtime"` // lxc | netns
	CPUs    int    `json:"cpus"`
	MemMB   int    `json:"mem_mb"`
	Dist    string `json:"dist,omitempty"`
	Release string `json:"release,omitempty"`
}

// ---- list / get / create -------------------------------------------------

// VRouters lists the org's vRouters (each with legs + parsed config + live state).
func (c *Client) VRouters() ([]VRouterView, error) {
	var out []VRouterView
	err := c.getJSON("/api/v1/vrouters", &out)
	return out, err
}

// VRouter fetches one vRouter's full view.
func (c *Client) VRouter(id int64) (*VRouterView, error) {
	var out VRouterView
	if err := c.getJSON(fmt.Sprintf("/api/v1/vrouters/%d", id), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateVRouter provisions a new vRouter and returns its id.
func (c *Client) CreateVRouter(in VRouterInput) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := c.apiPostDecode("/api/v1/vrouters", in, &out)
	return out.ID, err
}

// ---- lifecycle -----------------------------------------------------------

func (c *Client) StartVRouter(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/start", id), nil)
}
func (c *Client) StopVRouter(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/stop", id), nil)
}
func (c *Client) DeleteVRouter(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/delete", id), nil)
}

// ---- transit link --------------------------------------------------------

// VRouterAddTransit binds a free physical NIC to the transit leg (eth0).
func (c *Client) VRouterAddTransit(id int64, iface, cidr string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/transit", id),
		map[string]any{"iface": iface, "cidr": cidr})
}

// VRouterUpdateTransit changes the transit leg's IP/CIDR.
func (c *Client) VRouterUpdateTransit(id int64, cidr string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/transit/update", id),
		map[string]any{"cidr": cidr})
}

// ---- internal port groups + DHCP -----------------------------------------

// VRouterAddInternal creates an internal port group served by the vRouter.
func (c *Client) VRouterAddInternal(id int64, name, cidr, gateway string, dhcp bool, dhcpRange, dns string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/internal", id),
		map[string]any{"name": name, "cidr": cidr, "gateway": gateway, "dhcp": dhcp, "dhcp_range": dhcpRange, "dns": dns})
}

// VRouterUpdateInternal edits an internal port group's name/subnet/gateway.
func (c *Client) VRouterUpdateInternal(id int64, idx int, name, cidr, gateway string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/internal/%d/update", id, idx),
		map[string]any{"name": name, "cidr": cidr, "gateway": gateway})
}

// VRouterSetInternalDHCP changes an internal port group's DHCP settings.
func (c *Client) VRouterSetInternalDHCP(id int64, idx int, dhcp bool, dhcpRange, dns string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/internal/%d/dhcp", id, idx),
		map[string]any{"dhcp": dhcp, "dhcp_range": dhcpRange, "dns": dns})
}

// ---- static routes -------------------------------------------------------

func (c *Client) VRouterAddStatic(id int64, dest, nextHop string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/static", id),
		map[string]any{"dest": dest, "next_hop": nextHop})
}
func (c *Client) VRouterUpdateStatic(id int64, i int, dest, nextHop string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/static/%d/update", id, i),
		map[string]any{"dest": dest, "next_hop": nextHop})
}
func (c *Client) VRouterDeleteStatic(id int64, i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/static/%d/delete", id, i), nil)
}

// ---- OSPF ----------------------------------------------------------------

func (c *Client) VRouterSetOSPF(id int64, enabled bool, routerID string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/ospf", id),
		map[string]any{"enabled": enabled, "router_id": routerID})
}
func (c *Client) VRouterAddOSPFNet(id int64, cidr, area string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/ospf/net", id),
		map[string]any{"cidr": cidr, "area": area})
}
func (c *Client) VRouterUpdateOSPFNet(id int64, i int, cidr, area string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/ospf/net/%d/update", id, i),
		map[string]any{"cidr": cidr, "area": area})
}
func (c *Client) VRouterDeleteOSPFNet(id int64, i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/ospf/net/%d/delete", id, i), nil)
}

// ---- BGP -----------------------------------------------------------------

func (c *Client) VRouterSetBGP(id int64, enabled bool, asn int, routerID string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp", id),
		map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID})
}
func (c *Client) VRouterAddBGPNeighbor(id int64, addr string, remoteAS int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp/neighbor", id),
		map[string]any{"addr": addr, "remote_as": remoteAS})
}
func (c *Client) VRouterUpdateBGPNeighbor(id int64, i int, addr string, remoteAS int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp/neighbor/%d/update", id, i),
		map[string]any{"addr": addr, "remote_as": remoteAS})
}
func (c *Client) VRouterDeleteBGPNeighbor(id int64, i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp/neighbor/%d/delete", id, i), nil)
}
func (c *Client) VRouterAddBGPNetwork(id int64, cidr string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp/network", id),
		map[string]any{"cidr": cidr})
}
func (c *Client) VRouterUpdateBGPNetwork(id int64, i int, cidr string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp/network/%d/update", id, i),
		map[string]any{"cidr": cidr})
}
func (c *Client) VRouterDeleteBGPNetwork(id int64, i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/bgp/network/%d/delete", id, i), nil)
}

// ---- EIGRP ---------------------------------------------------------------

func (c *Client) VRouterSetEIGRP(id int64, enabled bool, asn int, routerID string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/eigrp", id),
		map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID})
}
func (c *Client) VRouterAddEIGRPNet(id int64, cidr string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/eigrp/net", id),
		map[string]any{"cidr": cidr})
}
func (c *Client) VRouterDeleteEIGRPNet(id int64, i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/vrouters/%d/eigrp/net/%d/delete", id, i), nil)
}
