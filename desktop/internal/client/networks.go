package client

import (
	"fmt"
	"net/url"
)

// Networking resources (port-group networks, NIC bonds, vSwitches). The server
// entity structs have no json tags, so list results decode from PascalCase
// field names; create inputs are posted with the snake_case keys the server
// handlers decode.

// Network is one port-group / bridge / VLAN / VXLAN network.
type Network struct {
	ID         int64  `json:"ID"`
	Name       string `json:"Name"`
	Mode       string `json:"Mode"` // user | bridge | vxlan
	Bridge     string `json:"Bridge"`
	VLANID     int    `json:"VLANID"`
	CIDR       string `json:"CIDR"`
	Gateway    string `json:"Gateway"`
	VNI        int    `json:"VNI"`
	VXLANPeers string `json:"VXLANPeers"`
	CreatedAt  string `json:"CreatedAt"`
}

// CreateNetworkInput carries the fields the server's createNetwork handler reads.
type CreateNetworkInput struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	Bridge     string `json:"bridge"`
	VLANID     int    `json:"vlan_id"`
	CIDR       string `json:"cidr"`
	Gateway    string `json:"gateway"`
	PoolStart  string `json:"pool_start"`
	PoolEnd    string `json:"pool_end"`
	VNI        int    `json:"vni"`
	Underlay   string `json:"underlay"`
	VXLANLocal string `json:"vxlan_local"`
	VXLANPeers string `json:"vxlan_peers"`
	DstPort    int    `json:"vxlan_dstport"`
	MTU        int    `json:"vxlan_mtu"`
}

// Bond is a stored NIC team.
type Bond struct {
	ID        int64    `json:"ID"`
	Name      string   `json:"Name"`
	Mode      string   `json:"Mode"` // label, e.g. "lacp/layer3+4" or "balance-alb"
	Members   []string `json:"Members"`
	CreatedAt string   `json:"CreatedAt"`
}

// VSwitch is a stored VLAN-filtering bridge with an uplink.
type VSwitch struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	Bridge    string `json:"Bridge"`
	Uplink    string `json:"Uplink"`
	CreatedAt string `json:"CreatedAt"`
}

// Networks lists the org's port-group networks.
func (c *Client) Networks() ([]Network, error) {
	var out []Network
	if err := c.getJSON("/api/v1/networks", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateNetwork records a new network/port group.
func (c *Client) CreateNetwork(in CreateNetworkInput) error {
	return c.apiPostJSON("/api/v1/networks", in)
}

// DeleteNetwork removes a network by id.
func (c *Client) DeleteNetwork(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/networks/%d/delete", id), nil)
}

// Bonds lists NIC teams (admin only server-side).
func (c *Client) Bonds() ([]Bond, error) {
	var out []Bond
	if err := c.getJSON("/api/v1/bonds", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateBond builds a NIC team. hashPolicy applies only to the hashing modes.
func (c *Client) CreateBond(name, mode, hashPolicy string, members []string) error {
	return c.apiPostJSON("/api/v1/bonds", map[string]any{
		"name": name, "mode": mode, "hash_policy": hashPolicy, "members": members,
	})
}

// DeleteBond removes a bond by name.
func (c *Client) DeleteBond(name string) error {
	return c.apiPostJSON("/api/v1/bonds/"+url.PathEscape(name)+"/delete", nil)
}

// VSwitches lists vSwitches (admin only server-side).
func (c *Client) VSwitches() ([]VSwitch, error) {
	var out []VSwitch
	if err := c.getJSON("/api/v1/vswitches", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateVSwitch builds a vSwitch with the given uplink (a NIC or bond).
func (c *Client) CreateVSwitch(name, uplink string) error {
	return c.apiPostJSON("/api/v1/vswitches", map[string]any{"name": name, "uplink": uplink})
}

// DeleteVSwitch removes a vSwitch by name.
func (c *Client) DeleteVSwitch(name string) error {
	return c.apiPostJSON("/api/v1/vswitches/"+url.PathEscape(name)+"/delete", nil)
}
