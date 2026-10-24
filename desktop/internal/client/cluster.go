package client

import "fmt"

// This file adds the cluster node-administration client calls: list nodes, add a
// node, probe a node, and remove a node. Thin wrappers over the CSRF-exempt REST
// API, reusing the cookie-authed helpers in client.go.
//
// Node mirrors cluster.Node, which the server serializes with NO json tags, so
// it decodes from the Go field names verbatim (PascalCase).

// Node mirrors cluster.Node (PascalCase, no server json tags).
type Node struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	Address   string `json:"Address"`
	SSHUser   string `json:"SSHUser"`
	Role      string `json:"Role"`   // local | peer | ...
	Status    string `json:"Status"` // reachability/health
	CPUs      int    `json:"CPUs"`
	MemTotal  int64  `json:"MemTotal"`
	MemFree   int64  `json:"MemFree"`
	LastSeen  string `json:"LastSeen"`
	CreatedAt string `json:"CreatedAt"`
}

// Nodes lists the cluster's nodes (empty when clustering is off).
func (c *Client) Nodes() ([]Node, error) {
	var out []Node
	if err := c.getJSON("/api/v1/cluster/nodes", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddNode registers a peer node by name/address/ssh user (admin only).
func (c *Client) AddNode(name, address, sshUser string) error {
	return c.apiPostJSON("/api/v1/cluster/nodes", map[string]any{
		"name": name, "address": address, "ssh_user": sshUser,
	})
}

// ProbeNode re-probes a node's reachability/capacity (admin only).
func (c *Client) ProbeNode(id int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/cluster/nodes/%d/probe", id))
}

// DeleteNode removes a node from the cluster (admin only).
func (c *Client) DeleteNode(id int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/cluster/nodes/%d/delete", id))
}
