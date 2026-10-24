package client

import "fmt"

// LXC containers. The server ContainerRow struct has no json tags, so results
// decode from PascalCase field names; create inputs post the snake_case keys the
// server's createContainer handler decodes.

// Container is one LXC system container (DB row + live lxc-info when running).
type Container struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	OrgID     int64  `json:"OrgID"`
	Dist      string `json:"Dist"`
	Release   string `json:"Release"`
	Arch      string `json:"Arch"`
	Bridge    string `json:"Bridge"`
	CPUs      int    `json:"CPUs"`
	MemoryMB  int    `json:"MemoryMB"`
	Status    string `json:"Status"` // creating | stopped | error (DB)
	CreatedAt string `json:"CreatedAt"`
	Storage   string `json:"Storage"`
	// Live fields (populated from lxc-info for non-creating containers).
	State    string `json:"State"` // RUNNING | STOPPED | ...
	PID      int    `json:"PID"`
	IP       string `json:"IP"`
	MemBytes int64  `json:"MemBytes"`
}

// CreateContainerInput carries the fields the server's createContainer handler
// reads. Copies > 1 provisions that many independently named containers.
type CreateContainerInput struct {
	Name          string `json:"name"`
	Dist          string `json:"dist"`
	Release       string `json:"release"`
	Bridge        string `json:"bridge"`
	CPUs          int    `json:"cpus"`
	MemoryMB      int    `json:"memory_mb"`
	StoragePoolID int64  `json:"storage_pool_id"`
	DiskGB        int    `json:"disk_gb"`
	Copies        int    `json:"copies"`
}

// Containers lists the org's LXC containers.
func (c *Client) Containers() ([]Container, error) {
	var out []Container
	if err := c.getJSON("/api/v1/containers", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateContainer provisions one or more containers asynchronously (poll
// Containers() for the status to move off "creating").
func (c *Client) CreateContainer(in CreateContainerInput) error {
	return c.apiPostJSON("/api/v1/containers", in)
}

// StartContainer boots a container.
func (c *Client) StartContainer(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/containers/%d/start", id), nil)
}

// StopContainer stops a container.
func (c *Client) StopContainer(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/containers/%d/stop", id), nil)
}

// DeleteContainer destroys a container and its row.
func (c *Client) DeleteContainer(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/containers/%d/delete", id), nil)
}

// SnapshotContainer takes a snapshot of a container.
func (c *Client) SnapshotContainer(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/containers/%d/snapshot", id), nil)
}
