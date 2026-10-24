package client

import (
	"fmt"
	"net/url"
)

// This file adds the Phase-1 VM lifecycle client calls: power (restart),
// autostart, hardware spec, NIC rebind, snapshots, and the installer-CD
// controls. Each is a thin wrapper over the CSRF-exempt REST API, reusing the
// cookie-authed helpers in client.go.

// Snapshot mirrors storage.Snapshot. The server serializes with no json tags,
// so keys are the Go field names verbatim (PascalCase).
type Snapshot struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	Tag       string `json:"Tag"`
	Online    bool   `json:"Online"`
	CreatedAt string `json:"CreatedAt"`
}

// HardwareSpec is the POST /spec body: launch-time QEMU choices for a stopped
// VM. Applied on the next start; never touches the data disk. (CPU/memory/disk
// sizing is a separate call — see Resize on the REST /resize endpoint.)
type HardwareSpec struct {
	Firmware    string `json:"firmware"`
	OSType      string `json:"os_type"`
	MachineType string `json:"machine_type"`
	DiskBus     string `json:"disk_bus"`
	NICModel    string `json:"nic_model"`
	VGA         string `json:"vga"`
	GuestAgent  bool   `json:"guest_agent"`
	TPM         bool   `json:"tpm"`
	SecureBoot  bool   `json:"secure_boot"`
	PinCPUs     bool   `json:"perf_pin"`
	HugePages   bool   `json:"perf_hugepages"`
}

// RestartSession power-cycles a VM via the REST API (graceful stop then a fresh
// start). Distinct from Restart, which uses the cookie-authed UI endpoint.
func (c *Client) RestartSession(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/restart")
}

// SetAutostart toggles a VM's "start at boot" flag.
func (c *Client) SetAutostart(id string, on bool) error {
	return c.apiPostJSON("/api/v1/sessions/"+url.PathEscape(id)+"/autostart", map[string]any{"on": on})
}

// UpdateSpec changes a stopped VM's hardware profile (firmware, bus, NIC, VGA,
// agent/TPM/Secure Boot, perf toggles). Applied on the next start.
func (c *Client) UpdateSpec(id string, hw HardwareSpec) error {
	return c.apiPostJSON("/api/v1/sessions/"+url.PathEscape(id)+"/spec", hw)
}

// SetNetwork rebinds a VM's NIC to a port group (0 = default/NAT).
func (c *Client) SetNetwork(id string, network int64) error {
	return c.apiPostJSON("/api/v1/sessions/"+url.PathEscape(id)+"/network", map[string]any{"network": network})
}

// Snapshots lists a VM's snapshots (newest first).
func (c *Client) Snapshots(id string) ([]Snapshot, error) {
	var out []Snapshot
	if err := c.getJSON("/api/v1/sessions/"+url.PathEscape(id)+"/snapshots", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateSnapshot takes a new named snapshot of a VM.
func (c *Client) CreateSnapshot(id, name string) error {
	return c.apiPostJSON("/api/v1/sessions/"+url.PathEscape(id)+"/snapshots", map[string]any{"name": name})
}

// RevertSnapshot rolls a VM back to a snapshot.
func (c *Client) RevertSnapshot(id string, snapID int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/sessions/%s/snapshots/%d/revert", url.PathEscape(id), snapID))
}

// DeleteSnapshot removes a snapshot.
func (c *Client) DeleteSnapshot(id string, snapID int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/sessions/%s/snapshots/%d/delete", url.PathEscape(id), snapID))
}

// EjectISO detaches the boot/installer ISO so the VM boots its disk (next start).
func (c *Client) EjectISO(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/eject-iso")
}

// MountVirtio (re)enables auto-attaching the virtio-win driver CD (next start).
func (c *Client) MountVirtio(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/mount-virtio")
}

// EjectVirtio stops auto-attaching the virtio-win driver CD (next start).
func (c *Client) EjectVirtio(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/eject-virtio")
}
