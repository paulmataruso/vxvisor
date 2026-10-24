package client

import (
	"fmt"
	"net/url"
)

// This file adds the Phase-1 library/lifecycle client calls: the Trash
// (soft-deleted VMs), VM templates, and installer ISOs. Thin wrappers over the
// CSRF-exempt REST API, reusing the helpers in client.go.

// Template mirrors storage.Template (PascalCase keys; we decode the fields a
// management UI shows).
type Template struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	ImageName string `json:"ImageName"`
	Kind      string `json:"Kind"`
	Firmware  string `json:"Firmware"`
	CPUs      int    `json:"CPUs"`
	MemoryMB  int    `json:"MemoryMB"`
	DiskGB    int    `json:"DiskGB"`
	CloudInit bool   `json:"CloudInit"`
	CreatedAt string `json:"CreatedAt"`
}

// ISO mirrors storage.ISO (PascalCase keys).
type ISO struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	SizeBytes int64  `json:"SizeBytes"`
	Status    string `json:"Status"`
	SourceURL string `json:"SourceURL"`
	CreatedAt string `json:"CreatedAt"`
}

// Trash lists the org's soft-deleted instances (reusing the Session shape).
func (c *Client) Trash() ([]Session, error) {
	var out []Session
	if err := c.getJSON("/api/v1/trash", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RestoreSession brings a trashed instance back (server enforces admin).
func (c *Client) RestoreSession(id string) error {
	return c.apiPost("/api/v1/trash/" + url.PathEscape(id) + "/restore")
}

// PurgeSession permanently deletes a trashed instance (server enforces admin).
func (c *Client) PurgeSession(id string) error {
	return c.apiPost("/api/v1/trash/" + url.PathEscape(id) + "/purge")
}

// Templates lists the org's VM templates.
func (c *Client) Templates() ([]Template, error) {
	var out []Template
	if err := c.getJSON("/api/v1/templates", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// LaunchTemplate creates a new instance from a template. The server returns the
// new instance id; refresh Sessions() to pick it up.
func (c *Client) LaunchTemplate(id int64, name string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/templates/%d/launch", id), map[string]any{"name": name})
}

// DeleteTemplate removes a template (server enforces admin).
func (c *Client) DeleteTemplate(id int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/templates/%d/delete", id))
}

// ISOs lists the org's (and global) installer ISOs.
func (c *Client) ISOs() ([]ISO, error) {
	var out []ISO
	if err := c.getJSON("/api/v1/isos", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PullISO starts an async download of an ISO from a URL. Poll ISOs() for the
// row's Status to flip to "ready".
func (c *Client) PullISO(name, isoURL string) error {
	return c.apiPostJSON("/api/v1/isos/pull", map[string]any{"name": name, "url": isoURL})
}

// DeleteISO removes an ISO (server enforces admin).
func (c *Client) DeleteISO(id int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/isos/%d/delete", id))
}
