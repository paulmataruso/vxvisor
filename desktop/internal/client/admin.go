package client

// This file adds the admin / self-update client calls: update status/check/
// apply/channel and the host power ops. Thin wrappers over the CSRF-exempt REST
// API, reusing the cookie-authed helpers in client.go / tenancy.go.
//
// UpdateStatus/UpdateAsset mirror service.UpdateStatus, which DOES carry
// snake_case json tags, so these decode snake_case (unlike the PascalCase store
// structs in tenancy.go).

// UpdateAsset is a downloadable file from the latest release.
type UpdateAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// UpdateStatus mirrors service.UpdateStatus. GET /update/status fills only
// Current + Channel (no GitHub call); POST /update/check fills the rest.
type UpdateStatus struct {
	Current     string        `json:"current"`
	Latest      string        `json:"latest"`
	UpToDate    bool          `json:"up_to_date"`
	Notes       string        `json:"notes"`
	PublishedAt string        `json:"published_at"`
	Source      string        `json:"source"`
	Channel     string        `json:"channel"`
	Assets      []UpdateAsset `json:"assets"`
}

// UpdateStatusInfo returns the running version + channel WITHOUT contacting
// GitHub (GET /update/status). Only Current and Channel are populated.
func (c *Client) UpdateStatusInfo() (UpdateStatus, error) {
	var out UpdateStatus
	err := c.getJSON("/api/v1/update/status", &out)
	return out, err
}

// CheckUpdate performs the manual, admin-initiated remote update check — the one
// call that reaches out to GitHub (POST /update/check).
func (c *Client) CheckUpdate() (UpdateStatus, error) {
	var out UpdateStatus
	err := c.apiPostDecode("/api/v1/update/check", nil, &out)
	return out, err
}

// ApplyUpdate downloads + verifies + swaps the vdxd binary and schedules a
// restart. Returns the version being applied (POST /update/apply).
func (c *Client) ApplyUpdate() (string, error) {
	var out struct {
		Version string `json:"version"`
	}
	err := c.apiPostDecode("/api/v1/update/apply", nil, &out)
	return out.Version, err
}

// SetUpdateChannel sets the release channel ("stable" | "preview").
func (c *Client) SetUpdateChannel(channel string) error {
	return c.apiPostJSON("/api/v1/update/channel", map[string]any{"channel": channel})
}

// HostRestart reboots the physical host (admin-only, enforced server-side).
func (c *Client) HostRestart() error {
	return c.apiPost("/api/v1/host/restart")
}

// HostShutdown powers off the physical host (admin-only, enforced server-side).
func (c *Client) HostShutdown() error {
	return c.apiPost("/api/v1/host/shutdown")
}
