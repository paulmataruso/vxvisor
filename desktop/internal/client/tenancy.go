package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// This file adds the tenancy client calls: org members, API keys, orgs, the
// audit log, and per-org quotas. Each is a thin wrapper over the CSRF-exempt
// REST API, reusing the cookie-authed helpers in client.go.
//
// The server serializes store structs with NO json tags, so those decode from
// the Go field names verbatim (PascalCase). Quota likewise has no json tags.

// Member mirrors store.Member (PascalCase, no server json tags).
type Member struct {
	OrgID    int64  `json:"OrgID"`
	UserID   int64  `json:"UserID"`
	Role     string `json:"Role"`
	Username string `json:"Username"`
}

// APIKey mirrors store.APIKey. The secret is NOT included (only on create).
type APIKey struct {
	ID        int64  `json:"ID"`
	OrgID     int64  `json:"OrgID"`
	Prefix    string `json:"Prefix"`
	Label     string `json:"Label"`
	CreatedAt string `json:"CreatedAt"`
	LastUsed  string `json:"LastUsed"`
	Revoked   bool   `json:"Revoked"`
}

// CreatedAPIKey is the one-time response of CreateAPIKey. Key is the plaintext
// secret, shown only here and never retrievable again.
type CreatedAPIKey struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Readonly bool   `json:"readonly"`
}

// Org mirrors store.Org.
type Org struct {
	ID        int64  `json:"ID"`
	Name      string `json:"Name"`
	Slug      string `json:"Slug"`
	CreatedAt string `json:"CreatedAt"`
}

// AuditEntry mirrors store.AuditEntry (newest first from the server).
type AuditEntry struct {
	ID         int64  `json:"ID"`
	OrgID      int64  `json:"OrgID"`
	ActorID    int64  `json:"ActorID"`
	ActorKind  string `json:"ActorKind"`
	ActorName  string `json:"ActorName"`
	Action     string `json:"Action"`
	TargetType string `json:"TargetType"`
	TargetID   string `json:"TargetID"`
	Detail     string `json:"Detail"`
	IP         string `json:"IP"`
	CreatedAt  string `json:"CreatedAt"`
}

// Quota mirrors service.Quota (PascalCase, no server json tags). A 0 field means
// unlimited.
type Quota struct {
	OrgID       int64 `json:"OrgID"`
	PlanID      int64 `json:"PlanID"`
	MaxServers  int   `json:"MaxServers"`
	MaxRunning  int   `json:"MaxRunning"`
	MaxVCPUs    int   `json:"MaxVCPUs"`
	MaxMemoryMB int   `json:"MaxMemoryMB"`
	MaxDiskGB   int   `json:"MaxDiskGB"`
}

// Members lists the current org's members.
func (c *Client) Members() ([]Member, error) {
	var out []Member
	if err := c.getJSON("/api/v1/members", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddMember adds an EXISTING user to the org with a role (owner/admin/member/
// viewer). It does not create an account or set a password.
func (c *Client) AddMember(username, role string) error {
	return c.apiPostJSON("/api/v1/members/add", map[string]any{"username": username, "role": role})
}

// RemoveMember drops a user from the org by user id.
func (c *Client) RemoveMember(uid int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/members/%d/remove", uid))
}

// ResetMemberPassword sets a user's password without the current one (admin).
func (c *Client) ResetMemberPassword(uid int64, password string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/members/%d/password", uid), map[string]any{"password": password})
}

// APIKeys lists the org's API keys (metadata only — never the secret).
func (c *Client) APIKeys() ([]APIKey, error) {
	var out []APIKey
	if err := c.getJSON("/api/v1/apikeys", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateAPIKey mints a new key and returns the plaintext secret ONCE.
func (c *Client) CreateAPIKey(label string, readonly bool) (CreatedAPIKey, error) {
	var out CreatedAPIKey
	err := c.apiPostDecode("/api/v1/apikeys", map[string]any{"label": label, "readonly": readonly}, &out)
	return out, err
}

// RevokeAPIKey disables an API key by id.
func (c *Client) RevokeAPIKey(id int64) error {
	return c.apiPost(fmt.Sprintf("/api/v1/apikeys/%d/revoke", id))
}

// Orgs lists the orgs the authenticated principal belongs to.
func (c *Client) Orgs() ([]Org, error) {
	var out []Org
	if err := c.getJSON("/api/v1/orgs", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateOrg creates a new org (instance-admin only) and returns its id.
func (c *Client) CreateOrg(name, slug string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := c.apiPostDecode("/api/v1/orgs", map[string]any{"name": name, "slug": slug}, &out)
	return out.ID, err
}

// Audit lists the org's audit log (newest first). limit <= 0 returns the server
// default (up to 200).
func (c *Client) Audit(limit int) ([]AuditEntry, error) {
	path := "/api/v1/audit"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out []AuditEntry
	if err := c.getJSON(path, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AuditFiltered is Audit with a server-side action-prefix filter (e.g. "session").
func (c *Client) AuditFiltered(action string, limit int) ([]AuditEntry, error) {
	q := url.Values{}
	if action != "" {
		q.Set("action", action)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/api/v1/audit"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out []AuditEntry
	if err := c.getJSON(path, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Quota returns the current org's quota.
func (c *Client) Quota() (Quota, error) {
	var out Quota
	err := c.getJSON("/api/v1/quota", &out)
	return out, err
}

// SetQuota sets the current org's quota (instance-admin only). OrgID is ignored;
// the server applies it to the principal's current org.
func (c *Client) SetQuota(q Quota) error {
	return c.apiPostJSON("/api/v1/quota", map[string]any{
		"max_servers":   q.MaxServers,
		"max_running":   q.MaxRunning,
		"max_vcpus":     q.MaxVCPUs,
		"max_memory_mb": q.MaxMemoryMB,
		"max_disk_gb":   q.MaxDiskGB,
	})
}

// apiPostDecode POSTs a JSON body (nil = no body) and decodes the JSON response
// into out (nil out = ignore the body), reporting a server error message if one
// comes back. Shared by the tenancy and admin client calls.
func (c *Client) apiPostDecode(path string, body, out any) error {
	var r io.Reader
	req, _ := http.NewRequest(http.MethodPost, c.base.String()+path, nil)
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
		req, _ = http.NewRequest(http.MethodPost, c.base.String()+path, r)
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(rb, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(rb, out)
}
