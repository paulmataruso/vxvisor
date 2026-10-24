package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

// This file holds the tenancy JSON endpoints: org members, API keys, orgs,
// the audit log, and per-org quotas. Each is a thin wrapper over an existing
// service method — all authz + audit live in the service layer, so these only
// decode the body, call through, and map the error (writeErr maps
// ErrUnauthorized→403, ErrNotFound→404).
//
// registerTenancyRoutes wires these onto a mux. api.go's Routes does not call
// it; the parent wires it in later.
func (a *API) registerTenancyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/members", a.auth("read", a.listMembers))
	mux.HandleFunc("POST /api/v1/members/add", a.auth("write", a.addMember))
	mux.HandleFunc("POST /api/v1/members/{uid}/remove", a.auth("write", a.removeMember))
	mux.HandleFunc("POST /api/v1/members/{uid}/password", a.auth("write", a.resetMemberPassword))
	mux.HandleFunc("GET /api/v1/apikeys", a.auth("read", a.listAPIKeys))
	mux.HandleFunc("POST /api/v1/apikeys", a.auth("write", a.createAPIKey))
	mux.HandleFunc("POST /api/v1/apikeys/{id}/revoke", a.auth("write", a.revokeAPIKey))
	mux.HandleFunc("GET /api/v1/orgs", a.auth("read", a.listOrgs))
	mux.HandleFunc("POST /api/v1/orgs", a.auth("write", a.createOrg))
	mux.HandleFunc("GET /api/v1/audit", a.auth("read", a.listAudit))
	mux.HandleFunc("GET /api/v1/quota", a.auth("read", a.getQuota))
	mux.HandleFunc("POST /api/v1/quota", a.auth("write", a.setQuota))
}

// listMembers returns the members of the principal's current org.
func (a *API) listMembers(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	m, err := a.svc.ListMembers(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, m)
}

// addMember adds an EXISTING user to the org with a role. (The service resolves
// the user by name; it does not create an account or set a password here.)
func (a *API) addMember(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AddMember(p, body.Username, body.Role, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// removeMember drops a user from the org by user id.
func (a *API) removeMember(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	uid, _ := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	if err := a.svc.RemoveMember(p, uid, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// resetMemberPassword sets a user's password without the current one (admin).
func (a *API) resetMemberPassword(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	uid, _ := strconv.ParseInt(r.PathValue("uid"), 10, 64)
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AdminResetPassword(p, uid, body.Password, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// listAPIKeys returns the org's API keys (metadata only — never the secret).
func (a *API) listAPIKeys(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	keys, err := a.svc.ListAPIKeys(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, keys)
}

// createAPIKey mints a new key and returns the plaintext secret ONCE. The secret
// is shown only in this response and is never retrievable again.
func (a *API) createAPIKey(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Label    string `json:"label"`
		Readonly bool   `json:"readonly"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	plaintext, err := a.svc.CreateAPIKey(p, body.Label, body.Readonly, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"key": plaintext, "label": body.Label, "readonly": body.Readonly})
}

// revokeAPIKey disables an API key by id.
func (a *API) revokeAPIKey(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.RevokeAPIKey(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// listOrgs returns the orgs the principal belongs to (already resolved on the
// principal at auth time).
func (a *API) listOrgs(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, 200, p.Orgs)
}

// createOrg creates a new org (instance-admin only) and returns its id.
func (a *API) createOrg(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.CreateOrg(p, body.Name, body.Slug, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

// listAudit returns the org's audit log (newest first). Optional ?action= is a
// server-side action-prefix filter; optional ?limit= caps the returned count
// (the service already caps at 200).
func (a *API) listAudit(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	entries, err := a.svc.ListAuditFiltered(p, r.URL.Query().Get("action"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n < len(entries) {
		entries = entries[:n]
	}
	writeJSON(w, 200, entries)
}

// getQuota returns the current org's quota (0 = unlimited for a field).
func (a *API) getQuota(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, 200, a.svc.GetQuota(p.OrgID))
}

// setQuota sets the current org's quota (instance-admin only). OrgID is forced
// to the principal's current org, matching the web Billing page.
func (a *API) setQuota(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		MaxServers  int `json:"max_servers"`
		MaxRunning  int `json:"max_running"`
		MaxVCPUs    int `json:"max_vcpus"`
		MaxMemoryMB int `json:"max_memory_mb"`
		MaxDiskGB   int `json:"max_disk_gb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	q := service.Quota{
		OrgID:       p.OrgID,
		MaxServers:  body.MaxServers,
		MaxRunning:  body.MaxRunning,
		MaxVCPUs:    body.MaxVCPUs,
		MaxMemoryMB: body.MaxMemoryMB,
		MaxDiskGB:   body.MaxDiskGB,
	}
	if err := a.svc.SetQuota(p, q, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
