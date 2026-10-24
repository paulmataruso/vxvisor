package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

// This file holds the Phase-1 library/lifecycle JSON endpoints: the Trash
// (soft-deleted instances), VM templates, and installer ISOs. Thin wrappers
// over existing service methods; all authz + audit live in the service layer,
// so these only decode the body, call through, and map the error.

// ---- trash ---------------------------------------------------------------

// listTrash returns the org's soft-deleted instances ([]*session.Session).
func (a *API) listTrash(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListTrash(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

// restoreSession brings a trashed instance back (service enforces admin).
func (a *API) restoreSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.RestoreSession(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// purgeSession permanently deletes a trashed instance (service enforces admin).
func (a *API) purgeSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.PurgeSession(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- templates -----------------------------------------------------------

func (a *API) listTemplates(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListTemplates(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

// launchTemplate creates a new instance from a saved template and returns its
// new session id.
func (a *API) launchTemplate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	newID, err := a.svc.LaunchFromTemplate(p, id, body.Name, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": newID})
}

// deleteTemplate removes a template (service enforces admin).
func (a *API) deleteTemplate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteTemplate(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- ISOs -----------------------------------------------------------------

func (a *API) listISOs(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListISOs(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

// pullISO starts an async download of an ISO from a URL and returns the new row
// id (poll GET /api/v1/isos for the status to flip to "ready").
func (a *API) pullISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.PullISO(p, body.Name, body.URL, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

// deleteISO removes an ISO (service enforces admin).
func (a *API) deleteISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteISO(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
