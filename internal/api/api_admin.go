package api

import (
	"encoding/json"
	"net/http"

	"vdxclone/internal/service"
)

// This file holds the admin / self-update JSON endpoints: update status/check/
// apply/channel and the host power ops. Each is a thin wrapper over an existing
// service method; all authz + audit live in the service layer.
//
// registerAdminRoutes wires these onto a mux. api.go's Routes does not call it;
// the parent wires it in later.
func (a *API) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/update/status", a.auth("read", a.updateStatus))
	mux.HandleFunc("POST /api/v1/update/check", a.auth("write", a.updateCheck))
	mux.HandleFunc("POST /api/v1/update/apply", a.auth("write", a.updateApply))
	mux.HandleFunc("POST /api/v1/update/channel", a.auth("write", a.updateChannel))
	mux.HandleFunc("POST /api/v1/host/restart", a.auth("write", a.hostRestart))
	mux.HandleFunc("POST /api/v1/host/shutdown", a.auth("write", a.hostShutdown))
}

// updateStatus reports the running version + configured release channel WITHOUT
// contacting GitHub. Use POST /update/check for the (admin-only) remote check.
func (a *API) updateStatus(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, 200, map[string]any{
		"current": service.BuildVersion(),
		"channel": a.svc.UpdateChannel(),
	})
}

// updateCheck performs the manual, admin-initiated remote update check. This is
// the only call that reaches out to GitHub; admin-only is enforced in service.
func (a *API) updateCheck(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	st, err := a.svc.CheckForUpdate(p, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

// updateApply downloads + verifies + swaps the vdxd binary and schedules a
// restart. Returns the version being applied. Admin-only (enforced in service).
func (a *API) updateApply(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	ver, err := a.svc.ApplyServerUpdate(p, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "version": ver})
}

// updateChannel sets the release channel ("stable" | "preview"). Admin-only.
func (a *API) updateChannel(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Channel string `json:"channel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.SetUpdateChannel(p, body.Channel, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "channel": body.Channel})
}

// hostRestart reboots the physical host (admin-only, enforced in service). The
// reboot fires after the response flushes.
func (a *API) hostRestart(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.HostRestart(p, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// hostShutdown powers off the physical host (admin-only, enforced in service).
func (a *API) hostShutdown(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.HostShutdown(p, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
