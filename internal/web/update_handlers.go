package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// updatePage renders the admin Update page: current version + a manual
// "Check for updates" action (the only thing that contacts GitHub) and, after a
// check, the latest version/notes + an Apply & Restart action.
func (s *Server) updatePage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, p, "update.html", "update", map[string]any{
		"Current": service.BuildVersion(),
		"Channel": s.svc.UpdateChannel(),
	})
}

// updateChannel persists the release channel (stable | preview).
func (s *Server) updateChannel(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.SetUpdateChannel(p, r.FormValue("channel"), clientIP(r)); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// updateCheck performs the manual, admin-initiated update check (AJAX JSON).
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	st, err := s.svc.CheckForUpdate(p, clientIP(r))
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, st)
}

// updateApply downloads + verifies + swaps the vdxd binary, refreshes the client
// binaries, and schedules a restart. Returns JSON; the page then polls until the
// new version answers.
func (s *Server) updateApply(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	ver, err := s.svc.ApplyServerUpdate(p, clientIP(r))
	if err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "version": ver})
}
