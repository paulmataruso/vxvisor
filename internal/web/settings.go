package web

import (
	"net/http"
	"net/url"

	"vdxclone/internal/config"
	"vdxclone/internal/service"
)

// ---- Settings → Authentication (Active Directory / LDAP) -----------------

// settingsAuth renders the AD/LDAP authentication settings page. Admin only.
// The bind password is never echoed back to the browser; a "set" flag tells the
// template to show a placeholder instead.
func (s *Server) settingsAuth(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	c := s.svc.ADConfig()
	s.render(w, p, "settings_auth.html", "settings", map[string]any{
		"AD":        c,
		"HasBindPW": c.BindPassword != "",
		"FromDB":    s.svc.ADConfigStored(),
		"Ok":        r.URL.Query().Get("ok") == "1",
		"Err":       r.URL.Query().Get("error"),
	})
}

// adFormConfig reads the AD settings form into a config.ADConfig. The bind
// password is left blank when the field is empty (meaning "keep existing").
func adFormConfig(r *http.Request) config.ADConfig {
	return config.ADConfig{
		Enabled:      r.FormValue("enabled") == "on",
		URL:          r.FormValue("url"),
		Domain:       r.FormValue("domain"),
		StartTLS:     r.FormValue("starttls") == "on",
		Insecure:     r.FormValue("insecure") == "on",
		BindDN:       r.FormValue("bind_dn"),
		BindPassword: r.FormValue("bind_password"),
		BaseDN:       r.FormValue("base_dn"),
		UserFilter:   r.FormValue("user_filter"),
		AdminGroup:   r.FormValue("admin_group"),
	}
}

// saveAuthSettings persists AD settings and pushes them to the live provider so
// they take effect immediately (no restart).
func (s *Server) saveAuthSettings(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	// SaveADConfig fires the registered reload hook (srv.ad.SetConfig) on success,
	// so the live provider is updated without an explicit call here.
	if _, err := s.svc.SaveADConfig(p, adFormConfig(r), clientIP(r)); err != nil {
		http.Redirect(w, r, "/settings/auth?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/auth?ok=1", http.StatusSeeOther)
}

// testAuthSettings validates the posted config against the directory without
// saving. Returns JSON {ok, message} for the inline "Test connection" button.
func (s *Server) testAuthSettings(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	msg, err := s.svc.TestADConfig(p, adFormConfig(r))
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg})
}
