package api

import (
	"encoding/json"
	"net/http"

	"vdxclone/internal/config"
	"vdxclone/internal/service"
)

// This file holds the Settings → Authentication (Active Directory / LDAP) JSON
// endpoints: read the current directory settings, save them, and test a bind.
// Each is a thin wrapper over an existing service method; SaveADConfig and
// TestADConfig are admin-gated + audited in the service layer, so these only
// decode the body, call through, and map the error.
//
// Only AD/LDAP is exposed here — the OIDC block has no service getter/setter
// (it is TOML-only config, not managed through the service), so there is no
// backing method to wrap for it.
//
// registerAuthSettingsRoutes wires these onto a mux. api.go's Routes does not
// call it; the parent wires it in later.
func (a *API) registerAuthSettingsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/settings/auth", a.auth("read", a.getAuthSettings))
	mux.HandleFunc("POST /api/v1/settings/auth", a.auth("write", a.saveAuthSettings))
	mux.HandleFunc("POST /api/v1/settings/auth/test", a.auth("write", a.testAuthSettings))
}

// authSettings is the GET response: the effective AD/LDAP config with the bind
// password REDACTED (never echoed) — HasBindPassword only reports whether one is
// set. No json tags → PascalCase, matching the store-struct convention.
type authSettings struct {
	Enabled         bool
	URL             string
	Domain          string
	StartTLS        bool
	Insecure        bool
	BindDN          string
	HasBindPassword bool
	BaseDN          string
	UserFilter      string
	AdminGroup      string
	Stored          bool // true = admin-saved in the DB (vs. TOML fallback)
}

// getAuthSettings returns the effective AD/LDAP settings (bind password redacted).
func (a *API) getAuthSettings(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	c := a.svc.ADConfig()
	writeJSON(w, 200, authSettings{
		Enabled:         c.Enabled,
		URL:             c.URL,
		Domain:          c.Domain,
		StartTLS:        c.StartTLS,
		Insecure:        c.Insecure,
		BindDN:          c.BindDN,
		HasBindPassword: c.BindPassword != "",
		BaseDN:          c.BaseDN,
		UserFilter:      c.UserFilter,
		AdminGroup:      c.AdminGroup,
		Stored:          a.svc.ADConfigStored(),
	})
}

// authSettingsBody is the POST body for save/test (snake_case). An empty
// bind_password means "keep the existing secret" (handled in the service).
type authSettingsBody struct {
	Enabled      bool   `json:"enabled"`
	URL          string `json:"url"`
	Domain       string `json:"domain"`
	StartTLS     bool   `json:"starttls"`
	Insecure     bool   `json:"insecure"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`
	AdminGroup   string `json:"admin_group"`
}

func (b authSettingsBody) toConfig() config.ADConfig {
	return config.ADConfig{
		Enabled:      b.Enabled,
		URL:          b.URL,
		Domain:       b.Domain,
		StartTLS:     b.StartTLS,
		Insecure:     b.Insecure,
		BindDN:       b.BindDN,
		BindPassword: b.BindPassword,
		BaseDN:       b.BaseDN,
		UserFilter:   b.UserFilter,
		AdminGroup:   b.AdminGroup,
	}
}

// saveAuthSettings persists AD/LDAP settings (admin only, enforced + audited in
// the service, which also pushes them to the live provider).
func (a *API) saveAuthSettings(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body authSettingsBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if _, err := a.svc.SaveADConfig(p, body.toConfig(), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// testAuthSettings validates a candidate config against the directory WITHOUT
// saving. Returns {ok,message}: a reachable+bindable directory → ok:true with a
// summary; a bind failure → ok:false with the reason (a 200, like the web "Test
// connection" button). Only the authz error maps to a non-200.
func (a *API) testAuthSettings(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body authSettingsBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	msg, err := a.svc.TestADConfig(p, body.toConfig())
	if err != nil {
		if err == service.ErrUnauthorized {
			writeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": false, "message": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": msg})
}
