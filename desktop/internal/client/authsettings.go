package client

// This file adds the Settings → Authentication (Active Directory / LDAP) client
// calls: read the current settings, save them, and test a directory bind. Thin
// wrappers over the CSRF-exempt REST API, reusing the cookie-authed helpers.
//
// The GET response is the api.authSettings struct, serialized with NO json tags
// (PascalCase). The bind password is never returned — HasBindPassword only tells
// whether one is set. Save/test bodies are snake_case.

// AuthSettings mirrors the server's redacted AD/LDAP settings response.
type AuthSettings struct {
	Enabled         bool   `json:"Enabled"`
	URL             string `json:"URL"`
	Domain          string `json:"Domain"`
	StartTLS        bool   `json:"StartTLS"`
	Insecure        bool   `json:"Insecure"`
	BindDN          string `json:"BindDN"`
	HasBindPassword bool   `json:"HasBindPassword"`
	BaseDN          string `json:"BaseDN"`
	UserFilter      string `json:"UserFilter"`
	AdminGroup      string `json:"AdminGroup"`
	Stored          bool   `json:"Stored"`
}

// AuthTestResult is the {ok,message} response of a directory-bind test.
type AuthTestResult struct {
	Ok      bool   `json:"ok"`
	Message string `json:"message"`
}

// AuthSettings returns the effective AD/LDAP settings (bind password redacted).
func (c *Client) AuthSettings() (AuthSettings, error) {
	var out AuthSettings
	err := c.getJSON("/api/v1/settings/auth", &out)
	return out, err
}

// SaveAuthSettings persists AD/LDAP settings (admin only). A blank bindPassword
// keeps the existing secret.
func (c *Client) SaveAuthSettings(s AuthSettings, bindPassword string) error {
	return c.apiPostJSON("/api/v1/settings/auth", authSettingsPayload(s, bindPassword))
}

// TestAuthSettings validates a candidate config against the directory without
// saving. Returns {ok,message}; a bind failure is ok:false (not a transport
// error).
func (c *Client) TestAuthSettings(s AuthSettings, bindPassword string) (AuthTestResult, error) {
	var out AuthTestResult
	err := c.apiPostDecode("/api/v1/settings/auth/test", authSettingsPayload(s, bindPassword), &out)
	return out, err
}

// authSettingsPayload builds the snake_case save/test body.
func authSettingsPayload(s AuthSettings, bindPassword string) map[string]any {
	return map[string]any{
		"enabled":       s.Enabled,
		"url":           s.URL,
		"domain":        s.Domain,
		"starttls":      s.StartTLS,
		"insecure":      s.Insecure,
		"bind_dn":       s.BindDN,
		"bind_password": bindPassword,
		"base_dn":       s.BaseDN,
		"user_filter":   s.UserFilter,
		"admin_group":   s.AdminGroup,
	}
}
