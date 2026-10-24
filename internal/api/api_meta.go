package api

import (
	"net/http"

	"vdxclone/internal/service"
)

// me returns the authenticated principal's identity plus the running server
// version. The desktop client uses this to learn whether the user is an
// instance admin (so it can hide admin-only management pages) and to gate
// features on the server build it is talking to.
func (a *API) me(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	username, role := "", ""
	if p.User != nil {
		username = p.User.Username
		role = p.User.Role
	}
	writeJSON(w, 200, map[string]any{
		"Username": username,
		"Role":     role,
		"IsAdmin":  p.IsAdmin,
		"OrgID":    p.OrgID,
		"OrgRole":  p.OrgRole,
		"Unified":  p.Unified,
		"Version":  service.BuildVersion(),
	})
}
