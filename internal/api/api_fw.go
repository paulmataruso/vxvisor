package api

import (
	"encoding/json"
	"net/http"

	"vdxclone/internal/service"
)

// Unified NSX-style vFirewall JSON endpoints — a REST mirror of the /vfirewall
// web page. One org-level document (VM Groups + Internal/External zones +
// North-South / East-West rules) authored here; the service recompiles both
// enforcement planes on every mutation. All authz + audit live in the service
// layer, so each handler just decodes, calls through, and maps the error.
//
// The parent wires this into Routes(); an unused register method is not an error.
func (a *API) registerFirewallRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/firewall", a.auth("read", a.fwView))
	mux.HandleFunc("POST /api/v1/firewall/enabled", a.auth("write", a.fwSetEnabled))

	mux.HandleFunc("POST /api/v1/firewall/group", a.auth("write", a.fwAddGroup))
	mux.HandleFunc("POST /api/v1/firewall/group/{gid}/rename", a.auth("write", a.fwRenameGroup))
	mux.HandleFunc("POST /api/v1/firewall/group/{gid}/delete", a.auth("write", a.fwDelGroup))
	mux.HandleFunc("POST /api/v1/firewall/group/{gid}/members", a.auth("write", a.fwSetGroupMembers))
	mux.HandleFunc("POST /api/v1/firewall/group/{gid}/zone", a.auth("write", a.fwSetGroupZone))

	mux.HandleFunc("POST /api/v1/firewall/rule", a.auth("write", a.fwAddRule))
	mux.HandleFunc("POST /api/v1/firewall/rule/{dir}/{i}/delete", a.auth("write", a.fwDelRule))
	mux.HandleFunc("POST /api/v1/firewall/rule/{dir}/{i}/update", a.auth("write", a.fwUpdateRule))
	mux.HandleFunc("POST /api/v1/firewall/rule/{dir}/{i}/move", a.auth("write", a.fwMoveRule))
}

// fwDir normalises a direction to the "ns"/"ew" the service expects ("ew" →
// East-West / host bridge; anything else → North-South / vRouter).
func fwDir(s string) string {
	if s == "ew" {
		return "ew"
	}
	return "ns"
}

// ---- view -----------------------------------------------------------------

func (a *API) fwView(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	view, err := a.svc.ListFirewallView(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, view)
}

func (a *API) fwSetEnabled(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.FWSetEnabled(p, body.Enabled, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- groups ---------------------------------------------------------------

func (a *API) fwAddGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	id, err := a.svc.FWAddGroup(p, body.Name, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

func (a *API) fwRenameGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.FWRenameGroup(p, r.PathValue("gid"), body.Name, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) fwDelGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.FWDelGroup(p, r.PathValue("gid"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// fwSetGroupMembers replaces the group's full membership (the drag-and-drop drop
// handler sends the complete post-drop set).
func (a *API) fwSetGroupMembers(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		MACs     []string `json:"macs"`
		Networks []int64  `json:"networks"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.FWSetGroupMembers(p, r.PathValue("gid"), body.MACs, body.Networks, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) fwSetGroupZone(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Zone string `json:"zone"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.FWSetGroupZone(p, r.PathValue("gid"), body.Zone, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- rules ----------------------------------------------------------------

// fwAddRule adds one rule in the given direction (body "dir": ns|ew). The rule
// fields decode straight into service.FWRule via its snake_case json tags;
// "reverse" also inserts the mirror rule.
func (a *API) fwAddRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Dir     string `json:"dir"`
		Reverse bool   `json:"reverse"`
		service.FWRule
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.FWAddRule(p, fwDir(body.Dir), body.FWRule, body.Reverse, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) fwDelRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.FWDelRule(p, fwDir(r.PathValue("dir")), pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) fwUpdateRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var rule service.FWRule
	json.NewDecoder(r.Body).Decode(&rule)
	if err := a.svc.FWUpdateRule(p, fwDir(r.PathValue("dir")), pathIdx(r), rule, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// fwMoveRule reorders one rule within its From→To group by one step
// (body "step": up|down).
func (a *API) fwMoveRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Step string `json:"step"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.FWMoveRule(p, fwDir(r.PathValue("dir")), pathIdx(r), body.Step, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
