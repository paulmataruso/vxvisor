package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

// This file holds the cluster node-administration JSON endpoints: list nodes,
// add a node, probe a node, and remove a node. Each is a thin wrapper over an
// existing service method — all authz + audit live in the service layer (node
// administration is instance-admin only), so these only decode the body, call
// through, and map the error (writeErr maps ErrUnauthorized→403, ErrNotFound→404).
//
// registerClusterRoutes wires these onto a mux. api.go's Routes does not call
// it; the parent wires it in later.
func (a *API) registerClusterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/cluster/nodes", a.auth("read", a.listClusterNodes))
	mux.HandleFunc("POST /api/v1/cluster/nodes", a.auth("write", a.addClusterNode))
	mux.HandleFunc("POST /api/v1/cluster/nodes/{id}/probe", a.auth("write", a.probeClusterNode))
	mux.HandleFunc("POST /api/v1/cluster/nodes/{id}/delete", a.auth("write", a.deleteClusterNode))
}

// listClusterNodes returns the cluster's nodes ([]cluster.Node, serialized with
// no json tags → PascalCase). Empty when clustering is off.
func (a *API) listClusterNodes(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	nodes, err := a.svc.ListNodes(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, nodes)
}

// addClusterNode registers a peer node by name/address/ssh user (admin only).
func (a *API) addClusterNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		SSHUser string `json:"ssh_user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AddNode(p, body.Name, body.Address, body.SSHUser, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// probeClusterNode re-probes a node's reachability/capacity (admin only).
func (a *API) probeClusterNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.ProbeNode(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// deleteClusterNode removes a node from the cluster (admin only).
func (a *API) deleteClusterNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteNode(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
