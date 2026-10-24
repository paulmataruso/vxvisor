package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
)

// Networking JSON endpoints: port-group networks, NIC bonds, and vSwitches.
// Each is a thin wrapper over an existing service method — all authz + audit
// live in the service layer, so these only decode the body, call through, and
// map the error (writeErr maps ErrUnauthorized→403, ErrNotFound→404).
//
// The parent wires this into Routes(); an unused method is not a compile error.
func (a *API) registerNetworkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/networks", a.auth("read", a.listNetworks))
	mux.HandleFunc("POST /api/v1/networks", a.auth("write", a.createNetwork))
	mux.HandleFunc("POST /api/v1/networks/{id}/delete", a.auth("write", a.deleteNetwork))
	mux.HandleFunc("GET /api/v1/bonds", a.auth("read", a.listBonds))
	mux.HandleFunc("POST /api/v1/bonds", a.auth("write", a.createBond))
	mux.HandleFunc("POST /api/v1/bonds/{name}/delete", a.auth("write", a.deleteBond))
	mux.HandleFunc("GET /api/v1/vswitches", a.auth("read", a.listVSwitches))
	mux.HandleFunc("POST /api/v1/vswitches", a.auth("write", a.createVSwitch))
	mux.HandleFunc("POST /api/v1/vswitches/{name}/delete", a.auth("write", a.deleteVSwitch))
}

// ---- networks (port groups) ----------------------------------------------

func (a *API) listNetworks(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListNetworks(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

// createNetwork records a port-group / bridge / VLAN / VXLAN network. Field set
// mirrors the web createNetwork handler. Returns the new row id.
func (a *API) createNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name       string `json:"name"`
		Mode       string `json:"mode"`
		Bridge     string `json:"bridge"`
		VLANID     int    `json:"vlan_id"`
		CIDR       string `json:"cidr"`
		Gateway    string `json:"gateway"`
		PoolStart  string `json:"pool_start"`
		PoolEnd    string `json:"pool_end"`
		VNI        int    `json:"vni"`
		Underlay   string `json:"underlay"`
		VXLANLocal string `json:"vxlan_local"`
		VXLANPeers string `json:"vxlan_peers"`
		DstPort    int    `json:"vxlan_dstport"`
		MTU        int    `json:"vxlan_mtu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.CreateNetwork(p, netdrv.Network{
		Name: body.Name, Mode: body.Mode, Bridge: body.Bridge, VLANID: body.VLANID,
		CIDR: body.CIDR, Gateway: body.Gateway, PoolStart: body.PoolStart, PoolEnd: body.PoolEnd,
		VNI: body.VNI, Underlay: body.Underlay, VXLANLocal: body.VXLANLocal,
		VXLANPeers: body.VXLANPeers, DstPort: body.DstPort, MTU: body.MTU,
	}, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

func (a *API) deleteNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteNetwork(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- bonds (NIC teams) ----------------------------------------------------

func (a *API) listBonds(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListBonds(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) createBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name       string   `json:"name"`
		Mode       string   `json:"mode"`
		HashPolicy string   `json:"hash_policy"`
		Members    []string `json:"members"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.CreateBond(p, body.Name, body.Mode, body.HashPolicy, body.Members, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) deleteBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteBond(p, r.PathValue("name"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- vSwitches ------------------------------------------------------------

func (a *API) listVSwitches(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListVSwitches(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) createVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name   string `json:"name"`
		Uplink string `json:"uplink"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.CreateVSwitch(p, body.Name, body.Uplink, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) deleteVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteVSwitch(p, r.PathValue("name"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
