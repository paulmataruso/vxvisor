package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

// NSX-lite per-tenant vRouter (FRR in LXC/netns) JSON endpoints. Each handler is
// a thin wrapper over an existing service method — all authz (admin-gated) and
// audit live in the service layer, so these only parse the path, decode the body
// (snake_case), call through, and map the error (writeErr maps
// ErrUnauthorized→403, ErrNotFound→404).
//
// Paths mirror the web vrouter_handlers routes field-for-field: {id} is the
// vRouter id, {idx} an internal leg index, {i} a routing-entry index.
//
// The parent wires this into Routes() via registerVRouterRoutes; an unused
// method is not a compile error.
func (a *API) registerVRouterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/vrouters", a.auth("read", a.listVRouters))
	mux.HandleFunc("GET /api/v1/vrouters/{id}", a.auth("read", a.getVRouter))
	mux.HandleFunc("POST /api/v1/vrouters", a.auth("write", a.createVRouter))
	// lifecycle
	mux.HandleFunc("POST /api/v1/vrouters/{id}/start", a.auth("write", a.startVRouter))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/stop", a.auth("write", a.stopVRouter))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/delete", a.auth("write", a.deleteVRouter))
	// transit link
	mux.HandleFunc("POST /api/v1/vrouters/{id}/transit", a.auth("write", a.vrAddTransit))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/transit/update", a.auth("write", a.vrUpdateTransit))
	// internal port groups + DHCP
	mux.HandleFunc("POST /api/v1/vrouters/{id}/internal", a.auth("write", a.vrAddInternal))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/internal/{idx}/update", a.auth("write", a.vrUpdateInternal))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/internal/{idx}/dhcp", a.auth("write", a.vrInternalDHCP))
	// static routes
	mux.HandleFunc("POST /api/v1/vrouters/{id}/static", a.auth("write", a.vrAddStatic))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/static/{i}/update", a.auth("write", a.vrUpdateStatic))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/static/{i}/delete", a.auth("write", a.vrDelStatic))
	// OSPF
	mux.HandleFunc("POST /api/v1/vrouters/{id}/ospf", a.auth("write", a.vrSetOSPF))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/ospf/net", a.auth("write", a.vrAddOSPFNet))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/ospf/net/{i}/update", a.auth("write", a.vrUpdateOSPFNet))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/ospf/net/{i}/delete", a.auth("write", a.vrDelOSPFNet))
	// BGP
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp", a.auth("write", a.vrSetBGP))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp/neighbor", a.auth("write", a.vrAddBGPNeighbor))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp/neighbor/{i}/update", a.auth("write", a.vrUpdateBGPNeighbor))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp/neighbor/{i}/delete", a.auth("write", a.vrDelBGPNeighbor))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp/network", a.auth("write", a.vrAddBGPNet))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp/network/{i}/update", a.auth("write", a.vrUpdateBGPNet))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/bgp/network/{i}/delete", a.auth("write", a.vrDelBGPNet))
	// EIGRP
	mux.HandleFunc("POST /api/v1/vrouters/{id}/eigrp", a.auth("write", a.vrSetEIGRP))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/eigrp/net", a.auth("write", a.vrAddEIGRPNet))
	mux.HandleFunc("POST /api/v1/vrouters/{id}/eigrp/net/{i}/delete", a.auth("write", a.vrDelEIGRPNet))
}

// ---- path helpers --------------------------------------------------------

func vrID(r *http.Request) int64              { id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64); return id }
func vrPathInt(r *http.Request, k string) int { n, _ := strconv.Atoi(r.PathValue(k)); return n }

// ---- list / get / create -------------------------------------------------

func (a *API) listVRouters(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListVRouters(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) getVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	v, err := a.svc.GetVRouterView(p, vrID(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// createVRouter mirrors the web createVRouter form (service.VRouterInput).
func (a *API) createVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name    string `json:"name"`
		Runtime string `json:"runtime"`
		CPUs    int    `json:"cpus"`
		MemMB   int    `json:"mem_mb"`
		Dist    string `json:"dist"`
		Release string `json:"release"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.CreateVRouter(p, service.VRouterInput{
		Name: body.Name, Runtime: body.Runtime, CPUs: body.CPUs, MemMB: body.MemMB,
		Dist: body.Dist, Release: body.Release,
	}, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

// ---- lifecycle -----------------------------------------------------------

func (a *API) startVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.StartVRouter(p, vrID(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) stopVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.StopVRouter(p, vrID(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) deleteVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteVRouter(p, vrID(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- transit link --------------------------------------------------------

func (a *API) vrAddTransit(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Iface string `json:"iface"`
		CIDR  string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AddTransitLink(p, vrID(r), body.Iface, body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrUpdateTransit(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.UpdateTransitLink(p, vrID(r), body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- internal port groups + DHCP -----------------------------------------

func (a *API) vrAddInternal(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name      string `json:"name"`
		CIDR      string `json:"cidr"`
		Gateway   string `json:"gateway"`
		DHCP      bool   `json:"dhcp"`
		DHCPRange string `json:"dhcp_range"`
		DNS       string `json:"dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AttachInternalNetwork(p, vrID(r), body.Name, body.CIDR, body.Gateway,
		body.DHCP, body.DHCPRange, body.DNS, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrUpdateInternal(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name    string `json:"name"`
		CIDR    string `json:"cidr"`
		Gateway string `json:"gateway"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.UpdateInternalNetwork(p, vrID(r), vrPathInt(r, "idx"), body.Name, body.CIDR, body.Gateway, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrInternalDHCP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		DHCP      bool   `json:"dhcp"`
		DHCPRange string `json:"dhcp_range"`
		DNS       string `json:"dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.UpdateInternalDHCP(p, vrID(r), vrPathInt(r, "idx"), body.DHCP, body.DHCPRange, body.DNS, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- static routes -------------------------------------------------------

func (a *API) vrAddStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Dest    string `json:"dest"`
		NextHop string `json:"next_hop"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRAddStaticRoute(p, vrID(r), body.Dest, body.NextHop, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrUpdateStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Dest    string `json:"dest"`
		NextHop string `json:"next_hop"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRUpdateStaticRoute(p, vrID(r), vrPathInt(r, "i"), body.Dest, body.NextHop, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrDelStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.VRDelStaticRoute(p, vrID(r), vrPathInt(r, "i"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- OSPF ----------------------------------------------------------------

func (a *API) vrSetOSPF(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		RouterID string `json:"router_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRSetOSPF(p, vrID(r), body.Enabled, body.RouterID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrAddOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
		Area string `json:"area"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRAddOSPFNet(p, vrID(r), body.CIDR, body.Area, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrUpdateOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
		Area string `json:"area"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRUpdateOSPFNet(p, vrID(r), vrPathInt(r, "i"), body.CIDR, body.Area, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrDelOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.VRDelOSPFNet(p, vrID(r), vrPathInt(r, "i"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- BGP -----------------------------------------------------------------

func (a *API) vrSetBGP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		ASN      int    `json:"asn"`
		RouterID string `json:"router_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRSetBGP(p, vrID(r), body.Enabled, body.ASN, body.RouterID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrAddBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Addr     string `json:"addr"`
		RemoteAS int    `json:"remote_as"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRAddBGPNeighbor(p, vrID(r), body.Addr, body.RemoteAS, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrUpdateBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Addr     string `json:"addr"`
		RemoteAS int    `json:"remote_as"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRUpdateBGPNeighbor(p, vrID(r), vrPathInt(r, "i"), body.Addr, body.RemoteAS, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrDelBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.VRDelBGPNeighbor(p, vrID(r), vrPathInt(r, "i"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrAddBGPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRAddBGPNetwork(p, vrID(r), body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrUpdateBGPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRUpdateBGPNetwork(p, vrID(r), vrPathInt(r, "i"), body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrDelBGPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.VRDelBGPNetwork(p, vrID(r), vrPathInt(r, "i"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- EIGRP ---------------------------------------------------------------

func (a *API) vrSetEIGRP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		ASN      int    `json:"asn"`
		RouterID string `json:"router_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRSetEIGRP(p, vrID(r), body.Enabled, body.ASN, body.RouterID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrAddEIGRPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.VRAddEIGRPNet(p, vrID(r), body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) vrDelEIGRPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.VRDelEIGRPNet(p, vrID(r), vrPathInt(r, "i"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
