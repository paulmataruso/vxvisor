package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/routing"
	"vdxclone/internal/service"
)

// Host L3 routing (FRR + nftables) JSON endpoints — a thin REST mirror of the
// /routing web page. Each handler decodes the body, calls one existing service
// method, and maps the error. All authz + audit live in the service layer; the
// routing model is GRANULAR (per-item Add*/Delete*/Set*), matching the
// button-driven web page: the stored routing.Config is loaded, mutated by one
// item, persisted, and the whole managed FRR + nft state is re-applied.
//
// The parent wires this into Routes(); an unused register method is not an error.
func (a *API) registerRoutingRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/routing", a.auth("read", a.getRouting))
	mux.HandleFunc("POST /api/v1/routing/apply", a.auth("write", a.rtApply))
	mux.HandleFunc("POST /api/v1/routing/uplink", a.auth("write", a.rtSetUplink))

	mux.HandleFunc("POST /api/v1/routing/static", a.auth("write", a.rtAddStatic))
	mux.HandleFunc("POST /api/v1/routing/static/{i}/delete", a.auth("write", a.rtDelStatic))

	mux.HandleFunc("POST /api/v1/routing/prefix", a.auth("write", a.rtAddPrefix))
	mux.HandleFunc("POST /api/v1/routing/prefix/{i}/delete", a.auth("write", a.rtDelPrefix))

	mux.HandleFunc("POST /api/v1/routing/firewall", a.auth("write", a.rtAddFirewall))
	mux.HandleFunc("POST /api/v1/routing/firewall/{i}/delete", a.auth("write", a.rtDelFirewall))

	mux.HandleFunc("POST /api/v1/routing/prefixlist", a.auth("write", a.rtAddPrefixList))
	mux.HandleFunc("POST /api/v1/routing/prefixlist/{i}/delete", a.auth("write", a.rtDelPrefixList))

	mux.HandleFunc("POST /api/v1/routing/routemap", a.auth("write", a.rtAddRouteMap))
	mux.HandleFunc("POST /api/v1/routing/routemap/{i}/delete", a.auth("write", a.rtDelRouteMap))

	mux.HandleFunc("POST /api/v1/routing/ospf", a.auth("write", a.rtSetOSPF))
	mux.HandleFunc("POST /api/v1/routing/ospf/net", a.auth("write", a.rtAddOSPFNet))
	mux.HandleFunc("POST /api/v1/routing/ospf/net/{i}/delete", a.auth("write", a.rtDelOSPFNet))

	mux.HandleFunc("POST /api/v1/routing/bgp", a.auth("write", a.rtSetBGP))
	mux.HandleFunc("POST /api/v1/routing/bgp/neighbor", a.auth("write", a.rtAddBGPNeighbor))
	mux.HandleFunc("POST /api/v1/routing/bgp/neighbor/{i}/delete", a.auth("write", a.rtDelBGPNeighbor))
	mux.HandleFunc("POST /api/v1/routing/bgp/network", a.auth("write", a.rtAddBGPNetwork))
	mux.HandleFunc("POST /api/v1/routing/bgp/network/{i}/delete", a.auth("write", a.rtDelBGPNetwork))

	mux.HandleFunc("POST /api/v1/routing/eigrp", a.auth("write", a.rtSetEIGRP))
	mux.HandleFunc("POST /api/v1/routing/eigrp/network", a.auth("write", a.rtAddEIGRPNetwork))
	mux.HandleFunc("POST /api/v1/routing/eigrp/network/{i}/delete", a.auth("write", a.rtDelEIGRPNetwork))
}

// pathIdx reads the {i} path value as an int (the list index to delete).
func pathIdx(r *http.Request) int { n, _ := strconv.Atoi(r.PathValue("i")); return n }

// ---- config read / apply --------------------------------------------------

func (a *API) getRouting(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	cfg, err := a.svc.GetRoutingConfig(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, cfg)
}

// rtApply re-saves and re-applies the stored config (forwarding + nft + FRR),
// mirroring the web "Apply" button (load current config → SaveRoutingConfig).
func (a *API) rtApply(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	cfg, err := a.svc.GetRoutingConfig(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := a.svc.SaveRoutingConfig(p, cfg, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- uplink / static / prefixes / firewall --------------------------------

func (a *API) rtSetUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Uplink string `json:"uplink"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.SetRoutingUplink(p, body.Uplink, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Dest    string `json:"dest"`
		NextHop string `json:"next_hop"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.AddStaticRoute(p, body.Dest, body.NextHop, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteStaticRoute(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddPrefix(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Iface string `json:"iface"`
		CIDR  string `json:"cidr"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.AddIfPrefix(p, body.Iface, body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelPrefix(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteIfPrefix(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddFirewall(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Action string `json:"action"`
		Proto  string `json:"proto"`
		DPort  string `json:"dport"`
		Source string `json:"source"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.AddFirewallRule(p, body.Action, body.Proto, body.DPort, body.Source, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelFirewall(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteFirewallRule(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- prefix-lists / route-maps --------------------------------------------

func (a *API) rtAddPrefixList(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var pl routing.PrefixList
	json.NewDecoder(r.Body).Decode(&pl)
	if err := a.svc.AddPrefixList(p, pl, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelPrefixList(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeletePrefixList(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddRouteMap(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var rm routing.RouteMapClause
	json.NewDecoder(r.Body).Decode(&rm)
	if err := a.svc.AddRouteMap(p, rm, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelRouteMap(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteRouteMap(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- OSPF -----------------------------------------------------------------

func (a *API) rtSetOSPF(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		RouterID string `json:"router_id"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.SetOSPF(p, body.Enabled, body.RouterID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
		Area string `json:"area"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.AddOSPFNetwork(p, body.CIDR, body.Area, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteOSPFNetwork(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- BGP ------------------------------------------------------------------

func (a *API) rtSetBGP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		ASN      int    `json:"asn"`
		RouterID string `json:"router_id"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.SetBGP(p, body.Enabled, body.ASN, body.RouterID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var nb routing.Neighbor
	json.NewDecoder(r.Body).Decode(&nb)
	if err := a.svc.AddBGPNeighbor(p, nb, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteBGPNeighbor(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddBGPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.AddBGPNetwork(p, body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelBGPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteBGPNetwork(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- EIGRP ----------------------------------------------------------------

func (a *API) rtSetEIGRP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled  bool   `json:"enabled"`
		ASN      int    `json:"asn"`
		RouterID string `json:"router_id"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.SetEIGRP(p, body.Enabled, body.ASN, body.RouterID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtAddEIGRPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := a.svc.AddEIGRPNetwork(p, body.CIDR, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) rtDelEIGRPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteEIGRPNetwork(p, pathIdx(r), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
