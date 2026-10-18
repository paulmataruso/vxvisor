package web

import (
	"net/http"
	"strconv"
	"strings"

	"vdxclone/internal/routing"
	"vdxclone/internal/service"
)

// ---- JSON AJAX endpoints (admin-gated inside the service) ----------------

func (s *Server) apiInterfaces(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	ifaces, err := s.svc.HostInterfaces(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, map[string]any{"interfaces": ifaces})
}

func (s *Server) apiBlockDevices(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	devs, err := s.svc.HostBlockDevices(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, map[string]any{"devices": devs})
}

func (s *Server) apiFS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	dir, entries, err := s.svc.HostBrowseDir(p, r.URL.Query().Get("path"))
	if err != nil {
		// Still return the resolved dir + empty list so the box degrades gracefully.
		writeJSON(w, map[string]any{"dir": dir, "entries": []any{}, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"dir": dir, "entries": entries})
}

func (s *Server) apiTopology(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	topo, err := s.svc.NetworkTopology(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, topo)
}

// ---- ZFS / LVM management (form POSTs) -----------------------------------

func (s *Server) createZFSPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	devices := r.Form["devices"]
	force := r.FormValue("force") == "1"
	if err := s.svc.CreateZFSPool(p, r.FormValue("name"), r.FormValue("raid"), devices, force, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) destroyZFSPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DestroyZFSPool(p, r.PathValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) createZFSDataset(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CreateZFSDataset(p, r.FormValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) replaceZFSDevice(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.ZFSReplace(p, r.FormValue("pool"), r.FormValue("old"), r.FormValue("new"), r.FormValue("force") == "1", clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) addZFSCache(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.ZFSAddCache(p, r.FormValue("pool"), r.Form["devices"], r.FormValue("force") == "1", clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) addZFSLog(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.ZFSAddLog(p, r.FormValue("pool"), r.Form["devices"], r.FormValue("mirror") == "1", r.FormValue("force") == "1", clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) createLVMPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	devices := r.Form["devices"]
	if err := s.svc.CreateLVMThinPool(p, r.FormValue("vg"), r.FormValue("thinpool"), devices, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) removeVG(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.RemoveVG(p, r.PathValue("vg"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

// ---- L3 routing page (button-driven CRUD) --------------------------------

func (s *Server) routingPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	cfg, _ := s.svc.GetRoutingConfig(p)
	status, _ := s.svc.RoutingStatus(p)
	ifaces, _ := s.svc.HostInterfaces(p)
	transit, _ := s.svc.TransitCandidates(p)
	s.render(w, p, "routing.html", "routing", map[string]any{
		"Cfg":        cfg,
		"Status":     status,
		"Interfaces": ifaces,
		"Transit":    transit,
		"FRRReady":   s.svc.RoutingAvailable(p),
	})
}

// routingDo runs one routing mutation and redirects back, surfacing apply errors.
func (s *Server) routingDo(w http.ResponseWriter, r *http.Request, p *service.Principal, fn func() error) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := fn(); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/routing", http.StatusSeeOther)
}

func pidx(r *http.Request) int { n, _ := strconv.Atoi(r.PathValue("i")); return n }

func (s *Server) applyRouting(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		cfg, _ := s.svc.GetRoutingConfig(p)
		return s.svc.SaveRoutingConfig(p, cfg, clientIP(r))
	})
}

func (s *Server) rtSetUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.SetRoutingUplink(p, r.FormValue("uplink"), clientIP(r)) })
}
func (s *Server) rtAddStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.AddStaticRoute(p, r.FormValue("dest"), r.FormValue("next_hop"), clientIP(r)) })
}
func (s *Server) rtDelStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteStaticRoute(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtAddFirewall(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		return s.svc.AddFirewallRule(p, r.FormValue("action"), r.FormValue("proto"), r.FormValue("dport"), r.FormValue("source"), clientIP(r))
	})
}
func (s *Server) rtDelFirewall(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteFirewallRule(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtAddPrefix(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.AddIfPrefix(p, r.FormValue("iface"), r.FormValue("cidr"), clientIP(r)) })
}
func (s *Server) rtDelPrefix(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteIfPrefix(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtAddPrefixList(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		pl := routing.PrefixList{Name: r.FormValue("name"), Action: r.FormValue("action"), Prefix: r.FormValue("prefix")}
		pl.Seq = atoiInt(r.FormValue("seq"))
		pl.Ge = atoiInt(r.FormValue("ge"))
		pl.Le = atoiInt(r.FormValue("le"))
		return s.svc.AddPrefixList(p, pl, clientIP(r))
	})
}
func (s *Server) rtDelPrefixList(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeletePrefixList(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtAddRouteMap(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		rm := routing.RouteMapClause{Name: r.FormValue("name"), Action: r.FormValue("action"), MatchPrefixList: r.FormValue("match_prefix_list")}
		rm.Seq = atoiInt(r.FormValue("seq"))
		rm.SetMetric = atoiInt(r.FormValue("set_metric"))
		rm.SetLocalPref = atoiInt(r.FormValue("set_local_pref"))
		return s.svc.AddRouteMap(p, rm, clientIP(r))
	})
}
func (s *Server) rtDelRouteMap(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteRouteMap(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtSetOSPF(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.SetOSPF(p, r.FormValue("enabled") == "1", r.FormValue("router_id"), clientIP(r)) })
}
func (s *Server) rtAddOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.AddOSPFNetwork(p, r.FormValue("cidr"), r.FormValue("area"), clientIP(r)) })
}
func (s *Server) rtDelOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteOSPFNetwork(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtSetBGP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		return s.svc.SetBGP(p, r.FormValue("enabled") == "1", atoiInt(r.FormValue("asn")), r.FormValue("router_id"), clientIP(r))
	})
}
func (s *Server) rtAddBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		nb := routing.Neighbor{Addr: r.FormValue("addr"), RemoteAS: atoiInt(r.FormValue("remote_as")),
			RouteMapIn: r.FormValue("route_map_in"), RouteMapOut: r.FormValue("route_map_out")}
		return s.svc.AddBGPNeighbor(p, nb, clientIP(r))
	})
}
func (s *Server) rtDelBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteBGPNeighbor(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtAddBGPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.AddBGPNetwork(p, r.FormValue("cidr"), clientIP(r)) })
}
func (s *Server) rtDelBGPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteBGPNetwork(p, pidx(r), clientIP(r)) })
}
func (s *Server) rtSetEIGRP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error {
		return s.svc.SetEIGRP(p, r.FormValue("enabled") == "1", atoiInt(r.FormValue("asn")), r.FormValue("router_id"), clientIP(r))
	})
}
func (s *Server) rtAddEIGRPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.AddEIGRPNetwork(p, r.FormValue("cidr"), clientIP(r)) })
}
func (s *Server) rtDelEIGRPNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.routingDo(w, r, p, func() error { return s.svc.DeleteEIGRPNetwork(p, pidx(r), clientIP(r)) })
}

func atoiInt(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }
