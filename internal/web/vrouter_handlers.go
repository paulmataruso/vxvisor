package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// vroutersPage renders the vRouter management page. Per-org admins manage their
// own org's routers (netns, internal-only); only an instance admin additionally
// sees the transit (physical uplink) controls and the lxc runtime.
func (s *Server) vroutersPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.OrgAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	views, _ := s.svc.ListVRouters(p)
	var transit []service.TransitIface
	if p.IsAdmin {
		transit, _ = s.svc.TransitCandidates(p)
	}
	segs, _ := s.svc.AttachableSegments(p)
	s.render(w, p, "vrouters.html", "vrouters", map[string]any{
		"VRouters":  views,
		"Transit":   transit,
		"Segments":  segs,
		"Runtimes":  s.svc.VRouterRuntimes(),
		"Available": s.svc.VRouterAvailable(p),
		"UserMode":  s.svc.NetworkModeUser(),
		"InstAdmin": p.IsAdmin,
	})
}

func (s *Server) createVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	in := service.VRouterInput{
		Name:    r.FormValue("name"),
		Runtime: r.FormValue("runtime"),
		CPUs:    int(atoi(r.FormValue("cpus"))),
		MemMB:   int(atoi(r.FormValue("mem_mb"))),
		Dist:    r.FormValue("dist"),
		Release: r.FormValue("release"),
	}
	if _, err := s.svc.CreateVRouter(p, in, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "vRouter is being created — it provisions FRR in the background; refresh to watch its status.")
	}
	http.Redirect(w, r, "/vrouters", http.StatusSeeOther)
}

// apiVRouterStatus returns a vRouter's live routing state as JSON for the poller.
func (s *Server) apiVRouterStatus(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	ls, err := s.svc.VRouterLive(p, int64(atoi(r.PathValue("id"))))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, ls)
}

// apiVRouterDiagram returns the network-diagram data (port groups → vRouter →
// transit → external) for one vRouter as JSON.
func (s *Server) apiVRouterDiagram(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	d, err := s.svc.VRouterDiagram(p, int64(atoi(r.PathValue("id"))))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, d)
}

// attachSegment attaches one of the org's existing (gatewayless) segments to a
// vRouter as an internal leg; the router leg becomes its gateway.
func (s *Server) attachSegment(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(vrID int64) error {
		return s.svc.AttachSegment(p, vrID, int64(atoi(r.FormValue("tnet_id"))), r.FormValue("gateway"),
			r.FormValue("dhcp") == "1", r.FormValue("dhcp_range"), r.FormValue("dhcp_dns"), clientIP(r))
	})
}

// detachSegment removes a segment's leg from a vRouter without destroying it.
func (s *Server) detachSegment(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(vrID int64) error {
		return s.svc.DetachSegment(p, vrID, int64(atoi(r.FormValue("net_id"))), clientIP(r))
	})
}

// vrDo wraps a mutation: CSRF, run, redirect back to /vrouters with a flash.
func (s *Server) vrDo(w http.ResponseWriter, r *http.Request, p *service.Principal, fn func(vrID int64) error) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	vrID := int64(atoi(r.PathValue("id")))
	if err := fn(vrID); err != nil {
		setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/vrouters", http.StatusSeeOther)
}

func (s *Server) startVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.StartVRouter(p, id, clientIP(r)) })
}
func (s *Server) stopVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.StopVRouter(p, id, clientIP(r)) })
}
func (s *Server) deleteVRouter(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.DeleteVRouter(p, id, clientIP(r)) })
}

func (s *Server) addTransitLink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.AddTransitLink(p, id, r.FormValue("iface"), r.FormValue("cidr"), clientIP(r))
	})
}
func (s *Server) attachInternal(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.AttachInternalNetwork(p, id, r.FormValue("name"), r.FormValue("cidr"),
			r.FormValue("gateway"), r.FormValue("dhcp") != "", r.FormValue("dhcp_range"), r.FormValue("dns"), clientIP(r))
	})
}

func (s *Server) updateInternalDHCP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.UpdateInternalDHCP(p, id, int(atoi(r.PathValue("idx"))),
			r.FormValue("dhcp") != "", r.FormValue("dhcp_range"), r.FormValue("dns"), clientIP(r))
	})
}

// ---- dynamic routing (scoped to a vRouter) ----
func (s *Server) vrAddStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRAddStaticRoute(p, id, r.FormValue("dest"), r.FormValue("next_hop"), clientIP(r))
	})
}
func (s *Server) vrDelStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRDelStaticRoute(p, id, int(atoi(r.PathValue("i"))), clientIP(r)) })
}
func (s *Server) vrSetOSPF(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRSetOSPF(p, id, r.FormValue("enabled") != "", r.FormValue("router_id"), clientIP(r))
	})
}
func (s *Server) vrAddOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRAddOSPFNet(p, id, r.FormValue("cidr"), r.FormValue("area"), clientIP(r))
	})
}
func (s *Server) vrDelOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRDelOSPFNet(p, id, int(atoi(r.PathValue("i"))), clientIP(r)) })
}
func (s *Server) vrSetBGP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRSetBGP(p, id, r.FormValue("enabled") != "", int(atoi(r.FormValue("asn"))), r.FormValue("router_id"), clientIP(r))
	})
}
func (s *Server) vrAddBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRAddBGPNeighbor(p, id, r.FormValue("addr"), int(atoi(r.FormValue("remote_as"))), clientIP(r))
	})
}
func (s *Server) vrDelBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRDelBGPNeighbor(p, id, int(atoi(r.PathValue("i"))), clientIP(r)) })
}
func (s *Server) vrAddBGPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRAddBGPNetwork(p, id, r.FormValue("cidr"), clientIP(r)) })
}
func (s *Server) vrDelBGPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRDelBGPNetwork(p, id, int(atoi(r.PathValue("i"))), clientIP(r)) })
}
func (s *Server) vrSetEIGRP(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRSetEIGRP(p, id, r.FormValue("enabled") != "", int(atoi(r.FormValue("asn"))), r.FormValue("router_id"), clientIP(r))
	})
}
func (s *Server) vrAddEIGRPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRAddEIGRPNet(p, id, r.FormValue("cidr"), clientIP(r)) })
}
func (s *Server) vrDelEIGRPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.VRDelEIGRPNet(p, id, int(atoi(r.PathValue("i"))), clientIP(r)) })
}

// ---- edit existing entries ----
func (s *Server) vrUpdateStatic(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRUpdateStaticRoute(p, id, int(atoi(r.PathValue("i"))), r.FormValue("dest"), r.FormValue("next_hop"), clientIP(r))
	})
}
func (s *Server) vrUpdateOSPFNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRUpdateOSPFNet(p, id, int(atoi(r.PathValue("i"))), r.FormValue("cidr"), r.FormValue("area"), clientIP(r))
	})
}
func (s *Server) vrUpdateBGPNeighbor(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRUpdateBGPNeighbor(p, id, int(atoi(r.PathValue("i"))), r.FormValue("addr"), int(atoi(r.FormValue("remote_as"))), clientIP(r))
	})
}
func (s *Server) vrUpdateBGPNet(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.VRUpdateBGPNetwork(p, id, int(atoi(r.PathValue("i"))), r.FormValue("cidr"), clientIP(r))
	})
}
func (s *Server) updateTransitLink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error { return s.svc.UpdateTransitLink(p, id, r.FormValue("cidr"), clientIP(r)) })
}
func (s *Server) updateInternalNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.vrDo(w, r, p, func(id int64) error {
		return s.svc.UpdateInternalNetwork(p, id, int(atoi(r.PathValue("idx"))), r.FormValue("name"), r.FormValue("cidr"), r.FormValue("gateway"), clientIP(r))
	})
}
