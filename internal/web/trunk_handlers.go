package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// Tenant networking v3 — the instance-admin "Tenant Egress" console (/trunks):
// designate external trunks, define per-tenant VLAN pools, create/bind tenant
// uplinks (access / qinq / dedicated NIC), verify QinQ, and the global teardown.

func (s *Server) trunksPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	trunks, _ := s.svc.ListExtTrunks(p)
	uplinks, _ := s.svc.ListAllUplinks(p)
	pools, _ := s.svc.ListVlanPools(p)
	orgs, _ := s.svc.ListOrgsLite(p)
	cands, _ := s.svc.TransitCandidates(p)      // free NICs/bonds (already excludes trunks/mgmt/storage)
	shared, _ := s.svc.SharedTrunkCandidates(p) // mgmt vSwitch uplink(s) — access-only shared trunks
	s.render(w, p, "trunks.html", "trunks", map[string]any{
		"Trunks":      trunks,
		"Uplinks":     uplinks,
		"Pools":       pools,
		"Orgs":        orgs,
		"Candidates":  cands,
		"SharedCands": shared,
	})
}

func (s *Server) designateTrunk(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DesignateTrunk(p, r.FormValue("iface"), r.FormValue("qinq") == "1",
		int(atoi(r.FormValue("mtu"))), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "External trunk designated.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) undesignateTrunk(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.UndesignateTrunk(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Trunk removed and its original MTU/offload restored.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

// verifyTrunkQinQ is an AJAX check: are offloads off + MTU high enough on this NIC?
func (s *Server) verifyTrunkQinQ(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	ok, detail, err := s.svc.VerifyTrunkQinQ(p, atoi(r.PathValue("id")))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, map[string]any{"ok": ok, "detail": detail})
}

func (s *Server) setVlanPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.SetVlanPool(p, atoi(r.FormValue("org_id")), atoi(r.FormValue("trunk_id")),
		int(atoi(r.FormValue("vid_min"))), int(atoi(r.FormValue("vid_max"))), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "VLAN pool saved.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) deleteVlanPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteVlanPool(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "VLAN pool removed.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) createUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_, err := s.svc.CreateUplink(p, atoi(r.FormValue("org_id")), r.FormValue("name"), r.FormValue("mode"),
		atoi(r.FormValue("trunk_id")), int(atoi(r.FormValue("vid"))), r.FormValue("ded_iface"), clientIP(r))
	if err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Uplink created. The tenant can now connect a network to it from their Networks page.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) deleteUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteUplink(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Uplink removed.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) disableTenantEgress(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DisableTenantEgress(p, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Tenant egress disabled — all subinterfaces torn down and trunks restored to their original state.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}
