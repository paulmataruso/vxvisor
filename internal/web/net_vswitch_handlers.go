package web

import (
	"net/http"

	"vdxclone/internal/service"
)

func (s *Server) createBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CreateBond(p, r.FormValue("name"), r.FormValue("mode"), r.Form["members"], clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteBond(p, r.PathValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) createVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CreateVSwitch(p, r.FormValue("name"), r.FormValue("uplink"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteVSwitch(p, r.PathValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}
