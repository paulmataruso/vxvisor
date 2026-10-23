package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// Software RAID (mdraid) + filesystem-pool handlers. All admin-gated via the
// service layer; they redirect back to /storage with a flash on error.

func (s *Server) createMDArray(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_ = r.ParseForm()
	if err := s.svc.CreateMDArray(p, r.FormValue("name"), r.FormValue("level"), r.Form["devices"], clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "software RAID array created")
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) destroyMDArray(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DestroyMDArray(p, r.PathValue("name"), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

func (s *Server) createFilesystemPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CreateFilesystemPool(p, r.FormValue("device"), r.FormValue("fstype"), r.FormValue("name"), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "filesystem pool created and registered")
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}
