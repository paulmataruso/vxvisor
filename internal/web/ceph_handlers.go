package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// Hyperconverged Ceph page: cluster status + bootstrap/grow the on-node Ceph
// cluster that backs VM disks with RBD. Admin only; every mutation is CSRF-checked
// and audited in the service layer.

func (s *Server) cephPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	status, _ := s.svc.CephStatus(p)
	s.render(w, p, "ceph.html", "ceph", map[string]any{
		"Avail":        s.svc.CephAvailable(p),
		"Status":       status,
		"StorageIface": s.svc.StorageIface(),
		"Pool":         s.svc.CephPool(),
		"Disks":        s.svc.DiskStatus(p),
	})
}

func (s *Server) bootstrapCeph(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.BootstrapCeph(p, r.FormValue("pool"), r.FormValue("osd_disk"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/ceph", http.StatusSeeOther)
}

func (s *Server) addCephOSD(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.AddCephOSD(p, r.FormValue("osd_disk"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/ceph", http.StatusSeeOther)
}
