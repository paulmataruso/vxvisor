package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// Shared storage page: dedicated storage NIC + NFS/CIFS/Ceph mounts + iSCSI.

func (s *Server) sharedPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	ifaces, _ := s.svc.HostInterfaces(p)
	mounts, _ := s.svc.ListSharedMounts(p)
	iscsi, _ := s.svc.ListISCSI(p)
	s.render(w, p, "shared.html", "shared", map[string]any{
		"Interfaces":   ifaces,
		"StorageIface": s.svc.StorageIface(),
		"Mounts":       mounts,
		"ISCSI":        iscsi,
		"Caps":         s.svc.SharedCaps(p),
	})
}

func (s *Server) setStorageIface(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.SetStorageIface(p, r.FormValue("iface"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/shared", http.StatusSeeOther)
}

func (s *Server) sharedDo(w http.ResponseWriter, r *http.Request, p *service.Principal, fn func() error) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := fn(); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/shared", http.StatusSeeOther)
}

func (s *Server) addNFS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.sharedDo(w, r, p, func() error {
		return s.svc.AddNFS(p, r.FormValue("name"), r.FormValue("server"), r.FormValue("export"), r.FormValue("options"), clientIP(r))
	})
}
func (s *Server) addCIFS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.sharedDo(w, r, p, func() error {
		return s.svc.AddCIFS(p, r.FormValue("name"), r.FormValue("unc"), r.FormValue("username"), r.FormValue("password"), r.FormValue("options"), clientIP(r))
	})
}
func (s *Server) addCeph(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.sharedDo(w, r, p, func() error {
		return s.svc.AddCeph(p, r.FormValue("name"), r.FormValue("mons"), r.FormValue("path"), r.FormValue("ceph_name"), r.FormValue("secret"), r.FormValue("options"), clientIP(r))
	})
}
func (s *Server) unmountShared(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.sharedDo(w, r, p, func() error { return s.svc.UnmountShared(p, atoi(r.PathValue("id")), clientIP(r)) })
}
func (s *Server) iscsiLogin(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.sharedDo(w, r, p, func() error { return s.svc.ISCSILogin(p, r.FormValue("portal"), r.FormValue("target"), clientIP(r)) })
}
func (s *Server) iscsiLogout(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.sharedDo(w, r, p, func() error { return s.svc.ISCSILogout(p, atoi(r.PathValue("id")), clientIP(r)) })
}

// apiISCSIDiscover returns discovered target IQNs at a portal as JSON.
func (s *Server) apiISCSIDiscover(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	iqns, err := s.svc.ISCSIDiscover(p, r.URL.Query().Get("portal"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, map[string]any{"targets": iqns})
}
