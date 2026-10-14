package web

import (
	"net/http"

	"vdxclone/internal/service"
)

func (s *Server) cluster(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	nodes, err := s.svc.ListNodes(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "cluster.html", "cluster", map[string]any{
		"Nodes":      nodes,
		"Capability": s.svc.HostCapability(p),
	})
}

func (s *Server) importImage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.ImportImageURL(p, r.FormValue("name"), r.FormValue("url"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

func (s *Server) addNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.AddNode(p, r.FormValue("name"), r.FormValue("address"), r.FormValue("ssh_user"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteNode(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

func (s *Server) probeNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.ProbeNode(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

// migrateSession live-migrates a running VM to another node. The result (or the
// honest precondition error) is surfaced on the instance page via a flash.
func (s *Server) migrateSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	dst := int64(atoi(r.FormValue("dst_node")))
	shared := r.FormValue("shared_storage") == "on"
	if err := s.svc.MigrateSession(p, id, dst, shared, clientIP(r)); err != nil {
		http.Error(w, "migration: "+err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}
