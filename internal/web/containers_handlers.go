package web

import (
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

func (s *Server) containersPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, _ := s.svc.ListContainers(p)
	ifaces, _ := s.svc.HostInterfaces(p)
	pools, _ := s.svc.ListPools(p)
	s.render(w, p, "containers.html", "containers", map[string]any{
		"Containers": list,
		"Interfaces": ifaces,
		"Pools":      pools,
		"LXCReady":   s.svc.LXCAvailable(p),
	})
}

func (s *Server) createContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	copies, _ := strconv.Atoi(r.FormValue("copies"))
	in := service.CreateContainerInput{
		Name:          r.FormValue("name"),
		Dist:          r.FormValue("dist"),
		Release:       r.FormValue("release"),
		Bridge:        r.FormValue("bridge"),
		CPUs:          cpus,
		MemoryMB:      mem,
		StoragePoolID: atoi(r.FormValue("storage_pool_id")),
		Copies:        copies,
	}
	if err := s.svc.CreateContainer(p, in, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/containers", http.StatusSeeOther)
}

func (s *Server) ctDo(w http.ResponseWriter, r *http.Request, p *service.Principal, fn func(int64) error) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := fn(atoi(r.PathValue("id"))); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/containers", http.StatusSeeOther)
}

func (s *Server) startContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.ctDo(w, r, p, func(id int64) error { return s.svc.StartContainer(p, id, clientIP(r)) })
}
func (s *Server) stopContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.ctDo(w, r, p, func(id int64) error { return s.svc.StopContainer(p, id, clientIP(r)) })
}
func (s *Server) deleteContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.ctDo(w, r, p, func(id int64) error { return s.svc.DeleteContainer(p, id, clientIP(r)) })
}
func (s *Server) snapshotContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.ctDo(w, r, p, func(id int64) error { return s.svc.SnapshotContainer(p, id, clientIP(r)) })
}
