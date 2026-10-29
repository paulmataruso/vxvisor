package web

import (
	"net/http"
	"os"
	"strconv"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
)

func (s *Server) containersPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, _ := s.svc.ListContainers(p)
	pools, _ := s.svc.ListPools(p)
	localNode := s.svc.ClusterSelfName()
	if localNode == "" {
		localNode, _ = os.Hostname()
	}
	// Port-group pickers: each container's OWN org's port groups (an instance
	// admin sees every org's containers), plus the viewer's org for "New".
	// lxcbr0 (value 0) is offered only to the Default org.
	portGroups := map[int64][]netdrv.Network{}
	tenantOrgs := map[int64]bool{}
	for _, org := range append([]int64{p.OrgID}, containerOrgs(list)...) {
		if _, done := portGroups[org]; done {
			continue
		}
		pgs, _ := s.svc.ContainerPortGroups(p, org)
		portGroups[org] = pgs
		tenantOrgs[org] = s.svc.TenantOrg(org)
	}
	s.render(w, p, "containers.html", "containers", map[string]any{
		"Containers":   list,
		"PortGroups":   portGroups,
		"TenantOrgs":   tenantOrgs,
		"MyPortGroups": portGroups[p.OrgID],
		"MyTenant":     tenantOrgs[p.OrgID],
		"Pools":        pools,
		"LXCReady":     s.svc.LXCAvailable(p),
		"LocalNode":    localNode,
	})
}

func containerOrgs(list []service.ContainerRow) []int64 {
	out := make([]int64, 0, len(list))
	for _, c := range list {
		out = append(out, c.OrgID)
	}
	return out
}

func (s *Server) createContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	copies, _ := strconv.Atoi(r.FormValue("copies"))
	diskGB, _ := strconv.Atoi(r.FormValue("disk_gb"))
	in := service.CreateContainerInput{
		Name:          r.FormValue("name"),
		Dist:          r.FormValue("dist"),
		Release:       r.FormValue("release"),
		NetworkID:     atoi(r.FormValue("network_id")),
		CPUs:          cpus,
		MemoryMB:      mem,
		StoragePoolID: atoi(r.FormValue("storage_pool_id")),
		DiskGB:        diskGB,
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

func (s *Server) updateContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.ctDo(w, r, p, func(id int64) error {
		return s.svc.UpdateContainer(p, id, atoi(r.FormValue("network_id")), int(atoi(r.FormValue("cpus"))), int(atoi(r.FormValue("mem_mb"))), clientIP(r))
	})
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
