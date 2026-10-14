package web

import (
	"net/http"

	"vdxclone/internal/service"
)

func (s *Server) billing(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	report, err := s.svc.UsageReport(p, 30)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "billing.html", "billing", map[string]any{
		"Report": report,
		"Quota":  s.svc.GetQuota(p.OrgID),
	})
}

func (s *Server) setQuota(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	q := service.Quota{
		OrgID:       p.OrgID,
		MaxServers:  int(atoi(r.FormValue("max_servers"))),
		MaxRunning:  int(atoi(r.FormValue("max_running"))),
		MaxVCPUs:    int(atoi(r.FormValue("max_vcpus"))),
		MaxMemoryMB: int(atoi(r.FormValue("max_memory_mb"))),
		MaxDiskGB:   int(atoi(r.FormValue("max_disk_gb"))),
	}
	if err := s.svc.SetQuota(p, q, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/billing", http.StatusSeeOther)
}

// ---- trash ---------------------------------------------------------------

func (s *Server) trash(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := s.svc.ListTrash(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "trash.html", "trash", map[string]any{"Sessions": list})
}

func (s *Server) restoreSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.RestoreSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/trash", http.StatusSeeOther)
}

func (s *Server) purgeSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.PurgeSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/trash", http.StatusSeeOther)
}
