package web

import (
	"net/http"
	"strconv"

	"vdxclone/internal/auth"
	"vdxclone/internal/image"
	"vdxclone/internal/service"
)

// ---- auth pages ----------------------------------------------------------

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if s.svc.Principal(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Error": r.URL.Query().Get("error"),
		"OIDC":  s.oidc.Enabled(),
	})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	u, err := auth.Authenticate(s.svc.DB(), r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	if err := auth.StartSession(s.svc.DB(), w, u.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	auth.EndSession(s.svc.DB(), w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) switchOrg(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_ = s.svc.SwitchOrg(p, atoi(r.FormValue("org_id")))
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// ---- compute -------------------------------------------------------------

// overview is the landing page: an at-a-glance dashboard of every subsystem
// (compute, storage, networking, backups, usage, recent activity).
func (s *Server) overview(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.render(w, p, "overview.html", "overview", map[string]any{
		"O": s.svc.Overview(p),
	})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sessions, _ := s.svc.ListSessions(p)
	images, _ := image.List(s.svc.DB())
	isos, _ := s.svc.ListISOs(p)
	templates, _ := s.svc.ListTemplates(p)
	networks, _ := s.svc.ListNetworks(p)
	pools, _ := s.svc.ListPools(p)
	zfspools, _ := s.svc.ZFSPools(p) // for the raw-zvol disk option (admin; empty otherwise)
	s.render(w, p, "dashboard.html", "compute", map[string]any{
		"Sessions":  sessions,
		"Images":    images,
		"ISOs":      isos,
		"Templates": templates,
		"Networks":  networks,
		"Pools":     pools,
		"ZFSPools":  zfspools,
	})
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	disk, _ := strconv.Atoi(r.FormValue("disk_gb"))
	if cpus == 0 {
		cpus = 2
	}
	if mem == 0 {
		mem = 2048
	}
	in := service.CreateInput{
		Name:       r.FormValue("name"),
		Image:      r.FormValue("image"),
		Kind:       r.FormValue("kind"),
		Firmware:   r.FormValue("firmware"),
		BootISOID:  atoi(r.FormValue("boot_iso_id")),
		CPUs:       cpus,
		MemoryMB:   mem,
		DiskGB:     disk,
		CloudInit:   r.FormValue("cloud_init") != "",
		CIUsername:  r.FormValue("ci_username"),
		CIPassword:  r.FormValue("ci_password"),
		CISSHKey:    r.FormValue("ci_ssh_key"),
		Passthrough:   r.FormValue("passthrough"),
		NetworkID:     atoi(r.FormValue("network_id")),
		StoragePoolID: atoi(r.FormValue("storage_pool_id")),
		Display:       r.FormValue("display"),
		DiskBackend:   r.FormValue("disk_backend"),
		ZvolPool:      r.FormValue("zvol_pool"),
		Desktop:       r.FormValue("desktop"),
	}
	sess, err := s.svc.CreateSession(p, in, clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/instances/"+sess.ID, http.StatusSeeOther)
}

func (s *Server) instanceDetail(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sess, err := s.svc.GetSession(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	events, _ := s.svc.SessionEvents(p, sess.ID)
	snapshots, _ := s.svc.ListSnapshots(p, sess.ID)
	forwards, _ := s.svc.ListPortForwards(p, sess.ID)
	nodes, _ := s.svc.ListNodes(p)
	s.render(w, p, "instance.html", "compute", map[string]any{
		"Session":     sess,
		"Running":     s.svc.Manager().Running(sess),
		"Events":      events,
		"Snapshots":   snapshots,
		"Forwards":    forwards,
		"ForwardHost": s.svc.ForwardHost(),
		"Nodes":       nodes,
		"IsAdmin":     p.IsAdmin,
	})
}

func (s *Server) resizeSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	disk, _ := strconv.Atoi(r.FormValue("disk_gb"))
	if err := s.svc.ResizeSession(p, id, cpus, mem, disk, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) ejectISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.EjectISO(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.StartSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

// redirectBack returns to the submitting page (Referer) or the dashboard.
func redirectBack(w http.ResponseWriter, r *http.Request) {
	dest := r.Header.Get("Referer")
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) stopSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.StopSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) console(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sess, err := s.svc.ConsoleTarget(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "console.html", "compute", map[string]any{"Session": sess})
}

// ---- tenancy screens -----------------------------------------------------

func (s *Server) members(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	members, err := s.svc.ListMembers(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "members.html", "members", map[string]any{"Members": members})
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.AddMember(p, r.FormValue("username"), r.FormValue("role"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/members", http.StatusSeeOther)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.RemoveMember(p, atoi(r.PathValue("uid")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/members", http.StatusSeeOther)
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	keys, err := s.svc.ListAPIKeys(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "apikeys.html", "apikeys", map[string]any{
		"Keys":   keys,
		"NewKey": r.URL.Query().Get("new"),
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	plaintext, err := s.svc.CreateAPIKey(p, r.FormValue("label"), r.FormValue("readonly") != "", clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/apikeys?new="+plaintext, http.StatusSeeOther)
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.RevokeAPIKey(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/apikeys", http.StatusSeeOther)
}

func (s *Server) orgs(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.render(w, p, "orgs.html", "orgs", nil)
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.CreateOrg(p, r.FormValue("name"), r.FormValue("slug"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/orgs", http.StatusSeeOther)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	filter := r.URL.Query().Get("action")
	entries, err := s.svc.ListAuditFiltered(p, filter)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "audit.html", "audit", map[string]any{"Entries": entries, "Filter": filter})
}

func statusFor(err error) int {
	switch err {
	case service.ErrUnauthorized:
		return http.StatusForbidden
	case service.ErrNotFound:
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}
