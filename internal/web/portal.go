package web

import (
	"net/http"

	"vdxclone/internal/broker"
	"vdxclone/internal/image"
	"vdxclone/internal/service"
)

// PublicRoutes registers ONLY the internet-facing VDI surface: login/logout,
// OIDC, the "My Desktops" portal, connect/release, the desktop page and its
// WebSocket, and static assets. The admin/management screens are deliberately
// absent — they live on the separate admin listener (Server.Routes).
func (s *Server) PublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.postLogout)
	mux.HandleFunc("GET /oidc/login", s.oidcLogin)
	mux.HandleFunc("GET /oidc/callback", s.oidcCallback)

	mux.HandleFunc("GET /", s.auth(s.portal))
	mux.HandleFunc("POST /connect", s.auth(s.connectDesktop))
	mux.HandleFunc("POST /apps/launch", s.auth(s.launchApp))
	mux.HandleFunc("POST /desktops/{id}/disconnect", s.auth(s.disconnectDesktop))

	mux.HandleFunc("GET /desktop/{id}", s.auth(s.desktop))
	mux.HandleFunc("GET /desktop/{id}/ws", s.desktopProxy) // token- or cookie-authorized inside

	mux.Handle("GET /static/", http.FileServerFS(staticFS))
}

// portal renders the user's "My Desktops" page.
func (s *Server) portal(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	desks, err := s.svc.MyDesktops(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	apps, _ := s.svc.MyApps(p)
	s.render(w, p, "portal.html", "", map[string]any{"Desktops": desks, "Apps": apps})
}

// connectDesktop leases/creates a desktop from a pool and redirects the browser
// to the desktop page with a short-lived connection token.
func (s *Server) connectDesktop(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	poolID := int64(atoi(r.FormValue("pool_id")))
	sid, token, err := s.svc.ConnectDesktop(p, poolID, clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/desktop/"+sid+"?t="+token, http.StatusSeeOther)
}

// ---- admin: desktop pool management --------------------------------------

func (s *Server) adminPools(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	pools, err := s.svc.ListDesktopPools(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	images, _ := image.List(s.svc.DB())
	apps, _ := s.svc.ListApps(p)
	s.render(w, p, "pools.html", "pools", map[string]any{"Pools": pools, "Images": images, "Apps": apps})
}

// createApp publishes an app to the portal (admin).
func (s *Server) createApp(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	a := broker.App{
		Name:   r.FormValue("name"),
		Kind:   r.FormValue("kind"),
		PoolID: int64(atoi(r.FormValue("pool_id"))),
		Target: r.FormValue("target"),
		Args:   r.FormValue("args"),
		Icon:   r.FormValue("icon"),
	}
	if _, err := s.svc.CreateApp(p, a, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/pools", http.StatusSeeOther)
}

func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteApp(p, int64(atoi(r.PathValue("id"))), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/pools", http.StatusSeeOther)
}

// launchApp (portal) launches a published app: a web app redirects to its URL,
// a desktop/remoteapp app leases a pool VM and opens the browser desktop.
func (s *Server) launchApp(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	redirect, err := s.svc.ConnectApp(p, int64(atoi(r.FormValue("app_id"))), clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) createPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	pool := broker.Pool{
		Name:       r.FormValue("name"),
		ImageName:  r.FormValue("image"),
		AssignMode: r.FormValue("assign_mode"),
		CPUs:       int(atoi(r.FormValue("cpus"))),
		MemoryMB:   int(atoi(r.FormValue("memory_mb"))),
		DiskGB:     int(atoi(r.FormValue("disk_gb"))),
		MinSize:    int(atoi(r.FormValue("min_size"))),
		MaxSize:    int(atoi(r.FormValue("max_size"))),
	}
	if _, err := s.svc.CreatePool(p, pool, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/pools", http.StatusSeeOther)
}

func (s *Server) deletePool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeletePool(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/pools", http.StatusSeeOther)
}

func (s *Server) grantPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.GrantPool(p, atoi(r.PathValue("id")), r.FormValue("username"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/pools", http.StatusSeeOther)
}

// disconnectDesktop releases a pooled desktop (stops it; pooled VMs return to the
// free set). Users trigger it from the portal; the idle reaper does it too.
func (s *Server) disconnectDesktop(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	s.svc.ReleaseDesktop(r.PathValue("id"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
