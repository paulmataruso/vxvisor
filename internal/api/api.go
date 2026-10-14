// Package api exposes a small JSON REST surface for sessions and images.
//
// This is an original API design (our own paths and payloads). Requests
// authenticate with either the web cookie session or an "Authorization: Bearer
// vdx_..." API key; all access goes through the service layer, which enforces
// org-scoped authorization and writes audit events.
package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"vdxclone/internal/image"
	"vdxclone/internal/service"
)

type API struct {
	svc *service.Service
	rl  *rateLimiter
}

func New(svc *service.Service) *API { return &API{svc: svc, rl: newRateLimiter(10, 20)} }

func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/sessions", a.auth("read", a.listSessions))
	mux.HandleFunc("POST /api/v1/sessions", a.auth("write", a.createSession))
	mux.HandleFunc("POST /api/v1/sessions/{id}/resize", a.auth("write", a.resizeSession))
	mux.HandleFunc("POST /api/v1/sessions/{id}/start", a.auth("write", a.startSession))
	mux.HandleFunc("POST /api/v1/sessions/{id}/stop", a.auth("write", a.stopSession))
	mux.HandleFunc("POST /api/v1/sessions/{id}/delete", a.auth("write", a.deleteSession))
	mux.HandleFunc("GET /api/v1/images", a.auth("read", a.listImages))
	mux.HandleFunc("GET /api/v1/usage", a.auth("read", a.usage))
}

// auth resolves the principal, enforces the API-key scope the route needs, and
// applies a per-principal rate limit before dispatching.
func (a *API) auth(scope string, h func(http.ResponseWriter, *http.Request, *service.Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := a.svc.APIPrincipal(r)
		if p == nil {
			writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
			return
		}
		key := p.ActorKind + ":" + itoa(p.User.ID)
		if !a.rl.allow(key) {
			writeJSON(w, 429, map[string]string{"error": "rate limited"})
			return
		}
		if !p.HasScope(scope) {
			writeJSON(w, 403, map[string]string{"error": "insufficient scope: " + scope})
			return
		}
		h(w, r, p)
	}
}

func (a *API) usage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	rep, err := a.svc.UsageReport(p, 30)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, rep)
}

// ---- rate limiter (token bucket per principal) ---------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens/sec
	capacity float64
}

func newRateLimiter(rate, capacity float64) *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}, rate: rate, capacity: capacity}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.capacity {
		b.tokens = l.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (a *API) listSessions(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s, err := a.svc.ListSessions(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s)
}

func (a *API) createSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name       string `json:"name"`
		Image      string `json:"image"`
		Kind       string `json:"kind"`
		Firmware   string `json:"firmware"`
		CPUs       int    `json:"cpus"`
		MemoryMB   int    `json:"memory_mb"`
		DiskGB     int    `json:"disk_gb"`
		CloudInit  *bool  `json:"cloud_init"`
		CIUsername string `json:"ci_username"`
		CIPassword string `json:"ci_password"`
		CISSHKey   string `json:"ci_ssh_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if body.CPUs == 0 {
		body.CPUs = 2
	}
	if body.MemoryMB == 0 {
		body.MemoryMB = 2048
	}
	cloudInit := true // default on, since a cloud image is unusable without it
	if body.CloudInit != nil {
		cloudInit = *body.CloudInit
	}
	s, err := a.svc.CreateSession(p, service.CreateInput{
		Name: body.Name, Image: body.Image, Kind: body.Kind, Firmware: body.Firmware,
		CPUs: body.CPUs, MemoryMB: body.MemoryMB, DiskGB: body.DiskGB,
		CloudInit: cloudInit, CIUsername: body.CIUsername, CIPassword: body.CIPassword, CISSHKey: body.CISSHKey,
	}, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, s)
}

func (a *API) resizeSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		CPUs     int `json:"cpus"`
		MemoryMB int `json:"memory_mb"`
		DiskGB   int `json:"disk_gb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.ResizeSession(p, r.PathValue("id"), body.CPUs, body.MemoryMB, body.DiskGB, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "resized"})
}

func (a *API) startSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s, err := a.svc.StartSession(p, r.PathValue("id"), ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, s)
}

func (a *API) stopSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.StopSession(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"state": "stopped"})
}

func (a *API) deleteSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if err := a.svc.DeleteSession(p, r.PathValue("id"), ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (a *API) listImages(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	im, err := image.List(a.svc.DB())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, im)
}

func writeErr(w http.ResponseWriter, err error) {
	code := 400
	switch err {
	case service.ErrUnauthorized:
		code = 403
	case service.ErrNotFound:
		code = 404
	}
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func ip(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
