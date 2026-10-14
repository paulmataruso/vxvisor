package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"vdxclone/internal/auth"
)

const oidcStateCookie = "vdx_oidc_state"

// oidcLogin starts the OIDC authorization-code flow: it stores a random state in
// a short-lived cookie and redirects the browser to the identity provider.
func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if !s.oidc.Enabled() {
		http.Error(w, "SSO is not configured", http.StatusNotFound)
		return
	}
	state := randToken()
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: "/oidc", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u, err := s.oidc.AuthURL(ctx, state)
	if err != nil {
		http.Error(w, "SSO unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// oidcCallback completes the flow: verify state, exchange the code, read the
// userinfo, JIT-provision the local user, and start a web session.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if !s.oidc.Enabled() {
		http.Error(w, "SSO is not configured", http.StatusNotFound)
		return
	}
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || c.Value == "" || c.Value != r.URL.Query().Get("state") {
		http.Error(w, "invalid SSO state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/oidc", MaxAge: -1})

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := s.oidc.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "SSO exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	info, err := s.oidc.UserInfo(ctx, token)
	if err != nil {
		http.Error(w, "SSO userinfo failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	u, err := auth.UpsertOIDCUser(s.svc.DB(), info.Subject, info.Username, info.Email)
	if err != nil {
		http.Error(w, "SSO provisioning failed", http.StatusInternalServerError)
		return
	}
	if err := auth.StartSession(s.svc.DB(), w, u.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
