package web

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"vdxclone/internal/service"
)

// Advanced-console (rustguac) integration — OPTIONAL test add-on.
//
// rustguac binds to loopback only. The browser can reach it solely through this
// cookie-gated reverse proxy, which vdxd runs on a separate browser-reachable
// port (cfg.Guac.ProxyAddr). Every request must carry a valid vdx_session
// cookie (the same session as the main UI — cookies are host-scoped, not
// port-scoped, so a logged-in user's browser sends it here too); otherwise it is
// bounced to the login page on the main listener. rustguac owns the whole path
// space of this port, so its absolute asset/WebSocket URLs (/guac/*, /ws/*)
// resolve correctly. httputil.ReverseProxy transparently handles the WebSocket
// Upgrade for /ws.
//
// The feature is inert unless cfg.Guac is enabled; the proxy listener is only
// started in that case (see cmd/vdxd/main.go), so disabling it is a clean
// rollback.

// GuacProxyHandler builds the cookie-gated reverse proxy to the local rustguac.
func (s *Server) GuacProxyHandler() http.Handler {
	upstream := &url.URL{Scheme: "http", Host: s.svc.Config().Guac.Upstream}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gate: require a valid vdxd session. The ticket in /client/{id}?ticket=
		// authenticates rustguac's WebSocket; THIS gate ensures only a logged-in
		// vdxd user can reach rustguac at all.
		if p := s.svc.Principal(r); p == nil {
			if r.Header.Get("Upgrade") != "" { // a WebSocket with no session: just refuse
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// Send the browser to the main listener's login page.
			http.Redirect(w, r, s.guacLoginURL(r), http.StatusSeeOther)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// guacLoginURL points at the main UI's login on the same host (the main
// listener's port), preserving the scheme.
func (s *Server) guacLoginURL(r *http.Request) string {
	return "/login"
}

// advancedConsole is the broker endpoint on the MAIN listener: it authorizes the
// VM (via the service), creates a rustguac session + single-use ticket, and
// redirects the browser to the proxy port's client page. The API key never
// reaches the browser; the ticket is single-use and short-lived.
func (s *Server) advancedConsole(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.svc.GuacEnabled() {
		http.Error(w, "advanced console is not enabled", http.StatusNotFound)
		return
	}
	gs, err := s.svc.AdvancedConsole(p, r.PathValue("id"), r.URL.Query().Get("proto"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	// Redirect to the browser-reachable proxy address (host:port) for rustguac.
	// ProxyAddr must be a routable mgmt host:port (not loopback/0.0.0.0).
	target := "http://" + s.svc.Config().Guac.ProxyAddr + "/client/" + gs.SessionID + "?ticket=" + url.QueryEscape(gs.Ticket)
	http.Redirect(w, r, target, http.StatusSeeOther)
}
