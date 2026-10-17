package web

import (
	"net"
	"net/http"
	"time"

	"vdxclone/internal/service"
)

// resolveVNC authorizes a portal VDI connection by its short-lived signed token
// (?t=) or, on the admin listener, the session cookie, and returns the loopback
// VNC target for the VM. This is the noVNC equivalent of resolveDesktop — the VDI
// portal uses the SAME noVNC path the admin console uses (RFB client → raw VNC
// websocket bridge), which is the console technology that actually renders.
func (s *Server) resolveVNC(r *http.Request) (*service.DesktopInfo, error) {
	id := r.PathValue("id")
	if t := r.URL.Query().Get("t"); t != "" {
		return s.svc.DesktopTargetByToken(t, id)
	}
	p := s.svc.Principal(r)
	if p == nil {
		return nil, service.ErrUnauthorized
	}
	return s.svc.DesktopTarget(p, id)
}

// vdiDesktop renders the portal noVNC desktop page. Authorized by a connection
// token (public portal) or a cookie (admin). The page connects an RFB client to
// /vnc/{id}/ws, exactly like the admin console does.
func (s *Server) vdiDesktop(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	di, err := s.resolveVNC(r)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "vnc_desktop.html", "", map[string]any{"Desktop": di, "Token": r.URL.Query().Get("t")})
}

// vdiVNCProxy bridges the browser websocket to the VM's loopback QEMU VNC port.
// It is the token/cookie-authorized twin of vncProxy's local branch — the VNC
// stays loopback-only; the only external path is this authenticated websocket.
func (s *Server) vdiVNCProxy(w http.ResponseWriter, r *http.Request) {
	di, err := s.resolveVNC(r)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	hostport := net.JoinHostPort(di.Hostname, di.Port)
	tcp, derr := net.DialTimeout("tcp", hostport, 5*time.Second)
	if derr != nil {
		http.Error(w, "cannot reach VNC: "+derr.Error(), http.StatusBadGateway)
		return
	}
	defer tcp.Close()
	nagleOff(tcp) // keystrokes/pointer/incremental updates must not wait on Nagle
	ws, uerr := vncUpgrader.Upgrade(w, r, nil)
	if uerr != nil {
		return
	}
	defer ws.Close()
	nagleOff(ws.UnderlyingConn())
	bridgeWSTCP(ws, tcp)
}
