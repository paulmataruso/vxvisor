package web

import (
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"vdxclone/internal/gateway"
	"vdxclone/internal/service"
)

// guacUpgrader upgrades the browser connection for the Guacamole tunnel.
// guacamole-common-js uses the "guacamole" WebSocket subprotocol.
var guacUpgrader = websocket.Upgrader{
	Subprotocols:    []string{"guacamole"},
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// resolveDesktop authorizes desktop access by either a signed connection token
// (public portal path, `?t=`) or the session cookie (admin path), returning the
// guacd target. The token is a per-connection grant that cannot be replayed past
// its short TTL.
func (s *Server) resolveDesktop(r *http.Request) (*service.DesktopInfo, error) {
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

// desktop renders the full-desktop page (guacamole-common-js canvas). It accepts
// a connection token or a cookie so it serves both the public portal and admins.
func (s *Server) desktop(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	di, err := s.resolveDesktop(r)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "desktop.html", "compute", map[string]any{"Desktop": di, "Token": r.URL.Query().Get("t")})
}

// desktopProxy is the WebSocket↔guacd tunnel. It performs the guacd connection
// handshake server-side (selecting RDP or VNC against the guest), then relays
// the Guacamole instruction stream between the browser and guacd verbatim.
// Authorization is a connection token (public) or the session cookie (admin).
func (s *Server) desktopProxy(w http.ResponseWriter, r *http.Request) {
	di, err := s.resolveDesktop(r)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}

	guacdAddr := s.cfg.Gateway.GuacdAddr
	if guacdAddr == "" {
		guacdAddr = "127.0.0.1:4822"
	}
	params := gateway.Params{
		Protocol:        di.Protocol,
		Hostname:        di.Hostname,
		Port:            di.Port,
		Username:        di.Username,
		Password:        di.Password,
		Width:           1280,
		Height:          720,
		DPI:             96,
		EnableAudio:     true,
		EnableClipboard: true,
		EnableMic:       true,
		RemoteApp:       di.RemoteApp,
		RemoteAppArgs:   di.RemoteAppArgs,
	}
	guac, _, err := gateway.Handshake(guacdAddr, params)
	if err != nil {
		http.Error(w, "gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer guac.Close()

	ws, err := guacUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done) }) }

	// guacd -> browser (text frames of guacd instructions)
	go func() {
		defer closeBoth()
		buf := make([]byte, 64*1024)
		for {
			n, err := guac.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.TextMessage, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// browser -> guacd
	go func() {
		defer closeBoth()
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, err := guac.Write(data); err != nil {
				return
			}
		}
	}()

	<-done
}
