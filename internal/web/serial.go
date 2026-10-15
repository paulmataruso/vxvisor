package web

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	"vdxclone/internal/peer"
	"vdxclone/internal/service"
)

// Serial (text) console: xterm.js in the browser bridged to the guest's ttyS0
// over the authenticated websocket proxy. Cloud images and cirros run their
// login/getty on the serial line, so this is the console that actually accepts
// input for headless guests (the VGA/noVNC console shows only boot output there).
// Like the VNC console it works cluster-wide: a VM on another node is relayed to
// its owning node's authenticated peer serial endpoint.

// serialConsole renders the xterm.js serial console page for a VM (local or,
// in the unified view, hosted on another node).
func (s *Server) serialConsole(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sess, _, err := s.svc.ConsoleTargetCluster(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "serial.html", "", map[string]any{"Session": sess})
}

// serialProxy bridges a browser websocket (xterm.js) to the guest's serial unix
// socket. Local VM → dial the loopback socket directly; remote VM → relay to the
// owning node's authenticated peer serial websocket.
func (s *Server) serialProxy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sock, owner, err := s.svc.SerialTargetCluster(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	if owner == "" {
		uconn, derr := net.DialTimeout("unix", sock, 5*time.Second)
		if derr != nil {
			http.Error(w, "cannot reach serial console: "+derr.Error(), http.StatusBadGateway)
			return
		}
		defer uconn.Close()
		ws, uerr := vncUpgrader.Upgrade(w, r, nil)
		if uerr != nil {
			return
		}
		defer ws.Close()
		bridgeWSTCP(ws, uconn)
		return
	}
	s.relaySerial(w, r, owner, r.PathValue("id"))
}

// relaySerial dials the owning node's authenticated peer serial websocket and
// pipes it to the browser websocket.
func (s *Server) relaySerial(w http.ResponseWriter, r *http.Request, ownerAddr, id string) {
	if s.clusterAuth == nil {
		http.Error(w, "cluster serial relay unavailable", http.StatusBadGateway)
		return
	}
	path := "/cluster/v1/serial/" + id + "/ws"
	host := ownerAddr
	if h, _, e := net.SplitHostPort(ownerAddr); e == nil {
		host = h
	}
	url := "ws://" + net.JoinHostPort(host, strconv.Itoa(peer.APIPort)) + path
	hdr := http.Header{}
	hdr.Set("X-Cluster-Auth", s.clusterAuth.Header(path))
	dialer := websocket.Dialer{Subprotocols: []string{"binary"}, HandshakeTimeout: 8 * time.Second}
	up, _, derr := dialer.Dial(url, hdr)
	if derr != nil {
		http.Error(w, "reach owning node: "+derr.Error(), http.StatusBadGateway)
		return
	}
	defer up.Close()
	ws, uerr := vncUpgrader.Upgrade(w, r, nil)
	if uerr != nil {
		return
	}
	defer ws.Close()
	bridgeWSWS(ws, up)
}

// peerSerialWS (peer API, owning node) bridges an inbound relay websocket to this
// node's local serial unix socket for the VM.
func (s *Server) peerSerialWS(w http.ResponseWriter, r *http.Request) {
	sock, err := s.svc.LocalSerialSock(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	uconn, derr := net.DialTimeout("unix", sock, 5*time.Second)
	if derr != nil {
		http.Error(w, "cannot reach serial console: "+derr.Error(), http.StatusBadGateway)
		return
	}
	defer uconn.Close()
	ws, uerr := vncUpgrader.Upgrade(w, r, nil)
	if uerr != nil {
		return
	}
	defer ws.Close()
	bridgeWSTCP(ws, uconn)
}
