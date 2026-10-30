package web

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"vdxclone/internal/peer"
	"vdxclone/internal/service"
)

// vncUpgrader upgrades the browser connection. noVNC requests the "binary"
// subprotocol; we must echo it back or noVNC refuses the socket.
var vncUpgrader = websocket.Upgrader{
	Subprotocols:    []string{"binary"},
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	// Same-origin page reached by IP or hostname on the LAN; the request is
	// already authenticated + authorized via the service before we get here.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// vncProxy bridges a browser websocket to the VM's QEMU VNC console. If the VM is
// hosted on THIS node it bridges to the loopback VNC port directly. If it lives on
// another cluster node (single pane via the VIP), it RELAYS the websocket to the
// owning node's authenticated peer console endpoint, which bridges to that node's
// loopback VNC — so loopback-only consoles still work cross-node without exposing
// any VNC port off-box. Authorization is the same service check the console page
// uses; no weaker copy lives here.
func (s *Server) vncProxy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sess, owner, err := s.svc.ConsoleTargetCluster(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}

	if owner == "" {
		// Local VM: bridge straight to its loopback VNC.
		tcp, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(sess.VNCPort), 5*time.Second)
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
		return
	}

	// Remote VM: relay to the owning node's peer console WS.
	s.relayConsole(w, r, owner, r.PathValue("id"))
}

// relayConsole dials the owning node's authenticated peer console websocket and
// pipes it to the browser websocket, frame for frame.
func (s *Server) relayConsole(w http.ResponseWriter, r *http.Request, ownerAddr, id string) {
	if s.clusterAuth == nil {
		http.Error(w, "cluster console relay unavailable", http.StatusBadGateway)
		return
	}
	path := "/cluster/v1/console/" + id + "/ws"
	host := ownerAddr
	if h, _, e := net.SplitHostPort(ownerAddr); e == nil {
		host = h
	}
	url := "ws://" + net.JoinHostPort(host, strconv.Itoa(peer.APIPort)) + path
	hdr := http.Header{}
	s.clusterAuth.SetHeader(hdr, http.MethodGet, path, "")
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

// peerConsoleWS (peer API, owning node) upgrades the inbound relay websocket and
// bridges it to this node's loopback VNC for the VM.
func (s *Server) peerConsoleWS(w http.ResponseWriter, r *http.Request) {
	info, err := s.svc.LocalConsoleInfo(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	tcp, derr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(info.VNCPort), 5*time.Second)
	if derr != nil {
		http.Error(w, "cannot reach VNC: "+derr.Error(), http.StatusBadGateway)
		return
	}
	defer tcp.Close()
	nagleOff(tcp)
	ws, uerr := vncUpgrader.Upgrade(w, r, nil)
	if uerr != nil {
		return
	}
	defer ws.Close()
	nagleOff(ws.UnderlyingConn())
	bridgeWSTCP(ws, tcp)
}

// peerConsoleInfo (peer API) serves a local VM's console details for the leader
// to render the console page of a VM it does not host.
func (s *Server) peerConsoleInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.svc.LocalConsoleInfo(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, info)
}

// Console keepalive: ping the browser so a half-open / stalled WebSocket is
// detected and torn down promptly (the client then auto-reconnects) instead of
// the console silently freezing and going black until a manual refresh.
const (
	vncPingPeriod = 45 * time.Second
	vncWriteWait  = 30 * time.Second
)

// nagleOff disables Nagle's algorithm on a TCP connection so small console
// packets (keystrokes, pointer moves, incremental framebuffer updates) are sent
// immediately instead of being coalesced (up to a ~40ms delay). Go enables
// TCP_NODELAY by default, but we set it explicitly so a transport change can't
// silently reintroduce input lag. No-op for a non-TCP conn.
func nagleOff(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.SetNoDelay(true)
	}
}

// bridgeWSTCP forwards bytes between a websocket and a TCP conn until either ends.
func bridgeWSTCP(ws *websocket.Conn, tcp net.Conn) {
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done) }) }

	// Serialize all websocket writes (data frames + pings) — gorilla forbids
	// concurrent writers — and bound each write with a deadline.
	var wmu sync.Mutex
	wsWrite := func(mt int, data []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = ws.SetWriteDeadline(time.Now().Add(vncWriteWait))
		return ws.WriteMessage(mt, data)
	}

	// Periodic ping keeps intermediaries from idling the socket out AND detects a
	// dead/half-open peer: the ping write fails (or hits the write deadline) within
	// ~vncWriteWait, tearing the bridge down so the client reconnects. We do NOT
	// impose a read deadline — a healthy console is idle inbound for long stretches
	// (input only flows on user activity), and dropping it on silence is exactly
	// what caused the console to flap.
	go func() { // periodic ping
		t := time.NewTicker(vncPingPeriod)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if wsWrite(websocket.PingMessage, nil) != nil {
					closeBoth()
					return
				}
			}
		}
	}()

	go func() { // TCP (QEMU) -> browser
		defer closeBoth()
		buf := make([]byte, 32*1024)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if wsWrite(websocket.BinaryMessage, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // browser -> TCP (QEMU)
		defer closeBoth()
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
				continue
			}
			if _, err := tcp.Write(data); err != nil {
				return
			}
		}
	}()
	<-done
}

// bridgeWSWS forwards messages between two websockets (the leader relay hop).
func bridgeWSWS(a, b *websocket.Conn) {
	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done) }) }
	pipe := func(src, dst *websocket.Conn) {
		defer closeBoth()
		for {
			mt, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			if err := dst.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
}
