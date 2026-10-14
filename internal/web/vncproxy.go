package web

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

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

// vncProxy bridges a browser websocket to the session's loopback QEMU VNC port.
// Authorization is the SAME service check the console page uses (B2): no weaker
// copy lives here. Bytes are forwarded verbatim in both directions, so noVNC
// talks to QEMU unmodified (and completes VNC password auth itself).
func (s *Server) vncProxy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sess, err := s.svc.ConsoleTarget(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}

	tcp, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(sess.VNCPort), 5*time.Second)
	if err != nil {
		http.Error(w, "cannot reach VNC: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer tcp.Close()

	ws, err := vncUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote an error
	}
	defer ws.Close()

	var once sync.Once
	done := make(chan struct{})
	closeBoth := func() { once.Do(func() { close(done) }) }

	// QEMU TCP -> browser websocket (binary frames)
	go func() {
		defer closeBoth()
		buf := make([]byte, 32*1024)
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// browser websocket -> QEMU TCP
	go func() {
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
