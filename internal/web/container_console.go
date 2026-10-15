package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// containerConsole renders the xterm.js terminal page for an LXC container.
func (s *Server) containerConsole(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	_, name, err := s.svc.ContainerConsole(p, int64(atoi(r.PathValue("id"))))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "container_console.html", "", map[string]any{"ID": r.PathValue("id"), "Name": name})
}

// containerConsoleWS bridges the browser terminal to a shell inside the container
// (lxc-attach on a PTY). Admin/member authorized via the service.
func (s *Server) containerConsoleWS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	cmd, _, err := s.svc.ContainerConsole(p, int64(atoi(r.PathValue("id"))))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	ws, uerr := vncUpgrader.Upgrade(w, r, nil)
	if uerr != nil {
		return
	}
	defer ws.Close()
	ptmx, perr := startPTY(cmd, 120, 32)
	if perr != nil {
		_ = ws.WriteMessage(1, []byte("failed to open console: "+perr.Error()))
		return
	}
	defer func() { _ = ptmx.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	bridgeWSPTY(ws, ptmx)
}
