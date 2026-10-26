package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Optional rustguac "advanced console" integration (a test add-on).
//
// rustguac + guacd run locally, bound to loopback only. vdxd brokers each
// console session SERVER-SIDE with its admin API key, then hands the browser a
// single-use WebSocket ticket; the browser reaches rustguac only through vdxd's
// cookie-gated reverse proxy (see web/guac_proxy.go). The guest consoles vdxd
// already exposes on loopback (VNC/SPICE) are the targets, so nothing new binds
// to the network. The whole feature is gated by GuacEnabled(): with the [guac]
// config section absent or Enabled=false it is completely inert — the rollback
// is a config flag, with no schema or data-plane change.

// GuacSession is what the web layer needs to point a browser at rustguac: the
// session id and the single-use ticket that authenticates its WebSocket.
type GuacSession struct {
	SessionID string
	Ticket    string
}

// GuacEnabled reports whether the advanced-console add-on is fully configured.
func (s *Service) GuacEnabled() bool {
	g := s.cfg.Guac
	return g.Enabled && g.Upstream != "" && g.APIKey != ""
}

var guacHTTP = &http.Client{Timeout: 8 * time.Second}

func (s *Service) guacDo(method, path string, body any) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rdr = bytes.NewReader(b)
	}
	// Upstream is a loopback address (e.g. 127.0.0.1:8089); plain HTTP there is
	// fine — it never leaves the host, and the only external path is vdxd's
	// authenticated proxy.
	req, err := http.NewRequest(method, "http://"+s.cfg.Guac.Upstream+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Guac.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := guacHTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("rustguac unreachable: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, nil
}

// AdvancedConsole creates a rustguac session to a VM's loopback console and
// mints a single-use WebSocket ticket. proto is "vnc" (default) or "spice".
// Authorization reuses ConsoleTarget — the exact access check the noVNC console
// uses — so an org member can only reach their own org's running VMs.
func (s *Service) AdvancedConsole(p *Principal, id, proto string) (GuacSession, error) {
	if !s.GuacEnabled() {
		return GuacSession{}, fmt.Errorf("advanced console is not enabled")
	}
	sess, err := s.ConsoleTarget(p, id)
	if err != nil {
		return GuacSession{}, err
	}

	body := map[string]any{"hostname": "127.0.0.1"}
	switch proto {
	case "", "vnc":
		if sess.VNCPort == 0 {
			return GuacSession{}, fmt.Errorf("VM has no VNC console")
		}
		body["session_type"] = "vnc"
		body["port"] = sess.VNCPort
		if sess.VNCPassword != "" {
			body["password"] = sess.VNCPassword
		}
	case "spice":
		if sess.SPICEPort == 0 {
			return GuacSession{}, fmt.Errorf("VM has no SPICE console")
		}
		body["session_type"] = "spice"
		body["port"] = sess.SPICEPort
	default:
		return GuacSession{}, fmt.Errorf("unsupported protocol %q", proto)
	}

	// 1) Create the ad-hoc session.
	out, code, err := s.guacDo(http.MethodPost, "/api/sessions", body)
	if err != nil {
		return GuacSession{}, err
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return GuacSession{}, fmt.Errorf("rustguac session create failed (%d): %s", code, string(out))
	}
	var sr struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(out, &sr); err != nil || sr.SessionID == "" {
		return GuacSession{}, fmt.Errorf("rustguac session: unexpected response: %s", string(out))
	}

	// 2) Mint a single-use WebSocket ticket (valid ~30s). Do this last and open
	// the browser promptly — guacd drops a session with no client in ~15s.
	out, code, err = s.guacDo(http.MethodPost, "/api/ws-ticket", nil)
	if err != nil {
		return GuacSession{}, err
	}
	if code != http.StatusOK && code != http.StatusCreated {
		return GuacSession{}, fmt.Errorf("rustguac ticket failed (%d): %s", code, string(out))
	}
	var tr struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(out, &tr); err != nil || tr.Ticket == "" {
		return GuacSession{}, fmt.Errorf("rustguac ticket: unexpected response: %s", string(out))
	}

	s.audit(p, p.OrgID, "console.advanced", "session", id, "", map[string]any{"proto": body["session_type"]})
	return GuacSession{SessionID: sr.SessionID, Ticket: tr.Ticket}, nil
}
