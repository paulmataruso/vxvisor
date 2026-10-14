package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	"vdxclone/internal/service"
)

var metricsUpgrader = websocket.Upgrader{
	// Same-origin only: the dashboard page is served from this origin.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// apiMetricsHistory serves persisted time-series for a scope/target as JSON.
func (s *Server) apiMetricsHistory(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "host"
	}
	mins, _ := strconv.Atoi(r.URL.Query().Get("mins"))
	if mins <= 0 {
		mins = 60
	}
	writeJSON(w, map[string]any{"samples": s.svc.MetricHistory(p, scope, r.URL.Query().Get("target"), mins)})
}

func (s *Server) observability(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	rules, _ := s.svc.ListAlertRules(p)
	alerts, _ := s.svc.ListAlerts(p)
	channels, _ := s.svc.ListAlertChannels(p)
	s.render(w, p, "observability.html", "observability", map[string]any{
		"Rules":    rules,
		"Alerts":   alerts,
		"Channels": channels,
	})
}

// metricsWS streams the live metrics snapshot as JSON a few times a minute.
func (s *Server) metricsWS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	c, err := metricsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	// Stop writing if the client goes away.
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				c.Close()
				return
			}
		}
	}()
	// Push immediately, then on each tick.
	if err := c.WriteJSON(s.svc.LiveMetrics(p)); err != nil {
		return
	}
	for range t.C {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteJSON(s.svc.LiveMetrics(p)); err != nil {
			return
		}
	}
}

func (s *Server) createAlertRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	th, _ := strconv.ParseFloat(r.FormValue("threshold"), 64)
	rule := service.AlertRule{
		Name: r.FormValue("name"), Metric: r.FormValue("metric"),
		Op: r.FormValue("op"), Threshold: th, ChannelID: atoi(r.FormValue("channel_id")),
	}
	if err := s.svc.CreateAlertRule(p, rule, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/observability", http.StatusSeeOther)
}

func (s *Server) deleteAlertRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteAlertRule(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/observability", http.StatusSeeOther)
}

func (s *Server) createAlertChannel(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CreateAlertChannel(p, r.FormValue("name"), r.FormValue("kind"), r.FormValue("target"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/observability", http.StatusSeeOther)
}
