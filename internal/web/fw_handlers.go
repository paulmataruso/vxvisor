package web

import (
	"net/http"

	"vdxclone/internal/service"
)

// Unified NSX-style firewall UI (one page, drag-and-drop groups/zones + N-S/E-W
// rule tables). All routes are org-scoped (the org comes from the principal, not
// the path). Mutations go through fwDo, which supports both a drag-and-drop
// fetch (?ajax=1 → JSON) and a classic form POST (→ redirect) fallback.

func (s *Server) fwPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	view, err := s.svc.ListFirewallView(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, p, "vfirewall.html", "vfirewall", map[string]any{
		"FW":     view,
		"Protos": []string{"any", "tcp", "udp", "icmp"},
	})
}

// fwDo runs a mutation and responds as JSON for a drag-and-drop fetch (?ajax=1)
// or redirects to /vfirewall for a plain form POST.
func (s *Server) fwDo(w http.ResponseWriter, r *http.Request, p *service.Principal, fn func() error) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	err := fn()
	if r.URL.Query().Get("ajax") != "" || r.FormValue("ajax") != "" {
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})
		return
	}
	if err != nil {
		setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/vfirewall", http.StatusSeeOther)
}

func (s *Server) fwSetEnabled(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWSetEnabled(p, r.FormValue("enabled") != "", clientIP(r))
	})
}

func (s *Server) fwAddGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		_, err := s.svc.FWAddGroup(p, r.FormValue("name"), clientIP(r))
		return err
	})
}

func (s *Server) fwRenameGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWRenameGroup(p, r.PathValue("gid"), r.FormValue("name"), clientIP(r))
	})
}

func (s *Server) fwDelGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWDelGroup(p, r.PathValue("gid"), clientIP(r))
	})
}

func (s *Server) fwSetGroupMembers(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		_ = r.ParseForm()
		var nets []int64
		for _, n := range r.Form["net"] {
			if id := atoi(n); id > 0 {
				nets = append(nets, id)
			}
		}
		return s.svc.FWSetGroupMembers(p, r.PathValue("gid"), r.Form["mac"], nets, clientIP(r))
	})
}

func (s *Server) fwSetGroupZone(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWSetGroupZone(p, r.PathValue("gid"), r.FormValue("zone"), clientIP(r))
	})
}

func fwRuleFromForm(r *http.Request) service.FWRule {
	return service.FWRule{
		From:   r.FormValue("from"),
		FromVM: r.FormValue("from_vm"),
		To:     r.FormValue("to"),
		ToVM:   r.FormValue("to_vm"),
		Action: r.FormValue("action"),
		Proto:  r.FormValue("proto"),
		DPort:  r.FormValue("dport"),
		Desc:   r.FormValue("desc"),
	}
}

// ruleDir normalises the section path value to "ns" or "ew".
func ruleDir(r *http.Request) string {
	if r.PathValue("dir") == "ew" {
		return "ew"
	}
	return "ns"
}

func (s *Server) fwAddRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		dir := "ns"
		if r.FormValue("dir") == "ew" {
			dir = "ew"
		}
		return s.svc.FWAddRule(p, dir, fwRuleFromForm(r), r.FormValue("reverse") != "", clientIP(r))
	})
}

func (s *Server) fwDelRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWDelRule(p, ruleDir(r), int(atoi(r.PathValue("i"))), clientIP(r))
	})
}

func (s *Server) fwUpdateRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWUpdateRule(p, ruleDir(r), int(atoi(r.PathValue("i"))), fwRuleFromForm(r), clientIP(r))
	})
}

func (s *Server) fwMoveRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.fwDo(w, r, p, func() error {
		return s.svc.FWMoveRule(p, ruleDir(r), int(atoi(r.PathValue("i"))), r.FormValue("step"), clientIP(r))
	})
}
