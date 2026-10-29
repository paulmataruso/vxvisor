package web

import (
	"fmt"
	"net/http"
	"strings"

	"vdxclone/internal/service"
)

// Tenant networking v3 — the instance-admin "Tenant Egress" console (/trunks):
// designate external trunks, define per-tenant VLAN pools, create/bind tenant
// uplinks (access / qinq / dedicated NIC), verify QinQ, and the global teardown.
// Everything is editable in place, and the "+ Add tenant egress" wizard sets up a
// tenant's trunk, pool, uplink and vSwitch in one go.

func (s *Server) trunksPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	trunks, _ := s.svc.ListExtTrunks(p)
	uplinks, _ := s.svc.ListAllUplinks(p)
	pools, _ := s.svc.ListVlanPools(p)
	orgs, _ := s.svc.ListOrgsLite(p)
	cands, _ := s.svc.TransitCandidates(p)      // free NICs/bonds (already excludes trunks/mgmt/storage)
	shared, _ := s.svc.SharedTrunkCandidates(p) // mgmt vSwitch uplink(s) — access-only shared trunks
	tnets, _ := s.svc.AllTenantNetworks(p)
	s.render(w, p, "trunks.html", "trunks", map[string]any{
		"Trunks":      trunks,
		"Uplinks":     uplinks,
		"Pools":       pools,
		"Orgs":        orgs,
		"Candidates":  cands,
		"SharedCands": shared,
		"TenantNets":  tnets,
	})
}

func (s *Server) designateTrunk(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DesignateTrunk(p, r.FormValue("iface"), r.FormValue("qinq") == "1",
		int(atoi(r.FormValue("mtu"))), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "External trunk designated.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) undesignateTrunk(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.UndesignateTrunk(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Trunk removed and its original MTU/offload restored.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) editTrunk(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.UpdateTrunk(p, atoi(r.PathValue("id")), int(atoi(r.FormValue("mtu"))),
		r.FormValue("qinq") == "1", clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Trunk updated.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

// verifyTrunkQinQ is an AJAX check: are offloads off + MTU high enough on this NIC?
func (s *Server) verifyTrunkQinQ(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	ok, detail, err := s.svc.VerifyTrunkQinQ(p, atoi(r.PathValue("id")))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, map[string]any{"ok": ok, "detail": detail})
}

func (s *Server) setVlanPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.SetVlanPool(p, atoi(r.FormValue("org_id")), atoi(r.FormValue("trunk_id")),
		int(atoi(r.FormValue("vid_min"))), int(atoi(r.FormValue("vid_max"))), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "VLAN pool saved.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) deleteVlanPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteVlanPool(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "VLAN pool removed.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) createUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_, err := s.svc.CreateUplink(p, atoi(r.FormValue("org_id")), r.FormValue("name"), r.FormValue("mode"),
		atoi(r.FormValue("trunk_id")), int(atoi(r.FormValue("vid"))), r.FormValue("ded_iface"), clientIP(r))
	if err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Uplink created. The tenant can now connect a network to it from their Networks page.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

// editUplink saves an uplink's name / wiring / tag, then which vSwitch it is
// connected to.
func (s *Server) editUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := atoi(r.PathValue("id"))
	err := s.svc.UpdateUplink(p, id, r.FormValue("name"), r.FormValue("mode"), atoi(r.FormValue("trunk_id")),
		int(atoi(r.FormValue("vid"))), r.FormValue("ded_iface"), clientIP(r))
	if err == nil {
		err = s.svc.SetUplinkConnection(p, id, atoi(r.FormValue("tnet_id")), clientIP(r))
	}
	if err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Uplink updated.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

// egressWizard runs "+ Add tenant egress": trunk → pool → uplink → vSwitch.
func (s *Server) egressWizard(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	f := r.FormValue
	wz := service.EgressWizard{OrgID: atoi(f("org_id")), Mode: f("mode")}
	if f("trunk_choice") == "new" {
		wz.NewIface, wz.NewMTU, wz.NewQinQ = f("new_iface"), int(atoi(f("new_mtu"))), f("new_qinq") == "1"
	} else {
		wz.TrunkID = atoi(f("trunk_id"))
	}
	wz.PoolMin, wz.PoolMax = int(atoi(f("pool_min"))), int(atoi(f("pool_max")))
	if f("uplink_choice") == "existing" {
		wz.UplinkID = atoi(f("uplink_id"))
	} else {
		wz.UplinkName = f("uplink_name")
		if f("vid_auto") != "1" {
			wz.VID = int(atoi(f("vid")))
		}
	}
	switch f("vs_choice") {
	case "new":
		wz.VSwitchName, wz.VSwitchCIDR, wz.MakeDefault = f("vs_name"), f("vs_cidr"), f("vs_default") == "1"
	case "existing":
		wz.VSwitchID = atoi(f("vs_id"))
	}
	res, err := s.svc.ProvisionTenantEgress(p, wz, clientIP(r))
	if err != nil {
		setFlash(w, err.Error())
	} else {
		msg := []string{fmt.Sprintf("Tenant egress set up for %s: trunk %s", res.Org, res.Trunk)}
		if res.Pool != "" {
			msg = append(msg, "VLAN pool "+res.Pool)
		}
		msg = append(msg, "uplink "+res.Uplink)
		if res.VSwitch != "" {
			msg = append(msg, "connected to vSwitch "+res.VSwitch)
		}
		setFlashOK(w, strings.Join(msg, ", ")+".")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) deleteUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteUplink(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Uplink removed.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}

func (s *Server) disableTenantEgress(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DisableTenantEgress(p, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Tenant egress disabled — all subinterfaces torn down and trunks restored to their original state.")
	}
	http.Redirect(w, r, "/trunks", http.StatusSeeOther)
}
