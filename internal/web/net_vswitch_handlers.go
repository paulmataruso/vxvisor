package web

import (
	"net/http"

	"vdxclone/internal/service"
)

func (s *Server) createBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	name := r.FormValue("name")
	mode := r.FormValue("mode")
	hash := r.FormValue("hash_policy")
	members := r.Form["members"]
	// If the user chose a vSwitch to attach to, create the bond AND migrate that
	// vSwitch's uplink onto it in one safe step (its current uplink is kept in the
	// team). Otherwise create a standalone bond to attach later.
	if vsw := r.FormValue("attach_vswitch"); vsw != "" {
		if err := s.svc.UpgradeVSwitchToBond(p, vsw, name, mode, hash, members, clientIP(r)); err != nil {
			http.Error(w, err.Error(), statusFor(err))
			return
		}
		setFlashOK(w, "Bond "+name+" created and attached to "+vsw+".")
		http.Redirect(w, r, "/networks", http.StatusSeeOther)
		return
	}
	if err := s.svc.CreateBond(p, name, mode, hash, members, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// bondVSwitch upgrades a vSwitch's uplink to a NIC team (bond) in one operation:
// create the bond from the current uplink + the selected NICs, then repoint the
// vSwitch onto it (netplan + rollback for the mgmt vSwitch, live for the rest).
func (s *Server) bondVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	name := r.PathValue("name")
	err := s.svc.UpgradeVSwitchToBond(p, name,
		r.FormValue("bond_name"), r.FormValue("mode"), r.FormValue("hash_policy"),
		r.Form["members"], clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "vSwitch "+name+" uplink upgraded to a bonded team.")
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteBond(p, r.PathValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) createVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CreateVSwitch(p, r.FormValue("name"), r.FormValue("uplink"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteVSwitch(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteVSwitch(p, r.PathValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}
