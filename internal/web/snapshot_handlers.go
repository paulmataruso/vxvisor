package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"vdxclone/internal/service"
)

// ---- snapshots + instant clones (instance page) --------------------------

func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	sn, err := s.svc.CreateSnapshot(p, id, r.FormValue("name"), clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, fmt.Sprintf("Snapshot %q taken (%s).", sn.Name, sn.Consistency))
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) revertSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	if err := s.svc.RevertSnapshot(p, id, atoi(r.PathValue("sid")), r.FormValue("discard_newer") == "1", clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "Instance reverted to the snapshot.")
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	if err := s.svc.DeleteSnapshot(p, id, atoi(r.PathValue("sid")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "Snapshot deleted.")
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) cloneSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	clone, err := s.svc.CloneSession(p, id, atoi(r.FormValue("snapshot_id")), r.FormValue("name"), clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "Instant clone "+clone.Name+" created (stopped).")
	http.Redirect(w, r, "/instances/"+clone.ID, http.StatusSeeOther)
}

// ---- snapshot policies ---------------------------------------------------

func (s *Server) snapshotPolicies(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	pols, err := s.svc.ListSnapshotPolicies(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	form, _ := s.svc.SnapshotPolicyForm(p)
	data := map[string]any{"Policies": pols, "Form": form}
	if pid := atoi(r.URL.Query().Get("policy")); pid > 0 {
		if snaps, err := s.svc.PolicySnapshots(p, pid); err == nil {
			data["PolicySnaps"] = snaps
			data["SelectedID"] = pid
			for _, pl := range pols {
				if pl.ID == pid {
					data["SelectedName"] = pl.Name
				}
			}
		}
	}
	s.render(w, p, "snapshot_policies.html", "snapshot-policies", data)
}

// parseHHMM parses "HH:MM" (an <input type=time> value).
func parseHHMM(v string) (h, m int, err error) {
	hs, ms, ok := strings.Cut(strings.TrimSpace(v), ":")
	if !ok {
		return 0, 0, fmt.Errorf("time must be HH:MM")
	}
	h, e1 := strconv.Atoi(hs)
	m, e2 := strconv.Atoi(ms)
	if e1 != nil || e2 != nil {
		return 0, 0, fmt.Errorf("time must be HH:MM")
	}
	return h, m, nil
}

func (s *Server) createSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	in := service.PolicyInput{
		OrgID:        atoi(r.FormValue("org_id")),
		Name:         r.FormValue("name"),
		TargetKind:   r.FormValue("target_kind"),
		TargetVM:     r.FormValue("target_vm"),
		TargetFolder: atoi(r.FormValue("target_folder")),
		Schedule:     r.FormValue("schedule"),
		Weekday:      atoiInt(r.FormValue("weekday")),
		KeepLast:     atoiInt(r.FormValue("keep_last")),
		KeepDays:     atoiInt(r.FormValue("keep_days")),
		Immutable:    r.FormValue("immutable") == "1",
	}
	if in.Schedule == "hourly" {
		in.AtMinute = atoiInt(r.FormValue("minute"))
	} else {
		h, m, err := parseHHMM(r.FormValue("at"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		in.AtHour, in.AtMinute = h, m
	}
	if _, err := s.svc.CreateSnapshotPolicy(p, in, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "Snapshot policy "+strings.TrimSpace(in.Name)+" created.")
	http.Redirect(w, r, "/snapshot-policies", http.StatusSeeOther)
}

func (s *Server) deleteSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteSnapshotPolicy(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "Snapshot policy deleted; its snapshots were kept.")
	http.Redirect(w, r, "/snapshot-policies", http.StatusSeeOther)
}

func (s *Server) toggleSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	on := r.FormValue("enabled") == "1"
	if err := s.svc.SetSnapshotPolicyEnabled(p, atoi(r.PathValue("id")), on, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	if on {
		setFlashOK(w, "Snapshot policy resumed.")
	} else {
		setFlashOK(w, "Snapshot policy paused.")
	}
	http.Redirect(w, r, "/snapshot-policies", http.StatusSeeOther)
}

func (s *Server) runSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := atoi(r.PathValue("id"))
	if err := s.svc.RunSnapshotPolicyNow(p, id, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	setFlashOK(w, "Snapshot policy run started; refresh to see its result.")
	http.Redirect(w, r, "/snapshot-policies?policy="+strconv.FormatInt(id, 10), http.StatusSeeOther)
}
