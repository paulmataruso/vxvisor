package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

// Snapshot, instant-clone and snapshot-policy endpoints (docs/SNAPSHOTS.md).
// Same service calls (authz, org scoping, immutability, audit) as the web UI.

func (a *API) snapshotRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/sessions/{id}/snapshots", a.auth("read", a.listSnapshots))
	mux.HandleFunc("POST /api/v1/sessions/{id}/snapshots", a.auth("write", a.createSnapshot))
	mux.HandleFunc("POST /api/v1/sessions/{id}/snapshots/{sid}/revert", a.auth("write", a.revertSnapshot))
	mux.HandleFunc("POST /api/v1/sessions/{id}/snapshots/{sid}/delete", a.auth("write", a.deleteSnapshot))
	mux.HandleFunc("POST /api/v1/sessions/{id}/clone", a.auth("write", a.cloneSession))
	mux.HandleFunc("GET /api/v1/snapshot-policies", a.auth("read", a.listSnapshotPolicies))
	mux.HandleFunc("POST /api/v1/snapshot-policies", a.auth("write", a.createSnapshotPolicy))
	mux.HandleFunc("POST /api/v1/snapshot-policies/{id}/delete", a.auth("write", a.deleteSnapshotPolicy))
	mux.HandleFunc("POST /api/v1/snapshot-policies/{id}/enable", a.auth("write", a.enableSnapshotPolicy))
	mux.HandleFunc("POST /api/v1/snapshot-policies/{id}/run", a.auth("write", a.runSnapshotPolicy))
}

type snapshotJSON struct {
	ID          int64    `json:"id"`
	SessionID   string   `json:"session_id"`
	Name        string   `json:"name"`
	Tag         string   `json:"tag"`
	Backend     string   `json:"backend"`
	Online      bool     `json:"online"`
	Consistency string   `json:"consistency"`
	PolicyID    int64    `json:"policy_id,omitempty"`
	PolicyName  string   `json:"policy_name,omitempty"`
	GroupID     string   `json:"group_id,omitempty"`
	Immutable   bool     `json:"immutable"`
	LockedUntil string   `json:"locked_until,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	CloneBase   bool     `json:"clone_base,omitempty"`
	Clones      []string `json:"dependent_clones,omitempty"`
	CreatedAt   string   `json:"created_at"`
}

func toSnapJSON(r session.SnapRecord) snapshotJSON {
	j := snapshotJSON{ID: r.ID, SessionID: r.SessionID, Name: r.Name, Tag: r.Tag, Backend: r.Backend,
		Online: r.Online, Consistency: r.Consistency, PolicyID: r.PolicyID, PolicyName: r.PolicyName,
		GroupID: r.GroupID, Immutable: r.Immutable, LockedUntil: r.LockedUntil, ExpiresAt: r.ExpiresAt,
		CloneBase: r.Transient, CreatedAt: r.CreatedAt}
	for _, c := range r.Clones {
		j.Clones = append(j.Clones, c.ID)
	}
	return j
}

// snapErr maps engine refusals to 409 Conflict.
func snapErr(w http.ResponseWriter, err error) {
	if errors.Is(err, service.ErrImmutable) || errors.Is(err, service.ErrHasClones) || errors.Is(err, session.ErrLockedSnapshots) {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeErr(w, err)
}

func (a *API) listSnapshots(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListSnapshots(p, r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	out := []snapshotJSON{}
	for _, s := range list {
		out = append(out, toSnapJSON(s))
	}
	writeJSON(w, 200, out)
}

func (a *API) createSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // name is optional
	sn, err := a.svc.CreateSnapshot(p, r.PathValue("id"), body.Name, ip(r))
	if err != nil {
		snapErr(w, err)
		return
	}
	writeJSON(w, 201, toSnapJSON(sn))
}

func (a *API) revertSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		DiscardNewer bool `json:"discard_newer"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	sid, _ := parseID(r.PathValue("sid"))
	if err := a.svc.RevertSnapshot(p, r.PathValue("id"), sid, body.DiscardNewer, ip(r)); err != nil {
		snapErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "reverted"})
}

func (a *API) deleteSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sid, _ := parseID(r.PathValue("sid"))
	if err := a.svc.DeleteSnapshot(p, r.PathValue("id"), sid, ip(r)); err != nil {
		snapErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (a *API) cloneSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name       string `json:"name"`
		SnapshotID int64  `json:"snapshot_id"` // 0 = from now (transient snapshot)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	s, err := a.svc.CloneSession(p, r.PathValue("id"), body.SnapshotID, body.Name, ip(r))
	if err != nil {
		snapErr(w, err)
		return
	}
	writeJSON(w, 201, s)
}

func (a *API) listSnapshotPolicies(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListSnapshotPolicies(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	if list == nil {
		list = []service.SnapshotPolicy{}
	}
	writeJSON(w, 200, list)
}

func (a *API) createSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		OrgID        int64  `json:"org_id"`
		Name         string `json:"name"`
		TargetKind   string `json:"target_kind"` // vm | folder | org
		TargetVM     string `json:"target_vm"`
		TargetFolder int64  `json:"target_folder"`
		Schedule     string `json:"schedule"` // hourly | daily | weekly
		AtHour       int    `json:"at_hour"`
		AtMinute     int    `json:"at_minute"`
		Weekday      int    `json:"weekday"` // 0 = Sunday
		KeepLast     int    `json:"keep_last"`
		KeepDays     int    `json:"keep_days"`
		Immutable    bool   `json:"immutable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.CreateSnapshotPolicy(p, service.PolicyInput{
		OrgID: body.OrgID, Name: body.Name, TargetKind: body.TargetKind, TargetVM: body.TargetVM,
		TargetFolder: body.TargetFolder, Schedule: body.Schedule, AtHour: body.AtHour, AtMinute: body.AtMinute,
		Weekday: body.Weekday, KeepLast: body.KeepLast, KeepDays: body.KeepDays, Immutable: body.Immutable,
	}, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]int64{"id": id})
}

func (a *API) deleteSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := parseID(r.PathValue("id"))
	if err := a.svc.DeleteSnapshotPolicy(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (a *API) enableSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, _ := parseID(r.PathValue("id"))
	if err := a.svc.SetSnapshotPolicyEnabled(p, id, body.Enabled, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"enabled": body.Enabled})
}

func (a *API) runSnapshotPolicy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := parseID(r.PathValue("id"))
	if err := a.svc.RunSnapshotPolicyNow(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 202, map[string]string{"status": "started"})
}

func parseID(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }
