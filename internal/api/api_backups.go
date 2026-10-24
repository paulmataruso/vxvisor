package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
	"vdxclone/internal/sharedstg"
)

// Backup / backup-schedule / backup-target JSON endpoints, plus the iSCSI
// session list / login / logout. Thin wrappers over existing service methods;
// authorization + audit live in the service layer, so these just decode the
// request, call the method, and map the error.
//
// The parent wires this into Routes(); an unused method is not a compile error.
func (a *API) registerBackupRoutes(mux *http.ServeMux) {
	// Backups
	mux.HandleFunc("GET /api/v1/backups", a.auth("read", a.listBackups))
	mux.HandleFunc("POST /api/v1/backups/create", a.auth("write", a.createBackup))
	mux.HandleFunc("POST /api/v1/backups/{id}/restore", a.auth("write", a.restoreBackup))
	mux.HandleFunc("POST /api/v1/backups/{id}/delete", a.auth("write", a.deleteBackup))
	// Schedules
	mux.HandleFunc("GET /api/v1/backup-schedules", a.auth("read", a.listSchedules))
	mux.HandleFunc("POST /api/v1/backup-schedules/create", a.auth("write", a.createSchedule))
	mux.HandleFunc("POST /api/v1/backup-schedules/{id}/delete", a.auth("write", a.deleteSchedule))
	// Targets
	mux.HandleFunc("GET /api/v1/backup-targets", a.auth("read", a.listBackupTargets))
	mux.HandleFunc("POST /api/v1/backup-targets", a.auth("write", a.createBackupTarget))
	mux.HandleFunc("POST /api/v1/backup-targets/{id}/delete", a.auth("write", a.deleteBackupTarget))
	mux.HandleFunc("POST /api/v1/backup-targets/{id}/test", a.auth("write", a.testBackupTarget))
	// iSCSI
	mux.HandleFunc("GET /api/v1/iscsi", a.auth("read", a.listISCSI))
	mux.HandleFunc("POST /api/v1/iscsi/login", a.auth("write", a.iscsiLogin))
	mux.HandleFunc("POST /api/v1/iscsi/{id}/logout", a.auth("write", a.iscsiLogout))
}

// ---- backups -------------------------------------------------------------

func (a *API) listBackups(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListBackups(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) createBackup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		SessionID string `json:"session_id"`
		Name      string `json:"name"`
		TargetID  int64  `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if body.Name == "" {
		body.Name = "manual"
	}
	id, err := a.svc.CreateBackup(p, body.SessionID, body.Name, body.TargetID, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

func (a *API) restoreBackup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	img, err := a.svc.RestoreBackup(p, id, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"image": img})
}

func (a *API) deleteBackup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteBackup(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- backup schedules ----------------------------------------------------

func (a *API) listSchedules(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListSchedules(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) createSchedule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		SessionID     string `json:"session_id"`
		IntervalHours int    `json:"interval_hours"`
		Keep          int    `json:"keep"`
		TargetID      int64  `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.CreateSchedule(p, body.SessionID, body.IntervalHours, body.Keep, body.TargetID, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) deleteSchedule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteSchedule(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- backup targets ------------------------------------------------------

func (a *API) listBackupTargets(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListBackupTargets(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) createBackupTarget(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Path     string `json:"path"`
		Server   string `json:"server"`
		Share    string `json:"share"`
		Username string `json:"username"`
		Password string `json:"password"`
		Domain   string `json:"domain"`
		Vers     string `json:"vers"`
		Options  string `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.CreateBackupTarget(p, service.BackupTargetInput{
		Name: body.Name, Kind: body.Kind, Path: body.Path, Server: body.Server,
		Share: body.Share, Username: body.Username, Password: body.Password,
		Domain: body.Domain, Vers: body.Vers, Options: body.Options,
	}, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": id})
}

func (a *API) deleteBackupTarget(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteBackupTarget(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// testBackupTarget mounts (if needed) and write-probes the target. The service
// returns only an error, so success is reported as a fixed human message.
func (a *API) testBackupTarget(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.TestBackupTarget(p, id); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "target is reachable and writable"})
}

// ---- iSCSI ---------------------------------------------------------------

func (a *API) listISCSI(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListISCSI(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) iscsiLogin(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Portal     string `json:"portal"`
		Target     string `json:"target"`
		ChapUser   string `json:"chap_user"`
		ChapPass   string `json:"chap_pass"`
		ChapUserIn string `json:"chap_user_in"`
		ChapPassIn string `json:"chap_pass_in"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	chap := sharedstg.CHAP{
		Username: body.ChapUser, Password: body.ChapPass,
		InUsername: body.ChapUserIn, InPassword: body.ChapPassIn,
	}
	if err := a.svc.ISCSILogin(p, body.Portal, body.Target, chap, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *API) iscsiLogout(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.ISCSILogout(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
