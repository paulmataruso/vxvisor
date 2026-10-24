package api

import (
	"encoding/json"
	"net/http"

	"vdxclone/internal/service"
	"vdxclone/internal/vmexport"
	"vdxclone/internal/vmware"
)

// This file holds the Import / Export JSON endpoints: connect to a vCenter/ESXi
// and list its VMs, start a single-VM import, poll in-flight import/export
// progress, and start an export. Each is a thin wrapper over an existing service
// method — all authz (admin-gated, except export download-* which is member) +
// audit live in the service layer, so these only decode the body, call through,
// and map the error.
//
// The batch "Plan Migration" wizard (MigratePlan) and the per-job log-tail /
// download endpoints are intentionally NOT exposed here.
//
// registerMigrateRoutes wires these onto a mux. api.go's Routes does not call
// it; the parent wires it in later.
func (a *API) registerMigrateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/import/vmware/connect", a.auth("write", a.vmwareConnect))
	mux.HandleFunc("POST /api/v1/import/vmware/start", a.auth("write", a.vmwareImportStart))
	mux.HandleFunc("GET /api/v1/import/status", a.auth("read", a.vmwareImportStatus))
	mux.HandleFunc("GET /api/v1/export/status", a.auth("read", a.exportStatus))
	mux.HandleFunc("POST /api/v1/export/start", a.auth("write", a.exportStart))
}

// vmwareCreds is the shared connection body (snake_case). "host" maps to the
// vmware.Creds URL (an ldap-style host/URL accepted by the connector).
type vmwareCreds struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Insecure bool   `json:"insecure"`
}

func (c vmwareCreds) toCreds() vmware.Creds {
	return vmware.Creds{URL: c.Host, User: c.User, Pass: c.Pass, Insecure: c.Insecure}
}

// vmwareConnect connects read-only and returns the source VM inventory. The
// password is used in memory only (never audited).
func (a *API) vmwareConnect(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body vmwareCreds
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	vms, err := a.svc.VMwareConnectList(p, body.toCreds(), ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"vms": vms})
}

// vmwareImportStart kicks off a single-VM async import and returns its tracking
// id. Poll GET /api/v1/import/status for progress.
func (a *API) vmwareImportStart(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		vmwareCreds
		MOID         string `json:"moid"`
		OSType       string `json:"os_type"`
		Transport    string `json:"transport"`
		TargetPoolID int64  `json:"target_pool_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	id, err := a.svc.VMwareImport(p, body.toCreds(), body.MOID, body.OSType, body.Transport, body.TargetPoolID, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

// vmwareImportStatus returns in-flight + recent import rows (snake_case json tags
// on service.VMwareImportState).
func (a *API) vmwareImportStatus(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, 200, a.svc.VMwareImportStates(p))
}

// exportStatus returns in-flight + recent export rows (snake_case json tags on
// service.VMExportState).
func (a *API) exportStatus(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, 200, a.svc.ExportStates(p))
}

// exportStart kicks off an async export and returns its tracking id. target is
// download-image | download-ova | push; the pvc_* fields apply only to push.
func (a *API) exportStart(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		SessionID      string `json:"session_id"`
		Target         string `json:"target"`
		Format         string `json:"format"`
		PushURL        string `json:"pvc_url"`
		PushUser       string `json:"pvc_user"`
		PushPass       string `json:"pvc_pass"`
		PushInsecure   bool   `json:"pvc_insecure"`
		PushName       string `json:"pvc_name"`
		PushDatacenter string `json:"pvc_datacenter"`
		PushPool       string `json:"pvc_pool"`
		PushDatastore  string `json:"pvc_datastore"`
		PushFolder     string `json:"pvc_folder"`
		PushNetwork    string `json:"pvc_network"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	push := vmexport.Target{
		URL:          body.PushURL,
		User:         body.PushUser,
		Pass:         body.PushPass,
		Insecure:     body.PushInsecure,
		Name:         body.PushName,
		Datacenter:   body.PushDatacenter,
		ResourcePool: body.PushPool,
		Datastore:    body.PushDatastore,
		Folder:       body.PushFolder,
		Network:      body.PushNetwork,
	}
	id, err := a.svc.ExportVM(p, body.SessionID, body.Target, body.Format, push, ip(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}
