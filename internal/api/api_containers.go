package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

// LXC container JSON endpoints. Thin wrappers over existing service methods;
// authz + audit live in the service layer. Create is asynchronous (the rootfs
// download runs in the background), mirroring the web handler.
//
// The parent wires this into Routes(); an unused method is not a compile error.
func (a *API) registerContainerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/containers", a.auth("read", a.listContainers))
	mux.HandleFunc("POST /api/v1/containers", a.auth("write", a.createContainer))
	mux.HandleFunc("POST /api/v1/containers/{id}/start", a.auth("write", a.startContainer))
	mux.HandleFunc("POST /api/v1/containers/{id}/stop", a.auth("write", a.stopContainer))
	mux.HandleFunc("POST /api/v1/containers/{id}/delete", a.auth("write", a.deleteContainer))
	mux.HandleFunc("POST /api/v1/containers/{id}/snapshot", a.auth("write", a.snapshotContainer))
}

func (a *API) listContainers(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListContainers(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

// createContainer provisions one or more LXC containers (status starts at
// "creating"; poll GET /containers for completion).
func (a *API) createContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name          string `json:"name"`
		Dist          string `json:"dist"`
		Release       string `json:"release"`
		Bridge        string `json:"bridge"`
		CPUs          int    `json:"cpus"`
		MemoryMB      int    `json:"memory_mb"`
		StoragePoolID int64  `json:"storage_pool_id"`
		DiskGB        int    `json:"disk_gb"`
		Copies        int    `json:"copies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.CreateContainer(p, service.CreateContainerInput{
		Name: body.Name, Dist: body.Dist, Release: body.Release, Bridge: body.Bridge,
		CPUs: body.CPUs, MemoryMB: body.MemoryMB, StoragePoolID: body.StoragePoolID,
		DiskGB: body.DiskGB, Copies: body.Copies,
	}, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 202, map[string]any{"status": "creating"})
}

func (a *API) startContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.StartContainer(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"state": "running"})
}

func (a *API) stopContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.StopContainer(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"state": "stopped"})
}

func (a *API) deleteContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.DeleteContainer(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "deleted"})
}

func (a *API) snapshotContainer(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.SnapshotContainer(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
