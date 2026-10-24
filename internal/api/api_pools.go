package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"vdxclone/internal/service"
)

// Storage JSON endpoints: registered storage pools (+ datastore browser),
// shared mounts (NFS/CIFS/Ceph), the on-node Ceph cluster status, and read-only
// ZFS / LVM-thin / mdraid listings. Thin wrappers over existing service methods;
// authz + audit live in the service layer.
//
// The parent wires this into Routes(); an unused method is not a compile error.
func (a *API) registerPoolRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/pools", a.auth("read", a.listPools))
	mux.HandleFunc("POST /api/v1/pools", a.auth("write", a.upsertPool))
	mux.HandleFunc("POST /api/v1/pools/{id}/delete", a.auth("write", a.deletePool))
	mux.HandleFunc("GET /api/v1/pools/{id}/browse", a.auth("read", a.browsePool))
	mux.HandleFunc("GET /api/v1/shared", a.auth("read", a.listShared))
	mux.HandleFunc("POST /api/v1/shared/nfs", a.auth("write", a.addNFS))
	mux.HandleFunc("POST /api/v1/shared/cifs", a.auth("write", a.addCIFS))
	mux.HandleFunc("POST /api/v1/shared/ceph", a.auth("write", a.addCeph))
	mux.HandleFunc("POST /api/v1/shared/{id}/unmount", a.auth("write", a.unmountShared))
	mux.HandleFunc("GET /api/v1/ceph", a.auth("read", a.cephStatus))
	// GET-only ZFS / LVM-thin / mdraid listings. Destructive create/destroy is
	// intentionally not exposed here (those wipe disks).
	mux.HandleFunc("GET /api/v1/zfs/pools", a.auth("read", a.listZFSPools))
	mux.HandleFunc("GET /api/v1/lvm/pools", a.auth("read", a.listLVMPools))
	mux.HandleFunc("GET /api/v1/mdraid", a.auth("read", a.listMDArrays))
}

// ---- registered storage pools --------------------------------------------

func (a *API) listPools(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListPools(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

// upsertPool registers (or updates) a pool pointing at an existing backend.
func (a *API) upsertPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.UpsertPool(p, body.Name, body.Kind, body.Path, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

// deletePool removes a pool registry row. The service deletes by name (names can
// contain "/" for LVM "vg/pool"), so we resolve the numeric path id to its name.
func (a *API) deletePool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	pools, err := a.svc.ListPools(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	name := ""
	for _, pl := range pools {
		if pl.ID == id {
			name = pl.Name
			break
		}
	}
	if name == "" {
		writeErr(w, service.ErrNotFound)
		return
	}
	if err := a.svc.DeleteStoragePool(p, name, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// browsePool returns a read-only file/volume listing of one pool.
func (a *API) browsePool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	pool, entries, err := a.svc.BrowsePool(p, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"name": pool.Name, "kind": pool.Kind, "path": pool.Path, "entries": entries,
	})
}

// ---- shared mounts (NFS / CIFS / Ceph) ------------------------------------

func (a *API) listShared(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ListSharedMounts(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) addNFS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name    string `json:"name"`
		Server  string `json:"server"`
		Export  string `json:"export"`
		Vers    string `json:"vers"`
		Options string `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AddNFS(p, body.Name, body.Server, body.Export, body.Vers, body.Options, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) addCIFS(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name     string `json:"name"`
		UNC      string `json:"unc"`
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
	if err := a.svc.AddCIFS(p, body.Name, body.UNC, body.Username, body.Password, body.Domain, body.Vers, body.Options, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) addCeph(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	var body struct {
		Name     string `json:"name"`
		Mons     string `json:"mons"`
		Path     string `json:"path"`
		CephName string `json:"ceph_name"`
		Secret   string `json:"secret"`
		Options  string `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if err := a.svc.AddCeph(p, body.Name, body.Mons, body.Path, body.CephName, body.Secret, body.Options, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"ok": true})
}

func (a *API) unmountShared(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.svc.UnmountShared(p, id, ip(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Ceph cluster status --------------------------------------------------

func (a *API) cephStatus(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	h, err := a.svc.CephStatus(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, h)
}

// ---- read-only ZFS / LVM-thin / mdraid listings ---------------------------

func (a *API) listZFSPools(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.ZFSPools(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) listLVMPools(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := a.svc.LVMThinPools(p)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *API) listMDArrays(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, 200, a.svc.ListMDArrays(p))
}
