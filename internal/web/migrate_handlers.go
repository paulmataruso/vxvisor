package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"vdxclone/internal/service"
	"vdxclone/internal/storage"
	"vdxclone/internal/vmexport"
)

// migrate renders the dedicated Import / Export page (admin only). It carries the
// vCenter import flow (moved off /cluster), the VDDK accelerator, the batch "Plan
// Migration" wizard, and VM export.
func (s *Server) migrate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	var pools []storage.Pool
	pools, _ = s.svc.ListPools(p)
	networks, _ := s.svc.ListNetworks(p)
	sessions, _ := s.svc.ListSessions(p)
	importedImages, _ := s.svc.ImportedImages(p)
	defaultTransport := "datastore"
	if s.svc.VDDKReady(p) {
		defaultTransport = "vddk"
	}
	s.render(w, p, "migrate.html", "migrate", map[string]any{
		"Pools":            pools,
		"Networks":         networks,
		"Sessions":         sessions,
		"ImportedImages":   importedImages,
		"VDDKReady":        s.svc.VDDKReady(p),
		"VDDKInstalled":    s.svc.VDDKInstalled(p),
		"VDDKLibDir":       s.svc.VDDKLibDir(),
		"DefaultTransport": defaultTransport,
	})
}

// migratePlanStart runs a batch migration. The wizard posts a normal form (so
// CSRF applies) carrying the vCenter creds plus a hidden "plan" field holding the
// ordered per-VM rows as JSON.
func (s *Server) migratePlanStart(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	var rows []struct {
		MOID         string `json:"moid"`
		Name         string `json:"name"`
		OSType       string `json:"os_type"`
		Transport    string `json:"transport"`
		TargetPoolID int64  `json:"target_pool_id"`
		NetworkID    int64  `json:"network_id"`
		CPUs         int    `json:"cpus"`
		MemMB        int    `json:"mem_mb"`
		Firmware     string `json:"firmware"`
	}
	if err := json.Unmarshal([]byte(r.FormValue("plan")), &rows); err != nil {
		setFlash(w, "could not read migration plan: "+err.Error())
		http.Redirect(w, r, "/migrate", http.StatusSeeOther)
		return
	}
	items := make([]service.PlanItem, 0, len(rows))
	for _, rrow := range rows {
		items = append(items, service.PlanItem{
			MOID: rrow.MOID, Name: rrow.Name, OSType: rrow.OSType, Transport: rrow.Transport,
			TargetPoolID: rrow.TargetPoolID, NetworkID: rrow.NetworkID,
			CPUs: rrow.CPUs, MemMB: rrow.MemMB, Firmware: rrow.Firmware,
		})
	}
	if _, err := s.svc.MigratePlan(p, vmwareCredsFromForm(r), items, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Migration plan started — importing the selected VMs in order. Watch progress below; each becomes a ready-to-run instance as it completes.")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// ---- export --------------------------------------------------------------

func (s *Server) exportStart(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	target := r.FormValue("target")
	format := r.FormValue("format")
	var push vmexport.Target
	if target == "push" {
		push = vmexport.Target{
			URL:          r.FormValue("pvc_url"),
			User:         r.FormValue("pvc_user"),
			Pass:         r.FormValue("pvc_pass"),
			Insecure:     r.FormValue("pvc_insecure") != "",
			Name:         r.FormValue("pvc_name"),
			Datacenter:   r.FormValue("pvc_datacenter"),
			ResourcePool: r.FormValue("pvc_pool"),
			Datastore:    r.FormValue("pvc_datastore"),
			Folder:       r.FormValue("pvc_folder"),
			Network:      r.FormValue("pvc_network"),
		}
	}
	if _, err := s.svc.ExportVM(p, r.FormValue("session_id"), target, format, push, clientIP(r)); err != nil {
		setFlash(w, "export: "+err.Error())
	} else {
		setFlashOK(w, "Export started — watch progress below. A download link appears when it's ready (push uploads straight to the target vCenter).")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// apiExport returns live/recent export progress for the poller.
func (s *Server) apiExport(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, map[string]any{"exports": s.svc.ExportStates(p)})
}

// imageDelete removes an imported base image (row + file) left behind by a
// VMware import, from the "Imported base images" card on the migrate page.
func (s *Server) imageDelete(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteBaseImage(p, r.PathValue("name"), clientIP(r)); err != nil {
		setFlash(w, "Delete failed: "+err.Error())
	} else {
		setFlashOK(w, "Imported base image deleted.")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// exportDelete removes a finished export's file from disk (XHR from the export
// table's Delete button), so exported images don't linger after download.
func (s *Server) exportDelete(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteExport(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// apiExportLog serves one export's durable log as plain text.
func (s *Server) apiExportLog(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	txt, err := s.svc.VMExportLog(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(txt))
}

// exportDownload streams a finished disk-image/OVA export to the browser as an
// attachment. http.ServeContent gives Range support (resumable downloads) and
// sets Content-Length from the file.
func (s *Server) exportDownload(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	path, filename, err := s.svc.ExportDownload(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeHeader(filename)+"\"")
	http.ServeContent(w, r, filename, fi.ModTime(), f)
}

// sanitizeHeader strips characters that would break a Content-Disposition header.
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "\\", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	if s == "" {
		return "export.bin"
	}
	return s
}
