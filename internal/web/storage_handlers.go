package web

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/image"
	"vdxclone/internal/service"
	"vdxclone/internal/storage"
	"vdxclone/internal/zfs"
)

// ---- ISO library ---------------------------------------------------------

func (s *Server) isos(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := s.svc.ListISOs(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "isos.html", "isos", map[string]any{"ISOs": list})
}

func (s *Server) uploadISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	// NOTE: CSRF is validated from the streamed "csrf" part below, NOT via
	// s.checkCSRF here — that calls ParseMultipartForm and would consume the body
	// before MultipartReader can stream it.
	// Stream the file part DIRECTLY to the ISO store. We do NOT use
	// ParseMultipartForm/FormFile here: those spill the whole upload to a temp
	// file under os.TempDir() first (which is tmpfs/RAM on this host), so a
	// multi-GB ISO fills RAM and crashes the server. MultipartReader lets us copy
	// the file part straight to disk with no intermediate buffer. The form sends
	// csrf and name before the file, so we can validate and name as we go.
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected a multipart upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	var csrfOK bool
	var name string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "csrf":
			b, _ := io.ReadAll(io.LimitReader(part, 512))
			csrfOK = strings.TrimSpace(string(b)) == csrfToken(p.Token())
		case "name":
			b, _ := io.ReadAll(io.LimitReader(part, 1024))
			name = strings.TrimSpace(string(b))
		case "iso":
			if !csrfOK { // CSRF must have arrived before the file
				s.badCSRF(w)
				return
			}
			if name == "" {
				name = part.FileName()
			}
			id, err := s.svc.UploadISO(p, name, part, clientIP(r))
			if err != nil {
				http.Error(w, err.Error(), statusFor(err))
				return
			}
			if r.URL.Query().Get("ajax") == "1" {
				writeJSON(w, map[string]any{"ok": true, "id": id, "name": name})
				return
			}
			http.Redirect(w, r, "/isos", http.StatusSeeOther)
			return
		}
		part.Close()
	}
	http.Error(w, "no file uploaded", http.StatusBadRequest)
}

func (s *Server) pullISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id, err := s.svc.PullISO(p, r.FormValue("name"), r.FormValue("url"), clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	if r.URL.Query().Get("ajax") == "1" {
		writeJSON(w, map[string]any{"ok": true, "id": id, "name": r.FormValue("name")})
		return
	}
	http.Redirect(w, r, "/isos", http.StatusSeeOther)
}

// apiISOs returns the org's ISOs as JSON (id/name/status/size) so the upload
// and URL-download toasts can poll for completion without a full page reload.
func (s *Server) apiISOs(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := s.svc.ListISOs(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, i := range list {
		out = append(out, map[string]any{"id": i.ID, "name": i.Name, "status": i.Status, "size": i.SizeBytes})
	}
	writeJSON(w, map[string]any{"isos": out})
}

func (s *Server) deleteISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteISO(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/isos", http.StatusSeeOther)
}

// ---- templates -----------------------------------------------------------

func (s *Server) templates(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := s.svc.ListTemplates(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "templates.html", "templates", map[string]any{
		"Templates": list,
		"Images":    imageNames(s),
	})
}

// imageNames returns the names of ready base images for select menus.
func imageNames(s *Server) []string {
	imgs, _ := image.List(s.svc.DB())
	var out []string
	for _, im := range imgs {
		if im.Status == "ready" {
			out = append(out, im.Name)
		}
	}
	return out
}

func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	disk, _ := strconv.Atoi(r.FormValue("disk_gb"))
	t := storage.Template{
		Name: r.FormValue("name"), ImageName: r.FormValue("image"),
		Kind: r.FormValue("kind"), Firmware: r.FormValue("firmware"),
		CPUs: cpus, MemoryMB: mem, DiskGB: disk,
		CloudInit: r.FormValue("cloud_init") != "", CIUsername: r.FormValue("ci_username"),
		CISSHKey: r.FormValue("ci_ssh_key"),
	}
	if _, err := s.svc.CreateTemplate(p, t, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteTemplate(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

func (s *Server) launchTemplate(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id, err := s.svc.LaunchFromTemplate(p, atoi(r.PathValue("id")), r.FormValue("name"), clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

// ---- snapshots (on the instance detail page) -----------------------------

func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	if err := s.svc.CreateSnapshot(p, id, r.FormValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) revertSnapshot(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	if err := s.svc.RevertSnapshot(p, id, atoi(r.PathValue("sid")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
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
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

// ---- backups + schedules -------------------------------------------------

func (s *Server) backups(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := s.svc.ListBackups(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	scheds, _ := s.svc.ListSchedules(p)
	s.render(w, p, "backups.html", "backups", map[string]any{"Backups": list, "Schedules": scheds})
}

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	name := r.FormValue("name")
	if name == "" {
		name = "manual"
	}
	if _, err := s.svc.CreateBackup(p, id, name, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.RestoreBackup(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/backups", http.StatusSeeOther)
}

func (s *Server) deleteBackup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteBackup(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/backups", http.StatusSeeOther)
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	interval, _ := strconv.Atoi(r.FormValue("interval_hours"))
	keep, _ := strconv.Atoi(r.FormValue("keep"))
	if err := s.svc.CreateSchedule(p, id, interval, keep, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) deleteSchedule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteSchedule(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/backups", http.StatusSeeOther)
}

// ---- retention -----------------------------------------------------------

func (s *Server) setRetention(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	days, _ := strconv.Atoi(r.FormValue("days"))
	if days <= 0 {
		days = 7
	}
	at := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	if err := s.svc.SetRetention(p, id, at, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

// ---- storage pools -------------------------------------------------------

func (s *Server) storagePools(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	pools, err := s.svc.ListPools(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	// Live ZFS / LVM state + the disk picker (admin only; empty otherwise).
	zfsPools, _ := s.svc.ZFSPools(p)
	lvmPools, _ := s.svc.LVMThinPools(p)
	disks, _ := s.svc.HostBlockDevices(p)
	// ZFS datasets across all pools (so a dataset the admin created is visible and
	// can be registered as a storage pool for VM disks), plus a parsed status tree
	// per pool for the health view.
	var datasets []zfs.Dataset
	statusByPool := map[string]zfs.PoolStatus{}
	for _, zp := range zfsPools {
		if ds, err := s.svc.ZFSDatasets(p, zp.Name); err == nil {
			datasets = append(datasets, ds...)
		}
		if st, err := s.svc.ZFSStatusTree(p, zp.Name); err == nil {
			statusByPool[zp.Name] = st
		}
	}
	s.render(w, p, "storage.html", "storage", map[string]any{
		"Pools":       pools,
		"ZFSPools":    zfsPools,
		"ZFSDatasets": datasets,
		"ZFSStatus":   statusByPool,
		"LVMPools":    lvmPools,
		"Disks":       disks,
		"DiskStatus":  s.svc.DiskStatus(p),
		"ZFSReady":    s.svc.ZFSAvailable(p),
		"LVMReady":    s.svc.LVMAvailable(p),
	})
}

func (s *Server) upsertPool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.UpsertPool(p, r.FormValue("name"), r.FormValue("kind"), r.FormValue("path"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

// deletePool removes a registered pool entry (registry only; name may contain a
// slash for LVM "vg/pool", so it comes via a form field, not a path param).
func (s *Server) deleteStoragePool(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteStoragePool(p, r.FormValue("name"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}
