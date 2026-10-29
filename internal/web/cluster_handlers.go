package web

import (
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	"vdxclone/internal/service"
	"vdxclone/internal/storage"
	"vdxclone/internal/vmware"
)

func (s *Server) cluster(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	nodes, err := s.svc.ListNodes(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	var vms []service.ClusterVM
	if p.IsAdmin && s.svc.ClusterEnabled() {
		vms, _ = s.svc.ClusterVMs(p)
	}
	leaderName, vip, isLeaderHere := s.svc.ClusterLeader()
	var pools []storage.Pool
	if p.IsAdmin {
		pools, _ = s.svc.ListPools(p) // for the import target-storage selector
	}
	s.render(w, p, "cluster.html", "cluster", map[string]any{
		"Nodes":        nodes,
		"Capability":   s.svc.HostCapability(p),
		"ClusterOn":    s.svc.ClusterEnabled(),
		"ClusterVMs":   vms,
		"LeaderName":   leaderName,
		"VIP":          vip,
		"IsLeaderHere": isLeaderHere,
		"Joins":        s.svc.JoinStates(p),
		"Pools":         pools,
		"VDDKReady":     s.svc.VDDKReady(p),
		"VDDKInstalled": s.svc.VDDKInstalled(p),
		"VDDKLibDir":    s.svc.VDDKLibDir(),
	})
}

// uploadVDDK receives the operator-supplied VMware VDDK archive and installs it
// so the fastest import transport lights up — no SSH/host unpacking needed. The
// file is streamed straight to disk (MultipartReader, like ISO upload) so a
// ~100 MB tarball never buffers into RAM. Admin only.
func (s *Server) uploadVDDK(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "admin only", http.StatusForbidden)
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected a multipart upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	var csrfOK bool
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
		case "vddk":
			if !csrfOK { // CSRF must have arrived before the file
				s.badCSRF(w)
				return
			}
			dir, err := s.svc.UploadVDDK(p, part, clientIP(r))
			if err != nil {
				setFlash(w, "VDDK install failed: "+err.Error())
			} else {
				setFlashOK(w, "VMware VDDK installed ("+dir+"). The VDDK transfer method is now available in the import dialog.")
			}
			http.Redirect(w, r, "/migrate", http.StatusSeeOther)
			return
		}
		part.Close()
	}
	http.Error(w, "no file uploaded", http.StatusBadRequest)
}

// clusterVMAction dispatches a single-pane lifecycle action to the owning node.
func (s *Server) clusterVMAction(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	node := r.PathValue("node")
	id := r.PathValue("id")
	action := r.PathValue("action")
	if err := s.svc.ClusterVMAction(p, node, id, action, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	// Return to the page the action was invoked from (the unified Instances page
	// or the Cluster page), not always /cluster — a same-origin referer only.
	dest := "/cluster"
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := neturl.Parse(ref); err == nil && u.Path != "" {
			dest = u.Path
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) importImage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.ImportImageURL(p, r.FormValue("name"), r.FormValue("url"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

func (s *Server) addNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.AddNode(p, r.FormValue("name"), r.FormValue("address"), r.FormValue("ssh_user"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

// joinNode kicks off a zero-touch worker-node join (async). Progress is polled
// via GET /api/node-join. The SSH/sudo password is used in memory only.
func (s *Server) joinNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	in := service.JoinInput{
		Address:      r.FormValue("address"),
		SSHUser:      r.FormValue("ssh_user"),
		SSHPass:      r.FormValue("ssh_pass"),
		SSHKey:       r.FormValue("ssh_key"),
		MgmtIface:    r.FormValue("mgmt_iface"),
		MgmtCIDR:     r.FormValue("mgmt_cidr"),
		Gateway:      r.FormValue("gateway"),
		ClusterIface: r.FormValue("cluster_iface"),
		ClusterCIDR:  r.FormValue("cluster_cidr"),
		Bootstrap:    r.FormValue("bootstrap") != "",
	}
	if dns := r.FormValue("dns"); dns != "" {
		for _, d := range strings.Split(dns, ",") {
			if d = strings.TrimSpace(d); d != "" {
				in.DNS = append(in.DNS, d)
			}
		}
	}
	if _, err := s.svc.JoinNode(p, in, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Worker join started — watch progress below. The node auto-reverts if it can't be reached on the new IP.")
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

// apiNodeJoin returns the live/recent join progress as JSON for the poller.
func (s *Server) apiNodeJoin(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, map[string]any{"joins": s.svc.JoinStates(p)})
}

// ---- vCenter / ESXi import -----------------------------------------------

func vmwareCredsFromForm(r *http.Request) vmware.Creds {
	return vmware.Creds{
		URL:      r.FormValue("vc_url"),
		User:     r.FormValue("vc_user"),
		Pass:     r.FormValue("vc_pass"),
		Insecure: r.FormValue("vc_insecure") != "",
	}
}

// vmwareConnect connects read-only and returns the VM inventory as JSON.
func (s *Server) vmwareConnect(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	vms, err := s.svc.VMwareConnectList(p, vmwareCredsFromForm(r), clientIP(r))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"vms": vms})
}

// vmwareImport starts an async import and redirects back with progress polling.
// With the "Use CBT (warm migration)" box ticked (cbt=1) it starts a warm import
// instead — the tick is the operator's consent to enable CBT on that VM and take
// short-lived snapshots of it; unticked, the import stays read-only as before.
func (s *Server) vmwareImport(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if r.FormValue("cbt") != "" {
		if _, err := s.svc.VMwareImportCBT(p, vmwareCredsFromForm(r), r.FormValue("moid"), r.FormValue("os_type"),
			atoi(r.FormValue("target_pool_id")), atoiInt(r.FormValue("cbt_interval")), clientIP(r)); err != nil {
			setFlash(w, err.Error())
		} else {
			setFlashOK(w, "Warm migration started — the source keeps running while its disks copy, then changes sync on a schedule. Cut over from the Warm migrations table when you're ready.")
		}
		http.Redirect(w, r, "/migrate", http.StatusSeeOther)
		return
	}
	if _, err := s.svc.VMwareImport(p, vmwareCredsFromForm(r), r.FormValue("moid"), r.FormValue("os_type"), r.FormValue("transport"), int64(atoi(r.FormValue("target_pool_id"))), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Import started — the source VM is only read, never changed. Watch progress below; when it finishes it creates a ready-to-run instance (same CPU/memory/firmware) you'll find on the Instances page.")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// apiVmwareImport returns live/recent import progress for the poller: the cold
// imports, plus the CBT warm imports (persistent, with their sync state).
func (s *Server) apiVmwareImport(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	writeJSON(w, map[string]any{"imports": s.svc.VMwareImportStates(p), "cbt": s.svc.CBTImportStates(p)})
}

// vmwareCBTSync runs a warm import's delta pass now ("Sync now").
func (s *Server) vmwareCBTSync(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CBTSyncNow(p, r.PathValue("id"), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Sync pass started.")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// vmwareCBTCutover starts a warm import's cut-over (from the confirm modal).
func (s *Server) vmwareCBTCutover(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CBTCutover(p, r.PathValue("id"), r.FormValue("shutdown_guest") != "", clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Cut-over started — one more sync, then the source powers off, the last changes copy, and the instance is created. Watch the Warm migrations table.")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// vmwareCBTCancel cancels a warm import (removes our snapshots, restores CBT).
func (s *Server) vmwareCBTCancel(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.CBTCancel(p, r.PathValue("id"), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Warm migration cancelled — removing our snapshots, restoring CBT, deleting the staged copy.")
	}
	http.Redirect(w, r, "/migrate", http.StatusSeeOther)
}

// apiVmwareImportLog serves the full durable log for one import as plain text so
// a failed import can be diagnosed after the fact (even once the live tracker row
// has aged out).
func (s *Server) apiVmwareImportLog(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	txt, err := s.svc.VMwareImportLog(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(txt))
}

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteNode(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

func (s *Server) probeNode(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.ProbeNode(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/cluster", http.StatusSeeOther)
}

// migrateSession live-migrates a running VM to another node. The result (or the
// honest precondition error) is surfaced on the instance page via a flash.
func (s *Server) migrateSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	dst := int64(atoi(r.FormValue("dst_node")))
	// storage_pool_id: "-1" (or absent) = keep current storage; >=0 = move disk
	// to that pool (0 = default disk dir). The old "shared storage present"
	// checkbox is gone — shared storage is auto-detected server-side.
	pool := int64(-1)
	if v := r.FormValue("storage_pool_id"); v != "" {
		pool = int64(atoi(v))
	}
	if err := s.svc.Relocate(p, id, dst, pool, clientIP(r)); err != nil {
		http.Error(w, "migration: "+err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}
