package web

import (
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"vdxclone/internal/auth"
	"vdxclone/internal/image"
	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

// ---- auth pages ----------------------------------------------------------

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if s.svc.Principal(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = s.tmpl.ExecuteTemplate(w, "login.html", map[string]any{
		"Error": r.URL.Query().Get("error"),
		"OIDC":  s.oidc.Enabled(),
		"AD":    s.ad.Enabled(),
	})
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	username, password := r.FormValue("username"), r.FormValue("password")
	u, err := auth.Authenticate(s.svc.DB(), username, password)
	if err != nil && s.ad.Enabled() {
		// Fall back to Active Directory: bind, then JIT-provision/re-sync locally.
		// Covers both a user with no local account and a local account whose
		// password is managed in AD.
		if id, aerr := s.ad.Authenticate(username, password); aerr == nil {
			u, err = auth.UpsertADUser(s.svc.DB(), id.Username, id.DN, id.Admin)
		}
	}
	if err != nil {
		// Failed login: record the attempted username (NEVER the password) with no
		// actor identity, so brute-force / wrong-password attempts are accountable.
		s.svc.AuditAuth(0, username, "auth.login_failed", clientIP(r), map[string]any{"username": username})
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	if err := auth.StartSession(s.svc.DB(), w, u.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.svc.AuditAuth(u.ID, u.Username, "auth.login", clientIP(r), nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	// Resolve who is logging out before the session is torn down.
	if u := auth.FromRequest(s.svc.DB(), r); u != nil {
		s.svc.AuditAuth(u.ID, u.Username, "auth.logout", clientIP(r), nil)
	}
	auth.EndSession(s.svc.DB(), w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) switchOrg(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_ = s.svc.SwitchOrg(p, atoi(r.FormValue("org_id")))
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

// ---- compute -------------------------------------------------------------

// overview is the landing page: an at-a-glance dashboard of every subsystem
// (compute, storage, networking, backups, usage, recent activity).
func (s *Server) overview(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	s.render(w, p, "overview.html", "overview", map[string]any{
		"O": s.svc.Overview(p),
	})
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sessions, _ := s.svc.ListSessions(p)
	images, _ := image.List(s.svc.DB())
	isos, _ := s.svc.ListISOs(p)
	templates, _ := s.svc.ListTemplates(p)
	networks, _ := s.svc.ListNetworks(p)
	pools, _ := s.svc.ListPools(p)
	zfspools, _ := s.svc.ZFSPools(p) // for the raw-zvol disk option (admin; empty otherwise)
	hasLVM := false                  // enables the raw-LVM-thin disk option
	for _, pl := range pools {
		if pl.Kind == "lvm" {
			hasLVM = true
			break
		}
	}
	data := map[string]any{
		"Sessions":  sessions,
		"Images":    images,
		"ISOs":      isos,
		"Templates": templates,
		"Networks":  networks,
		"Pools":     pools,
		"ZFSPools":  zfspools,
		"HasLVMPool": hasLVM,
	}
	// Unified cluster view (VIP, admin): list every node's VMs — the single pane.
	// Actions route to the owning node; the local table is used otherwise.
	if p.Unified && p.IsAdmin {
		if cvms, err := s.svc.ClusterVMs(p); err == nil {
			data["ClusterMode"] = true
			data["ClusterVMs"] = cvms
			data["SelfNode"] = s.svc.ClusterSelfName()
		}
	}
	s.render(w, p, "dashboard.html", "compute", data)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	disk, _ := strconv.Atoi(r.FormValue("disk_gb"))
	if cpus == 0 {
		cpus = 2
	}
	if mem == 0 {
		mem = 2048
	}
	in := service.CreateInput{
		Name:       r.FormValue("name"),
		Image:      r.FormValue("image"),
		Kind:       r.FormValue("kind"),
		Firmware:   r.FormValue("firmware"),
		BootISOID:  atoi(r.FormValue("boot_iso_id")),
		CPUs:       cpus,
		MemoryMB:   mem,
		DiskGB:     disk,
		CloudInit:   r.FormValue("cloud_init") != "",
		CIUsername:  r.FormValue("ci_username"),
		CIPassword:  r.FormValue("ci_password"),
		CISSHKey:    r.FormValue("ci_ssh_key"),
		Passthrough:   r.FormValue("passthrough"),
		NetworkID:     atoi(r.FormValue("network_id")),
		StoragePoolID: atoi(r.FormValue("storage_pool_id")),
		Display:       r.FormValue("display"),
		DiskBackend:   r.FormValue("disk_backend"),
		ZvolPool:      r.FormValue("zvol_pool"),
		Desktop:       r.FormValue("desktop"),
		MachineType:   r.FormValue("machine_type"),
		DiskBus:       r.FormValue("disk_bus"),
		NICModel:      r.FormValue("nic_model"),
		VGA:           r.FormValue("vga"),
		GuestAgent:    r.FormValue("guest_agent") != "",
		TPM:           r.FormValue("tpm") != "",
		SecureBoot:    r.FormValue("secureboot") != "",
		OSType:        r.FormValue("os_type"),
		PinCPUs:       r.FormValue("perf_pin") != "",
		HugePages:     r.FormValue("perf_hugepages") != "",
	}
	sess, err := s.svc.CreateSession(p, in, clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	http.Redirect(w, r, "/instances/"+sess.ID, http.StatusSeeOther)
}

func (s *Server) instanceDetail(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	sess, err := s.svc.GetSession(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	events, _ := s.svc.SessionEvents(p, sess.ID)
	snapshots, _ := s.svc.ListSnapshots(p, sess.ID)
	forwards, _ := s.svc.ListPortForwards(p, sess.ID)
	nodes, _ := s.svc.ListNodes(p)
	pools, _ := s.svc.ListPools(p)
	networks, _ := s.svc.ListNetworks(p)
	targets, _ := s.svc.ListBackupTargets(p)
	s.render(w, p, "instance.html", "compute", map[string]any{
		"Session":     sess,
		"Running":     s.svc.Manager().Running(sess),
		"Events":      events,
		"Snapshots":   snapshots,
		"Forwards":    forwards,
		"ForwardHost": s.svc.ForwardHost(),
		"Nodes":       nodes,
		"Pools":       pools,
		"Networks":    networks,
		"Targets":     targets,
		"IsAdmin":     p.IsAdmin,
		"HostCPUs":    runtime.NumCPU(),
		"HostMemMB":   hostMemTotalMB(),
		"VirtioAvail": s.svc.VirtioISOAvailable(),
	})
}

// hostMemTotalMB returns the host's total RAM in MB (0 if unreadable), used to
// show the ceiling when inline-editing an instance's memory.
func hostMemTotalMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "MemTotal:") {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				return int(kb / 1024)
			}
		}
	}
	return 0
}


func (s *Server) resizeSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	cpus, _ := strconv.Atoi(r.FormValue("cpus"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mb"))
	disk, _ := strconv.Atoi(r.FormValue("disk_gb"))
	if err := s.svc.ResizeSession(p, id, cpus, mem, disk, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

// updateSessionSpec applies the full hardware-specification edit form.
func (s *Server) updateSessionSpec(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	hw := session.HardwareSpec{
		Firmware:    r.FormValue("firmware"),
		OSType:      r.FormValue("os_type"),
		MachineType: r.FormValue("machine_type"),
		DiskBus:     r.FormValue("disk_bus"),
		NICModel:    r.FormValue("nic_model"),
		VGA:         r.FormValue("vga"),
		GuestAgent:  r.FormValue("guest_agent") == "on",
		TPM:         r.FormValue("tpm") == "on",
		SecureBoot:  r.FormValue("secure_boot") == "on",
		PinCPUs:     r.FormValue("perf_pin") == "on",
		HugePages:   r.FormValue("perf_hugepages") == "on",
	}
	if err := s.svc.UpdateSessionSpec(p, id, hw, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

// setSpecField applies a SINGLE inline-edited spec field. It loads the current
// session, overrides just the one field, and routes to the right service call
// (resize for cpu/mem/disk, network rebind, or a hardware-profile update). On
// error (e.g. a running VM that must be stopped first) it flashes the reason.
func (s *Server) setSpecField(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	field := r.FormValue("field")
	val := r.FormValue("value")
	sess, err := s.svc.GetSession(p, id)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	on := func(v string) bool { return v == "1" || v == "on" || v == "true" }
	switch field {
	case "cpus", "memory_mb", "disk_gb":
		cpus, mem, disk := sess.CPUs, sess.MemoryMB, sess.DiskGB
		n := int(atoi(val))
		switch field {
		case "cpus":
			cpus = n
		case "memory_mb":
			mem = n
		case "disk_gb":
			disk = n
		}
		err = s.svc.ResizeSession(p, id, cpus, mem, disk, clientIP(r))
	case "network_id":
		_, err = s.svc.SetSessionNetwork(p, id, int64(atoi(val)), clientIP(r))
	default:
		hw := session.HardwareSpec{
			Firmware: sess.Firmware, OSType: sess.OSType, MachineType: sess.MachineType,
			DiskBus: sess.DiskBus, NICModel: sess.NICModel, VGA: sess.VGA,
			GuestAgent: sess.GuestAgent, TPM: sess.TPM, SecureBoot: sess.SecureBoot,
			PinCPUs: sess.PinCPUs, HugePages: sess.HugePages,
		}
		switch field {
		case "firmware":
			hw.Firmware = val
		case "os_type":
			hw.OSType = val
		case "machine_type":
			hw.MachineType = val
		case "disk_bus":
			hw.DiskBus = val
		case "nic_model":
			hw.NICModel = val
		case "vga":
			hw.VGA = val
		case "guest_agent":
			hw.GuestAgent = on(val)
		case "tpm":
			hw.TPM = on(val)
		case "secure_boot":
			hw.SecureBoot = on(val)
		case "perf_pin":
			hw.PinCPUs = on(val)
		case "perf_hugepages":
			hw.HugePages = on(val)
		default:
			http.Error(w, "unknown field", http.StatusBadRequest)
			return
		}
		err = s.svc.UpdateSessionSpec(p, id, hw, clientIP(r))
	}
	if err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Updated.")
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

// setSessionNetwork rebinds an instance's NIC to a chosen port group (0 = NAT).
func (s *Server) setSessionNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	live, err := s.svc.SetSessionNetwork(p, id, atoi(r.FormValue("network_id")), clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	if live {
		setFlashOK(w, "Network moved live — no restart needed.")
	} else {
		setFlashOK(w, "Network binding saved — applies on next start.")
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) ejectISO(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.EjectISO(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) ejectVirtio(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.EjectVirtioISO(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) mountVirtio(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.MountVirtioISO(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.StartSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

// redirectBack returns to the submitting page (Referer) or the dashboard.
func redirectBack(w http.ResponseWriter, r *http.Request) {
	dest := r.Header.Get("Referer")
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) stopSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.StopSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	redirectBack(w, r)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteSession(p, r.PathValue("id"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// apiGuestInfo returns qemu-guest-agent data for a VM as JSON (polled by the
// instance page). Fail-soft: any error yields an empty, non-responsive result.
func (s *Server) apiGuestInfo(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	gi, err := s.svc.GuestAgentInfo(p, r.PathValue("id"))
	if err != nil {
		writeJSON(w, map[string]any{"responsive": false})
		return
	}
	writeJSON(w, gi)
}

func (s *Server) console(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	// Cluster-aware: renders the console for a VM on this node or (admin, cluster
	// mode) on another node — the websocket relay reaches the owning node.
	sess, _, err := s.svc.ConsoleTargetCluster(p, r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "console.html", "compute", map[string]any{"Session": sess})
}

// ---- tenancy screens -----------------------------------------------------

func (s *Server) members(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	members, err := s.svc.ListMembers(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	flash := ""
	switch r.URL.Query().Get("pw") {
	case "ok":
		flash = "Your password was changed."
	case "reset":
		flash = "Password reset."
	}
	self := ""
	if p.User != nil {
		self = p.User.Username
	}
	s.render(w, p, "members.html", "members", map[string]any{
		"Members": members,
		"IsAdmin": p.IsAdmin,
		"Self":    self,
		"PWFlash": flash,
	})
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.AddMember(p, r.FormValue("username"), r.FormValue("role"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/members", http.StatusSeeOther)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.RemoveMember(p, atoi(r.PathValue("uid")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/members", http.StatusSeeOther)
}

// changePassword lets the logged-in user change their own password.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	next := r.FormValue("new_password")
	if next != r.FormValue("confirm_password") {
		http.Error(w, "the new passwords do not match", http.StatusBadRequest)
		return
	}
	if err := s.svc.ChangeOwnPassword(p, r.FormValue("current_password"), next, clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/members?pw=ok", http.StatusSeeOther)
}

// resetPassword lets an instance admin set another user's password.
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.AdminResetPassword(p, int64(atoi(r.PathValue("uid"))), r.FormValue("new_password"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/members?pw=reset", http.StatusSeeOther)
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	keys, err := s.svc.ListAPIKeys(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "apikeys.html", "apikeys", map[string]any{
		"Keys":   keys,
		"NewKey": r.URL.Query().Get("new"),
	})
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	plaintext, err := s.svc.CreateAPIKey(p, r.FormValue("label"), r.FormValue("readonly") != "", clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/apikeys?new="+plaintext, http.StatusSeeOther)
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.RevokeAPIKey(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/apikeys", http.StatusSeeOther)
}

func (s *Server) orgs(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.render(w, p, "orgs.html", "orgs", nil)
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if _, err := s.svc.CreateOrg(p, r.FormValue("name"), r.FormValue("slug"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/orgs", http.StatusSeeOther)
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	filter := r.URL.Query().Get("action")
	entries, err := s.svc.ListAuditFiltered(p, filter)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	s.render(w, p, "audit.html", "audit", map[string]any{"Entries": entries, "Filter": filter})
}

func statusFor(err error) int {
	switch err {
	case service.ErrUnauthorized:
		return http.StatusForbidden
	case service.ErrNotFound:
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}
