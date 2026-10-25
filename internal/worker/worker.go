// Package worker runs supervised background loops. Each loop is a ticker that
// recovers from panics and exits cleanly on context cancellation, so the daemon
// shuts down gracefully. All DB writes here flow through the same single
// connection as the request path.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"vdxclone/internal/cluster"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/gossip"
	"vdxclone/internal/metrics"
	"vdxclone/internal/service"
	"vdxclone/internal/session"
	"vdxclone/internal/storage"
)

type Supervisor struct {
	cfg  *config.Config
	db   *db.DB
	mgr  *session.Manager
	stg  *storage.Store
	mc   *metrics.Collector
	cl   *cluster.Store
	g    *gossip.Cluster
	svc  *service.Service
	role *cluster.Role

	// startedAt gates destructive auto-actions (retention) for a grace window
	// after boot, so a restored/stale DB can't immediately deprovision VMs
	// before boot adoption + an admin have a chance to react.
	startedAt time.Time
}

func New(cfg *config.Config, d *db.DB, mgr *session.Manager, stg *storage.Store, mc *metrics.Collector, cl *cluster.Store) *Supervisor {
	return &Supervisor{cfg: cfg, db: d, mgr: mgr, stg: stg, mc: mc, cl: cl, startedAt: time.Now()}
}

// retentionGrace is how long after boot auto-retention is suppressed.
const retentionGrace = 10 * time.Minute

// SetGossip attaches the gossip membership handle. When present, node-health
// advertises this node's live capacity into the mesh and reflects every peer's
// gossiped capacity back into the nodes table (no central coordinator polls).
func (s *Supervisor) SetGossip(g *gossip.Cluster) { s.g = g }

// SetService attaches the service so service-level background loops
// can run. Optional — without it those loops are no-ops.
func (s *Supervisor) SetService(svc *service.Service) { s.svc = svc }

// SetRole attaches the cluster election role. Cluster-singleton loops
// (account sync, HA monitor) run ONLY on the leader so a
// multi-node cluster does not double-provision or double-write. A nil role (the
// single-host default) is treated as "always leader".
func (s *Supervisor) SetRole(role *cluster.Role) { s.role = role }

// isLeader reports whether cluster-singleton work should run here.
func (s *Supervisor) isLeader() bool { return s.role == nil || s.role.IsLeader() }

// Run starts all background loops and blocks until ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context) {
	// Before anything else, re-adopt any QEMU VMs already running on this host
	// whose DB rows are missing/stale (e.g. after a DB restore or a fresh DB).
	// This is what makes a broken/rolled-back control plane non-disruptive:
	// live VMs are rediscovered and made manageable again rather than orphaned.
	s.mgr.AdoptRunningVMs()
	// Resolve any storage move interrupted by a crash/restart (prefer target only
	// if it verifies; otherwise keep the untouched source). Runs before any
	// reconcile could act on a half-moved VM.
	s.mgr.RecoverMigrations()
	// When the management interface is a default vSwitch, ensure its attachable
	// "VM Network" port group exists (ESXi-style). One-shot at boot so an admin's
	// deletion stays deleted; a fresh install / mgmt-NIC conversion gets it here.
	if s.svc != nil {
		if err := s.svc.EnsureDefaultPortGroup(); err != nil {
			log.Printf("ensure default port group: %v", err)
		}
		// Bring every physical NIC up (even unconfigured ones) so the UI can show
		// which ports have a live cable (carrier). One-shot at boot.
		s.svc.EnsurePhysicalLinksUp()
		// Remount any configured network backup targets (NFS/CIFS/CephFS) so
		// scheduled + manual backups to shares work after a reboot.
		s.svc.EnsureBackupMounts()
		// Rebuild vRouters (NSX-lite): ensure their bridges/veths exist and the
		// transit NIC is re-enslaved, then start each runtime. vdxd owns the start
		// order (containers are lxc.start.auto=0) so veth legs never race their
		// bridges at boot.
		s.svc.ReensureVRouters()
		// Rebuild per-org isolated tenant-network bridges (+ their DHCP) that the
		// kernel loses across a reboot. After vRouters, before autostart, so a VM
		// on its tenant bridge finds it ready.
		s.svc.ReensureTenantNetworks()
		// Rebuild the distributed-firewall (port-group microsegmentation) host
		// bridge nftables table — the kernel clears it on reboot.
		s.svc.ReensureNetFirewalls()
		// Unified firewall: seed the org document from any legacy per-vRouter /
		// per-network config on first upgrade, then recompile both planes so the
		// NSX-style model is authoritative after a reboot.
		s.svc.ReensureFirewall()
	}
	// Autostart flagged VMs — but ONLY after a real HOST reboot, never on a plain
	// control-plane restart/upgrade (where KillMode=process keeps guests alive and
	// adoption above re-attaches them). We tell the two apart by the kernel boot_id:
	// it changes across a reboot but is stable across a vdxd restart. Runs after
	// adoption (so a running VM is skipped) AND after the network layer above
	// (default port group, physical links, vRouter bridges/veths, firewalls) so a
	// VM attached to a vRouter's internal bridge doesn't try to start before that
	// bridge exists — the boot-ordering race that otherwise lands such VMs in "error".
	s.bootAutostart()
	go s.loop(ctx, "reconciler", 5*time.Second, s.reconcile)
	go s.loop(ctx, "session-gc", 1*time.Hour, s.gcWebSessions)
	go s.loop(ctx, "retention", 10*time.Minute, s.retention)
	go s.loop(ctx, "backup-scheduler", 5*time.Minute, s.runDueBackups)
	go s.loop(ctx, "db-backup", 6*time.Hour, s.backupControlPlane)
	go s.loop(ctx, "metrics", 10*time.Second, s.collectMetrics)
	go s.loop(ctx, "alerts", 30*time.Second, s.evalAlerts)
	go s.loop(ctx, "metrics-gc", 6*time.Hour, s.gcMetrics)
	go s.loop(ctx, "metering", 60*time.Second, s.meter)
	go s.loop(ctx, "node-health", 30*time.Second, s.nodeHealth)
	go s.loop(ctx, "account-sync", 10*time.Second, s.syncAccounts)
	go s.loop(ctx, "guest-os", 60*time.Second, s.detectGuestOS)
	<-ctx.Done()
}

func (s *Supervisor) loop(ctx context.Context, name string, every time.Duration, fn func()) {
	safe := func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("worker %s panic: %v", name, r)
			}
		}()
		fn()
	}
	safe() // run once at startup
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safe()
		}
	}
}

// bootAutostart powers on every autostart-flagged VM, but only once per host
// boot. It compares the current kernel boot_id against the one recorded at the
// last run: equal means this is a control-plane restart (do nothing — adoption
// already handled live VMs and a stopped VM stays stopped); different (or no
// record) means the host rebooted, so flagged VMs are started. The boot_id is
// then recorded so a subsequent vdxd restart within the same boot is a no-op.
func (s *Supervisor) bootAutostart() {
	cur := currentBootID()
	marker := filepath.Join(s.cfg.Paths.DataDir, "last_boot_id")
	prev := ""
	if b, err := os.ReadFile(marker); err == nil {
		prev = strings.TrimSpace(string(b))
	}
	if cur != "" && cur == prev {
		return // same boot → vdxd restarted, not a host reboot
	}
	// Record the new boot_id first, so a crash-restart mid-autostart doesn't
	// re-trigger a second mass start within the same boot.
	if cur != "" {
		if err := os.WriteFile(marker, []byte(cur+"\n"), 0o600); err != nil {
			log.Printf("autostart: record boot_id: %v", err)
		}
	}
	// First run ever on this host (no marker): do NOT mass-start — just establish
	// the baseline, so installing this feature on a live host doesn't disturb it.
	if prev == "" {
		log.Printf("autostart: baseline boot_id recorded; VMs will autostart on the next host reboot")
		return
	}
	ids, err := s.mgr.AutostartIDs()
	if err != nil {
		log.Printf("autostart: list candidates: %v", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	log.Printf("autostart: host reboot detected — starting %d VM(s) flagged start-at-boot", len(ids))
	for _, id := range ids {
		if _, err := s.mgr.Start(id); err != nil {
			log.Printf("autostart: start %s: %v", id, err)
		} else {
			log.Printf("autostart: started %s", id)
		}
		time.Sleep(500 * time.Millisecond) // stagger so a mass boot doesn't thrash disk/CPU
	}
}

// currentBootID reads the kernel's per-boot random id (stable for the life of a
// boot, regenerated on reboot). Empty string if unreadable (then autostart falls
// back to the marker-file presence check, which still fires at most once).
func currentBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// reconcile marks sessions whose QEMU process has died as stopped.
func (s *Supervisor) reconcile() { s.mgr.Reconcile() }

// detectGuestOS fills in the guest OS for running ISO-install VMs that don't have
// one yet, so the Image column shows the installed OS instead of the placeholder.
// Self-limiting: a VM drops out of the query as soon as its OS is recorded.
func (s *Supervisor) detectGuestOS() { s.mgr.DetectGuestOS() }

// gcWebSessions deletes expired browser session rows.
func (s *Supervisor) gcWebSessions() {
	_, _ = s.db.Exec(`DELETE FROM web_sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
}

// retention soft-deletes (moves to Trash) any instance past its retention cutoff.
// This mirrors the decompiled deprovision-past-cutoff behaviour, kept local.
func (s *Supervisor) retention() {
	// Boot grace: never auto-deprovision in the first minutes after start. If a
	// stale/restored DB resurrected an expired retention_at, this prevents it
	// from stopping a live VM before adoption + an operator can intervene.
	if time.Since(s.startedAt) < retentionGrace {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := s.db.Query(`SELECT id FROM sessions WHERE retention_at IS NOT NULL AND retention_at<=? AND deleted_at IS NULL`, now)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		// SAFETY: auto-retention must never stop a VM that is actually running.
		// A running VM past its cutoff is skipped and logged for an operator —
		// the user's rule is that control-plane state never disrupts live VMs.
		sess, gerr := s.mgr.Get(id)
		if gerr == nil && s.mgr.Running(sess) {
			log.Printf("retention: %s is past cutoff but RUNNING — skipping auto-deprovision (needs manual action)", id)
			continue
		}
		if err := s.mgr.Delete(id); err == nil {
			log.Printf("retention: auto-deprovisioned %s", id)
			if s.svc != nil {
				var org int64
				if gerr == nil {
					org = sess.OrgID
				}
				s.svc.SysAudit(org, "session.retention_delete", "session", id, map[string]any{"reason": "retention cutoff reached"})
			}
		}
	}
}

// runDueBackups runs any backup schedule whose next_run_at has passed, backing up
// only stopped instances (a quiescent disk), then prunes to the keep count.
func (s *Supervisor) runDueBackups() {
	if s.stg == nil {
		return
	}
	due, err := s.stg.DueSchedules(time.Now())
	if err != nil {
		return
	}
	for _, sc := range due {
		sess, err := s.mgr.Get(sc.SessionID)
		if err != nil {
			_ = s.stg.MarkScheduleRun(sc.ID, sc.IntervalHours)
			continue
		}
		if s.mgr.Running(sess) {
			// Skip this tick; a later tick catches it once stopped.
			_ = s.stg.MarkScheduleRun(sc.ID, sc.IntervalHours)
			continue
		}
		destDir, terr := s.svc.ResolveBackupTargetDir(sc.TargetID)
		if terr != nil {
			log.Printf("scheduled backup %s: target unavailable: %v", sc.SessionID, terr)
			_ = s.stg.MarkScheduleRun(sc.ID, sc.IntervalHours)
			continue
		}
		id, err := s.stg.CreateBackupRow(sc.OrgID, sc.SessionID, "scheduled", sc.TargetID)
		if err == nil {
			rerr := s.stg.RunBackup(id, sess.DiskPath, destDir)
			if rerr != nil {
				log.Printf("scheduled backup %s failed: %v", sc.SessionID, rerr)
			}
			s.stg.PruneBackups(sc.SessionID, sc.Keep)
			if s.svc != nil {
				detail := map[string]any{"backup_id": id, "target_id": sc.TargetID, "schedule_id": sc.ID}
				if rerr != nil {
					detail["error"] = rerr.Error()
				}
				s.svc.SysAudit(sc.OrgID, "backup.scheduled", "session", sc.SessionID, detail)
			}
		}
		_ = s.stg.MarkScheduleRun(sc.ID, sc.IntervalHours)
	}
}

// meter appends a local usage-ledger row for each running instance every tick.
// This is the shape of the decompiled credit-metering loop, but entirely local:
// no network calls, no external accounting — the ledger just feeds usage reports
// and (when enabled at M9) the licensing enforcer.
func (s *Supervisor) meter() {
	const interval = 60 // seconds per tick; matches the loop cadence
	rows, err := s.db.Query(`SELECT id,org_id,cpus,memory_mb FROM sessions WHERE state='running' AND deleted_at IS NULL`)
	if err != nil {
		return
	}
	type vm struct {
		id        string
		org       int64
		cpus, mem int
	}
	var list []vm
	for rows.Next() {
		var v vm
		if err := rows.Scan(&v.id, &v.org, &v.cpus, &v.mem); err == nil {
			list = append(list, v)
		}
	}
	rows.Close()
	for _, v := range list {
		_, _ = s.db.Exec(`INSERT INTO usage_ledger(org_id,session_id,seconds,vcpu_seconds,mem_mb_seconds)
			VALUES(?,?,?,?,?)`, v.org, v.id, interval, v.cpus*interval, v.mem*interval)
	}
}

// collectMetrics samples host + per-VM resource usage into the ring + DB.
func (s *Supervisor) collectMetrics() {
	if s.mc != nil {
		s.mc.Collect()
	}
}

// nodeHealth records the local node's live memory and probes remote workers.
func (s *Supervisor) nodeHealth() {
	if s.cl == nil {
		return
	}
	var memTotal, memFree int64
	cpus := runtime.NumCPU()
	if s.mc != nil {
		h := s.mc.Live().Host
		if h.MemTotal > 0 {
			s.cl.UpdateLocalHealth(h.MemUsed, h.MemTotal)
			memTotal, memFree = h.MemTotal, h.MemTotal-h.MemUsed
		}
	}
	// Decentralized path: advertise our capacity and fold in gossiped peers.
	if s.g != nil {
		s.g.UpdateLocal(cpus, memFree/(1024*1024), memTotal/(1024*1024))
		for _, m := range s.g.Members() {
			s.cl.UpsertGossipNode(m.Name, m.Address, m.CPUs, m.MemTotal*1024*1024, m.MemFreeMB*1024*1024, m.Alive)
		}
	}
	// SSH-probe path: for statically-added nodes that aren't in the gossip mesh.
	nodes, err := s.cl.ListNodes()
	if err != nil {
		return
	}
	for _, n := range nodes {
		if n.Role != "local" && n.Address != "" && n.LastSeen == "" {
			s.cl.Probe(n)
		}
	}
}

// syncAccounts pulls the leader's account snapshot on a follower so logins and
// API keys work cluster-wide. No-op on the leader / single-host.
func (s *Supervisor) syncAccounts() {
	if s.svc != nil {
		s.svc.PullAccountsIfFollower()
	}
}

// gcMetrics trims metric rollups older than 7 days.
func (s *Supervisor) gcMetrics() {
	_, _ = s.db.Exec(`DELETE FROM metric_samples WHERE ts < datetime('now','-7 days')`)
}

// evalAlerts checks enabled host alert rules against the latest sample, opening
// or resolving alerts and notifying a webhook channel on state change.
func (s *Supervisor) evalAlerts() {
	if s.mc == nil {
		return
	}
	live := s.mc.Live()
	host := live.Host
	metricVal := func(m string) (float64, bool) {
		switch m {
		case "host.cpu_pct":
			return host.CPUPct, true
		case "host.mem_pct":
			if host.MemTotal > 0 {
				return 100 * float64(host.MemUsed) / float64(host.MemTotal), true
			}
		case "host.disk_pct":
			if host.DiskTotal > 0 {
				return 100 * float64(host.DiskUsed) / float64(host.DiskTotal), true
			}
		}
		return 0, false
	}
	rows, err := s.db.Query(`SELECT id,name,metric,op,threshold,COALESCE(channel_id,0) FROM alert_rules WHERE enabled=1`)
	if err != nil {
		return
	}
	type rule struct {
		id, channel        int64
		name, metric, op   string
		threshold          float64
	}
	var rules []rule
	for rows.Next() {
		var r rule
		if err := rows.Scan(&r.id, &r.name, &r.metric, &r.op, &r.threshold, &r.channel); err == nil {
			rules = append(rules, r)
		}
	}
	rows.Close()

	for _, r := range rules {
		val, ok := metricVal(r.metric)
		if !ok {
			continue
		}
		breached := (r.op == ">" && val > r.threshold) || (r.op == "<" && val < r.threshold)
		var openID int64
		_ = s.db.QueryRow(`SELECT id FROM alerts WHERE rule_id=? AND state='firing'`, r.id).Scan(&openID)
		switch {
		case breached && openID == 0:
			_, _ = s.db.Exec(`INSERT INTO alerts(rule_id,state,value) VALUES(?,'firing',?)`, r.id, val)
			s.notify(r.channel, r.name, "firing", r.metric, val)
		case !breached && openID != 0:
			_, _ = s.db.Exec(`UPDATE alerts SET state='resolved', resolved_at=datetime('now') WHERE id=?`, openID)
			s.notify(r.channel, r.name, "resolved", r.metric, val)
		}
	}
}

func (s *Supervisor) notify(channelID int64, name, state, metric string, val float64) {
	if channelID == 0 {
		return
	}
	var kind, target string
	if err := s.db.QueryRow(`SELECT kind,target FROM alert_channels WHERE id=?`, channelID).Scan(&kind, &target); err != nil {
		return
	}
	if kind != "webhook" || target == "" {
		return // email delivery is documented/configured separately
	}
	body, _ := json.Marshal(map[string]any{"alert": name, "state": state, "metric": metric, "value": val})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// backupControlPlane writes a consistent snapshot of the SQLite control-plane DB
// via VACUUM INTO, keeping a small rolling set.
func (s *Supervisor) backupControlPlane() {
	if s.cfg == nil || s.cfg.Paths.BackupDir == "" {
		return
	}
	if _, err := s.db.Backup(s.cfg.Paths.BackupDir); err != nil {
		log.Printf("control-plane backup failed: %v", err)
		return
	}
	db.PruneBackups(s.cfg.Paths.BackupDir, 24)
}
