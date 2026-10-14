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
	"path/filepath"
	"runtime"
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
	cfg *config.Config
	db  *db.DB
	mgr *session.Manager
	stg *storage.Store
	mc  *metrics.Collector
	cl  *cluster.Store
	g   *gossip.Cluster
	svc *service.Service
}

func New(cfg *config.Config, d *db.DB, mgr *session.Manager, stg *storage.Store, mc *metrics.Collector, cl *cluster.Store) *Supervisor {
	return &Supervisor{cfg: cfg, db: d, mgr: mgr, stg: stg, mc: mc, cl: cl}
}

// SetGossip attaches the gossip membership handle. When present, node-health
// advertises this node's live capacity into the mesh and reflects every peer's
// gossiped capacity back into the nodes table (no central coordinator polls).
func (s *Supervisor) SetGossip(g *gossip.Cluster) { s.g = g }

// SetService attaches the service so broker-level loops (idle desktop reclaim)
// can run. Optional — without it those loops are no-ops.
func (s *Supervisor) SetService(svc *service.Service) { s.svc = svc }

// Run starts all background loops and blocks until ctx is cancelled.
func (s *Supervisor) Run(ctx context.Context) {
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
	go s.loop(ctx, "desktop-reclaim", 2*time.Minute, s.reclaimDesktops)
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

// reconcile marks sessions whose QEMU process has died as stopped.
func (s *Supervisor) reconcile() { s.mgr.Reconcile() }

// gcWebSessions deletes expired browser session rows.
func (s *Supervisor) gcWebSessions() {
	_, _ = s.db.Exec(`DELETE FROM web_sessions WHERE expires_at < ?`, time.Now().UTC().Format(time.RFC3339))
}

// retention soft-deletes (moves to Trash) any instance past its retention cutoff.
// This mirrors the decompiled deprovision-past-cutoff behaviour, kept local.
func (s *Supervisor) retention() {
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
		if err := s.mgr.Delete(id); err == nil {
			log.Printf("retention: auto-deprovisioned %s", id)
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
		id, err := s.stg.CreateBackupRow(sc.OrgID, sc.SessionID, "scheduled")
		if err == nil {
			if err := s.stg.RunBackup(id, sess.DiskPath); err != nil {
				log.Printf("scheduled backup %s failed: %v", sc.SessionID, err)
			}
			s.stg.PruneBackups(sc.SessionID, sc.Keep)
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

// reclaimDesktops stops and frees pooled desktops idle past the timeout.
func (s *Supervisor) reclaimDesktops() {
	if s.svc == nil {
		return
	}
	if n := s.svc.ReclaimIdle(); n > 0 {
		log.Printf("desktop-reclaim: freed %d idle pooled desktop(s)", n)
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
	dest := filepath.Join(s.cfg.Paths.BackupDir, "controlplane-"+time.Now().UTC().Format("20060102T150405")+".db")
	if _, err := s.db.Exec(`VACUUM INTO ?`, dest); err != nil {
		log.Printf("control-plane backup failed: %v", err)
	}
}
