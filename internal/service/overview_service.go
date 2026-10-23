package service

import (
	"sort"
	"strconv"

	"vdxclone/internal/image"
	"vdxclone/internal/store"
)

// Overview is the aggregated home-dashboard snapshot: a little about every
// subsystem so the landing page answers "what's going on" at a glance. Admin
// sections (host storage, cluster, members) are only populated for admins.

type OverviewStat struct {
	Running int `json:"running"`
	Stopped int `json:"stopped"`
	Total   int `json:"total"`
	Servers int `json:"servers"`
	Desktop int `json:"desktop"`
}

type OverviewData struct {
	VMs        OverviewStat
	VCPUs      int // allocated across all instances
	MemoryMB   int
	DiskGB     int
	Images     int
	ISOs       int
	Templates  int
	Backups    int
	BackupSize int64
	// networking
	PortGroups int
	VSwitches  int
	Bonds      int
	// storage
	Pools         int
	PoolUsedBytes int64
	PoolTotBytes  int64
	PoolUsedGB    float64
	PoolTotGB     float64
	PoolPct       int
	ZFSPools      int
	LVMPools      int
	BackupSizeGB  float64
	MemoryGB      float64
	DiskTB        float64
	// platform (admin)
	Nodes        int
	Members      int
	Containers   int // LXC system containers (this node)
	Routing      string // "", "off", or a short status line
	// usage / quota
	Usage UsageReport
	Quota Quota
	// activity
	Recent  []store.AuditEntry
	Runners []RunnerRow // a few running VMs for quick access
	// "top consumers" for the split dashboard cards
	TopVMs     []TopVMRow      // top 2 running VMs by combined CPU+memory load
	TopStorage *TopStorageRow  // the single VM with the largest disk allocation
	// trailing-average throughput for the live strip (bytes/sec)
	DiskTrend TrendAvg // host disk read+write
	RxTrend   TrendAvg // host network receive
	TxTrend   TrendAvg // host network transmit
}

// TrendAvg holds a stat's trailing averages over three windows (bytes/sec).
type TrendAvg struct {
	M5  int64 // last 5 minutes
	H1  int64 // last 1 hour
	H25 int64 // last 25 hours
}

// RunnerRow is a compact running-VM line for the overview.
type RunnerRow struct {
	ID   string
	Name string
	Kind string
	Node string // owning node name (unified view); "" for the local-only view
}

// TopVMRow ranks a running VM by live resource load (CPU% + memory%).
type TopVMRow struct {
	ID     string
	Name   string
	Kind   string
	CPUPct float64 // live host-CPU % this VM is using
	MemPct float64 // live % of its allocated memory in use
}

// TopStorageRow is the heaviest single disk consumer.
type TopStorageRow struct {
	ID     string
	Name   string
	DiskGB int
}

// hostTrends computes trailing-average throughput for the host's disk and
// network over 5m / 1h / 25h, straight from the persisted metric samples
// (scope "host"). Averages of the per-sample byte/sec rates.
func (s *Service) hostTrends() (disk, rx, tx TrendAvg) {
	win := func(expr string, mins int) int64 {
		var v float64
		_ = s.db.QueryRow(
			`SELECT COALESCE(AVG(`+expr+`),0) FROM metric_samples WHERE scope='host' AND target_id='' AND ts >= datetime('now', ?)`,
			"-"+strconv.Itoa(mins)+" minutes").Scan(&v)
		return int64(v)
	}
	const dexpr = "disk_read+disk_write"
	disk = TrendAvg{M5: win(dexpr, 5), H1: win(dexpr, 60), H25: win(dexpr, 1500)}
	rx = TrendAvg{M5: win("net_rx", 5), H1: win("net_rx", 60), H25: win("net_rx", 1500)}
	tx = TrendAvg{M5: win("net_tx", 5), H1: win("net_tx", 60), H25: win("net_tx", 1500)}
	return
}

// topConsumers ranks running VMs by live CPU+memory load (top 2) and finds the
// single VM with the largest disk allocation. Live load comes from the metrics
// collector's latest per-VM sample; a VM with no sample yet scores 0.
func (s *Service) topConsumers(running []RunnerRow, storage []TopStorageRow) ([]TopVMRow, *TopStorageRow) {
	var top []TopVMRow
	if len(running) > 0 && s.mc != nil {
		// Latest live CPU%/mem% per VM id.
		type load struct{ cpu, mem float64 }
		live := map[string]load{}
		for _, v := range s.mc.Live().VMs {
			mp := 0.0
			if v.MemTotal > 0 {
				mp = 100 * float64(v.MemUsed) / float64(v.MemTotal)
			}
			live[v.TargetID] = load{cpu: v.CPUPct, mem: mp}
		}
		for _, r := range running {
			l := live[r.ID]
			top = append(top, TopVMRow{ID: r.ID, Name: r.Name, Kind: r.Kind, CPUPct: l.cpu, MemPct: l.mem})
		}
		sort.SliceStable(top, func(i, j int) bool {
			return top[i].CPUPct+top[i].MemPct > top[j].CPUPct+top[j].MemPct
		})
		if len(top) > 2 {
			top = top[:2]
		}
	}
	var topStore *TopStorageRow
	for i := range storage {
		if topStore == nil || storage[i].DiskGB > topStore.DiskGB {
			topStore = &storage[i]
		}
	}
	return top, topStore
}

// Overview gathers the landing-page snapshot for the principal's org. It reuses
// the authorized service methods so each section honors the same access rules.
func (s *Service) Overview(p *Principal) OverviewData {
	var d OverviewData
	if p == nil || p.OrgID == 0 {
		return d
	}

	// Candidates for the split "top consumers" cards.
	var runningVMs []RunnerRow      // running VMs, for live CPU+mem scoring
	var storageCand []TopStorageRow // all VMs with a known disk size

	// In the unified cluster view (request on the VIP, admin), the headline VM
	// stats and the quick-access runners span the WHOLE cluster, not just this
	// node — so the VIP landing page matches the unified Instances inventory.
	if p.Unified && p.IsAdmin {
		if cvms, err := s.ClusterVMs(p); err == nil {
			for _, v := range cvms {
				d.VMs.Total++
				if v.State == "running" {
					d.VMs.Running++
					if len(d.Runners) < 6 {
						d.Runners = append(d.Runners, RunnerRow{ID: v.ID, Name: v.Name, Kind: v.Kind, Node: v.Node})
					}
					runningVMs = append(runningVMs, RunnerRow{ID: v.ID, Name: v.Name, Kind: v.Kind, Node: v.Node})
				} else {
					d.VMs.Stopped++
				}
				if v.Kind == "server" {
					d.VMs.Servers++
				} else {
					d.VMs.Desktop++
				}
				d.VCPUs += v.CPUs
				d.MemoryMB += v.MemoryMB
			}
		}
	} else if sessions, err := s.ListSessions(p); err == nil {
		for _, sess := range sessions {
			d.VMs.Total++
			if sess.State == "running" {
				d.VMs.Running++
				if len(d.Runners) < 6 {
					d.Runners = append(d.Runners, RunnerRow{ID: sess.ID, Name: sess.Name, Kind: sess.Kind})
				}
				runningVMs = append(runningVMs, RunnerRow{ID: sess.ID, Name: sess.Name, Kind: sess.Kind})
			} else {
				d.VMs.Stopped++
			}
			if sess.Kind == "server" {
				d.VMs.Servers++
			} else {
				d.VMs.Desktop++
			}
			d.VCPUs += sess.CPUs
			d.MemoryMB += sess.MemoryMB
			d.DiskGB += sess.DiskGB
			if sess.DiskGB > 0 {
				storageCand = append(storageCand, TopStorageRow{ID: sess.ID, Name: sess.Name, DiskGB: sess.DiskGB})
			}
		}
	}

	// Split-card "top consumers": rank the current running VMs by live load
	// (CPU% + % of allocated memory in use) and pick the heaviest disk VM.
	d.TopVMs, d.TopStorage = s.topConsumers(runningVMs, storageCand)

	// LXC containers (this node). Org-scoped for non-admins; all orgs for admins.
	{
		q := `SELECT COUNT(*) FROM containers`
		args := []any{}
		if !p.IsAdmin {
			q += ` WHERE org_id=?`
			args = append(args, p.OrgID)
		}
		_ = s.db.QueryRow(q, args...).Scan(&d.Containers)
	}

	if imgs, err := image.List(s.db); err == nil {
		for _, im := range imgs {
			if im.Status == "ready" {
				d.Images++
			}
		}
	}
	if isos, err := s.ListISOs(p); err == nil {
		for _, i := range isos {
			if i.Status == "ready" {
				d.ISOs++
			}
		}
	}
	if tpls, err := s.ListTemplates(p); err == nil {
		d.Templates = len(tpls)
	}
	if bks, err := s.ListBackups(p); err == nil {
		d.Backups = len(bks)
		for _, b := range bks {
			d.BackupSize += b.SizeBytes
		}
	}

	if nets, err := s.ListNetworks(p); err == nil {
		d.PortGroups = len(nets)
	}
	if vs, err := s.ListVSwitches(p); err == nil {
		d.VSwitches = len(vs)
	}
	if bl, err := s.ListBonds(p); err == nil {
		d.Bonds = len(bl)
	}

	if pools, err := s.ListPools(p); err == nil {
		d.Pools = len(pools)
		for _, pl := range pools {
			d.PoolUsedBytes += pl.UsedBytes
			d.PoolTotBytes += pl.TotalBytes
		}
	}

	d.DiskTrend, d.RxTrend, d.TxTrend = s.hostTrends()

	if u, err := s.UsageReport(p, 30); err == nil {
		d.Usage = u
	}
	d.Quota = s.GetQuota(p.OrgID)

	if p.IsAdmin {
		if zp, err := s.ZFSPools(p); err == nil {
			d.ZFSPools = len(zp)
		}
		if lp, err := s.LVMThinPools(p); err == nil {
			d.LVMPools = len(lp)
		}
		if nodes, err := s.ListNodes(p); err == nil {
			d.Nodes = len(nodes)
		}
		if mem, err := s.ListMembers(p); err == nil {
			d.Members = len(mem)
		}
		if st, err := s.RoutingStatus(p); err == nil && st != "" {
			d.Routing = "configured"
		} else {
			d.Routing = "off"
		}
	}

	if aud, err := s.ListAudit(p); err == nil {
		if len(aud) > 8 {
			aud = aud[:8]
		}
		d.Recent = aud
	}

	// Display-friendly derived values (so the template needs no math helpers).
	const gb = 1 << 30
	d.PoolUsedGB = float64(d.PoolUsedBytes) / gb
	d.PoolTotGB = float64(d.PoolTotBytes) / gb
	if d.PoolTotBytes > 0 {
		d.PoolPct = int(d.PoolUsedBytes * 100 / d.PoolTotBytes)
	}
	d.BackupSizeGB = float64(d.BackupSize) / gb
	d.MemoryGB = float64(d.MemoryMB) / 1024
	d.DiskTB = float64(d.DiskGB) / 1024
	return d
}
