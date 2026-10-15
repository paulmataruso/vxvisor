package service

import (
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
	DesktopPools int
	Routing      string // "", "off", or a short status line
	// usage / quota
	Usage UsageReport
	Quota Quota
	// activity
	Recent  []store.AuditEntry
	Runners []RunnerRow // a few running VMs for quick access
}

// RunnerRow is a compact running-VM line for the overview.
type RunnerRow struct {
	ID   string
	Name string
	Kind string
	Node string // owning node name (unified view); "" for the local-only view
}

// Overview gathers the landing-page snapshot for the principal's org. It reuses
// the authorized service methods so each section honors the same access rules.
func (s *Service) Overview(p *Principal) OverviewData {
	var d OverviewData
	if p == nil || p.OrgID == 0 {
		return d
	}

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
		}
	}

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

	if s.BrokerReady() {
		if pools, err := s.ListDesktopPools(p); err == nil {
			d.DesktopPools = len(pools)
		}
	}

	if pools, err := s.ListPools(p); err == nil {
		d.Pools = len(pools)
		for _, pl := range pools {
			d.PoolUsedBytes += pl.UsedBytes
			d.PoolTotBytes += pl.TotalBytes
		}
	}

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
