package service

import (
	"fmt"

	"vdxclone/internal/session"
)

// Billing, quotas and Trash (M6). All local — no external metering or phone-home.

// ---- quotas --------------------------------------------------------------

type Quota struct {
	OrgID       int64
	PlanID      int64
	MaxServers  int
	MaxRunning  int
	MaxVCPUs    int
	MaxMemoryMB int
	MaxDiskGB   int
}

func (s *Service) GetQuota(orgID int64) Quota {
	q := Quota{OrgID: orgID}
	_ = s.db.QueryRow(`SELECT COALESCE(plan_id,0),max_servers,max_running,max_vcpus,max_memory_mb,max_disk_gb
		FROM org_quotas WHERE org_id=?`, orgID).
		Scan(&q.PlanID, &q.MaxServers, &q.MaxRunning, &q.MaxVCPUs, &q.MaxMemoryMB, &q.MaxDiskGB)
	return q
}

func (s *Service) SetQuota(p *Principal, q Quota, ip string) error {
	if !p.ProviderAdmin {
		return ErrUnauthorized // instance admins set org quotas (also from TenantView)
	}
	_, err := s.db.Exec(`INSERT INTO org_quotas(org_id,max_servers,max_running,max_vcpus,max_memory_mb,max_disk_gb,updated_at)
		VALUES(?,?,?,?,?,?,datetime('now'))
		ON CONFLICT(org_id) DO UPDATE SET max_servers=excluded.max_servers,max_running=excluded.max_running,
		  max_vcpus=excluded.max_vcpus,max_memory_mb=excluded.max_memory_mb,max_disk_gb=excluded.max_disk_gb,updated_at=datetime('now')`,
		q.OrgID, q.MaxServers, q.MaxRunning, q.MaxVCPUs, q.MaxMemoryMB, q.MaxDiskGB)
	if err != nil {
		return err
	}
	s.audit(p, q.OrgID, "quota.set", "org", fmt.Sprint(q.OrgID), ip, map[string]any{"max_servers": q.MaxServers, "max_vcpus": q.MaxVCPUs})
	return nil
}

// orgTotals sums an org's live (non-deleted) resource commitments.
type orgTotals struct {
	servers, running, vcpus, memoryMB, diskGB int
}

func (s *Service) orgTotals(orgID int64) orgTotals {
	var t orgTotals
	_ = s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN kind='server' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN state='running' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(cpus),0), COALESCE(SUM(memory_mb),0), COALESCE(SUM(disk_gb),0)
		FROM sessions WHERE org_id=? AND deleted_at IS NULL`, orgID).
		Scan(&t.servers, &t.running, &t.vcpus, &t.memoryMB, &t.diskGB)
	return t
}

// checkQuotaCreate enforces per-org ceilings before provisioning (0 = unlimited).
func (s *Service) checkQuotaCreate(orgID int64, in CreateInput) error {
	q := s.GetQuota(orgID)
	t := s.orgTotals(orgID)
	if in.Kind == "server" && q.MaxServers > 0 && t.servers+1 > q.MaxServers {
		return fmt.Errorf("quota exceeded: max %d server VMs", q.MaxServers)
	}
	if q.MaxVCPUs > 0 && t.vcpus+in.CPUs > q.MaxVCPUs {
		return fmt.Errorf("quota exceeded: max %d vCPUs", q.MaxVCPUs)
	}
	if q.MaxMemoryMB > 0 && t.memoryMB+in.MemoryMB > q.MaxMemoryMB {
		return fmt.Errorf("quota exceeded: max %d MB memory", q.MaxMemoryMB)
	}
	if q.MaxDiskGB > 0 && t.diskGB+in.DiskGB > q.MaxDiskGB {
		return fmt.Errorf("quota exceeded: max %d GB disk", q.MaxDiskGB)
	}
	return nil
}

func (s *Service) checkQuotaStart(orgID int64) error {
	q := s.GetQuota(orgID)
	if q.MaxRunning <= 0 {
		return nil
	}
	t := s.orgTotals(orgID)
	if t.running+1 > q.MaxRunning {
		return fmt.Errorf("quota exceeded: max %d running instances", q.MaxRunning)
	}
	return nil
}

// ---- usage report --------------------------------------------------------

type UsageReport struct {
	Days          int
	VCPUSeconds   int64
	MemMBSeconds  int64
	InstanceHours float64
	CostMicros    int64   // against the org's plan, if any
	CostCredits   float64 // CostMicros / 1e6, for display
}

func (s *Service) UsageReport(p *Principal, days int) (UsageReport, error) {
	if !p.atLeast("member") {
		return UsageReport{}, ErrUnauthorized
	}
	if days <= 0 {
		days = 30
	}
	var r UsageReport
	r.Days = days
	var secs int64
	_ = s.db.QueryRow(fmt.Sprintf(`SELECT COALESCE(SUM(seconds),0),COALESCE(SUM(vcpu_seconds),0),COALESCE(SUM(mem_mb_seconds),0)
		FROM usage_ledger WHERE org_id=? AND ts >= datetime('now','-%d days')`, days), p.OrgID).
		Scan(&secs, &r.VCPUSeconds, &r.MemMBSeconds)
	r.InstanceHours = float64(secs) / 3600

	// Cost against the org's plan (micro-credits), if a plan is assigned.
	q := s.GetQuota(p.OrgID)
	if q.PlanID > 0 {
		var vcpuRate, memRate int64
		if err := s.db.QueryRow(`SELECT vcpu_micros_per_hr,mem_micros_per_gbhr FROM plans WHERE id=?`, q.PlanID).
			Scan(&vcpuRate, &memRate); err == nil {
			r.CostMicros = r.VCPUSeconds*vcpuRate/3600 + r.MemMBSeconds*memRate/1024/3600
		}
	}
	r.CostCredits = float64(r.CostMicros) / 1e6
	return r, nil
}

// ---- trash ---------------------------------------------------------------

func (s *Service) ListTrash(p *Principal) ([]*session.Session, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	return s.mgr.ListTrash(p.OrgID)
}

func (s *Service) RestoreSession(p *Principal, id, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	// Verify the trashed session belongs to the org before restoring.
	var orgID int64
	if err := s.db.QueryRow(`SELECT org_id FROM sessions WHERE id=?`, id).Scan(&orgID); err != nil {
		return ErrNotFound
	}
	if !p.IsAdmin && orgID != p.OrgID {
		return ErrUnauthorized
	}
	if err := s.mgr.Restore(id); err != nil {
		return err
	}
	s.audit(p, orgID, "session.restore", "session", id, ip, nil)
	return nil
}

func (s *Service) PurgeSession(p *Principal, id, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	var orgID int64
	if err := s.db.QueryRow(`SELECT org_id FROM sessions WHERE id=?`, id).Scan(&orgID); err != nil {
		return ErrNotFound
	}
	if !p.IsAdmin && orgID != p.OrgID {
		return ErrUnauthorized
	}
	if err := s.mgr.Purge(id); err != nil {
		return err
	}
	s.audit(p, orgID, "session.purge", "session", id, ip, nil)
	return nil
}
