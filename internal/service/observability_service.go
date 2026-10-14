package service

import (
	"fmt"

	"vdxclone/internal/metrics"
)

// Observability entry points (M5): the live metrics snapshot, alert rules, and
// notification channels.

// LiveMetrics returns the host sample plus the caller-org's VM samples.
func (s *Service) LiveMetrics(p *Principal) metrics.LiveSnapshot {
	if s.mc == nil {
		return metrics.LiveSnapshot{}
	}
	snap := s.mc.Live()
	if p.IsAdmin {
		return snap
	}
	// Restrict VM rows to the caller's current org.
	ids := map[string]bool{}
	rows, err := s.db.Query(`SELECT id FROM sessions WHERE org_id=? AND deleted_at IS NULL`, p.OrgID)
	if err == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids[id] = true
			}
		}
		rows.Close()
	}
	var vms []metrics.Sample
	for _, v := range snap.VMs {
		if ids[v.TargetID] {
			vms = append(vms, v)
		}
	}
	snap.VMs = vms
	return snap
}

func (s *Service) HostHistory(p *Principal) []metrics.Sample {
	if s.mc == nil {
		return nil
	}
	return s.mc.HostHistory()
}

// MetricHistory returns persisted time-series samples for a scope/target over
// the last `mins` minutes. Host history is visible to any member; a VM's history
// is restricted to its own org.
func (s *Service) MetricHistory(p *Principal, scope, target string, mins int) []metrics.Sample {
	if s.mc == nil || p.OrgID == 0 {
		return nil
	}
	if scope == "vm" && !p.IsAdmin {
		if _, err := s.sessionInOrg(p, target); err != nil {
			return nil
		}
	}
	return s.mc.History(scope, target, mins)
}

// ---- alert rules ---------------------------------------------------------

type AlertRule struct {
	ID        int64
	Name      string
	Metric    string
	Op        string
	Threshold float64
	ChannelID int64
	Enabled   bool
}

type Alert struct {
	ID         int64
	RuleName   string
	State      string
	Value      float64
	FiredAt    string
	ResolvedAt string
}

type AlertChannel struct {
	ID     int64
	Name   string
	Kind   string
	Target string
}

func (s *Service) ListAlertRules(p *Principal) ([]AlertRule, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,name,metric,op,threshold,COALESCE(channel_id,0),enabled
		FROM alert_rules WHERE org_id=? OR org_id IS NULL ORDER BY id DESC`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Metric, &r.Op, &r.Threshold, &r.ChannelID, &en); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) CreateAlertRule(p *Principal, r AlertRule, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	var ch any
	if r.ChannelID > 0 {
		ch = r.ChannelID
	}
	if _, err := s.db.Exec(`INSERT INTO alert_rules(org_id,name,metric,op,threshold,channel_id) VALUES(?,?,?,?,?,?)`,
		p.OrgID, r.Name, r.Metric, r.Op, r.Threshold, ch); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "alertrule.create", "alertrule", r.Name, ip, map[string]any{"metric": r.Metric, "op": r.Op, "threshold": r.Threshold})
	return nil
}

func (s *Service) DeleteAlertRule(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if _, err := s.db.Exec(`DELETE FROM alert_rules WHERE id=? AND (org_id=? OR org_id IS NULL)`, id, p.OrgID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "alertrule.delete", "alertrule", fmt.Sprint(id), ip, nil)
	return nil
}

func (s *Service) ListAlerts(p *Principal) ([]Alert, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT a.id,r.name,a.state,a.value,a.fired_at,COALESCE(a.resolved_at,'')
		FROM alerts a JOIN alert_rules r ON r.id=a.rule_id
		WHERE r.org_id=? OR r.org_id IS NULL ORDER BY a.id DESC LIMIT 100`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.RuleName, &a.State, &a.Value, &a.FiredAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Service) ListAlertChannels(p *Principal) ([]AlertChannel, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,name,kind,target FROM alert_channels WHERE org_id=? OR org_id IS NULL ORDER BY id DESC`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertChannel
	for rows.Next() {
		var c AlertChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Target); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) CreateAlertChannel(p *Principal, name, kind, target, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if _, err := s.db.Exec(`INSERT INTO alert_channels(org_id,name,kind,target) VALUES(?,?,?,?)`, p.OrgID, name, kind, target); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "alertchannel.create", "alertchannel", name, ip, map[string]any{"kind": kind})
	return nil
}
