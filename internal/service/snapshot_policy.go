package service

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/session"
)

// ---- snapshot policies (docs/SNAPSHOTS.md) -------------------------------
//
// A policy snapshots a target — one VM, a folder (recursively), or every VM of
// an org — on a schedule (hourly at :MM, daily at HH:MM, weekly on a day at
// HH:MM, host local time), as ONE best-effort consistency group per run, and
// prunes by retention (keep the last N per VM and/or D days). An immutable
// policy locks each snapshot it takes until its keep-days horizon.
//
// Authz: an instance admin manages every org's policies; an org admin
// (atLeast("admin"), incl. an instance admin in TenantView) manages only its own
// org's — every query below is scoped by org_id for them.

// SnapshotPolicy is one policy row, with display extras.
type SnapshotPolicy struct {
	ID           int64
	OrgID        int64
	OrgName      string
	Name         string
	TargetKind   string // vm | folder | org
	TargetVM     string
	TargetFolder int64
	TargetLabel  string
	Schedule     string // hourly | daily | weekly
	AtMinute     int
	AtHour       int
	Weekday      int // 0 = Sunday
	KeepLast     int
	KeepDays     int
	Immutable    bool
	Enabled      bool
	LastRunAt    string
	NextRunAt    string
	LastStatus   string
	CreatedAt    string
	Snapshots    int
	LastRunLocal string // host-local display forms of LastRunAt / NextRunAt
	NextRunLocal string
}

func localTime(s string) string {
	if t, ok := session.ParseDBTime(s); ok {
		return t.Local().Format("2006-01-02 15:04 MST")
	}
	return s
}

// ScheduleLabel renders the schedule for humans.
func (p SnapshotPolicy) ScheduleLabel() string {
	switch p.Schedule {
	case "hourly":
		return fmt.Sprintf("Hourly at :%02d", p.AtMinute)
	case "daily":
		return fmt.Sprintf("Daily at %02d:%02d", p.AtHour, p.AtMinute)
	case "weekly":
		return fmt.Sprintf("Weekly on %s at %02d:%02d", time.Weekday(p.Weekday), p.AtHour, p.AtMinute)
	}
	return p.Schedule
}

// RetentionLabel renders the retention rules for humans.
func (p SnapshotPolicy) RetentionLabel() string {
	var parts []string
	if p.KeepLast > 0 {
		parts = append(parts, fmt.Sprintf("last %d", p.KeepLast))
	}
	if p.KeepDays > 0 {
		parts = append(parts, fmt.Sprintf("%d days", p.KeepDays))
	}
	if len(parts) == 0 {
		return "keep all"
	}
	return "keep " + strings.Join(parts, " + ")
}

// PolicyInput creates a policy.
type PolicyInput struct {
	OrgID        int64 // instance admin only; others always act on their own org
	Name         string
	TargetKind   string
	TargetVM     string
	TargetFolder int64
	Schedule     string
	AtHour       int
	AtMinute     int
	Weekday      int
	KeepLast     int
	KeepDays     int
	Immutable    bool
}

const policyCols = `p.id,p.org_id,COALESCE(o.name,''),p.name,p.target_kind,p.target_vm,p.target_folder,p.schedule,
	p.at_minute,p.at_hour,p.weekday,p.keep_last,p.keep_days,p.immutable,p.enabled,
	COALESCE(p.last_run_at,''),COALESCE(p.next_run_at,''),p.last_status,p.created_at,
	(SELECT COUNT(*) FROM snapshots sn WHERE sn.policy_id=p.id)`

const policyFrom = ` FROM snapshot_policies p LEFT JOIN orgs o ON o.id=p.org_id `

func scanPolicy(sc interface{ Scan(...any) error }) (SnapshotPolicy, error) {
	var p SnapshotPolicy
	var imm, en int
	err := sc.Scan(&p.ID, &p.OrgID, &p.OrgName, &p.Name, &p.TargetKind, &p.TargetVM, &p.TargetFolder, &p.Schedule,
		&p.AtMinute, &p.AtHour, &p.Weekday, &p.KeepLast, &p.KeepDays, &imm, &en,
		&p.LastRunAt, &p.NextRunAt, &p.LastStatus, &p.CreatedAt, &p.Snapshots)
	p.Immutable, p.Enabled = imm != 0, en != 0
	return p, err
}

func (s *Service) queryPolicies(where string, args ...any) ([]SnapshotPolicy, error) {
	rows, err := s.db.Query(`SELECT `+policyCols+policyFrom+where, args...)
	if err != nil {
		return nil, err
	}
	var out []SnapshotPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].TargetLabel = s.policyTargetLabel(out[i])
		out[i].LastRunLocal, out[i].NextRunLocal = localTime(out[i].LastRunAt), localTime(out[i].NextRunAt)
	}
	return out, nil
}

func (s *Service) policyTargetLabel(p SnapshotPolicy) string {
	switch p.TargetKind {
	case "vm":
		var n string
		if s.db.QueryRow(`SELECT name FROM sessions WHERE id=? AND org_id=?`, p.TargetVM, p.OrgID).Scan(&n) == nil {
			return "Instance " + n
		}
		return "Instance (gone)"
	case "folder":
		var n string
		if s.db.QueryRow(`SELECT name FROM vm_folders WHERE id=? AND org_id=?`, p.TargetFolder, p.OrgID).Scan(&n) == nil {
			return "Folder " + n
		}
		return "Folder (gone)"
	}
	return "All instances"
}

// canManagePolicies: instance admins (any org) and org admins (own org).
func (p *Principal) canManagePolicies() bool { return p.IsAdmin || p.OrgAdmin() }

// ListSnapshotPolicies lists every org's policies for an instance admin, the
// caller's org's otherwise.
func (s *Service) ListSnapshotPolicies(p *Principal) ([]SnapshotPolicy, error) {
	if !p.canManagePolicies() {
		return nil, ErrUnauthorized
	}
	if p.IsAdmin {
		return s.queryPolicies(`ORDER BY o.name, p.name`)
	}
	return s.queryPolicies(`WHERE p.org_id=? ORDER BY p.name`, p.OrgID)
}

// policyFor loads a policy the caller may manage.
func (s *Service) policyFor(p *Principal, id int64) (SnapshotPolicy, error) {
	if !p.canManagePolicies() {
		return SnapshotPolicy{}, ErrUnauthorized
	}
	var list []SnapshotPolicy
	var err error
	if p.IsAdmin {
		list, err = s.queryPolicies(`WHERE p.id=?`, id)
	} else {
		list, err = s.queryPolicies(`WHERE p.id=? AND p.org_id=?`, id, p.OrgID)
	}
	if err != nil {
		return SnapshotPolicy{}, err
	}
	if len(list) == 0 {
		return SnapshotPolicy{}, ErrNotFound
	}
	return list[0], nil
}

// PolicySnapshots lists the snapshots a policy has taken (newest first).
func (s *Service) PolicySnapshots(p *Principal, id int64) ([]PolicySnap, error) {
	pol, err := s.policyFor(p, id)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT sn.id, sn.session_id, COALESCE(se.name, sn.session_id), sn.name,
		COALESCE(sn.consistency,''), COALESCE(sn.locked_until,''), COALESCE(sn.expires_at,''), sn.created_at
		FROM snapshots sn JOIN sessions se ON se.id=sn.session_id
		WHERE sn.policy_id=? AND se.org_id=? ORDER BY sn.id DESC LIMIT 500`, pol.ID, pol.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PolicySnap
	now := time.Now()
	for rows.Next() {
		var ps PolicySnap
		if err := rows.Scan(&ps.ID, &ps.SessionID, &ps.SessionName, &ps.Name, &ps.Consistency, &ps.LockedUntil, &ps.ExpiresAt, &ps.CreatedAt); err != nil {
			return nil, err
		}
		ps.Locked = session.SnapRecord{LockedUntil: ps.LockedUntil}.Locked(now)
		ps.LockedUntil, ps.ExpiresAt = localTime(ps.LockedUntil), localTime(ps.ExpiresAt)
		out = append(out, ps)
	}
	return out, rows.Err()
}

// PolicySnap is one snapshot taken by a policy.
type PolicySnap struct {
	ID          int64
	SessionID   string
	SessionName string
	Name        string
	Consistency string
	LockedUntil string
	ExpiresAt   string
	CreatedAt   string
	Locked      bool
}

func validatePolicy(in *PolicyInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return errors.New("policy name is required (max 64 characters)")
	}
	for _, r := range in.Name {
		if r < 0x20 || r == 0x7f {
			return errors.New("policy name contains control characters")
		}
	}
	switch in.TargetKind {
	case "vm":
		if in.TargetVM == "" {
			return errors.New("choose the instance to snapshot")
		}
		in.TargetFolder = 0
	case "folder":
		if in.TargetFolder <= 0 {
			return errors.New("choose the folder to snapshot")
		}
		in.TargetVM = ""
	case "org":
		in.TargetVM, in.TargetFolder = "", 0
	default:
		return errors.New("target must be an instance, a folder or the whole organization")
	}
	switch in.Schedule {
	case "hourly":
		in.AtHour, in.Weekday = 0, 0
	case "daily":
		in.Weekday = 0
	case "weekly":
		if in.Weekday < 0 || in.Weekday > 6 {
			return errors.New("weekday must be Sunday..Saturday")
		}
	default:
		return errors.New("schedule must be hourly, daily or weekly")
	}
	if in.AtMinute < 0 || in.AtMinute > 59 || in.AtHour < 0 || in.AtHour > 23 {
		return errors.New("time must be HH:MM (00:00..23:59)")
	}
	if in.KeepLast < 0 || in.KeepLast > 10000 || in.KeepDays < 0 || in.KeepDays > 3650 {
		return errors.New("retention out of range (keep last 0..10000, keep days 0..3650)")
	}
	if in.KeepLast == 0 && in.KeepDays == 0 {
		return errors.New("set a retention: keep the last N snapshots and/or keep D days")
	}
	if in.Immutable && in.KeepDays == 0 {
		return errors.New("an immutable policy needs keep-days: its snapshots stay locked for that long")
	}
	return nil
}

// CreateSnapshotPolicy adds a policy.
func (s *Service) CreateSnapshotPolicy(p *Principal, in PolicyInput, ip string) (int64, error) {
	if !p.canManagePolicies() {
		return 0, ErrUnauthorized
	}
	if !p.IsAdmin || in.OrgID == 0 {
		in.OrgID = p.OrgID
	}
	if in.OrgID == 0 {
		return 0, errors.New("no organization selected")
	}
	if err := validatePolicy(&in); err != nil {
		return 0, err
	}
	switch in.TargetKind {
	case "vm":
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=? AND org_id=? AND deleted_at IS NULL`, in.TargetVM, in.OrgID).Scan(&n)
		if n == 0 {
			return 0, ErrNotFound
		}
	case "folder":
		if err := s.folderInOrg(in.OrgID, in.TargetFolder); err != nil {
			return 0, err
		}
	}
	pol := SnapshotPolicy{Schedule: in.Schedule, AtHour: in.AtHour, AtMinute: in.AtMinute, Weekday: in.Weekday}
	next := nextRun(pol, time.Now(), time.Local)
	var uid int64
	if p.User != nil {
		uid = p.User.ID
	}
	res, err := s.db.Exec(`INSERT INTO snapshot_policies
		(org_id,name,target_kind,target_vm,target_folder,schedule,at_minute,at_hour,weekday,keep_last,keep_days,immutable,enabled,next_run_at,created_by)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)`,
		in.OrgID, in.Name, in.TargetKind, in.TargetVM, in.TargetFolder, in.Schedule, in.AtMinute, in.AtHour, in.Weekday,
		in.KeepLast, in.KeepDays, b2int(in.Immutable), next.UTC().Format(time.RFC3339), uid)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, fmt.Errorf("a snapshot policy named %q already exists", in.Name)
		}
		return 0, err
	}
	id, _ := res.LastInsertId()
	s.audit(p, in.OrgID, "snapshot_policy.create", "snapshot_policy", fmt.Sprint(id), ip, map[string]any{
		"name": in.Name, "target": in.TargetKind, "target_vm": in.TargetVM, "target_folder": in.TargetFolder,
		"schedule": in.Schedule, "keep_last": in.KeepLast, "keep_days": in.KeepDays, "immutable": in.Immutable})
	return id, nil
}

func b2int(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DeleteSnapshotPolicy removes a policy. Its snapshots stay (detached, keeping
// any immutability lock until it expires) and are no longer auto-pruned.
func (s *Service) DeleteSnapshotPolicy(p *Principal, id int64, ip string) error {
	pol, err := s.policyFor(p, id)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM snapshot_policies WHERE id=? AND org_id=?`, pol.ID, pol.OrgID); err != nil {
		return err
	}
	s.audit(p, pol.OrgID, "snapshot_policy.delete", "snapshot_policy", fmt.Sprint(id), ip, map[string]any{"name": pol.Name})
	return nil
}

// SetSnapshotPolicyEnabled pauses or resumes a policy.
func (s *Service) SetSnapshotPolicyEnabled(p *Principal, id int64, on bool, ip string) error {
	pol, err := s.policyFor(p, id)
	if err != nil {
		return err
	}
	next := nextRun(pol, time.Now(), time.Local).UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`UPDATE snapshot_policies SET enabled=?, next_run_at=? WHERE id=? AND org_id=?`,
		b2int(on), next, pol.ID, pol.OrgID); err != nil {
		return err
	}
	s.audit(p, pol.OrgID, "snapshot_policy.enable", "snapshot_policy", fmt.Sprint(id), ip, map[string]any{"name": pol.Name, "enabled": on})
	return nil
}

// RunSnapshotPolicyNow runs a policy immediately (in the background).
func (s *Service) RunSnapshotPolicyNow(p *Principal, id int64, ip string) error {
	pol, err := s.policyFor(p, id)
	if err != nil {
		return err
	}
	s.audit(p, pol.OrgID, "snapshot_policy.run_now", "snapshot_policy", fmt.Sprint(id), ip, map[string]any{"name": pol.Name})
	go s.runPolicy(pol, time.Now(), true, false)
	return nil
}

// ---- scheduler -----------------------------------------------------------

// policyRunMu serializes policy runs (the worker tick and run-now).
var policyRunMu sync.Mutex

// RunDueSnapshotPolicies runs every enabled policy whose next run is due. prune
// is false during the daemon's boot grace (nothing is destroyed then). Returns
// the number of policies run.
func (s *Service) RunDueSnapshotPolicies(now time.Time, prune bool) int {
	due, err := s.queryPolicies(`WHERE p.enabled=1 AND (p.next_run_at IS NULL OR p.next_run_at<=?) ORDER BY p.next_run_at`,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		log.Printf("snapshot policies: %v", err)
		return 0
	}
	n := 0
	for _, pol := range due {
		if pol.NextRunAt == "" { // never scheduled (shouldn't happen): schedule, don't fire
			_, _ = s.db.Exec(`UPDATE snapshot_policies SET next_run_at=? WHERE id=?`,
				nextRun(pol, now, time.Local).UTC().Format(time.RFC3339), pol.ID)
			continue
		}
		s.runPolicy(pol, now, prune, true)
		n++
	}
	return n
}

// runPolicy takes one group snapshot of the policy's targets, records each with
// the policy's retention/immutability, prunes, and logs + audits the run.
// scheduled advances next_run_at (a run-now leaves the schedule alone).
func (s *Service) runPolicy(pol SnapshotPolicy, now time.Time, prune, scheduled bool) {
	policyRunMu.Lock()
	defer policyRunMu.Unlock()
	// Re-read: it may have been deleted/disabled while queued.
	cur, err := s.queryPolicies(`WHERE p.id=?`, pol.ID)
	if err != nil || len(cur) == 0 {
		return
	}
	pol = cur[0]
	if scheduled && !pol.Enabled {
		return
	}
	ids, err := s.policyTargets(pol)
	var okN, failN, app, crash, offline int
	var fails []string
	if err == nil {
		group := randID()
		meta := session.SnapMeta{PolicyID: pol.ID, GroupID: group}
		if pol.KeepDays > 0 {
			meta.ExpiresAt = now.Add(time.Duration(pol.KeepDays) * 24 * time.Hour)
			if pol.Immutable {
				meta.LockedUntil = meta.ExpiresAt
			}
		}
		name := pol.Name + " " + now.Format("2006-01-02 15:04")
		results := s.mgr.SnapshotGroup(ids)
		for _, id := range ids {
			it := results[id]
			if it.Err == nil {
				_, it.Err = s.mgr.RecordSnapshot(id, name, it.Result, meta)
			}
			if it.Err != nil {
				failN++
				fails = append(fails, fmt.Sprintf("%s: %v", shortID(id), it.Err))
				continue
			}
			okN++
			switch it.Result.Consistency {
			case session.ConsistencyApp:
				app++
			case session.ConsistencyCrash:
				crash++
			default:
				offline++
			}
		}
	}
	var pruned []string
	if prune {
		pruned = s.prunePolicy(pol, now)
	}

	status := fmt.Sprintf("%d snapshot(s): %d app-consistent, %d crash-consistent, %d offline", okN, app, crash, offline)
	switch {
	case err != nil:
		status = "error: " + err.Error()
	case len(ids) == 0:
		status = "no instances matched the target"
	case failN > 0:
		status = fmt.Sprintf("partial: %d ok, %d failed (%s)", okN, failN, strings.Join(fails, "; "))
	}
	if len(pruned) > 0 {
		status += fmt.Sprintf("; pruned %d", len(pruned))
	}
	if len(status) > 500 {
		status = status[:500] + "…"
	}
	next := pol.NextRunAt
	if scheduled || next == "" {
		next = nextRun(pol, now, time.Local).UTC().Format(time.RFC3339)
	}
	_, _ = s.db.Exec(`UPDATE snapshot_policies SET last_run_at=?, last_status=?, next_run_at=? WHERE id=?`,
		now.UTC().Format(time.RFC3339), status, next, pol.ID)
	log.Printf("snapshot policy %q (org %d): %s", pol.Name, pol.OrgID, status)
	s.SysAudit(pol.OrgID, "snapshot_policy.run", "snapshot_policy", fmt.Sprint(pol.ID), map[string]any{
		"name": pol.Name, "targets": len(ids), "ok": okN, "failed": failN, "app": app, "crash": crash,
		"offline": offline, "pruned": pruned, "scheduled": scheduled})
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// policyTargets resolves a policy to the live instance ids it covers, always
// inside the policy's own org.
func (s *Service) policyTargets(pol SnapshotPolicy) ([]string, error) {
	var rows *sql.Rows
	var err error
	switch pol.TargetKind {
	case "vm":
		rows, err = s.db.Query(`SELECT id FROM sessions WHERE id=? AND org_id=? AND deleted_at IS NULL`, pol.TargetVM, pol.OrgID)
	case "folder":
		rows, err = s.db.Query(`WITH RECURSIVE tree(id) AS (
				SELECT id FROM vm_folders WHERE id=? AND org_id=?
				UNION SELECT f.id FROM vm_folders f JOIN tree t ON f.parent_id=t.id WHERE f.org_id=?)
			SELECT se.id FROM vm_folder_members m JOIN sessions se ON se.id=m.vm_id
			WHERE m.folder_id IN (SELECT id FROM tree) AND m.org_id=? AND se.org_id=? AND se.deleted_at IS NULL
			ORDER BY se.id`, pol.TargetFolder, pol.OrgID, pol.OrgID, pol.OrgID, pol.OrgID)
	case "org":
		rows, err = s.db.Query(`SELECT id FROM sessions WHERE org_id=? AND deleted_at IS NULL ORDER BY id`, pol.OrgID)
	default:
		return nil, fmt.Errorf("unknown target %q", pol.TargetKind)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// prunePolicy deletes the policy's snapshots that retention no longer keeps,
// per VM. Locked snapshots and snapshots with dependent clones are never pruned
// (the engine re-checks both). Returns "vm/snapshot" names it removed.
func (s *Service) prunePolicy(pol SnapshotPolicy, now time.Time) []string {
	rows, err := s.db.Query(`SELECT DISTINCT sn.session_id FROM snapshots sn JOIN sessions se ON se.id=sn.session_id
		WHERE sn.policy_id=? AND se.org_id=?`, pol.ID, pol.OrgID)
	if err != nil {
		return nil
	}
	var vms []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			vms = append(vms, id)
		}
	}
	rows.Close()
	var pruned []string
	for _, vm := range vms {
		all, err := s.mgr.ListSnapshots(vm)
		if err != nil {
			continue
		}
		var mine []session.SnapRecord
		for _, r := range all {
			if r.PolicyID == pol.ID {
				mine = append(mine, r)
			}
		}
		for _, r := range pruneSelect(mine, pol.KeepLast, pol.KeepDays, now) {
			if err := s.mgr.DeleteSnapshot(vm, r.ID); err != nil {
				log.Printf("snapshot policy %q: prune %s on %s: %v", pol.Name, r.Name, shortID(vm), err)
				continue
			}
			pruned = append(pruned, shortID(vm)+"/"+r.Name)
		}
	}
	return pruned
}

// pruneSelect returns the snapshots (all of ONE VM, taken by ONE policy) that
// retention drops. A snapshot is kept while it is among the newest keepLast OR
// younger than keepDays — a rule set to 0 is ignored, and with neither set
// nothing is pruned. Locked snapshots and snapshots instant clones depend on are
// always kept.
func pruneSelect(snaps []session.SnapRecord, keepLast, keepDays int, now time.Time) []session.SnapRecord {
	if keepLast <= 0 && keepDays <= 0 {
		return nil
	}
	sorted := append([]session.SnapRecord(nil), snaps...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID > sorted[j].ID }) // newest first
	horizon := now.Add(-time.Duration(keepDays) * 24 * time.Hour)
	var out []session.SnapRecord
	for i, r := range sorted {
		if keepLast > 0 && i < keepLast {
			continue
		}
		if keepDays > 0 {
			t, ok := session.ParseDBTime(r.CreatedAt)
			if !ok || t.After(horizon) {
				continue // young (or unknown age: keep)
			}
		}
		if r.Locked(now) || len(r.Clones) > 0 {
			continue
		}
		out = append(out, r)
	}
	return out
}

// nextRun is the first scheduled time strictly after `after`, in loc.
func nextRun(p SnapshotPolicy, after time.Time, loc *time.Location) time.Time {
	t := after.In(loc)
	y, mo, d := t.Date()
	switch p.Schedule {
	case "hourly":
		c := time.Date(y, mo, d, t.Hour(), p.AtMinute, 0, 0, loc)
		for !c.After(after) {
			c = c.Add(time.Hour)
		}
		return c
	case "weekly":
		off := (p.Weekday - int(t.Weekday()) + 7) % 7
		c := time.Date(y, mo, d+off, p.AtHour, p.AtMinute, 0, 0, loc)
		if !c.After(after) {
			c = time.Date(y, mo, d+off+7, p.AtHour, p.AtMinute, 0, 0, loc)
		}
		return c
	default: // daily
		c := time.Date(y, mo, d, p.AtHour, p.AtMinute, 0, 0, loc)
		if !c.After(after) {
			c = time.Date(y, mo, d+1, p.AtHour, p.AtMinute, 0, 0, loc)
		}
		return c
	}
}

// SnapshotPolicyFormData is what the policy create form needs: the orgs an
// instance admin can target, and the caller-visible instances and folders.
type SnapshotPolicyFormData struct {
	Orgs    []PolicyOrg
	VMs     []PolicyTarget
	Folders []PolicyTarget
}

// PolicyOrg / PolicyTarget are select options.
type PolicyOrg struct {
	ID   int64
	Name string
}

type PolicyTarget struct {
	ID      string
	OrgID   int64
	OrgName string
	Name    string
}

// SnapshotPolicyForm lists the create form's options (every org for an
// instance admin; the caller's org otherwise).
func (s *Service) SnapshotPolicyForm(p *Principal) (SnapshotPolicyFormData, error) {
	var fd SnapshotPolicyFormData
	if !p.canManagePolicies() {
		return fd, ErrUnauthorized
	}
	scope, args := `WHERE o.id=?`, []any{p.OrgID}
	if p.IsAdmin {
		scope, args = ``, nil
	}
	rows, err := s.db.Query(`SELECT o.id, o.name FROM orgs o `+scope+` ORDER BY o.name`, args...)
	if err != nil {
		return fd, err
	}
	for rows.Next() {
		var o PolicyOrg
		if rows.Scan(&o.ID, &o.Name) == nil {
			fd.Orgs = append(fd.Orgs, o)
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT se.id, se.org_id, o.name, se.name FROM sessions se JOIN orgs o ON o.id=se.org_id `+
		strings.Replace(scope, "o.id", "se.org_id", 1)+andDeleted(scope)+` ORDER BY o.name, se.name`, args...)
	if err != nil {
		return fd, err
	}
	for rows.Next() {
		var t PolicyTarget
		if rows.Scan(&t.ID, &t.OrgID, &t.OrgName, &t.Name) == nil {
			fd.VMs = append(fd.VMs, t)
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT f.id, f.org_id, o.name, f.name FROM vm_folders f JOIN orgs o ON o.id=f.org_id `+
		strings.Replace(scope, "o.id", "f.org_id", 1)+` ORDER BY o.name, f.name`, args...)
	if err != nil {
		return fd, err
	}
	for rows.Next() {
		var t PolicyTarget
		var id int64
		if rows.Scan(&id, &t.OrgID, &t.OrgName, &t.Name) == nil {
			t.ID = fmt.Sprint(id)
			fd.Folders = append(fd.Folders, t)
		}
	}
	rows.Close()
	return fd, nil
}

func andDeleted(scope string) string {
	if scope == "" {
		return ` WHERE se.deleted_at IS NULL`
	}
	return ` AND se.deleted_at IS NULL`
}
