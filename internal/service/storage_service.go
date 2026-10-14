package service

import (
	"errors"
	"fmt"
	"io"
	"time"

	"vdxclone/internal/storage"
)

// This file holds the authorized, audited entry points for the M3 storage
// features (ISOs, templates, snapshots, backups, schedules, pools). Every method
// re-checks org membership and records an audit event, exactly like the compute
// methods in service.go.

// ---- ISOs ----------------------------------------------------------------

func (s *Service) ListISOs(p *Principal) ([]storage.ISO, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.stg.ListISOs(p.OrgID)
}

func (s *Service) UploadISO(p *Principal, name string, body io.Reader, ip string) (int64, error) {
	if !p.atLeast("member") {
		return 0, ErrUnauthorized
	}
	id, err := s.stg.UploadISO(p.OrgID, name, body)
	if err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "iso.upload", "iso", fmt.Sprint(id), ip, map[string]any{"name": name})
	return id, nil
}

func (s *Service) PullISO(p *Principal, name, url, ip string) (int64, error) {
	if !p.atLeast("member") {
		return 0, ErrUnauthorized
	}
	id, err := s.stg.PullISO(p.OrgID, name, url)
	if err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "iso.pull", "iso", fmt.Sprint(id), ip, map[string]any{"name": name, "url": url})
	return id, nil
}

func (s *Service) DeleteISO(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.stg.DeleteISO(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "iso.delete", "iso", fmt.Sprint(id), ip, nil)
	return nil
}

// ---- templates -----------------------------------------------------------

func (s *Service) ListTemplates(p *Principal) ([]storage.Template, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.stg.ListTemplates(p.OrgID)
}

func (s *Service) CreateTemplate(p *Principal, t storage.Template, ip string) (int64, error) {
	if !p.atLeast("member") {
		return 0, ErrUnauthorized
	}
	t.OrgID = p.OrgID
	id, err := s.stg.CreateTemplate(t)
	if err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "template.create", "template", fmt.Sprint(id), ip, map[string]any{"name": t.Name, "image": t.ImageName})
	return id, nil
}

func (s *Service) DeleteTemplate(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.stg.DeleteTemplate(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "template.delete", "template", fmt.Sprint(id), ip, nil)
	return nil
}

// LaunchFromTemplate creates a new instance from a saved template.
func (s *Service) LaunchFromTemplate(p *Principal, templateID int64, name, ip string) (string, error) {
	if !p.atLeast("member") {
		return "", ErrUnauthorized
	}
	t, err := s.stg.GetTemplate(p.OrgID, templateID)
	if err != nil {
		return "", ErrNotFound
	}
	sess, err := s.CreateSession(p, CreateInput{
		Name: name, Image: t.ImageName, Kind: t.Kind, Firmware: t.Firmware,
		CPUs: t.CPUs, MemoryMB: t.MemoryMB, DiskGB: t.DiskGB,
		CloudInit: t.CloudInit, CIUsername: t.CIUsername, CISSHKey: t.CISSHKey,
	}, ip)
	if err != nil {
		return "", err
	}
	return sess.ID, nil
}

// ---- snapshots -----------------------------------------------------------

func (s *Service) ListSnapshots(p *Principal, sessionID string) ([]storage.Snapshot, error) {
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return nil, err
	}
	return s.stg.ListSnapshots(sessionID)
}

func (s *Service) CreateSnapshot(p *Principal, sessionID, name, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	tag, online, err := s.mgr.Snapshot(sessionID, name)
	if err != nil {
		return err
	}
	if _, err := s.stg.RecordSnapshot(sessionID, name, tag, online); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "snapshot.create", "session", sessionID, ip, map[string]any{"name": name, "online": online})
	return nil
}

func (s *Service) RevertSnapshot(p *Principal, sessionID string, snapID int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	sn, err := s.stg.GetSnapshot(sessionID, snapID)
	if err != nil {
		return ErrNotFound
	}
	if err := s.mgr.RevertSnapshot(sessionID, sn.Tag); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "snapshot.revert", "session", sessionID, ip, map[string]any{"snapshot": sn.Name})
	return nil
}

func (s *Service) DeleteSnapshot(p *Principal, sessionID string, snapID int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	sn, err := s.stg.GetSnapshot(sessionID, snapID)
	if err != nil {
		return ErrNotFound
	}
	if err := s.mgr.DeleteSnapshot(sessionID, sn.Tag, sn.Online); err != nil {
		return err
	}
	if err := s.stg.DeleteSnapshotRow(snapID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "snapshot.delete", "session", sessionID, ip, map[string]any{"snapshot": sn.Name})
	return nil
}

// ---- backups -------------------------------------------------------------

func (s *Service) ListBackups(p *Principal) ([]storage.Backup, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.stg.ListBackups(p.OrgID)
}

// CreateBackup runs a backup of a stopped instance synchronously (the caller is
// typically a short HTTP request; disks here are small). It records the row then
// streams the compressed copy.
func (s *Service) CreateBackup(p *Principal, sessionID, name, ip string) (int64, error) {
	if !p.atLeast("member") {
		return 0, ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return 0, err
	}
	if s.mgr.Running(sess) {
		return 0, errors.New("stop the instance before backing it up")
	}
	id, err := s.stg.CreateBackupRow(p.OrgID, sessionID, name)
	if err != nil {
		return 0, err
	}
	if err := s.stg.RunBackup(id, sess.DiskPath); err != nil {
		return id, err
	}
	s.audit(p, p.OrgID, "backup.create", "session", sessionID, ip, map[string]any{"name": name, "backup_id": id})
	return id, nil
}

// RestoreBackup registers a backup as a new base image for the org.
func (s *Service) RestoreBackup(p *Principal, backupID int64, ip string) (string, error) {
	if !p.atLeast("admin") {
		return "", ErrUnauthorized
	}
	b, err := s.stg.GetBackup(p.OrgID, backupID)
	if err != nil {
		return "", ErrNotFound
	}
	if b.Status != "ready" {
		return "", errors.New("backup is not ready")
	}
	img, err := s.stg.RestoreBackup(b)
	if err != nil {
		return "", err
	}
	s.audit(p, p.OrgID, "backup.restore", "backup", fmt.Sprint(backupID), ip, map[string]any{"image": img})
	return img, nil
}

func (s *Service) DeleteBackup(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.stg.DeleteBackup(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "backup.delete", "backup", fmt.Sprint(id), ip, nil)
	return nil
}

// ---- backup schedules ----------------------------------------------------

func (s *Service) ListSchedules(p *Principal) ([]storage.Schedule, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.stg.ListSchedules(p.OrgID)
}

func (s *Service) CreateSchedule(p *Principal, sessionID string, intervalHours, keep int, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	if intervalHours < 1 {
		intervalHours = 24
	}
	if keep < 1 {
		keep = 7
	}
	if _, err := s.stg.CreateSchedule(p.OrgID, sessionID, intervalHours, keep); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "schedule.create", "session", sessionID, ip, map[string]any{"interval_hours": intervalHours, "keep": keep})
	return nil
}

func (s *Service) DeleteSchedule(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.stg.DeleteSchedule(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "schedule.delete", "schedule", fmt.Sprint(id), ip, nil)
	return nil
}

// ---- storage pools -------------------------------------------------------

func (s *Service) ListPools(p *Principal) ([]storage.Pool, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	return s.stg.ListPools()
}

func (s *Service) UpsertPool(p *Principal, name, kind, path, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.stg.UpsertPool(name, kind, path); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "pool.upsert", "pool", name, ip, map[string]any{"kind": kind, "path": path})
	return nil
}

// ---- retention -----------------------------------------------------------

// SetRetention schedules an instance for auto-deprovision at a future time.
func (s *Service) SetRetention(p *Principal, sessionID string, at time.Time, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE sessions SET retention_at=? WHERE id=?`, at.UTC().Format(time.RFC3339), sessionID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "retention.set", "session", sessionID, ip, map[string]any{"at": at.UTC().Format(time.RFC3339)})
	return nil
}
