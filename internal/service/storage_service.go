package service

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"vdxclone/internal/ceph"
	"vdxclone/internal/lvm"
	"vdxclone/internal/storage"
	"vdxclone/internal/zfs"
)

// PoolEntry is one item inside a storage pool — a file (dir pool), ZFS dataset/
// zvol, LVM logical volume, or RBD image — for the datastore/filesystem browser.
// Bytes is the provisioned/used size; Kind is a coarse type for the UI icon.
type PoolEntry struct {
	Name     string `json:"name"`
	Bytes    int64  `json:"bytes"`
	Kind     string `json:"kind"` // qcow2|iso|raw|file|dir|dataset|zvol|lv|image
	Modified string `json:"modified,omitempty"`
}

// BrowsePool lists the contents of a registered storage pool, dispatching by the
// pool's kind. Read-only: it never creates, moves, or deletes anything. Admin
// only (a pool's raw contents can expose other orgs' disk names).
func (s *Service) BrowsePool(p *Principal, poolID int64) (storage.Pool, []PoolEntry, error) {
	if !p.IsAdmin {
		return storage.Pool{}, nil, ErrUnauthorized
	}
	pools, err := s.ListPools(p)
	if err != nil {
		return storage.Pool{}, nil, err
	}
	var pool storage.Pool
	found := false
	for _, pl := range pools {
		if pl.ID == poolID {
			pool, found = pl, true
			break
		}
	}
	if !found {
		return storage.Pool{}, nil, fmt.Errorf("storage pool %d not found", poolID)
	}

	var entries []PoolEntry
	switch pool.Kind {
	case "zfs":
		ds, e := zfs.ListDatasets(pool.Name)
		if e != nil {
			return pool, nil, e
		}
		for _, d := range ds {
			if d.Name == pool.Name {
				continue // skip the root dataset itself
			}
			k := "dataset"
			if d.Type == "volume" {
				k = "zvol"
			}
			entries = append(entries, PoolEntry{Name: d.Name, Bytes: d.UsedBytes, Kind: k})
		}
	case "lvm":
		vg := pool.Name // registered as "<vg>/<thinpool>"
		if i := strings.IndexByte(vg, '/'); i > 0 {
			vg = vg[:i]
		}
		lvs, e := lvm.ListLVs(vg)
		if e != nil {
			return pool, nil, e
		}
		for _, lv := range lvs {
			entries = append(entries, PoolEntry{Name: lv.Name, Bytes: lv.Bytes, Kind: "lv"})
		}
	case "rbd":
		imgs, e := ceph.ListImages(pool.Path)
		if e != nil {
			return pool, nil, e
		}
		for _, im := range imgs {
			entries = append(entries, PoolEntry{Name: im.Name, Bytes: im.Bytes, Kind: "image"})
		}
	default: // "dir" and any filesystem-like pool: list the directory
		ents, e := os.ReadDir(pool.Path)
		if e != nil {
			return pool, nil, e
		}
		for _, en := range ents {
			if en.IsDir() {
				entries = append(entries, PoolEntry{Name: en.Name() + "/", Kind: "dir"})
				continue
			}
			var sz int64
			var mod string
			if fi, ferr := en.Info(); ferr == nil {
				sz = fi.Size()
				mod = fi.ModTime().Format("2006-01-02 15:04")
			}
			entries = append(entries, PoolEntry{Name: en.Name(), Bytes: sz, Kind: fileKind(en.Name()), Modified: mod})
		}
	}
	return pool, entries, nil
}

func fileKind(name string) string {
	switch {
	case strings.HasSuffix(name, ".qcow2"):
		return "qcow2"
	case strings.HasSuffix(name, ".iso"):
		return "iso"
	case strings.HasSuffix(name, ".raw"), strings.HasSuffix(name, ".img"):
		return "raw"
	default:
		return "file"
	}
}

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

// ---- imported base images --------------------------------------------------

// ImportedImages lists the base images created by VMware imports, so the UI can
// clean up the templates left behind after an import. Admin only.
func (s *Service) ImportedImages(p *Principal) ([]storage.ImportedImage, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return s.stg.ListImportedImages()
}

// DeleteBaseImage removes an imported base image — its row and its on-disk file.
// Refused while any instance still references it (handled in the Store). Admin only.
func (s *Service) DeleteBaseImage(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	path, err := s.stg.DeleteImage(name)
	if err != nil {
		return err
	}
	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove image file: %w", err)
		}
	}
	s.audit(p, p.OrgID, "image.delete", "image", name, ip, map[string]any{"path": path})
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

// Snapshots and instant clones: snapshot_service.go.

// ---- backups -------------------------------------------------------------

func (s *Service) ListBackups(p *Principal) ([]storage.Backup, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	list, err := s.stg.ListBackups(p.OrgID)
	if err != nil {
		return nil, err
	}
	names := s.targetNames()
	for i := range list {
		list[i].Target = names[list[i].TargetID]
	}
	return list, nil
}

// Backup targets (first-class, pool-independent) live in backup_targets_service.go.

// CreateBackup runs a backup of a stopped instance synchronously (the caller is
// typically a short HTTP request; disks here are small). It records the row then
// streams the compressed copy.
func (s *Service) CreateBackup(p *Principal, sessionID, name string, targetID int64, ip string) (int64, error) {
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
	// Resolve + validate the target BEFORE recording a row, so a bad target
	// (unmounted share, block pool) fails fast with a clear message and never
	// leaves a stuck 'pending' backup behind.
	destDir, err := s.ResolveBackupTargetDir(targetID)
	if err != nil {
		return 0, err
	}
	id, err := s.stg.CreateBackupRow(p.OrgID, sessionID, name, targetID)
	if err != nil {
		return 0, err
	}
	if err := s.stg.RunBackup(id, sess.DiskPath, destDir); err != nil {
		return id, err
	}
	s.audit(p, p.OrgID, "backup.create", "session", sessionID, ip, map[string]any{"name": name, "backup_id": id, "target_id": targetID})
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
	list, err := s.stg.ListSchedules(p.OrgID)
	if err != nil {
		return nil, err
	}
	names := s.targetNames()
	for i := range list {
		list[i].Target = names[list[i].TargetID]
	}
	return list, nil
}

func (s *Service) CreateSchedule(p *Principal, sessionID string, intervalHours, keep int, targetID int64, ip string) error {
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
	// Validate the target now so a schedule can never be created pointing at an
	// unwritable destination (it would silently fail on every background run).
	if _, err := s.ResolveBackupTargetDir(targetID); err != nil {
		return err
	}
	if _, err := s.stg.CreateSchedule(p.OrgID, sessionID, intervalHours, keep, targetID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "schedule.create", "session", sessionID, ip, map[string]any{"interval_hours": intervalHours, "keep": keep, "target_id": targetID})
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
	pools, err := s.stg.ListPools()
	if err != nil {
		return nil, err
	}
	// An LVM-thin pool is not a filesystem, so the storage layer's statfs on its
	// device path (/dev/<vg>) reports a bogus size (e.g. devtmpfs). Overlay the
	// REAL thin-pool size + allocation from LVM so this matches the LVM Thin Pools
	// view (name is "<vg>/<pool>").
	var thin []lvm.ThinPool
	loaded := false
	for i := range pools {
		if pools[i].Kind != "lvm" {
			continue
		}
		if !loaded {
			thin, _ = lvm.ListThinPools()
			loaded = true
		}
		for _, tp := range thin {
			if tp.VG+"/"+tp.Name == pools[i].Name {
				pools[i].TotalBytes = tp.SizeBytes
				pools[i].UsedBytes = int64(float64(tp.SizeBytes) * tp.DataPct / 100)
				break
			}
		}
	}
	// An RBD pool is backed by the Ceph cluster, not a local filesystem — overlay
	// its real used/total from `ceph df` (path holds the Ceph pool name).
	for i := range pools {
		if pools[i].Kind != "rbd" {
			continue
		}
		if used, total := ceph.PoolUsage(pools[i].Path); total > 0 {
			pools[i].UsedBytes, pools[i].TotalBytes = used, total
		}
	}
	return pools, nil
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
