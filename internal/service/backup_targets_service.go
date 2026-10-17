package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"vdxclone/internal/sharedstg"
	"vdxclone/internal/storage"
)

// First-class backup targets: a backup destination is its own managed object,
// independent of storage pools. kind=local is a plain directory; nfs/cifs/cephfs
// are network shares mounted under <DataDir parent>/backup-mounts/<id>, mounted on
// boot (EnsureBackupMounts) and re-ensured right before every backup run so a
// scheduled job can never write into an unmounted share. Mount credentials are
// AES-GCM sealed at rest (encSeal/encOpen). The synthetic target id 0 is the
// built-in local default backup dir and is always available.

// BackupTargetView is the display/dropdown shape for a target.
type BackupTargetView struct {
	ID      int64
	Name    string
	Kind    string
	Path    string // where backups land (resolved dir, best-effort)
	Mounted bool   // network targets: is it mounted right now
	Detail  string // human summary (e.g. "nfs 10.0.0.5:/export")
}

// BackupTargetInput is the create form.
type BackupTargetInput struct {
	Name     string
	Kind     string // local|nfs|cifs|cephfs
	Path     string // local: the directory
	Server   string // nfs/cifs host; cephfs mon list (comma-separated)
	Share    string // nfs export / cifs share / cephfs path
	Username string // cifs user / ceph client name
	Password string // cifs password / ceph key (plaintext in; sealed at rest)
	Domain   string // cifs domain
	Vers     string // nfs/cifs version
	Options  string // extra mount options
}

// backupMountBase is the parent dir that network target mountpoints live under.
func (s *Service) backupMountBase() string {
	return filepath.Join(filepath.Dir(s.cfg.Paths.BackupDir), "backup-mounts")
}

// ListBackupTargets returns the local default (id 0) followed by every configured
// target for the org. Used by both the management card and the create dropdowns.
func (s *Service) ListBackupTargets(p *Principal) ([]BackupTargetView, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	out := []BackupTargetView{{
		ID: 0, Name: "Local (default backup storage)", Kind: "local",
		Path: s.cfg.Paths.BackupDir, Mounted: true, Detail: s.cfg.Paths.BackupDir,
	}}
	rows, err := s.stg.ListBackupTargets(p.OrgID)
	if err != nil {
		return out, nil
	}
	for _, t := range rows {
		out = append(out, BackupTargetView{
			ID: t.ID, Name: t.Name, Kind: t.Kind, Path: t.Mountpoint,
			Mounted: t.Kind == "local" || isMountpoint(t.Mountpoint),
			Detail:  targetDetail(t),
		})
	}
	return out, nil
}

// targetNames maps a target id to a human label for ListBackups/ListSchedules.
func (s *Service) targetNames() map[int64]string {
	m := map[int64]string{0: "Local"}
	if rows, err := s.stg.AllBackupTargets(); err == nil {
		for _, t := range rows {
			m[t.ID] = t.Name
		}
	}
	return m
}

func targetDetail(t storage.BackupTarget) string {
	switch t.Kind {
	case "nfs":
		return fmt.Sprintf("nfs %s:%s", t.Server, t.Share)
	case "cifs":
		return fmt.Sprintf("cifs //%s/%s", t.Server, t.Share)
	case "cephfs":
		return fmt.Sprintf("cephfs %s:%s", t.Server, t.Share)
	default:
		return t.Mountpoint
	}
}

// CreateBackupTarget persists a new target and, for network kinds, mounts it. If
// the mount fails the row is rolled back so a broken target is never saved.
func (s *Service) CreateBackupTarget(p *Principal, in BackupTargetInput, ip string) (int64, error) {
	if !p.atLeast("admin") {
		return 0, ErrUnauthorized
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return 0, fmt.Errorf("name is required")
	}
	sealed, err := s.encSeal(in.Password)
	if err != nil {
		return 0, err
	}
	t := storage.BackupTarget{
		OrgID: p.OrgID, Name: in.Name, Kind: in.Kind,
		Server: strings.TrimSpace(in.Server), Share: strings.TrimSpace(in.Share),
		Username: in.Username, Secret: sealed, Domain: in.Domain, Vers: in.Vers,
		Options: in.Options,
	}

	switch in.Kind {
	case "local":
		dir := strings.TrimSpace(in.Path)
		if dir == "" {
			return 0, fmt.Errorf("a directory path is required for a local target")
		}
		if strings.HasPrefix(dir, "/dev/") {
			return 0, fmt.Errorf("%q is a device path, not a directory", dir)
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return 0, fmt.Errorf("create %s: %w", dir, err)
		}
		t.Mountpoint = dir
		id, err := s.stg.CreateBackupTarget(t)
		if err != nil {
			return 0, err
		}
		s.audit(p, p.OrgID, "backuptarget.create", "backuptarget", in.Name, ip, map[string]any{"kind": "local", "path": dir})
		return id, nil

	case "nfs", "cifs", "cephfs":
		if t.Server == "" || t.Share == "" {
			return 0, fmt.Errorf("server and share/export are required for a %s target", in.Kind)
		}
		// Insert first (to get an id for the mountpoint path), then mount.
		id, err := s.stg.CreateBackupTarget(t)
		if err != nil {
			return 0, err
		}
		mp := filepath.Join(s.backupMountBase(), fmt.Sprint(id))
		if err := os.MkdirAll(mp, 0o750); err != nil {
			_ = s.stg.DeleteBackupTarget(p.OrgID, id)
			return 0, fmt.Errorf("create mountpoint: %w", err)
		}
		if err := s.stg.SetBackupTargetMountpoint(id, mp); err != nil {
			_ = s.stg.DeleteBackupTarget(p.OrgID, id)
			return 0, err
		}
		t.ID, t.Mountpoint = id, mp
		if err := s.mountBackupTarget(t); err != nil {
			_ = os.Remove(mp)
			_ = s.stg.DeleteBackupTarget(p.OrgID, id)
			return 0, fmt.Errorf("mount %s target: %w", in.Kind, err)
		}
		s.audit(p, p.OrgID, "backuptarget.create", "backuptarget", in.Name, ip, map[string]any{"kind": in.Kind, "server": in.Server, "share": in.Share})
		return id, nil

	default:
		return 0, fmt.Errorf("unknown backup target kind %q", in.Kind)
	}
}

// DeleteBackupTarget unmounts (network) and removes a target. It refuses while any
// backup or schedule still references it, so history never loses its destination.
func (s *Service) DeleteBackupTarget(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	t, err := s.stg.GetBackupTarget(p.OrgID, id)
	if err != nil {
		return ErrNotFound
	}
	if s.stg.BackupTargetInUse(id) {
		return fmt.Errorf("target %q is still used by backups or schedules — remove those first", t.Name)
	}
	if t.Kind != "local" && t.Mountpoint != "" && isMountpoint(t.Mountpoint) {
		if err := sharedstg.Unmount(t.Mountpoint); err != nil {
			return fmt.Errorf("unmount %s: %w", t.Mountpoint, err)
		}
	}
	if t.Kind != "local" && t.Mountpoint != "" {
		_ = os.Remove(t.Mountpoint)
	}
	if err := s.stg.DeleteBackupTarget(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "backuptarget.delete", "backuptarget", t.Name, ip, nil)
	return nil
}

// TestBackupTarget mounts (if needed) and writes+removes a probe file to prove the
// target is actually usable for backups.
func (s *Service) TestBackupTarget(p *Principal, id int64) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	dir, err := s.ResolveBackupTargetDir(id)
	if err != nil {
		return err
	}
	probe := filepath.Join(dir, ".vxvisor-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("target is not writable: %w", err)
	}
	_ = os.Remove(probe)
	return nil
}

// resolveBackupTargetDir returns the directory backups for targetID should be
// written to, ensuring a network target is mounted first. id 0 = local default.
func (s *Service) ResolveBackupTargetDir(targetID int64) (string, error) {
	if targetID == 0 {
		if err := os.MkdirAll(s.cfg.Paths.BackupDir, 0o750); err != nil {
			return "", err
		}
		return s.cfg.Paths.BackupDir, nil
	}
	// Target may belong to any org; look it up without org scoping (the caller
	// already authorized via the session/schedule it came from).
	t, err := s.stg.GetBackupTargetByID(targetID)
	if err != nil {
		return "", fmt.Errorf("backup target %d not found", targetID)
	}
	if t.Kind != "local" {
		if !isMountpoint(t.Mountpoint) {
			if err := s.mountBackupTarget(t); err != nil {
				return "", fmt.Errorf("mount backup target %q: %w", t.Name, err)
			}
		}
	}
	dir := filepath.Join(t.Mountpoint, "vxvisor-backups")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	return dir, nil
}

// EnsureBackupMounts remounts every configured network target. Called at boot (the
// worker) so scheduled/manual backups to shares work without a manual remount.
func (s *Service) EnsureBackupMounts() {
	rows, err := s.stg.AllBackupTargets()
	if err != nil {
		return
	}
	for _, t := range rows {
		if t.Kind == "local" || t.Mountpoint == "" || isMountpoint(t.Mountpoint) {
			continue
		}
		_ = os.MkdirAll(t.Mountpoint, 0o750)
		if err := s.mountBackupTarget(t); err != nil {
			// Non-fatal: log and continue; a run will retry + surface the error.
			fmt.Printf("backup target %q (%s) mount failed at boot: %v\n", t.Name, t.Kind, err)
		}
	}
}

// mountBackupTarget mounts a network target at its mountpoint using sharedstg.
func (s *Service) mountBackupTarget(t storage.BackupTarget) error {
	pw, err := s.encOpen(t.Secret)
	if err != nil {
		return err
	}
	switch t.Kind {
	case "nfs":
		return sharedstg.NFSMount(t.Server, t.Share, t.Mountpoint, "", t.Vers, t.Options)
	case "cifs":
		unc := "//" + strings.TrimPrefix(t.Server, "//") + "/" + strings.TrimPrefix(t.Share, "/")
		return sharedstg.CIFSMount(unc, t.Mountpoint, t.Username, pw, t.Domain, t.Vers, t.Options)
	case "cephfs":
		return sharedstg.CephMount(t.Server, t.Share, t.Mountpoint, t.Username, pw, "", t.Options)
	default:
		return fmt.Errorf("cannot mount target kind %q", t.Kind)
	}
}

// isMountpoint reports whether path is a mount point (its device differs from its
// parent's). Returns false for a plain directory or a missing path.
func isMountpoint(path string) bool {
	if path == "" {
		return false
	}
	var a, b syscall.Stat_t
	if err := syscall.Stat(path, &a); err != nil {
		return false
	}
	if err := syscall.Stat(filepath.Dir(path), &b); err != nil {
		return false
	}
	return a.Dev != b.Dev
}
