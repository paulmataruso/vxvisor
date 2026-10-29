// Package storage owns M3 "images & storage" entities: the ISO library, instance
// templates, disk snapshots, compressed backups and their schedules, and storage
// pools. Data access plus the IO-heavy pull/backup/restore operations live here;
// the service layer calls in and enforces authorization.
package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/qemu"
)

type Store struct {
	cfg *config.Config
	db  *db.DB
}

func New(cfg *config.Config, d *db.DB) *Store { return &Store{cfg: cfg, db: d} }

// ---- ISOs ----------------------------------------------------------------

type ISO struct {
	ID        int64
	OrgID     int64
	Name      string
	Path      string
	SourceURL string
	SizeBytes int64
	Checksum  string
	Status    string
	CreatedAt string
}

// ListISOs returns an org's ISOs plus any global (org_id NULL) ones.
func (s *Store) ListISOs(orgID int64) ([]ISO, error) {
	rows, err := s.db.Query(`SELECT id,COALESCE(org_id,0),name,path,source_url,size_bytes,checksum,status,created_at
		FROM isos WHERE org_id=? OR org_id IS NULL ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ISO
	for rows.Next() {
		var i ISO
		if err := rows.Scan(&i.ID, &i.OrgID, &i.Name, &i.Path, &i.SourceURL, &i.SizeBytes, &i.Checksum, &i.Status, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) GetISO(orgID, id int64) (ISO, error) {
	var i ISO
	err := s.db.QueryRow(`SELECT id,COALESCE(org_id,0),name,path,source_url,size_bytes,checksum,status,created_at
		FROM isos WHERE id=? AND (org_id=? OR org_id IS NULL)`, id, orgID).
		Scan(&i.ID, &i.OrgID, &i.Name, &i.Path, &i.SourceURL, &i.SizeBytes, &i.Checksum, &i.Status, &i.CreatedAt)
	return i, err
}

func (s *Store) DeleteISO(orgID, id int64) error {
	var path string
	if err := s.db.QueryRow(`SELECT path FROM isos WHERE id=? AND org_id=?`, id, orgID).Scan(&path); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM isos WHERE id=? AND org_id=?`, id, orgID); err != nil {
		return err
	}
	_ = os.Remove(path)
	return nil
}

// UploadISO stores an uploaded ISO body on disk and records it.
func (s *Store) UploadISO(orgID int64, name string, body io.Reader) (int64, error) {
	dest := filepath.Join(s.cfg.Paths.ISODir, fmt.Sprintf("org%d-%s-%s.iso", orgID, timestamp(), safeName(name)))
	f, err := os.Create(dest)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	n, err := io.Copy(f, io.TeeReader(body, h))
	f.Close()
	if err != nil {
		os.Remove(dest)
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO isos(org_id,name,path,size_bytes,checksum,status) VALUES(?,?,?,?,?,'ready')`,
		orgID, name, dest, n, hex.EncodeToString(h.Sum(nil)))
	if err != nil {
		os.Remove(dest)
		return 0, err
	}
	return res.LastInsertId()
}

// PullISO downloads an ISO from a URL (synchronously) and records it.
// PullISO downloads an ISO from a URL asynchronously. It records a 'downloading'
// row and returns immediately, so the request never blocks on a multi-GB
// transfer. A background goroutine streams to disk and flips the row to 'ready'
// (with size + checksum) or 'error' (removing the partial file). A failed pull
// therefore leaves a visible 'error' row the user can delete and retry — it
// never blocks a fresh attempt, and each attempt writes a uniquely-named file.
func (s *Store) PullISO(orgID int64, name, url string) (int64, error) {
	if name == "" {
		name = safeName(filepath.Base(url))
	}
	dest := filepath.Join(s.cfg.Paths.ISODir, fmt.Sprintf("org%d-%s-%s.iso", orgID, timestamp(), safeName(name)))
	res, err := s.db.Exec(`INSERT INTO isos(org_id,name,path,source_url,status) VALUES(?,?,?,?,'downloading')`,
		orgID, name, dest, url)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	go s.downloadISO(id, dest, url)
	return id, nil
}

// downloadISO performs the actual transfer for PullISO and finalizes the row.
func (s *Store) downloadISO(id int64, dest, url string) {
	markErr := func() {
		os.Remove(dest)
		_, _ = s.db.Exec(`UPDATE isos SET status='error' WHERE id=?`, id)
	}
	resp, err := http.Get(url)
	if err != nil {
		markErr()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		markErr()
		return
	}
	f, err := os.Create(dest)
	if err != nil {
		markErr()
		return
	}
	h := sha256.New()
	// Count bytes as they stream and flush the running total to the row every
	// ~16 MiB, so the UI toast can show live progress for a background download.
	pw := &progressWriter{db: s.db, id: id, every: 16 << 20}
	n, err := io.Copy(f, io.TeeReader(resp.Body, io.MultiWriter(h, pw)))
	f.Close()
	if err != nil {
		markErr()
		return
	}
	if _, err := s.db.Exec(`UPDATE isos SET status='ready', size_bytes=?, checksum=? WHERE id=?`,
		n, hex.EncodeToString(h.Sum(nil)), id); err != nil {
		os.Remove(dest)
	}
}

// progressWriter flushes the running byte count of an in-flight ISO download to
// its row, throttled so it writes a few times rather than on every chunk.
type progressWriter struct {
	db    *db.DB
	id    int64
	total int64
	last  int64
	every int64
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.total += int64(len(b))
	if p.total-p.last >= p.every {
		p.last = p.total
		_, _ = p.db.Exec(`UPDATE isos SET size_bytes=? WHERE id=?`, p.total, p.id)
	}
	return len(b), nil
}

// ---- templates -----------------------------------------------------------

type Template struct {
	ID         int64
	OrgID      int64
	Name       string
	ImageName  string
	Kind       string
	Firmware   string
	CPUs       int
	MemoryMB   int
	DiskGB     int
	CloudInit  bool
	CIUsername string
	CISSHKey   string
	CreatedAt  string
}

func (s *Store) CreateTemplate(t Template) (int64, error) {
	ci := 0
	if t.CloudInit {
		ci = 1
	}
	res, err := s.db.Exec(`INSERT INTO templates(org_id,name,image_name,kind,firmware,cpus,memory_mb,disk_gb,cloud_init,ci_username,ci_ssh_key)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		t.OrgID, t.Name, t.ImageName, t.Kind, t.Firmware, t.CPUs, t.MemoryMB, t.DiskGB, ci, t.CIUsername, t.CISSHKey)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListTemplates(orgID int64) ([]Template, error) {
	rows, err := s.db.Query(`SELECT id,org_id,name,image_name,kind,firmware,cpus,memory_mb,disk_gb,cloud_init,ci_username,ci_ssh_key,created_at
		FROM templates WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		var ci int
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.ImageName, &t.Kind, &t.Firmware, &t.CPUs, &t.MemoryMB, &t.DiskGB, &ci, &t.CIUsername, &t.CISSHKey, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.CloudInit = ci != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTemplate(orgID, id int64) (Template, error) {
	var t Template
	var ci int
	err := s.db.QueryRow(`SELECT id,org_id,name,image_name,kind,firmware,cpus,memory_mb,disk_gb,cloud_init,ci_username,ci_ssh_key,created_at
		FROM templates WHERE id=? AND org_id=?`, id, orgID).
		Scan(&t.ID, &t.OrgID, &t.Name, &t.ImageName, &t.Kind, &t.Firmware, &t.CPUs, &t.MemoryMB, &t.DiskGB, &ci, &t.CIUsername, &t.CISSHKey, &t.CreatedAt)
	t.CloudInit = ci != 0
	return t, err
}

func (s *Store) DeleteTemplate(orgID, id int64) error {
	_, err := s.db.Exec(`DELETE FROM templates WHERE id=? AND org_id=?`, id, orgID)
	return err
}

// Snapshot rows are owned by the session package (session/snaprecords.go).

// ---- backups -------------------------------------------------------------

type Backup struct {
	ID         int64
	OrgID      int64
	SessionID  string
	Name       string
	Path       string
	Compressor string
	SizeBytes  int64
	Status     string
	Error      string
	TargetID   int64
	Target     string // display name, filled by the service layer
	CreatedAt  string
}

func (s *Store) CreateBackupRow(orgID int64, sessionID, name string, targetID int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO backups(org_id,session_id,name,status,target_id) VALUES(?,?,?,'pending',?)`, orgID, sessionID, name, targetID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListBackups(orgID int64) ([]Backup, error) {
	rows, err := s.db.Query(`SELECT id,org_id,session_id,name,path,compressor,size_bytes,status,error,target_id,created_at
		FROM backups WHERE org_id=? ORDER BY id DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Backup
	for rows.Next() {
		var b Backup
		if err := rows.Scan(&b.ID, &b.OrgID, &b.SessionID, &b.Name, &b.Path, &b.Compressor, &b.SizeBytes, &b.Status, &b.Error, &b.TargetID, &b.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) GetBackup(orgID, id int64) (Backup, error) {
	var b Backup
	err := s.db.QueryRow(`SELECT id,org_id,session_id,name,path,compressor,size_bytes,status,error,target_id,created_at
		FROM backups WHERE id=? AND org_id=?`, id, orgID).
		Scan(&b.ID, &b.OrgID, &b.SessionID, &b.Name, &b.Path, &b.Compressor, &b.SizeBytes, &b.Status, &b.Error, &b.TargetID, &b.CreatedAt)
	return b, err
}

// BackupTarget is a first-class, pool-independent place to store backups. Network
// kinds carry mount details; 'secret' is AES-GCM sealed by the service layer.
type BackupTarget struct {
	ID         int64
	OrgID      int64
	Name       string
	Kind       string // local|nfs|cifs|cephfs
	Mountpoint string
	Server     string
	Share      string
	Username   string
	Secret     string // sealed (enc:…) at rest
	Domain     string
	Vers       string
	Options    string
	CreatedAt  string
}

const backupTargetCols = `id,org_id,name,kind,mountpoint,server,share,username,secret,domain,vers,options,created_at`

func scanBackupTarget(sc interface{ Scan(...any) error }) (BackupTarget, error) {
	var t BackupTarget
	err := sc.Scan(&t.ID, &t.OrgID, &t.Name, &t.Kind, &t.Mountpoint, &t.Server, &t.Share,
		&t.Username, &t.Secret, &t.Domain, &t.Vers, &t.Options, &t.CreatedAt)
	return t, err
}

func (s *Store) CreateBackupTarget(t BackupTarget) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO backup_targets(org_id,name,kind,mountpoint,server,share,username,secret,domain,vers,options)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		t.OrgID, t.Name, t.Kind, t.Mountpoint, t.Server, t.Share, t.Username, t.Secret, t.Domain, t.Vers, t.Options)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListBackupTargets(orgID int64) ([]BackupTarget, error) {
	rows, err := s.db.Query(`SELECT `+backupTargetCols+` FROM backup_targets WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupTarget
	for rows.Next() {
		t, err := scanBackupTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetBackupTarget(orgID, id int64) (BackupTarget, error) {
	return scanBackupTarget(s.db.QueryRow(`SELECT `+backupTargetCols+` FROM backup_targets WHERE id=? AND org_id=?`, id, orgID))
}

// GetBackupTargetByID looks up a target without org scoping — used when resolving
// a backup/schedule's destination (the caller is already authorized by the row it
// came from).
func (s *Store) GetBackupTargetByID(id int64) (BackupTarget, error) {
	return scanBackupTarget(s.db.QueryRow(`SELECT `+backupTargetCols+` FROM backup_targets WHERE id=?`, id))
}

// AllBackupTargets returns every target across all orgs (boot remount, name map).
func (s *Store) AllBackupTargets() ([]BackupTarget, error) {
	rows, err := s.db.Query(`SELECT ` + backupTargetCols + ` FROM backup_targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BackupTarget
	for rows.Next() {
		t, err := scanBackupTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) SetBackupTargetMountpoint(id int64, mp string) error {
	_, err := s.db.Exec(`UPDATE backup_targets SET mountpoint=? WHERE id=?`, mp, id)
	return err
}

func (s *Store) DeleteBackupTarget(orgID, id int64) error {
	_, err := s.db.Exec(`DELETE FROM backup_targets WHERE id=? AND org_id=?`, id, orgID)
	return err
}

// BackupTargetInUse reports whether any backup row or schedule still points at a
// target, so the service can refuse to delete a target that is still referenced.
func (s *Store) BackupTargetInUse(id int64) bool {
	var n int
	_ = s.db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM backups WHERE target_id=?) +
		(SELECT COUNT(*) FROM backup_schedules WHERE target_id=?)`, id, id).Scan(&n)
	return n > 0
}

func (s *Store) DeleteBackup(orgID, id int64) error {
	var path string
	if err := s.db.QueryRow(`SELECT path FROM backups WHERE id=? AND org_id=?`, id, orgID).Scan(&path); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM backups WHERE id=? AND org_id=?`, id, orgID); err != nil {
		return err
	}
	if path != "" {
		_ = os.Remove(path)
	}
	return nil
}

// RunBackup copies a stopped VM's disk into a standalone qcow2 and compresses it
// with the best available compressor (zstd, then gzip), recording size and any
// stderr. This mirrors the decompiled backup pipeline's detectCompressor stage
// while keeping everything local.
func (s *Store) RunBackup(id int64, diskPath, destDir string) error {
	_, _ = s.db.Exec(`UPDATE backups SET status='running' WHERE id=?`, id)
	fail := func(e error) error {
		_, _ = s.db.Exec(`UPDATE backups SET status='error', error=? WHERE id=?`, e.Error(), id)
		return e
	}
	if destDir == "" {
		destDir = s.cfg.Paths.BackupDir
	}

	tmp := filepath.Join(destDir, fmt.Sprintf("bk%d-%s.qcow2", id, timestamp()))
	if err := qemu.ConvertStandaloneCopy(diskPath, tmp); err != nil {
		return fail(err)
	}
	defer os.Remove(tmp)

	comp, ext := detectCompressor()
	final := tmp + ext
	if err := compressFile(comp, tmp, final); err != nil {
		return fail(err)
	}
	fi, _ := os.Stat(final)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	_, err := s.db.Exec(`UPDATE backups SET status='ready', path=?, compressor=?, size_bytes=? WHERE id=?`,
		final, comp, size, id)
	return err
}

// RestoreBackup decompresses a backup into a standalone qcow2 and registers it as
// a new base image, from which instances can be created. Returns the image name.
func (s *Store) RestoreBackup(b Backup) (string, error) {
	imgName := fmt.Sprintf("restore-%d-%s", b.ID, timestamp())
	dest := filepath.Join(s.cfg.Paths.ImageDir, imgName+".qcow2")
	if err := decompressFile(b.Compressor, b.Path, dest); err != nil {
		return "", err
	}
	size := int64(0)
	if fi, err := os.Stat(dest); err == nil {
		size = fi.Size()
	}
	if _, err := s.db.Exec(`INSERT INTO images(name,path,source_url,size_bytes,status) VALUES(?,?,?,?,'ready')`,
		imgName, dest, "backup:"+b.Name, size); err != nil {
		os.Remove(dest)
		return "", err
	}
	return imgName, nil
}

// RegisterImage records an existing qcow2 on disk as a ready base image (used by
// the vCenter import after it converts a source VMDK). ImageDir() exposes where
// imported disks should land.
func (s *Store) RegisterImage(name, path, sourceURL string) error {
	size := int64(0)
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	_, err := s.db.Exec(`INSERT INTO images(name,path,source_url,size_bytes,status) VALUES(?,?,?,?,'ready')
		ON CONFLICT(name) DO UPDATE SET path=excluded.path, size_bytes=excluded.size_bytes, status='ready'`,
		name, path, sourceURL, size)
	return err
}

// ImageDir returns the configured base-image directory.
func (s *Store) ImageDir() string { return s.cfg.Paths.ImageDir }

// ImportedImage is a base image created by a VMware import (source_url "vmware:").
type ImportedImage struct {
	Name      string
	Path      string
	Source    string
	Status    string
	SizeBytes int64
	CreatedAt string
}

// ListImportedImages returns the base images registered by VMware imports, so
// the UI can manage (and delete) the templates left behind after an import.
func (s *Store) ListImportedImages() ([]ImportedImage, error) {
	rows, err := s.db.Query(`SELECT name,path,COALESCE(source_url,''),COALESCE(status,'ready'),COALESCE(size_bytes,0),COALESCE(created_at,'')
		FROM images WHERE source_url LIKE 'vmware:%' ORDER BY created_at DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ImportedImage
	for rows.Next() {
		var im ImportedImage
		if err := rows.Scan(&im.Name, &im.Path, &im.Source, &im.Status, &im.SizeBytes, &im.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}

// DeleteImage removes a base-image row and returns its on-disk path for the
// caller to unlink. It refuses while any instance (even a trashed one) still
// references the image, so a VM never loses its backing template out from under
// it. Returns the path so the service layer can delete the file + audit.
func (s *Store) DeleteImage(name string) (path string, err error) {
	var n int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE image_name=?`, name).Scan(&n); err != nil {
		return "", err
	}
	if n > 0 {
		return "", fmt.Errorf("%d instance(s) still reference image %q — delete them first", n, name)
	}
	if err = s.db.QueryRow(`SELECT path FROM images WHERE name=?`, name).Scan(&path); err != nil {
		return "", err
	}
	if _, err = s.db.Exec(`DELETE FROM images WHERE name=?`, name); err != nil {
		return "", err
	}
	return path, nil
}

// FreeBytes returns the free space available at dir (0 if unknown).
func (s *Store) FreeBytes(dir string) int64 {
	used, total := diskUsage(dir)
	if total <= 0 {
		return 0
	}
	return total - used
}

// ---- backup schedules ----------------------------------------------------

type Schedule struct {
	ID            int64
	OrgID         int64
	SessionID     string
	IntervalHours int
	Keep          int
	Enabled       bool
	LastRunAt     string
	NextRunAt     string
	TargetID      int64
	Target        string // display name, filled by the service layer
	CreatedAt     string
}

func (s *Store) CreateSchedule(orgID int64, sessionID string, intervalHours, keep int, targetID int64) (int64, error) {
	next := time.Now().UTC().Add(time.Duration(intervalHours) * time.Hour).Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO backup_schedules(org_id,session_id,interval_hours,keep,next_run_at,target_id) VALUES(?,?,?,?,?,?)`,
		orgID, sessionID, intervalHours, keep, next, targetID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListSchedules(orgID int64) ([]Schedule, error) {
	rows, err := s.db.Query(`SELECT id,org_id,session_id,interval_hours,keep,enabled,COALESCE(last_run_at,''),COALESCE(next_run_at,''),target_id,created_at
		FROM backup_schedules WHERE org_id=? ORDER BY id DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSchedules(rows)
}

// DueSchedules returns enabled schedules whose next_run_at has passed.
func (s *Store) DueSchedules(now time.Time) ([]Schedule, error) {
	rows, err := s.db.Query(`SELECT id,org_id,session_id,interval_hours,keep,enabled,COALESCE(last_run_at,''),COALESCE(next_run_at,''),target_id,created_at
		FROM backup_schedules WHERE enabled=1 AND next_run_at IS NOT NULL AND next_run_at<=?`,
		now.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSchedules(rows)
}

func scanSchedules(rows *sql.Rows) ([]Schedule, error) {
	var out []Schedule
	for rows.Next() {
		var s Schedule
		var en int
		if err := rows.Scan(&s.ID, &s.OrgID, &s.SessionID, &s.IntervalHours, &s.Keep, &en, &s.LastRunAt, &s.NextRunAt, &s.TargetID, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.Enabled = en != 0
		out = append(out, s)
	}
	return out, rows.Err()
}

func (s *Store) MarkScheduleRun(id int64, interval int) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`UPDATE backup_schedules SET last_run_at=?, next_run_at=? WHERE id=?`,
		now.Format(time.RFC3339), now.Add(time.Duration(interval)*time.Hour).Format(time.RFC3339), id)
	return err
}

func (s *Store) DeleteSchedule(orgID, id int64) error {
	_, err := s.db.Exec(`DELETE FROM backup_schedules WHERE id=? AND org_id=?`, id, orgID)
	return err
}

// PruneBackups keeps the newest `keep` ready backups for a session, deleting the
// rest (rows and files).
func (s *Store) PruneBackups(sessionID string, keep int) {
	rows, err := s.db.Query(`SELECT id,path FROM backups WHERE session_id=? AND status='ready' ORDER BY id DESC`, sessionID)
	if err != nil {
		return
	}
	type bk struct {
		id   int64
		path string
	}
	var all []bk
	for rows.Next() {
		var b bk
		if err := rows.Scan(&b.id, &b.path); err == nil {
			all = append(all, b)
		}
	}
	rows.Close()
	for i := keep; i < len(all); i++ {
		_, _ = s.db.Exec(`DELETE FROM backups WHERE id=?`, all[i].id)
		if all[i].path != "" {
			_ = os.Remove(all[i].path)
		}
	}
}

// ---- storage pools -------------------------------------------------------

type Pool struct {
	ID         int64
	Name       string
	Kind       string
	Path       string
	UsedBytes  int64
	TotalBytes int64
	CreatedAt  string
}

func (s *Store) UpsertPool(name, kind, path string) error {
	_, err := s.db.Exec(`INSERT INTO storage_pools(name,kind,path) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, path=excluded.path`, name, kind, path)
	return err
}

// DeletePool removes a registered pool by name.
func (s *Store) DeletePool(name string) error {
	_, err := s.db.Exec(`DELETE FROM storage_pools WHERE name=?`, name)
	return err
}

// DeletePoolsByPath removes every registered pool whose path matches (used to
// clean up the registry when the underlying ZFS pool or LVM VG is destroyed).
func (s *Store) DeletePoolsByPath(path string) error {
	_, err := s.db.Exec(`DELETE FROM storage_pools WHERE path=?`, path)
	return err
}

// ListPools returns configured pools with live usage for dir pools.
func (s *Store) ListPools() ([]Pool, error) {
	rows, err := s.db.Query(`SELECT id,name,kind,path,created_at FROM storage_pools ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pool
	for rows.Next() {
		var p Pool
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Path, &p.CreatedAt); err != nil {
			return nil, err
		}
		if p.Path != "" {
			p.UsedBytes, p.TotalBytes = diskUsage(p.Path)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- compressor helpers --------------------------------------------------

// detectCompressor returns the best available compressor and the file extension
// it produces, preferring zstd, then gzip, then an uncompressed copy.
func detectCompressor() (name, ext string) {
	if _, err := exec.LookPath("zstd"); err == nil {
		return "zstd", ".zst"
	}
	if _, err := exec.LookPath("gzip"); err == nil {
		return "gzip", ".gz"
	}
	return "none", ""
}

func compressFile(comp, in, out string) error {
	switch comp {
	case "zstd":
		// Level 3 with all cores: fast enough for synchronous use, still ~2-3x.
		return runCapture(exec.Command("zstd", "-q", "-T0", "-3", "-o", out, in))
	case "gzip":
		return shellRedirect(out, exec.Command("gzip", "-c", in))
	default: // none: plain copy
		return copyFile(in, out)
	}
}

func decompressFile(comp, in, out string) error {
	switch comp {
	case "zstd":
		return runCapture(exec.Command("zstd", "-d", "-q", "-o", out, in))
	case "gzip":
		return shellRedirect(out, exec.Command("gzip", "-dc", in))
	default:
		return copyFile(in, out)
	}
}

// runCapture runs a command and surfaces its stderr on failure.
func runCapture(cmd *exec.Cmd) error {
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", cmd.Args[0], err, out)
	}
	return nil
}

// shellRedirect runs cmd with stdout written to the named file (for tools that
// only stream to stdout), capturing stderr for diagnostics.
func shellRedirect(out string, cmd *exec.Cmd) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd.Stdout = f
	errBuf := &capBuf{}
	cmd.Stderr = errBuf
	if err := cmd.Run(); err != nil {
		os.Remove(out)
		return fmt.Errorf("%s: %v: %s", cmd.Args[0], err, errBuf.String())
	}
	return nil
}

func copyFile(in, out string) error {
	src, err := os.Open(in)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(out)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// capBuf is a tiny bounded buffer for capturing command stderr.
type capBuf struct{ b []byte }

func (c *capBuf) Write(p []byte) (int, error) {
	if len(c.b) < 4096 {
		c.b = append(c.b, p...)
	}
	return len(p), nil
}
func (c *capBuf) String() string { return string(c.b) }

// diskUsage returns (used, total) bytes for the filesystem backing dir.
func diskUsage(dir string) (used, total int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0
	}
	total = int64(st.Blocks) * int64(st.Bsize)
	free := int64(st.Bavail) * int64(st.Bsize)
	return total - free, total
}

func timestamp() string { return time.Now().UTC().Format("20060102T150405") }

func safeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "iso"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}
