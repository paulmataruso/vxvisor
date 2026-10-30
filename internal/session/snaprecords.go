package session

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vdxclone/internal/ceph"
	"vdxclone/internal/cloudinit"
)

// ---- snapshot rows, clone links, purge -----------------------------------

// CloneRef names an instance.
type CloneRef struct {
	ID   string
	Name string
}

// SnapRecord is one recorded snapshot of an instance.
type SnapRecord struct {
	ID          int64
	SessionID   string
	Name        string
	Tag         string // backend snapshot name (snap-<hex>)
	Backend     string // qcow2 | zvol | lvm | rbd
	Ref         string // backend locator: ds@tag, vg/lv, pool/image@tag ("" for qcow2)
	Online      bool
	Consistency string // offline | app | crash
	VarsPath    string // copy of the UEFI NVRAM taken with the snapshot
	PolicyID    int64  // 0 = manual
	PolicyName  string
	GroupID     string // shared by every snapshot of one policy run
	LockedUntil string // RFC3339 UTC; immutable until then
	ExpiresAt   string // RFC3339 UTC; the policy's keep-days horizon
	Transient   bool   // taken only as an instant clone's base
	CreatedAt   string
	Clones      []CloneRef // instant clones that still DEPEND on this snapshot
	Newer       int        // zvol: newer snapshots a revert here would discard
	Immutable   bool       // Locked(now) as of when the row was read (for display)
}

// Locked reports whether the snapshot is immutable at now.
func (r SnapRecord) Locked(now time.Time) bool {
	if r.LockedUntil == "" {
		return false
	}
	t, ok := ParseDBTime(r.LockedUntil)
	return !ok || now.Before(t) // an unparsable lock fails closed
}

// ParseDBTime parses a timestamp as stored in the DB: RFC3339, or SQLite's
// datetime('now') form (UTC).
func ParseDBTime(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// SnapMeta is what a policy (or a clone) attaches to a recorded snapshot.
type SnapMeta struct {
	PolicyID    int64
	GroupID     string
	LockedUntil time.Time // zero = not immutable
	ExpiresAt   time.Time
	Transient   bool
}

func fmtTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// RecordSnapshot stores a snapshot just taken.
func (m *Manager) RecordSnapshot(sessionID, name string, r SnapResult, meta SnapMeta) (int64, error) {
	var pol any
	if meta.PolicyID > 0 {
		pol = meta.PolicyID
	}
	res, err := m.db.Exec(`INSERT INTO snapshots
		(session_id,name,tag,online,backend,ref,consistency,vars_path,policy_id,group_id,locked_until,expires_at,transient)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sessionID, name, r.Tag, b2i(r.Online), r.Backend, r.Ref, r.Consistency, r.VarsPath, pol, meta.GroupID,
		fmtTime(meta.LockedUntil), fmtTime(meta.ExpiresAt), b2i(meta.Transient))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const snapCols = `sn.id,sn.session_id,sn.name,sn.tag,sn.online,COALESCE(sn.backend,'qcow2'),COALESCE(sn.ref,''),
	COALESCE(sn.consistency,''),COALESCE(sn.vars_path,''),COALESCE(sn.policy_id,0),COALESCE(p.name,''),
	COALESCE(sn.group_id,''),COALESCE(sn.locked_until,''),COALESCE(sn.expires_at,''),COALESCE(sn.transient,0),sn.created_at`

const snapFrom = ` FROM snapshots sn LEFT JOIN snapshot_policies p ON p.id = sn.policy_id `

func scanSnap(sc interface{ Scan(...any) error }) (SnapRecord, error) {
	var r SnapRecord
	var on, tr int
	err := sc.Scan(&r.ID, &r.SessionID, &r.Name, &r.Tag, &on, &r.Backend, &r.Ref, &r.Consistency, &r.VarsPath,
		&r.PolicyID, &r.PolicyName, &r.GroupID, &r.LockedUntil, &r.ExpiresAt, &tr, &r.CreatedAt)
	r.Online, r.Transient = on != 0, tr != 0
	r.Immutable = r.Locked(time.Now())
	if r.Consistency == "" {
		r.Consistency = ConsistencyOffline
		if r.Online {
			r.Consistency = ConsistencyCrash
		}
	}
	return r, err
}

// ListSnapshots returns an instance's snapshots, newest first, with their
// dependent clones.
func (m *Manager) ListSnapshots(sessionID string) ([]SnapRecord, error) {
	rows, err := m.db.Query(`SELECT `+snapCols+snapFrom+`WHERE sn.session_id=? ORDER BY sn.id DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	var out []SnapRecord
	for rows.Next() {
		r, err := scanSnap(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Clones = m.clonesOf(out[i].ID)
		if out[i].Backend == "zvol" {
			ds, _, _ := strings.Cut(out[i].Ref, "@")
			for j := 0; j < i; j++ { // out is newest first
				if d2, _, _ := strings.Cut(out[j].Ref, "@"); out[j].Backend == "zvol" && d2 == ds {
					out[i].Newer++
				}
			}
		}
	}
	return out, nil
}

// GetSnapshot returns one of an instance's snapshots.
func (m *Manager) GetSnapshot(sessionID string, snapID int64) (SnapRecord, error) {
	r, err := scanSnap(m.db.QueryRow(`SELECT `+snapCols+snapFrom+`WHERE sn.id=? AND sn.session_id=?`, snapID, sessionID))
	if errors.Is(err, sql.ErrNoRows) {
		return r, fmt.Errorf("snapshot not found")
	}
	if err != nil {
		return r, err
	}
	r.Clones = m.clonesOf(r.ID)
	return r, nil
}

func (m *Manager) snapshotByID(snapID int64) (SnapRecord, bool) {
	r, err := scanSnap(m.db.QueryRow(`SELECT `+snapCols+snapFrom+`WHERE sn.id=?`, snapID))
	if err != nil {
		return r, false
	}
	r.Clones = m.clonesOf(r.ID)
	return r, true
}

// clonesOf lists the instances (live or in Trash) that depend on a snapshot.
func (m *Manager) clonesOf(snapID int64) []CloneRef {
	rows, err := m.db.Query(`SELECT c.clone_id, COALESCE(s.name, c.clone_id) FROM snapshot_clones c
		LEFT JOIN sessions s ON s.id = c.clone_id WHERE c.snapshot_id=? ORDER BY c.created_at`, snapID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []CloneRef
	for rows.Next() {
		var c CloneRef
		if rows.Scan(&c.ID, &c.Name) == nil {
			out = append(out, c)
		}
	}
	return out
}

// dropSnapshotRow forgets a snapshot (its host side is already gone).
func (m *Manager) dropSnapshotRow(r SnapRecord) {
	if _, err := m.db.Exec(`DELETE FROM snapshots WHERE id=?`, r.ID); err != nil {
		log.Printf("snapshot %d: drop row: %v", r.ID, err)
	}
	if r.VarsPath != "" {
		_ = os.Remove(r.VarsPath)
	}
}

// CloneLink is where an instant clone came from.
type CloneLink struct {
	CloneID      string
	OriginID     string
	OriginName   string
	SnapshotID   int64 // set while the clone depends on the snapshot (zvol/rbd)
	SnapshotName string
	Backend      string
	Method       string
	CreatedAt    string
	OriginExists bool
}

// CloneLinkOf returns the clone link of an instance, if it is a clone.
func (m *Manager) CloneLinkOf(id string) (CloneLink, bool) {
	var l CloneLink
	err := m.db.QueryRow(`SELECT c.clone_id,c.origin_id,c.origin_name,COALESCE(c.snapshot_id,0),c.snapshot_name,
		c.backend,c.method,c.created_at,(SELECT COUNT(*) FROM sessions s WHERE s.id=c.origin_id)
		FROM snapshot_clones c WHERE c.clone_id=?`, id).
		Scan(&l.CloneID, &l.OriginID, &l.OriginName, &l.SnapshotID, &l.SnapshotName, &l.Backend, &l.Method, &l.CreatedAt, &l.OriginExists)
	return l, err == nil
}

type dependent struct {
	cloneID string
	snapID  int64
	snapTag string
}

// dependentsOf lists the clones that depend on any of id's snapshots.
func (m *Manager) dependentsOf(id string) ([]dependent, error) {
	rows, err := m.db.Query(`SELECT c.clone_id, sn.id, sn.tag FROM snapshot_clones c
		JOIN snapshots sn ON sn.id = c.snapshot_id WHERE sn.session_id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dependent
	for rows.Next() {
		var d dependent
		if err := rows.Scan(&d.cloneID, &d.snapID, &d.snapTag); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// HasSnapshotDeps reports whether an instance has snapshots or is a dependent
// clone — storage moves and migrations must refuse it (they would strand the
// snapshots on the old storage / host, or break the clone's shared blocks).
func (m *Manager) HasSnapshotDeps(id string) (snaps int, dependentClone bool) {
	_ = m.db.QueryRow(`SELECT COUNT(*) FROM snapshots WHERE session_id=?`, id).Scan(&snaps)
	var n int
	_ = m.db.QueryRow(`SELECT COUNT(*) FROM snapshot_clones WHERE clone_id=? AND snapshot_id IS NOT NULL`, id).Scan(&n)
	return snaps, n > 0
}

// getAny reads a session row whether or not it is in the Trash.
func (m *Manager) getAny(id string) (*Session, error) {
	return scanSession(m.db.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE id=?`, id))
}

// buildSeed writes a clone's cloud-init seed: the origin's user/password/key with
// the clone's own instance-id, hostname, MAC and address lease.
func (m *Manager) buildSeed(id, name, mac string, orgID, netID int64, user, pass, key string) (string, error) {
	staticIP, gw, dhcp, err := m.guestAddressing(orgID, netID, id, mac)
	if err != nil {
		return "", err
	}
	if user == "" {
		user = "vdx"
	}
	if pass == "" {
		pass = randPassword()
	}
	var ns []string
	if staticIP != "" {
		ns = m.cfg.Cluster.Nameservers
		if len(ns) == 0 {
			ns = []string{"1.1.1.1", "8.8.8.8"}
		}
	}
	seed := filepath.Join(m.cfg.Paths.DiskDir, id+".seed.iso")
	cfg := cloudinit.Config{
		InstanceID: id, Hostname: sanitizeHostname(name),
		Username: user, Password: pass, SSHKey: key,
		MAC: mac, StaticIP: staticIP, Gateway: gw, Nameservers: ns, DHCP: dhcp,
		Clone: true,
	}
	if err := cloudinit.BuildSeedISO(m.cfg.Paths.DiskDir, seed, cfg); err != nil {
		return "", err
	}
	return seed, nil
}

// ErrLockedSnapshots refuses a purge while immutable snapshots exist.
var ErrLockedSnapshots = errors.New("instance has immutable snapshots")

// Purge permanently deletes a (trashed) session and its on-disk artifacts,
// including every snapshot it owns. Refused while any of its snapshots is
// immutable. Instant clones that depend on its snapshots are first made
// independent (detachDependents), so purging an origin never breaks a clone.
func (m *Manager) Purge(id string) error {
	if m.BackupBusy(id) {
		return ErrBackupBusy
	}
	m.purgeMu.Lock()
	defer m.purgeMu.Unlock()
	release, err := m.purgeLocked(id)
	if err != nil {
		return err
	}
	// Outside id's lock (these snapshots belong to other instances): a transient
	// clone base nothing depends on any more is removed — the one this instance
	// was cloned from, and any that a promotion moved to a former clone.
	for _, sid := range release {
		m.releaseTransientBase(sid)
	}
	return nil
}

func (m *Manager) purgeLocked(id string) (release []int64, err error) {
	unlock := m.lockVMs([]string{id})
	defer unlock()
	s, err := m.getAny(id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // already gone
	}
	if err != nil {
		return nil, err
	}
	snaps, err := m.ListSnapshots(id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, r := range snaps {
		if r.Locked(now) {
			return nil, fmt.Errorf("%w: %q is locked until %s", ErrLockedSnapshots, r.Name, r.LockedUntil)
		}
	}
	d, derr := diskOf(s)
	backend := s.DiskBackend
	if backend == "" {
		backend = "qcow2"
	}
	if derr == nil {
		rehomed, err := m.detachDependents(id, backend, d)
		if err != nil {
			return nil, fmt.Errorf("make dependent instant clones independent: %w", err)
		}
		release = append(release, rehomed...)
	} else if deps, _ := m.dependentsOf(id); len(deps) > 0 {
		return nil, fmt.Errorf("cannot detach %d dependent instant clone(s): %v", len(deps), derr)
	}
	if snaps, err = m.ListSnapshots(id); err != nil { // what's still ours after re-homing
		return nil, err
	}
	if l, ok := m.CloneLinkOf(id); ok && l.SnapshotID > 0 {
		release = append(release, l.SnapshotID)
	}

	if _, err := m.db.Exec(`DELETE FROM sessions WHERE id=?`, id); err != nil {
		return nil, err // e.g. the snapshot_clones RESTRICT backstop
	}
	m.releaseLeases(id) // give its static address back to the port group pool

	disk := s.DiskPath
	switch backend {
	case "zvol":
		// zfs destroy -r takes the zvol's remaining snapshots with it (none has
		// clones any more: detachDependents promoted them away).
		if ds, ok := strings.CutPrefix(disk, "/dev/zvol/"); ok {
			if err := ops.zfsDestroy(ds); err != nil {
				log.Printf("purge %s: destroy zvol %s: %v", id, ds, err)
			}
		}
		disk = "" // don't os.Remove a device node
	case "lvm":
		// Thin snapshots are separate LVs: remove the ones we recorded.
		for _, r := range snaps {
			if vg, name, ok := strings.Cut(r.Ref, "/"); ok && r.Backend == "lvm" {
				if err := ops.lvmRemove(vg, name); err != nil && !isGone(err) {
					log.Printf("purge %s: remove snapshot LV %s: %v", id, r.Ref, err)
				}
			}
		}
		if strings.HasPrefix(disk, "/dev/") {
			if err := ops.lvmRemoveDev(disk); err != nil {
				log.Printf("purge %s: remove LV %s: %v", id, disk, err)
			}
		}
		disk = ""
	case "rbd":
		// rbd rm refuses an image that still has snapshots.
		if pool, image, ok := ceph.ParseRBD(disk); ok {
			for _, r := range snaps {
				if p2, i2, tag, ok := parseRBDSnapRef(r.Ref); ok && r.Backend == "rbd" && p2 == pool && i2 == image {
					if err := ops.rbdSnapRemove(pool, image, tag); err != nil && !isGone(err) {
						log.Printf("purge %s: remove rbd snapshot %s: %v", id, r.Ref, err)
					}
				}
			}
			if err := ops.rbdRemove(pool, image); err != nil {
				log.Printf("purge %s: remove rbd image %s/%s: %v", id, pool, image, err)
			}
		}
		disk = ""
	}
	files := []string{disk, s.OVMFVarsPath, s.SeedPath,
		filepath.Join(m.cfg.Paths.DiskDir, id+".vncpw"),
		filepath.Join(m.cfg.Paths.DiskDir, id+".log"),
		filepath.Join(m.cfg.Paths.DiskDir, id+".qga"),
		filepath.Join(m.cfg.Paths.DiskDir, id+".qmp")}
	for _, r := range snaps {
		files = append(files, r.VarsPath)
	}
	for _, f := range files {
		if f != "" {
			_ = os.Remove(f)
		}
	}
	// Remove the per-VM swtpm NVRAM state directory (purge only).
	m.stopSwtpm(id)
	_ = os.RemoveAll(m.tpmStateDir(id))
	return release, nil
}
