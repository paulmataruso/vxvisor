package session

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"vdxclone/internal/ceph"
	"vdxclone/internal/lvm"
	"vdxclone/internal/qemu"
	"vdxclone/internal/zfs"
)

// Storage vMotion — move a VM's disk between storage backends (local↔shared),
// live or stopped. FAIL-SAFE IS THE CORE PRINCIPLE: the source disk is only ever
// READ, never mutated, until a move is durably committed; on ANY failure the VM
// stays fully recoverable from the untouched source. The source is retained
// (renamed *.pre-vmotion) and reclaimed only by an explicit admin action, never
// inline. A persisted state machine (migration_state) makes this hold across
// crashes/restarts. See memory: vmotion-failsafe-design.

// IsSharedStorage reports whether a disk path lives on a filesystem shared
// across hosts (so a cross-host LIVE migration can reuse the same path). It is
// deliberately CONSERVATIVE: a false "shared" is catastrophic (two nodes writing
// one disk), a false "local" merely refuses. Detection is by real mount FSTYPE;
// a zvol/raw block device is ALWAYS treated as local (cannot be imported twice).
func IsSharedStorage(path, backend string) bool {
	if backend == "zvol" {
		return false
	}
	// A Ceph RBD image lives in the distributed cluster, reachable by the same
	// rbd: path from every node — inherently shared, so a cross-node live
	// migration can reuse it without copying the disk.
	if backend == "rbd" {
		return true
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		real = path
	}
	out, err := exec.Command("findmnt", "-n", "-o", "FSTYPE", "-T", real).Output()
	if err != nil {
		return false
	}
	switch strings.TrimSpace(string(out)) {
	case "nfs", "nfs4", "cifs", "smb3", "ceph", "fuse.ceph", "ocfs2", "gfs2", "glusterfs", "fuse.glusterfs":
		return true
	}
	return false
}

// migrationState returns the persisted migration_state for a VM ("" if unknown).
func (m *Manager) migrationState(id string) string {
	var st string
	_ = m.db.QueryRow(`SELECT COALESCE(migration_state,'idle') FROM sessions WHERE id=?`, id).Scan(&st)
	return st
}

// MigrationBusy reports whether a VM is mid-move (lifecycle ops must refuse).
func (m *Manager) MigrationBusy(id string) bool {
	st := m.migrationState(id)
	return st != "" && st != "idle"
}

// chownRunAs hands moved files to the VM RunAs user so the dropped-privilege
// QEMU can open them (mirrors what Create/Start do for a VM's disk). No-op when
// no RunAs user is configured (QEMU runs as root).
func (m *Manager) chownRunAs(paths ...string) {
	if m.cfg.VM.RunAs == "" {
		return
	}
	uid, gid, _, ok := lookupUser(m.cfg.VM.RunAs)
	if !ok {
		return
	}
	for _, p := range paths {
		if p != "" {
			_ = qemu.Chown(p, uid, gid)
		}
	}
}

func (m *Manager) setMigState(id, state, target, source string) error {
	_, err := m.db.Exec(`UPDATE sessions SET migration_state=?, mig_target_path=?, mig_source_path=? WHERE id=?`,
		state, target, source, id)
	return err
}

// poolDir resolves a storage pool id to its directory ("" / 0 = default DiskDir).
func (m *Manager) poolDir(poolID int64) (string, error) {
	if poolID <= 0 {
		return m.cfg.Paths.DiskDir, nil
	}
	var p string
	if err := m.db.QueryRow(`SELECT COALESCE(path,'') FROM storage_pools WHERE id=?`, poolID).Scan(&p); err != nil || p == "" {
		return "", fmt.Errorf("storage pool %d not found", poolID)
	}
	return p, nil
}

// MoveStorage relocates a VM's disk to the storage pool targetPoolID (0 = default
// disk dir). It auto-selects the live (drive-mirror) or offline (qemu-img) path.
// The moved disk always becomes a qcow2 file in the target pool (covers dir /
// NFS / CIFS / Ceph / iSCSI-backed pools, and local↔shared).
// MoveStorage relocates an instance's disk to another pool. onProg (optional)
// receives (bytesDone, bytesTotal) during the offline copy so the caller can
// surface live progress + throughput; pass nil if not needed.
func (m *Manager) MoveStorage(id string, targetPoolID int64, onProg func(done, total int64)) error {
	if m.MigrationBusy(id) {
		return fmt.Errorf("a storage move is already in progress for this instance")
	}
	if m.BackupBusy(id) {
		return ErrBackupBusy
	}
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	tgt, err := m.resolveMoveTarget(id, targetPoolID)
	if err != nil {
		return err
	}
	if s.DiskBackend == tgt.backend && sameLocation(s.DiskPath, tgt) {
		return fmt.Errorf("instance disk is already on that storage")
	}
	// The moved disk does not carry the backup dirty bitmaps (neither a live
	// mirror nor an offline convert copies them): the next backup is a full one.
	m.DropCheckpoints(id)

	if m.Running(s) {
		// Live move pivots a running guest's writes; today that dance is only wired
		// for file (qcow2) source AND target. Moving to/from a block backend
		// (RBD/LVM/ZFS) requires the instance to be stopped so the disk can be
		// converted cold — refuse clearly rather than silently landing a qcow2.
		if s.DiskBackend != "qcow2" || tgt.backend != "qcow2" {
			return fmt.Errorf("stop the instance to move its disk to or from block storage (Ceph RBD / LVM / ZFS); live storage move is currently supported only between file (qcow2) pools")
		}
		if err := os.MkdirAll(tgt.dir, 0o750); err != nil {
			return fmt.Errorf("target pool dir: %w", err)
		}
		if _, err := os.Stat(tgt.disk); err == nil {
			return fmt.Errorf("a disk already exists at the target (%s) — refusing to overwrite", tgt.disk)
		}
		return m.moveStorageLive(s, targetPoolID, s.DiskPath, tgt.disk)
	}
	return m.moveStorageOffline(s, targetPoolID, tgt, onProg)
}

// moveTarget describes where a storage move will land, resolved from the target
// storage pool's kind. The disk field is the disk_path to persist; backend is the
// disk_backend to persist (qcow2 | rbd | lvm | zvol).
type moveTarget struct {
	backend  string
	disk     string
	dir      string // qcow2 colocation dir for the disk + vars/seed ("" for block)
	rbdPool  string
	rbdImage string
	lvmVG    string
	lvmPool  string
	lvDev    string // /dev/<vg>/<lv>
	zvolDS   string // ZFS dataset name (its device is /dev/zvol/<ds>)
}

// resolveMoveTarget maps a target storage pool to the backend + volume identity a
// move should create. A block pool (rbd/lvm/zfs) has no filesystem directory, so
// the disk becomes a provisioned volume rather than a qcow2 file in a dir.
func (m *Manager) resolveMoveTarget(id string, targetPoolID int64) (moveTarget, error) {
	short := id
	if len(short) > 8 {
		short = short[:8]
	}
	if targetPoolID <= 0 {
		d := m.cfg.Paths.DiskDir
		return moveTarget{backend: "qcow2", dir: d, disk: filepath.Join(d, id+".qcow2")}, nil
	}
	var kind, name, path string
	if err := m.db.QueryRow(`SELECT kind, COALESCE(name,''), COALESCE(path,'') FROM storage_pools WHERE id=?`, targetPoolID).Scan(&kind, &name, &path); err != nil {
		return moveTarget{}, fmt.Errorf("storage pool %d not found", targetPoolID)
	}
	switch kind {
	case "rbd":
		img := "vdx-" + short
		_, _ = ceph.EnsureClientKeyring(path) // QEMU keyring (idempotent)
		return moveTarget{backend: "rbd", rbdPool: path, rbdImage: img, disk: ceph.RBDPath(path, img)}, nil
	case "lvm":
		vg, tp, ok := strings.Cut(name, "/") // pool name is "<vg>/<thinpool>"
		if !ok {
			vg = name
		}
		dev := "/dev/" + vg + "/vdx-" + short
		return moveTarget{backend: "lvm", lvmVG: vg, lvmPool: tp, lvDev: dev, disk: dev}, nil
	case "zfs":
		ds := name + "/vdx-" + short
		return moveTarget{backend: "zvol", zvolDS: ds, disk: "/dev/zvol/" + ds}, nil
	default: // dir
		return moveTarget{backend: "qcow2", dir: path, disk: filepath.Join(path, id+".qcow2")}, nil
	}
}

// sameLocation reports whether a disk already lives at the move target (so the
// move is a no-op). For qcow2 it compares directories; for a block backend the
// deterministic volume name means the full device path matches.
func sameLocation(srcPath string, t moveTarget) bool {
	if t.backend == "qcow2" {
		return filepath.Clean(filepath.Dir(srcPath)) == filepath.Clean(t.dir)
	}
	return filepath.Clean(srcPath) == filepath.Clean(t.disk)
}

// moveStorageOffline converts a stopped VM's disk onto the target backend
// (qcow2 file / RBD image / LVM thin LV / ZFS zvol), verifies it, then commits
// atomically. The source is read-only throughout and is only reclaimed AFTER the
// target is durable and the DB is committed (files retained aside for the admin;
// block volumes removed, since they can't be renamed aside).
func (m *Manager) moveStorageOffline(s *Session, targetPoolID int64, tgt moveTarget, onProg func(done, total int64)) error {
	src := s.DiskPath
	vsz, err := qemu.VirtualSizeBytes(src)
	if err != nil || vsz <= 0 {
		return fmt.Errorf("source virtual size: %w", err)
	}
	// Bridge qemu-img's 0..1 fraction to the (bytesDone, bytesTotal) the status
	// card wants, using the known virtual size as the total.
	var frac qemu.ProgressFunc
	if onProg != nil {
		frac = func(f float64) {
			d := int64(f * float64(vsz))
			if d > vsz {
				d = vsz
			}
			onProg(d, vsz)
		}
	}
	if err := m.setMigState(s.ID, "offline", tgt.disk, src); err != nil {
		return err
	}
	fail := func(e error) error { _ = m.setMigState(s.ID, "idle", "", ""); return e }

	// 1. Provision the target volume and copy the source onto it (source read-only).
	var cleanupTarget func()
	switch tgt.backend {
	case "qcow2":
		if err := os.MkdirAll(tgt.dir, 0o750); err != nil {
			return fail(fmt.Errorf("target pool dir: %w", err))
		}
		if _, err := os.Stat(tgt.disk); err == nil {
			return fail(fmt.Errorf("a disk already exists at the target (%s) — refusing to overwrite", tgt.disk))
		}
		if free, err := freeBytes(tgt.dir); err == nil && free < vsz {
			return fail(fmt.Errorf("not enough free space on target (%d MB free, need %d MB)", free>>20, vsz>>20))
		}
		cleanupTarget = func() { _ = os.Remove(tgt.disk) }
		if err := qemu.ConvertToQcow2P(src, tgt.disk, frac); err != nil {
			cleanupTarget()
			return fail(fmt.Errorf("copy disk: %w", err))
		}
	case "rbd":
		if !ceph.Bootstrapped() {
			return fail(fmt.Errorf("the target Ceph cluster is not available"))
		}
		cleanupTarget = func() { _ = ceph.RemoveImage(tgt.rbdPool, tgt.rbdImage) }
		if err := ceph.ImportImageProgress(tgt.rbdPool, tgt.rbdImage, src, frac); err != nil {
			cleanupTarget()
			return fail(fmt.Errorf("copy disk to Ceph RBD: %w", err))
		}
	case "lvm":
		if !lvm.Available() {
			return fail(fmt.Errorf("LVM2 is not available on the host"))
		}
		if err := lvm.CreateThinVolume(tgt.lvmVG, tgt.lvmPool, filepath.Base(tgt.lvDev), vsz); err != nil {
			return fail(fmt.Errorf("create LVM volume: %w", err))
		}
		cleanupTarget = func() { _ = lvm.RemoveLV(tgt.lvDev) }
		if err := qemu.ConvertToRawP(src, tgt.disk, frac); err != nil {
			cleanupTarget()
			return fail(fmt.Errorf("copy disk to LVM: %w", err))
		}
	case "zvol":
		if !zfs.Available() {
			return fail(fmt.Errorf("ZFS is not available on the host"))
		}
		if err := zfs.CreateZvol(tgt.zvolDS, vsz, false); err != nil {
			return fail(fmt.Errorf("create zvol: %w", err))
		}
		cleanupTarget = func() { _ = zfs.DestroyDataset(tgt.zvolDS) }
		if err := qemu.ConvertToRawP(src, tgt.disk, frac); err != nil {
			cleanupTarget()
			return fail(fmt.Errorf("copy disk to zvol: %w", err))
		}
	default:
		return fail(fmt.Errorf("unsupported target storage backend %q", tgt.backend))
	}

	// 2. Verify the target. qcow2 gets a full consistency check; raw block targets
	//    (rbd/lvm/zvol) have no check metadata, so confirm qemu-img can read them.
	verify := qemu.ProbeReadable
	if tgt.backend == "qcow2" {
		verify = qemu.ImageOK
	}
	if err := verify(tgt.disk); err != nil {
		cleanupTarget()
		return fail(fmt.Errorf("target failed verification: %w", err))
	}

	// 3. The per-VM NVRAM + seed travel WITH the disk: to the target pool dir for a
	//    qcow2 disk, or the default disk dir for a block-backed disk (which has no
	//    directory of its own, so its metadata always lives in the disk dir). A
	//    relocation is skipped when the file is already there.
	metaDir := m.cfg.Paths.DiskDir
	if tgt.backend == "qcow2" {
		metaDir = tgt.dir
	}
	newVars, newSeed := s.OVMFVarsPath, s.SeedPath
	if s.OVMFVarsPath != "" && filepath.Clean(filepath.Dir(s.OVMFVarsPath)) != filepath.Clean(metaDir) {
		if err := os.MkdirAll(metaDir, 0o750); err != nil {
			cleanupTarget()
			return fail(fmt.Errorf("target metadata dir: %w", err))
		}
		nv := filepath.Join(metaDir, s.ID+".ovmf_vars.fd")
		if err := copyRegular(s.OVMFVarsPath, nv); err != nil {
			cleanupTarget()
			return fail(fmt.Errorf("copy firmware vars: %w", err))
		}
		newVars = nv
	}
	if s.SeedPath != "" && filepath.Clean(filepath.Dir(s.SeedPath)) != filepath.Clean(metaDir) {
		ns := filepath.Join(metaDir, s.ID+".seed.iso")
		if err := copyRegular(s.SeedPath, ns); err == nil {
			newSeed = ns
		}
	}
	m.chownRunAs(newVars, newSeed)
	if tgt.backend == "qcow2" {
		m.chownRunAs(tgt.disk)
		fsyncFile(tgt.disk)
	}

	// 4. Durable, ordered commit.
	if _, err := m.db.Exec(`UPDATE sessions SET disk_path=?, disk_backend=?, ovmf_vars_path=?, seed_path=?,
		storage_pool_id=?, migration_state='idle', mig_target_path='', mig_source_path='' WHERE id=?`,
		tgt.disk, tgt.backend, newVars, newSeed, targetPoolID, s.ID); err != nil {
		cleanupTarget()
		return fmt.Errorf("commit: %w", err)
	}

	// 5. Reclaim the source now that the target is committed and durable.
	m.reclaimMovedSource(s.DiskBackend, src)
	if s.OVMFVarsPath != "" && newVars != s.OVMFVarsPath {
		retainAside(s.OVMFVarsPath)
	}
	if s.SeedPath != "" && newSeed != s.SeedPath {
		retainAside(s.SeedPath)
	}
	log.Printf("vmotion: offline-moved %s disk to %s (backend %s→%s)", s.ID, tgt.disk, s.DiskBackend, tgt.backend)
	return nil
}

// reclaimMovedSource releases the OLD disk after a successful move. A qcow2 file
// is retained aside (renamed) for admin reclaim; a block volume (rbd/lvm/zvol)
// can't be renamed aside, so it is removed best-effort (an orphan is logged, not
// fatal — the move already succeeded).
func (m *Manager) reclaimMovedSource(backend, src string) {
	switch backend {
	case "rbd":
		if pool, img, ok := ceph.ParseRBD(src); ok {
			if err := ceph.RemoveImage(pool, img); err != nil {
				log.Printf("vmotion: source rbd image %s/%s not reclaimed: %v", pool, img, err)
			}
		}
	case "lvm":
		if err := lvm.RemoveLV(src); err != nil {
			log.Printf("vmotion: source LV %s not reclaimed: %v", src, err)
		}
	case "zvol":
		ds := strings.TrimPrefix(src, "/dev/zvol/")
		if err := zfs.DestroyDataset(ds); err != nil {
			log.Printf("vmotion: source zvol %s not reclaimed: %v", ds, err)
		}
	default:
		retainAside(src)
	}
}

// moveStorageLive mirrors the running VM's active disk to the target, then
// pivots. Guest writes go to the source until pivot, so an abort is always safe.
func (m *Manager) moveStorageLive(s *Session, targetPoolID int64, srcPath, target string) error {
	q, err := qemu.DialQMP(s.QMPSocket)
	if err != nil {
		return fmt.Errorf("source QMP: %w", err)
	}
	defer q.Close()

	if err := m.setMigState(s.ID, "mirroring", target, srcPath); err != nil {
		return err
	}
	abort := func(reason error) error {
		_ = q.BlockJobCancel("disk0")
		// Give QEMU a moment to drop the job, then remove the partial target.
		time.Sleep(300 * time.Millisecond)
		_ = os.Remove(target)
		_ = m.setMigState(s.ID, "idle", "", "")
		return reason
	}

	// Pre-create the target sized to the source's virtual size and hand it to the
	// RunAs user, so the dropped-privilege QEMU opens an OWNED file (mode=existing)
	// rather than trying to create one in a root-owned pool dir (EPERM on NFS etc).
	vsz, err := qemu.VirtualSizeBytes(srcPath)
	if err != nil || vsz <= 0 {
		_ = m.setMigState(s.ID, "idle", "", "")
		return fmt.Errorf("source virtual size: %w", err)
	}
	if err := qemu.CreateQcow2Sized(target, vsz); err != nil {
		_ = m.setMigState(s.ID, "idle", "", "")
		return err
	}
	m.chownRunAs(target)
	if err := q.DriveMirror("disk0", target, "qcow2", "existing"); err != nil {
		_ = os.Remove(target)
		_ = m.setMigState(s.ID, "idle", "", "")
		return fmt.Errorf("start mirror: %w", err)
	}

	// Poll for ready (mirror copied the whole disk and is tracking writes). A
	// disappearing job before ready means the mirror failed → abort to source.
	deadline := time.Now().Add(2 * time.Hour)
	for {
		ready, _, _, present, err := q.BlockJobProgress("disk0")
		if err != nil {
			return abort(fmt.Errorf("mirror poll: %w", err))
		}
		if !present {
			return abort(fmt.Errorf("mirror job vanished before ready (source left intact)"))
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			return abort(fmt.Errorf("mirror did not reach ready within timeout"))
		}
		time.Sleep(1 * time.Second)
	}

	// Persist the intent to pivot BEFORE completing, so a crash in the pivot→
	// commit window is recoverable (prefer the target, which holds latest writes).
	if err := m.setMigState(s.ID, "pivoting", target, srcPath); err != nil {
		return abort(err)
	}
	if err := q.BlockJobComplete("disk0"); err != nil {
		return abort(fmt.Errorf("pivot: %w", err))
	}
	// Wait for the job to disappear, then verify disk0 is now the target.
	for i := 0; i < 60; i++ {
		_, _, _, present, _ := q.BlockJobProgress("disk0")
		if !present {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if ins, _ := q.InsertedFile("disk0"); ins != "" && filepath.Clean(ins) != filepath.Clean(target) {
		// Pivot didn't land on the target — do NOT commit; VM is still consistent
		// on whatever disk0 points at. Leave state for recovery/inspection.
		return fmt.Errorf("pivot verification failed (disk0=%s, expected %s)", ins, target)
	}

	// Durable commit: the guest now writes only to the target.
	fsyncFile(target)
	if _, err := m.db.Exec(`UPDATE sessions SET disk_path=?, disk_backend='qcow2', storage_pool_id=?,
		migration_state='idle', mig_target_path='', mig_source_path='' WHERE id=?`, target, targetPoolID, s.ID); err != nil {
		return fmt.Errorf("commit (VM is running on target; DB update failed): %w", err)
	}
	retainAside(srcPath) // never delete inline
	log.Printf("vmotion: live-moved %s disk to %s (source retained as %s.pre-vmotion)", s.ID, target, srcPath)
	return nil
}

// RecoverMigrations is called at boot to resolve any move interrupted by a crash
// or restart. It NEVER starts a VM and NEVER deletes a source.
func (m *Manager) RecoverMigrations() {
	rows, err := m.db.Query(`SELECT id, COALESCE(migration_state,'idle'), COALESCE(mig_target_path,''), COALESCE(mig_source_path,''), disk_path
		FROM sessions WHERE migration_state IS NOT NULL AND migration_state!='idle' AND deleted_at IS NULL`)
	if err != nil {
		return
	}
	type rec struct{ id, state, target, source, disk string }
	var recs []rec
	for rows.Next() {
		var r rec
		if rows.Scan(&r.id, &r.state, &r.target, &r.source, &r.disk) == nil {
			recs = append(recs, r)
		}
	}
	rows.Close()
	for _, r := range recs {
		switch r.state {
		case "mirroring", "offline":
			// Interrupted before pivot/commit → source is authoritative. Drop the
			// partial target, reset to idle. disk_path already points at source.
			if r.target != "" {
				_ = os.Remove(r.target)
			}
			_, _ = m.db.Exec(`UPDATE sessions SET migration_state='idle', mig_target_path='', mig_source_path='' WHERE id=?`, r.id)
			log.Printf("vmotion recover: %s was %q — discarded partial target, kept source", r.id, r.state)
		case "pivoting":
			// The guest may have pivoted to the target before the commit. Prefer
			// the target IF it exists and verifies (it holds the latest writes);
			// otherwise fall back to the retained source. Never auto-start.
			if r.target != "" {
				if err := qemu.ImageOK(r.target); err == nil {
					_, _ = m.db.Exec(`UPDATE sessions SET disk_path=?, disk_backend='qcow2', migration_state='idle', mig_target_path='', mig_source_path='' WHERE id=?`, r.target, r.id)
					if r.source != "" {
						retainAside(r.source)
					}
					log.Printf("vmotion recover: %s was pivoting — committed to verified target %s", r.id, r.target)
					continue
				}
			}
			src := r.source
			if src == "" {
				src = r.disk
			}
			_, _ = m.db.Exec(`UPDATE sessions SET disk_path=?, migration_state='idle', mig_target_path='', mig_source_path='' WHERE id=?`, src, r.id)
			log.Printf("vmotion recover: %s was pivoting but target unusable — reverted to source %s", r.id, src)
		case "blk-live", "blk-ram":
			// Interrupted BEFORE the switchover handover (mirror/RAM/pre-switchover):
			// the source is authoritative and revivable. Reconnect its QMP, cancel the
			// mirror + migration, reactivate its disks (no-op if not yet inactivated)
			// and resume. Never delete/start-fresh. If QMP is gone, leave idle for the
			// normal reconciler to mark stopped (disk untouched).
			m.recoverBlockLiveSource(r.id, false)
		case "blk-commit":
			// Interrupted DURING the switchover (after migrate-continue): ownership is
			// ambiguous (the destination may already run the guest). Do NOT resume —
			// that would risk two live copies of the same guest. Mark stopped and keep
			// the (intact) source disk; an admin verifies and starts the surviving one.
			m.recoverBlockLiveSource(r.id, true)
		}
	}
}

// recoverBlockLiveSource restores a source VM left mid block-live migration by a
// daemon crash. committed=true means we were past migrate-continue (ambiguous —
// never auto-resume); false means the source is still authoritative and revivable.
func (m *Manager) recoverBlockLiveSource(id string, committed bool) {
	var qmpSock string
	_ = m.db.QueryRow(`SELECT COALESCE(qmp_socket,'') FROM sessions WHERE id=?`, id).Scan(&qmpSock)
	if committed {
		_, _ = m.db.Exec(`UPDATE sessions SET state='stopped', migration_state='idle', pid=NULL WHERE id=?`, id)
		log.Printf("blocklive recover: %s was mid-switchover — NOT auto-resuming (verify which node has it); source disk retained", id)
		return
	}
	if qmpSock != "" {
		if q, err := qemu.DialQMP(qmpSock); err == nil {
			_ = q.BlockJobCancel("disk0")
			_ = q.MigrateCancel()
			_ = q.BlockdevSetActive("", true)
			_, _ = q.Execute("cont", nil)
			q.Close()
		}
	}
	_, _ = m.db.Exec(`UPDATE sessions SET migration_state='idle' WHERE id=?`, id)
	log.Printf("blocklive recover: %s was mid-mirror/RAM — cancelled job + resumed source", id)
}

// ---- small fail-safe file helpers ----------------------------------------

func copyRegular(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fsyncFile(path string) {
	if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

// retainAside renames a source file to <path>.pre-vmotion so it is kept for
// rollback/reclaim but out of the way. Never deletes.
func retainAside(path string) {
	if path == "" {
		return
	}
	dst := path + ".pre-vmotion"
	_ = os.Remove(dst) // clear any older retained copy
	if err := os.Rename(path, dst); err != nil {
		log.Printf("vmotion: could not retain source %s: %v", path, err)
	}
}
