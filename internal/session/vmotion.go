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

	"vdxclone/internal/qemu"
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
func (m *Manager) MoveStorage(id string, targetPoolID int64) error {
	if m.MigrationBusy(id) {
		return fmt.Errorf("a storage move is already in progress for this instance")
	}
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	targetDir, err := m.poolDir(targetPoolID)
	if err != nil {
		return err
	}
	srcPath := s.DiskPath
	srcDir := filepath.Dir(srcPath)
	if filepath.Clean(targetDir) == filepath.Clean(srcDir) {
		return fmt.Errorf("instance disk is already on that storage")
	}
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		return fmt.Errorf("target pool dir: %w", err)
	}
	target := filepath.Join(targetDir, id+".qcow2")
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("a disk already exists at the target (%s) — refusing to overwrite", target)
	}
	// Preflight free space: need at least the source's virtual size.
	if vsz, err := qemu.VirtualSizeBytes(srcPath); err == nil && vsz > 0 {
		if free, err := freeBytes(targetDir); err == nil && free < vsz {
			return fmt.Errorf("not enough free space on target (%d MB free, need %d MB)", free>>20, vsz>>20)
		}
	}

	if m.Running(s) {
		return m.moveStorageLive(s, targetPoolID, srcPath, target)
	}
	return m.moveStorageOffline(s, targetPoolID, srcPath, target)
}

// moveStorageOffline copies disk + firmware vars + seed to the target pool, then
// commits atomically. Source files are retained (renamed) for rollback.
func (m *Manager) moveStorageOffline(s *Session, targetPoolID int64, srcPath, target string) error {
	targetDir := filepath.Dir(target)
	if err := m.setMigState(s.ID, "offline", target, srcPath); err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(target) }

	// 1. Copy the disk (source read-only) and verify the result.
	if err := qemu.ConvertToQcow2(srcPath, target); err != nil {
		cleanup()
		_ = m.setMigState(s.ID, "idle", "", "")
		return fmt.Errorf("copy disk: %w", err)
	}
	if err := qemu.ImageOK(target); err != nil {
		cleanup()
		_ = m.setMigState(s.ID, "idle", "", "")
		return fmt.Errorf("target failed verification: %w", err)
	}

	// 2. Relocate per-VM OVMF vars + seed ISO (small; copy+verify-by-presence).
	newVars := s.OVMFVarsPath
	if s.OVMFVarsPath != "" {
		nv := filepath.Join(targetDir, s.ID+".ovmf_vars.fd")
		if err := copyRegular(s.OVMFVarsPath, nv); err != nil {
			cleanup()
			_ = m.setMigState(s.ID, "idle", "", "")
			return fmt.Errorf("copy firmware vars: %w", err)
		}
		newVars = nv
	}
	newSeed := s.SeedPath
	if s.SeedPath != "" {
		ns := filepath.Join(targetDir, s.ID+".seed.iso")
		if err := copyRegular(s.SeedPath, ns); err == nil {
			newSeed = ns
		}
	}

	// Hand the copied files to the RunAs user (convert/copy ran as root) so the
	// VM can open them on next start.
	m.chownRunAs(target, newVars, newSeed)

	// 3. Durable, ordered commit: fsync target, THEN the DB txn, THEN source-aside.
	fsyncFile(target)
	if _, err := m.db.Exec(`UPDATE sessions SET disk_path=?, ovmf_vars_path=?, seed_path=?, disk_backend='qcow2',
		storage_pool_id=?, migration_state='idle', mig_target_path='', mig_source_path='' WHERE id=?`,
		target, newVars, newSeed, targetPoolID, s.ID); err != nil {
		cleanup()
		return fmt.Errorf("commit: %w", err)
	}
	// 4. Retain the source (NEVER deleted inline — reclaimed by admin later).
	retainAside(srcPath)
	if s.OVMFVarsPath != "" && newVars != s.OVMFVarsPath {
		retainAside(s.OVMFVarsPath)
	}
	log.Printf("vmotion: offline-moved %s disk to %s (source retained as %s.pre-vmotion)", s.ID, target, srcPath)
	return nil
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
