package session

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/ceph"
	"vdxclone/internal/lvm"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/qemu"
	"vdxclone/internal/zfs"
)

// ---- snapshot engine -----------------------------------------------------
//
// Snapshots for every disk backend (docs/SNAPSHOTS.md): qcow2 internal tags,
// ZFS zvol snapshots, LVM thin snapshots and Ceph RBD snapshots, taken offline
// or live (guest filesystems frozen through the guest agent when it answers,
// crash-consistent otherwise), with the UEFI NVRAM copied alongside. A VM has
// exactly one data disk (sessions.disk_path), so one snapshot covers it; a
// policy run snapshots many VMs under ONE shared freeze window.
//
// Invariants the engine enforces itself (the service layer adds authz/audit):
//   - an immutable snapshot (locked_until in the future) is never destroyed —
//     not by delete, not as a side effect of a ZFS rollback, not by a purge;
//   - a snapshot an instant clone still depends on is never destroyed; purging
//     its VM first detaches the clone (zfs promote / rbd flatten);
//   - only snapshots recorded in our own table are ever destroyed.

// Consistency levels recorded on every snapshot.
const (
	ConsistencyOffline = "offline" // the VM was stopped: the disk was at rest
	ConsistencyApp     = "app"     // guest filesystems frozen by the guest agent
	ConsistencyCrash   = "crash"   // live without a freeze: like a power cut at that instant
)

// Bounds on the guest freeze. Windows VSS gives up on its own after ~10s; a
// Linux freeze holds until thawed, which is why the thaw is unconditional.
const (
	freezeTimeout = 30 * time.Second
	thawTimeout   = 45 * time.Second
)

var (
	// ErrImmutable: the snapshot is locked by an immutable policy.
	ErrImmutable = errors.New("snapshot is immutable")
	// ErrHasClones: instant clones still depend on the snapshot.
	ErrHasClones = errors.New("instant clones depend on this snapshot")
)

// SnapResult is a snapshot just taken on the host (not yet recorded).
type SnapResult struct {
	Tag         string
	Backend     string
	Ref         string
	Consistency string
	VarsPath    string
	Online      bool
}

// SnapItem is one VM's outcome in a group snapshot.
type SnapItem struct {
	Result SnapResult
	Err    error
}

// snapOps is every host-side storage call the engine makes. A var so the
// orchestration (immutability, clone dependencies, promote-on-purge, the freeze
// window) is unit-testable without ZFS, LVM, Ceph or QEMU.
type snapOps struct {
	qmpSnap, qmpSnapDelete                     func(sock, dev, tag string) error
	imgSnapCreate, imgSnapApply, imgSnapDelete func(disk, tag string) error
	imgClone                                   func(src, tag, dst string, live bool) (string, error)
	zfsSnap, zfsRollback, zfsDestroySnap       func(ds, tag string) error
	zfsClone                                   func(ds, tag, target string) error
	zfsPromote, zfsDestroy                     func(ds string) error
	zfsTags                                    func(ds string) ([]string, error)
	lvmSnap, lvmCopy                           func(vg, src, name string) error
	lvmRevert                                  func(vg, lv, snap, sfx string) error
	lvmRemove                                  func(vg, name string) error
	lvmRemoveDev                               func(dev string) error
	rbdSnap, rbdRollback, rbdSnapRemove        func(pool, image, tag string) error
	rbdClone                                   func(pool, image, tag, dst string) error
	rbdFlatten, rbdRemove                      func(pool, image string) error
	freeze                                     func(sock string, timeout time.Duration) (int, error)
	thaw                                       func(sock string, timeout time.Duration) error
}

var ops = snapOps{
	qmpSnap:        qemu.QMPInternalSnapshot,
	qmpSnapDelete:  qemu.QMPDeleteInternalSnapshot,
	imgSnapCreate:  qemu.SnapshotCreate,
	imgSnapApply:   qemu.SnapshotApply,
	imgSnapDelete:  qemu.SnapshotDelete,
	imgClone:       qemu.CloneSnapshot,
	zfsSnap:        zfs.Snapshot,
	zfsRollback:    zfs.Rollback,
	zfsDestroySnap: zfs.DestroySnapshot,
	zfsClone:       zfs.Clone,
	zfsPromote:     zfs.Promote,
	zfsDestroy:     zfs.DestroyDataset,
	zfsTags:        zfs.ListSnapshotTags,
	lvmSnap:        lvm.ThinSnapshot,
	lvmCopy:        lvm.ThinCopy,
	lvmRevert:      lvm.RevertThin,
	lvmRemove:      lvm.RemoveNamed,
	lvmRemoveDev:   lvm.RemoveLV,
	rbdSnap:        ceph.SnapCreate,
	rbdRollback:    ceph.SnapRollback,
	rbdSnapRemove:  ceph.SnapRemove,
	rbdClone:       ceph.Clone,
	rbdFlatten:     ceph.Flatten,
	rbdRemove:      ceph.RemoveImage,
	freeze:         qemu.GuestFsFreeze,
	thaw:           qemu.GuestFsThaw,
}

// diskRef is a VM disk resolved to its backend's own names.
type diskRef struct {
	backend     string
	path        string // qcow2 file / device path
	ds          string // zvol dataset
	vg, lv      string // LVM thin LV
	pool, image string // RBD image
}

func diskOf(s *Session) (diskRef, error) {
	d := diskRef{backend: s.DiskBackend, path: s.DiskPath}
	var ok bool
	switch s.DiskBackend {
	case "zvol":
		d.ds, ok = strings.CutPrefix(s.DiskPath, "/dev/zvol/")
	case "lvm":
		d.vg, d.lv, ok = lvm.SplitDevPath(s.DiskPath)
	case "rbd":
		d.pool, d.image, ok = ceph.ParseRBD(s.DiskPath)
	case "", "qcow2":
		d.backend, ok = "qcow2", s.DiskPath != ""
	default:
		return d, fmt.Errorf("snapshots are not supported on the %q disk backend", s.DiskBackend)
	}
	if !ok {
		return d, fmt.Errorf("cannot resolve the %s disk %q", s.DiskBackend, s.DiskPath)
	}
	return d, nil
}

// ---- per-VM serialization ------------------------------------------------

// lockVMs serializes snapshot/revert/clone/purge per VM (a policy run and a user
// action on the same VM must not interleave). Locks are taken in sorted order so
// two group runs can never deadlock. Returns the unlock func.
func (m *Manager) lockVMs(ids []string) func() {
	ids = uniqSorted(ids)
	var held []*sync.Mutex
	for _, id := range ids {
		v, _ := m.snapLocks.LoadOrStore(id, &sync.Mutex{})
		mu := v.(*sync.Mutex)
		mu.Lock()
		held = append(held, mu)
	}
	return func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i].Unlock()
		}
	}
}

func uniqSorted(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (m *Manager) qgaSock(id string) string { return filepath.Join(m.cfg.Paths.DiskDir, id+".qga") }

func (m *Manager) snapVarsPath(id, tag string) string {
	return filepath.Join(m.cfg.Paths.DiskDir, id+".vars."+tag+".fd")
}

var errMigrating = errors.New("instance is migrating its storage; try again when the move finishes")

// ---- take ----------------------------------------------------------------

// TakeSnapshot snapshots one VM (see SnapshotGroup).
func (m *Manager) TakeSnapshot(id string) (SnapResult, error) {
	it := m.SnapshotGroup([]string{id})[id]
	return it.Result, it.Err
}

// SnapshotGroup snapshots several VMs as one best-effort consistency group:
// every running guest with an agent is frozen IN PARALLEL, then each disk is
// snapshotted (each backend's snapshot is instant), then all are thawed — so the
// whole group shares one frozen window. The thaw runs in a defer: it happens on
// every path, including a panic in a backend call and a freeze that failed or
// timed out (it may still complete inside the guest after we gave up). A VM whose
// freeze or thaw didn't verifiably succeed is recorded crash-consistent.
func (m *Manager) SnapshotGroup(ids []string) map[string]SnapItem {
	ids = uniqSorted(ids)
	out := make(map[string]SnapItem, len(ids))
	unlock := m.lockVMs(ids)
	defer unlock()

	type member struct {
		s                    *Session
		d                    diskRef
		running, tried, cold bool
		frozen               bool
		tag, ref             string
		err                  error
	}
	var ms []*member
	for _, id := range ids {
		if m.MigrationBusy(id) {
			out[id] = SnapItem{Err: errMigrating}
			continue
		}
		s, err := m.Get(id)
		if err != nil {
			out[id] = SnapItem{Err: err}
			continue
		}
		d, err := diskOf(s)
		if err != nil {
			out[id] = SnapItem{Err: err}
			continue
		}
		ms = append(ms, &member{s: s, d: d, running: m.Running(s)})
	}

	var wg sync.WaitGroup
	for _, mb := range ms {
		if mb.running && mb.s.GuestAgent {
			mb.tried = true
			wg.Add(1)
			go func(mb *member) {
				defer wg.Done()
				n, err := ops.freeze(m.qgaSock(mb.s.ID), freezeTimeout)
				if err != nil {
					log.Printf("snapshot %s: guest freeze failed (%v) — taking a crash-consistent snapshot", mb.s.ID, err)
				}
				mb.frozen = err == nil && n > 0
			}(mb)
		}
	}
	wg.Wait()

	thawAll := func() {
		var tw sync.WaitGroup
		for _, mb := range ms {
			if !mb.tried {
				continue
			}
			tw.Add(1)
			go func(mb *member) {
				defer tw.Done()
				if err := ops.thaw(m.qgaSock(mb.s.ID), thawTimeout); err != nil {
					log.Printf("snapshot %s: %v — recorded as crash-consistent", mb.s.ID, err)
					mb.frozen = false
				}
			}(mb)
		}
		tw.Wait()
	}
	func() {
		defer thawAll()
		for _, mb := range ms {
			mb.tag = "snap-" + randHex(4)
			mb.ref, mb.err = m.snapDisk(mb.d, mb.s, mb.running, mb.tag)
		}
	}()

	for _, mb := range ms {
		if mb.err != nil {
			out[mb.s.ID] = SnapItem{Err: mb.err}
			continue
		}
		r := SnapResult{Tag: mb.tag, Backend: mb.d.backend, Ref: mb.ref, Online: mb.running,
			Consistency: ConsistencyOffline}
		if mb.running {
			r.Consistency = ConsistencyCrash
			if mb.frozen {
				r.Consistency = ConsistencyApp
			}
		}
		// The UEFI NVRAM (boot entries) is a separate small file: copy it with the
		// snapshot so a revert or clone gets the matching boot configuration.
		if mb.s.Firmware == "uefi" && mb.s.OVMFVarsPath != "" {
			dst := m.snapVarsPath(mb.s.ID, mb.tag)
			if err := copyRegular(mb.s.OVMFVarsPath, dst); err == nil {
				r.VarsPath = dst
			} else {
				log.Printf("snapshot %s: NVRAM copy: %v", mb.s.ID, err)
			}
		}
		out[mb.s.ID] = SnapItem{Result: r}
	}
	return out
}

// snapDisk takes the backend snapshot of one disk and returns its locator.
func (m *Manager) snapDisk(d diskRef, s *Session, running bool, tag string) (string, error) {
	switch d.backend {
	case "zvol":
		return d.ds + "@" + tag, ops.zfsSnap(d.ds, tag)
	case "lvm":
		name := d.lv + "-" + tag
		return d.vg + "/" + name, ops.lvmSnap(d.vg, d.lv, name)
	case "rbd":
		return d.pool + "/" + d.image + "@" + tag, ops.rbdSnap(d.pool, d.image, tag)
	default: // qcow2 internal snapshot, inside the disk file
		if running {
			return "", ops.qmpSnap(s.QMPSocket, qemu.DiskDevice, tag)
		}
		return "", ops.imgSnapCreate(d.path, tag)
	}
}

// ---- revert --------------------------------------------------------------

// RevertSnapshot restores the VM's disk (and UEFI NVRAM) to a snapshot. The VM
// must be stopped. Every other snapshot is kept, except on ZFS: a zvol can only
// roll back to its NEWEST snapshot, so reverting to an older one first destroys
// the newer ones — only when discardNewer is set, and only if every one of them
// is ours, not immutable, and has no dependent clones (checked before anything
// is destroyed).
func (m *Manager) RevertSnapshot(id string, snapID int64, discardNewer bool) error {
	unlock := m.lockVMs([]string{id})
	defer unlock()
	if m.MigrationBusy(id) {
		return errMigrating
	}
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if m.Running(s) {
		return errors.New("stop the instance before reverting a snapshot")
	}
	sn, err := m.GetSnapshot(id, snapID)
	if err != nil {
		return err
	}
	d, err := diskOf(s)
	if err != nil {
		return err
	}
	if sn.Backend != d.backend {
		return fmt.Errorf("snapshot %q was taken on a %s disk; this instance's disk is now %s", sn.Name, sn.Backend, d.backend)
	}
	switch d.backend {
	case "zvol":
		ds, tag, ok := strings.Cut(sn.Ref, "@")
		if !ok || ds != d.ds {
			return fmt.Errorf("snapshot %q is not on this instance's zvol (%s)", sn.Name, sn.Ref)
		}
		if err := m.discardNewerZFS(id, ds, tag, discardNewer); err != nil {
			return err
		}
		err = ops.zfsRollback(ds, tag)
	case "lvm":
		vg, name, ok := strings.Cut(sn.Ref, "/")
		if !ok || vg != d.vg {
			return fmt.Errorf("snapshot %q is not in this instance's volume group (%s)", sn.Name, sn.Ref)
		}
		err = ops.lvmRevert(d.vg, d.lv, name, randHex(3))
	case "rbd":
		err = ops.rbdRollback(d.pool, d.image, sn.Tag)
	default:
		err = ops.imgSnapApply(d.path, sn.Tag)
	}
	if err != nil {
		return err
	}
	if sn.VarsPath != "" && s.OVMFVarsPath != "" {
		if b, rerr := os.ReadFile(sn.VarsPath); rerr == nil {
			if werr := os.WriteFile(s.OVMFVarsPath, b, 0o644); werr != nil {
				log.Printf("revert %s: restore NVRAM: %v", id, werr)
			}
		}
	}
	return nil
}

// discardNewerZFS destroys the snapshots newer than tag on ds, refusing up front
// unless every one is ours, unlocked and clone-free.
func (m *Manager) discardNewerZFS(id, ds, tag string, discard bool) error {
	tags, err := ops.zfsTags(ds)
	if err != nil {
		return err
	}
	at := -1
	for i, t := range tags {
		if t == tag {
			at = i
		}
	}
	if at < 0 {
		return fmt.Errorf("snapshot %s@%s no longer exists on the host", ds, tag)
	}
	newer := tags[at+1:]
	if len(newer) == 0 {
		return nil
	}
	if !discard {
		return fmt.Errorf("ZFS can only roll back to the most recent snapshot: reverting here destroys the %d newer snapshot(s) — confirm discarding them, or create an instant clone from this snapshot instead", len(newer))
	}
	rows, err := m.ListSnapshots(id)
	if err != nil {
		return err
	}
	byTag := map[string]SnapRecord{}
	for _, r := range rows {
		if r.Backend == "zvol" && strings.HasPrefix(r.Ref, ds+"@") {
			byTag[r.Tag] = r
		}
	}
	now := time.Now()
	for _, t := range newer {
		r, ok := byTag[t]
		if !ok {
			return fmt.Errorf("refusing to destroy %s@%s: it was not created by VXVisor", ds, t)
		}
		if r.Locked(now) {
			return fmt.Errorf("%w: newer snapshot %q is locked until %s", ErrImmutable, r.Name, r.LockedUntil)
		}
		if len(r.Clones) > 0 {
			return fmt.Errorf("%w: newer snapshot %q (%s)", ErrHasClones, r.Name, cloneNames(r.Clones))
		}
	}
	for i := len(newer) - 1; i >= 0; i-- {
		r := byTag[newer[i]]
		if err := ops.zfsDestroySnap(ds, r.Tag); err != nil && !isGone(err) {
			return err
		}
		m.dropSnapshotRow(r)
	}
	return nil
}

// ---- delete --------------------------------------------------------------

// DeleteSnapshot destroys one snapshot (host side + NVRAM copy + row). Refused
// while it is immutable or instant clones depend on it.
func (m *Manager) DeleteSnapshot(id string, snapID int64) error {
	unlock := m.lockVMs([]string{id})
	defer unlock()
	sn, err := m.GetSnapshot(id, snapID)
	if err != nil {
		return err
	}
	if sn.Locked(time.Now()) {
		return fmt.Errorf("%w until %s", ErrImmutable, sn.LockedUntil)
	}
	if len(sn.Clones) > 0 {
		return fmt.Errorf("%w (%s): delete those instances first", ErrHasClones, cloneNames(sn.Clones))
	}
	s, err := m.getAny(id)
	if err != nil {
		return err
	}
	if err := m.removeBackendSnapshot(s, sn); err != nil {
		return err
	}
	m.dropSnapshotRow(sn)
	return nil
}

// removeBackendSnapshot destroys a snapshot on the host. The row's ref is the
// authority on where it lives. A snapshot already gone from the host is treated
// as removed, so a stale row can always be cleaned up.
func (m *Manager) removeBackendSnapshot(s *Session, sn SnapRecord) error {
	var err error
	switch sn.Backend {
	case "zvol":
		ds, tag, ok := strings.Cut(sn.Ref, "@")
		if !ok {
			return fmt.Errorf("malformed zvol snapshot ref %q", sn.Ref)
		}
		err = ops.zfsDestroySnap(ds, tag)
	case "lvm":
		vg, name, ok := strings.Cut(sn.Ref, "/")
		if !ok {
			return fmt.Errorf("malformed lvm snapshot ref %q", sn.Ref)
		}
		err = ops.lvmRemove(vg, name)
	case "rbd":
		pool, image, tag, ok := parseRBDSnapRef(sn.Ref)
		if !ok {
			return fmt.Errorf("malformed rbd snapshot ref %q", sn.Ref)
		}
		err = ops.rbdSnapRemove(pool, image, tag)
	default:
		if s.DiskBackend != "" && s.DiskBackend != "qcow2" {
			return fmt.Errorf("snapshot %q lives in a qcow2 file this instance no longer uses", sn.Name)
		}
		if m.Running(s) {
			err = ops.qmpSnapDelete(s.QMPSocket, qemu.DiskDevice, sn.Tag)
		} else {
			err = ops.imgSnapDelete(s.DiskPath, sn.Tag)
		}
	}
	if err != nil && !isGone(err) {
		return err
	}
	return nil
}

func parseRBDSnapRef(ref string) (pool, image, tag string, ok bool) {
	img, tag, ok1 := strings.Cut(ref, "@")
	pool, image, ok2 := strings.Cut(img, "/")
	return pool, image, tag, ok1 && ok2 && pool != "" && image != "" && tag != ""
}

// isGone recognizes "it isn't there" from each backend's CLI.
// A missing tool or a permission problem is NOT "gone": the row must stay.
func isGone(err error) bool {
	m := strings.ToLower(err.Error())
	for _, s := range []string{"executable file not found", "permission denied", "timed out", "deadline",
		"keyring", "conf", "connect"} { // rbd: a missing ceph.conf/keyring is not a missing snapshot
		if strings.Contains(m, s) {
			return false
		}
	}
	for _, s := range []string{"does not exist", "could not find", "failed to find", "no such file",
		"can't find the snapshot", "can't find snapshot", "snapshot not found"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func cloneNames(cs []CloneRef) string {
	var n []string
	for _, c := range cs {
		n = append(n, c.Name)
	}
	return strings.Join(n, ", ")
}

// ---- instant clone -------------------------------------------------------

// CloneOpts describes an instant clone of a recorded snapshot.
type CloneOpts struct {
	OriginID string
	SnapID   int64
	Name     string
	OwnerID  int64
}

// CloneFromSnapshot creates a new, stopped VM whose disk is an instant copy of
// the snapshot, with a new identity: new id, MAC, NVRAM, cloud-init instance-id
// and hostname (so cloud-init regenerates SSH host keys and re-renders networking
// for the new MAC), a fresh TPM, its own address lease and its own console ports
// (allocated at start). The disk:
//
//	qcow2  reflink copy (instant) or convert of the VM's own delta over the shared
//	       base — independent of the origin
//	zvol   zfs clone — instant, shares blocks, depends on the snapshot
//	lvm    thin snapshot of the snapshot — instant, shares blocks, independent
//	rbd    protected snapshot + rbd clone — instant, depends on the snapshot
//
// The clone→origin link is recorded; for the dependent kinds it pins the
// snapshot (it can't be deleted, and purging the origin detaches the clone first).
func (m *Manager) CloneFromSnapshot(o CloneOpts) (*Session, error) {
	unlock := m.lockVMs([]string{o.OriginID})
	defer unlock()
	if m.MigrationBusy(o.OriginID) {
		return nil, errMigrating
	}
	s, err := m.Get(o.OriginID)
	if err != nil {
		return nil, err
	}
	sn, err := m.GetSnapshot(o.OriginID, o.SnapID)
	if err != nil {
		return nil, err
	}
	d, err := diskOf(s)
	if err != nil {
		return nil, err
	}
	if sn.Backend != d.backend {
		return nil, fmt.Errorf("snapshot %q was taken on a %s disk; this instance's disk is now %s", sn.Name, sn.Backend, d.backend)
	}
	name := strings.TrimSpace(o.Name)
	if name == "" {
		name = s.Name + "-clone"
	}
	netID := s.NetworkID
	if netID <= 0 {
		netID = m.defaultTenantNetwork(s.OrgID)
	}
	if err := m.CheckPortGroup(s.OrgID, netID); err != nil {
		return nil, err
	}

	id := uuid.NewString()
	var created []string
	var undo []func()
	var tx *sql.Tx
	fail := func(e error) (*Session, error) {
		if tx != nil {
			_ = tx.Rollback() // first: it holds the DB's only writer connection
		}
		m.releaseLeases(id)
		for _, f := range created {
			_ = os.Remove(f)
		}
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return nil, e
	}

	var disk, method string
	dependent := false
	switch d.backend {
	case "zvol":
		ds, tag, ok := strings.Cut(sn.Ref, "@")
		if !ok {
			return fail(fmt.Errorf("malformed zvol snapshot ref %q", sn.Ref))
		}
		target := path.Dir(ds) + "/vdx-" + id[:8]
		if err := ops.zfsClone(ds, tag, target); err != nil {
			return fail(err)
		}
		undo = append(undo, func() { _ = ops.zfsDestroy(target) })
		disk, method, dependent = "/dev/zvol/"+target, "zfs-clone", true
	case "lvm":
		vg, snapLV, ok := strings.Cut(sn.Ref, "/")
		if !ok {
			return fail(fmt.Errorf("malformed lvm snapshot ref %q", sn.Ref))
		}
		lv := "vdx-" + id[:8]
		if err := ops.lvmCopy(vg, snapLV, lv); err != nil {
			return fail(err)
		}
		undo = append(undo, func() { _ = ops.lvmRemove(vg, lv) })
		disk, method = "/dev/"+vg+"/"+lv, "lvm-thin"
	case "rbd":
		pool, image, tag, ok := parseRBDSnapRef(sn.Ref)
		if !ok {
			return fail(fmt.Errorf("malformed rbd snapshot ref %q", sn.Ref))
		}
		img := "vdx-" + id[:8]
		if err := ops.rbdClone(pool, image, tag, img); err != nil {
			return fail(err)
		}
		undo = append(undo, func() { _ = ops.rbdRemove(pool, img) })
		disk, method, dependent = ceph.RBDPath(pool, img), "rbd-clone", true
	default:
		// Next to the origin's disk, so the clone lands on the same storage pool.
		dst := filepath.Join(filepath.Dir(d.path), id+".qcow2")
		mth, err := ops.imgClone(d.path, sn.Tag, dst, m.Running(s))
		if err != nil {
			return fail(err)
		}
		created = append(created, dst)
		disk, method = dst, mth
	}

	// UEFI NVRAM: the snapshot's copy when there is one, else the origin's
	// current vars, else a fresh template.
	var varsPath string
	if s.Firmware == "uefi" {
		varsPath = filepath.Join(m.cfg.Paths.DiskDir, id+".ovmf_vars.fd")
		src := sn.VarsPath
		if _, err := os.Stat(src); src == "" || err != nil {
			src = s.OVMFVarsPath
		}
		if err := copyRegular(src, varsPath); err != nil {
			_, tmpl, _ := qemu.OVMF()
			if s.SecureBoot {
				if _, msTmpl, ok := qemu.OVMFSecure(); ok {
					tmpl = msTmpl
				}
			}
			if err := qemu.PrepareUEFIVars(tmpl, varsPath); err != nil {
				return fail(fmt.Errorf("clone NVRAM: %w", err))
			}
		}
		created = append(created, varsPath)
	}

	mac := netdrv.GenMAC()
	seedPath := ""
	if s.CloudInit {
		seedPath, err = m.buildSeed(id, name, mac, s.OrgID, netID, s.CIUsername, s.CIPassword, s.CISSHKey)
		if err != nil {
			return fail(err)
		}
		created = append(created, seedPath)
	}

	var poolID any
	var pid int64
	if m.db.QueryRow(`SELECT COALESCE(storage_pool_id,0) FROM sessions WHERE id=?`, s.ID).Scan(&pid) == nil && pid > 0 {
		poolID = pid
	}
	var bootISO any
	if s.BootISOID > 0 {
		bootISO = s.BootISOID
	}
	tx, err = m.db.Begin()
	if err != nil {
		tx = nil
		return fail(err)
	}
	defer tx.Rollback()
	// Passthrough devices are host hardware one VM owns, so a clone starts
	// without them; start-at-boot is off until someone opts the clone in.
	_, err = tx.Exec(`INSERT INTO sessions
		(id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,boot_iso_id,mac,
		 cpus,memory_mb,disk_gb,state,cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,network_id,storage_pool_id,display,disk_backend,
		 machine_type,disk_bus,nic_model,vga,guest_agent,tpm,secureboot,os_type,perf_pin,perf_hugepages,guest_os,eject_virtio,autostart)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'stopped',?,?,?,?,?,'',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)`,
		id, name, s.OrgID, o.OwnerID, s.ImageName, disk, s.Kind, s.Firmware, varsPath, bootISO, mac,
		s.CPUs, s.MemoryMB, s.DiskGB, b2i(s.CloudInit), s.CIUsername, s.CIPassword, s.CISSHKey, seedPath, nullIf0(netID), poolID, s.Display, d.backend,
		s.MachineType, s.DiskBus, s.NICModel, s.VGA, b2i(s.GuestAgent), b2i(s.TPM), b2i(s.SecureBoot), s.OSType, b2i(s.PinCPUs), b2i(s.HugePages), nullIfEmpty(s.GuestOS), b2i(s.EjectVirtio))
	if err != nil {
		return fail(err)
	}
	var snapRef any
	if dependent {
		snapRef = sn.ID
	}
	if _, err := tx.Exec(`INSERT INTO snapshot_clones(clone_id,origin_id,origin_name,snapshot_id,snapshot_name,backend,method)
		VALUES(?,?,?,?,?,?,?)`, id, s.ID, s.Name, snapRef, sn.Name, d.backend, method); err != nil {
		return fail(err)
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	return m.Get(id)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- purge support -------------------------------------------------------

// detachDependents makes every instant clone that depends on one of id's
// snapshots independent of id, so id's disk and snapshots can be destroyed
// without breaking them. Nothing is destroyed here.
//
//	zvol  zfs promote the clone of the NEWEST snapshot that has clones: it takes
//	      ownership of that snapshot and every older one (their rows are re-homed
//	      to it, so other clones' links stay valid), and id's zvol becomes a clone
//	      of it — destroyable. Instant, no data copied.
//	rbd   rbd flatten each clone (copies the shared blocks into it; proportional
//	      to the image size), then its link no longer pins the snapshot.
func (m *Manager) detachDependents(id string, backend string, d diskRef) (rehomed []int64, err error) {
	deps, err := m.dependentsOf(id)
	if err != nil || len(deps) == 0 {
		return nil, err
	}
	switch backend {
	case "zvol":
		tags, err := ops.zfsTags(d.ds)
		if err != nil {
			return nil, err
		}
		order := map[string]int{}
		for i, t := range tags {
			order[t] = i
		}
		pick := deps[0]
		for _, dp := range deps[1:] {
			if order[dp.snapTag] > order[pick.snapTag] {
				pick = dp
			}
		}
		cs, err := m.getAny(pick.cloneID)
		if err != nil {
			return nil, err
		}
		cds, ok := strings.CutPrefix(cs.DiskPath, "/dev/zvol/")
		if !ok || cs.DiskBackend != "zvol" {
			return nil, fmt.Errorf("clone %s is no longer a zvol", cs.Name)
		}
		if err := ops.zfsPromote(cds); err != nil {
			return nil, err
		}
		moved, err := ops.zfsTags(cds)
		if err != nil {
			return nil, err
		}
		onClone := map[string]bool{}
		for _, t := range moved {
			onClone[t] = true
		}
		rows, err := m.ListSnapshots(id)
		if err != nil {
			return nil, err
		}
		own, ownDep := m.CloneLinkOf(id)
		tx, err := m.db.Begin()
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		for _, r := range rows {
			if r.Backend == "zvol" && onClone[r.Tag] {
				if _, err := tx.Exec(`UPDATE snapshots SET session_id=?, ref=? WHERE id=?`, cs.ID, cds+"@"+r.Tag, r.ID); err != nil {
					return nil, err
				}
				rehomed = append(rehomed, r.ID)
				// Clones of a moved snapshot now hang off the promoted clone.
				if _, err := tx.Exec(`UPDATE snapshot_clones SET origin_id=?, origin_name=? WHERE snapshot_id=? AND clone_id<>?`,
					cs.ID, cs.Name, r.ID, cs.ID); err != nil {
					return nil, err
				}
			}
		}
		// The promoted clone no longer depends on id; if id was itself a dependent
		// clone, the promoted one inherits that dependency (it now holds id's origin).
		if ownDep && own.SnapshotID != 0 {
			_, err = tx.Exec(`UPDATE snapshot_clones SET snapshot_id=?, origin_id=?, origin_name=?, snapshot_name=? WHERE clone_id=?`,
				own.SnapshotID, own.OriginID, own.OriginName, own.SnapshotName, cs.ID)
		} else {
			_, err = tx.Exec(`UPDATE snapshot_clones SET snapshot_id=NULL WHERE clone_id=?`, cs.ID)
		}
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	case "rbd":
		for _, dp := range deps {
			cs, err := m.getAny(dp.cloneID)
			if err != nil {
				return nil, err
			}
			pool, image, ok := ceph.ParseRBD(cs.DiskPath)
			if !ok {
				return nil, fmt.Errorf("clone %s is no longer an rbd image", cs.Name)
			}
			if err := ops.rbdFlatten(pool, image); err != nil {
				return nil, err
			}
			if _, err := m.db.Exec(`UPDATE snapshot_clones SET snapshot_id=NULL WHERE clone_id=?`, cs.ID); err != nil {
				return nil, err
			}
		}
	default:
		// qcow2 / LVM-thin clones never share blocks with their origin; a stale
		// link only needs clearing.
		if _, err := m.db.Exec(`UPDATE snapshot_clones SET snapshot_id=NULL
			WHERE snapshot_id IN (SELECT id FROM snapshots WHERE session_id=?)`, id); err != nil {
			return nil, err
		}
	}
	if left, err := m.dependentsOf(id); err != nil {
		return rehomed, err
	} else if len(left) > 0 {
		return rehomed, fmt.Errorf("%d instant clone(s) still depend on this instance's snapshots", len(left))
	}
	return rehomed, nil
}

// releaseTransientBase removes a snapshot that was taken only as an instant
// clone's base once nothing depends on it any more.
func (m *Manager) releaseTransientBase(snapID int64) {
	r, ok := m.snapshotByID(snapID)
	if !ok || !r.Transient || len(r.Clones) > 0 || r.Locked(time.Now()) {
		return
	}
	unlock := m.lockVMs([]string{r.SessionID})
	defer unlock()
	s, err := m.getAny(r.SessionID)
	if err != nil {
		return
	}
	if err := m.removeBackendSnapshot(s, r); err != nil {
		log.Printf("clone base %s on %s: %v", r.Tag, r.SessionID, err)
		return
	}
	m.dropSnapshotRow(r)
}
