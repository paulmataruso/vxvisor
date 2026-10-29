package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Orchestration tests for the snapshot engine: every host call goes through the
// `ops` seam, recorded here, so no ZFS / LVM / Ceph / QEMU is touched.

type opsRec struct {
	mu    sync.Mutex
	calls []string
	tags  map[string][]string // zfs dataset -> snapshot tags, oldest first
	fail  map[string]error    // call prefix -> error
}

func (r *opsRec) add(c string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
	for p, err := range r.fail {
		if strings.HasPrefix(c, p) {
			return err
		}
	}
	return nil
}

func (r *opsRec) has(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (r *opsRec) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func fakeSnapOps(t *testing.T) *opsRec {
	t.Helper()
	r := &opsRec{tags: map[string][]string{}, fail: map[string]error{}}
	old := ops
	f := func(name string, a ...string) error { return r.add(name + " " + strings.Join(a, " ")) }
	ops = snapOps{
		qmpSnap:       func(s, d, t string) error { return f("qmp-snap", d, t) },
		qmpSnapDelete: func(s, d, t string) error { return f("qmp-snap-delete", d, t) },
		imgSnapCreate: func(d, t string) error { return f("img-snap", d, t) },
		imgSnapApply:  func(d, t string) error { return f("img-apply", d, t) },
		imgSnapDelete: func(d, t string) error { return f("img-delete", d, t) },
		imgClone: func(s, t, d string, live bool) (string, error) {
			return "convert", f("img-clone", s, t, d, fmt.Sprint(live))
		},
		zfsSnap:        func(ds, t string) error { return f("zfs-snap", ds+"@"+t) },
		zfsRollback:    func(ds, t string) error { return f("zfs-rollback", ds+"@"+t) },
		zfsDestroySnap: func(ds, t string) error { return f("zfs-destroy-snap", ds+"@"+t) },
		zfsClone:       func(ds, t, tg string) error { return f("zfs-clone", ds+"@"+t, tg) },
		zfsPromote: func(ds string) error {
			// Promotion moves the origin's snapshots up to the clone's origin onto ds.
			return f("zfs-promote", ds)
		},
		zfsDestroy: func(ds string) error { return f("zfs-destroy", ds) },
		zfsTags: func(ds string) ([]string, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]string(nil), r.tags[ds]...), nil
		},
		lvmSnap:       func(vg, s, n string) error { return f("lvm-snap", vg+"/"+s, n) },
		lvmCopy:       func(vg, s, n string) error { return f("lvm-copy", vg+"/"+s, n) },
		lvmRevert:     func(vg, lv, s, sfx string) error { return f("lvm-revert", vg+"/"+lv, s) },
		lvmRemove:     func(vg, n string) error { return f("lvm-remove", vg+"/"+n) },
		lvmRemoveDev:  func(dev string) error { return f("lvm-remove-dev", dev) },
		rbdSnap:       func(p, i, t string) error { return f("rbd-snap", p+"/"+i+"@"+t) },
		rbdRollback:   func(p, i, t string) error { return f("rbd-rollback", p+"/"+i+"@"+t) },
		rbdSnapRemove: func(p, i, t string) error { return f("rbd-snap-rm", p+"/"+i+"@"+t) },
		rbdClone:      func(p, i, t, d string) error { return f("rbd-clone", p+"/"+i+"@"+t, d) },
		rbdFlatten:    func(p, i string) error { return f("rbd-flatten", p+"/"+i) },
		rbdRemove:     func(p, i string) error { return f("rbd-rm", p+"/"+i) },
		freeze:        func(s string, _ time.Duration) (int, error) { return 1, f("freeze", filepath.Base(s)) },
		thaw:          func(s string, _ time.Duration) error { return f("thaw", filepath.Base(s)) },
	}
	t.Cleanup(func() { ops = old })
	return r
}

func snapTestManager(t *testing.T) (*Manager, int64) {
	t.Helper()
	m, def, _ := testManager(t, "user")
	m.cfg.Paths.DiskDir = t.TempDir()
	if _, err := m.db.Exec(`INSERT INTO users(username,password_hash) VALUES('owner','x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := m.db.Exec(`INSERT OR IGNORE INTO images(name,path) VALUES('img','/img/base.qcow2')`); err != nil {
		t.Fatal(err)
	}
	return m, def
}

// mkVM inserts a stopped VM row. running=true marks it running as this test
// process (so Manager.Running sees a live pid).
func mkVM(t *testing.T, m *Manager, org int64, id, backend, disk string, running, agent bool) {
	t.Helper()
	state, pid := "stopped", 0
	if running {
		state, pid = "running", os.Getpid()
	}
	if _, err := m.db.Exec(`INSERT INTO sessions(id,name,owner_id,org_id,image_name,disk_path,disk_backend,firmware,mac,state,pid,guest_agent,qmp_socket,cloud_init)
		VALUES(?,?,1,?,'img',?,?,'bios','52:54:00:aa:bb:cc',?,?,?,?,0)`,
		id, "vm-"+id[:4], org, disk, backend, state, pid, b2i(agent), "/run/"+id+".qmp"); err != nil {
		t.Fatal(err)
	}
}

func record(t *testing.T, m *Manager, id string, r SnapResult, meta SnapMeta) int64 {
	t.Helper()
	sid, err := m.RecordSnapshot(id, r.Tag, r, meta)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestTakeSnapshotPerBackend(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	mkVM(t, m, org, "aaaa0001-zvol", "zvol", "/dev/zvol/tank/vdx-aaaa0001", false, false)
	mkVM(t, m, org, "aaaa0002-lvm", "lvm", "/dev/VG0/vdx-aaaa0002", false, false)
	mkVM(t, m, org, "aaaa0003-rbd", "rbd", "rbd:vms/vdx-aaaa0003", false, false)
	mkVM(t, m, org, "aaaa0004-qcow", "qcow2", "/disks/aaaa0004.qcow2", false, false)
	for id, wantRef := range map[string]string{
		"aaaa0001-zvol": "tank/vdx-aaaa0001@",
		"aaaa0002-lvm":  "VG0/vdx-aaaa0002-snap-",
		"aaaa0003-rbd":  "vms/vdx-aaaa0003@",
		"aaaa0004-qcow": "",
	} {
		r, err := m.TakeSnapshot(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if r.Consistency != ConsistencyOffline || r.Online {
			t.Errorf("%s: consistency %q online %v", id, r.Consistency, r.Online)
		}
		if wantRef == "" && r.Ref != "" || wantRef != "" && !strings.HasPrefix(r.Ref, wantRef) {
			t.Errorf("%s: ref %q, want prefix %q", id, r.Ref, wantRef)
		}
	}
	for _, p := range []string{"zfs-snap tank/vdx-aaaa0001@snap-", "lvm-snap VG0/vdx-aaaa0002 vdx-aaaa0002-snap-",
		"rbd-snap vms/vdx-aaaa0003@snap-", "img-snap /disks/aaaa0004.qcow2 snap-"} {
		if !rec.has(p) {
			t.Errorf("missing call %q in %q", p, rec.list())
		}
	}
	if rec.has("freeze") || rec.has("qmp-snap ") {
		t.Errorf("stopped VMs must not be frozen / live-snapshotted: %q", rec.list())
	}
}

func TestSnapshotGroupFreezeAlwaysThaws(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	mkVM(t, m, org, "bbbb0001-ok", "zvol", "/dev/zvol/tank/vdx-bbbb0001", true, true)
	mkVM(t, m, org, "bbbb0002-fail", "zvol", "/dev/zvol/tank/vdx-bbbb0002", true, true)
	mkVM(t, m, org, "bbbb0003-noagent", "qcow2", "/disks/bbbb0003.qcow2", true, false)
	rec.fail["zfs-snap tank/vdx-bbbb0002"] = errors.New("out of space")
	res := m.SnapshotGroup([]string{"bbbb0002-fail", "bbbb0001-ok", "bbbb0003-noagent"})
	if r := res["bbbb0001-ok"]; r.Err != nil || r.Result.Consistency != ConsistencyApp || !r.Result.Online {
		t.Errorf("ok VM: %+v", r)
	}
	if r := res["bbbb0002-fail"]; r.Err == nil {
		t.Errorf("failing VM should report its error: %+v", r)
	}
	if r := res["bbbb0003-noagent"]; r.Err != nil || r.Result.Consistency != ConsistencyCrash {
		t.Errorf("agentless VM must be crash-consistent: %+v", r)
	}
	calls := rec.list()
	// Both agent VMs frozen before ANY snapshot, and thawed after the last one —
	// including the one whose snapshot failed.
	lastFreeze, firstSnap, lastSnap, firstThaw := -1, len(calls), -1, len(calls)
	thawed := map[string]bool{}
	for i, c := range calls {
		switch {
		case strings.HasPrefix(c, "freeze"):
			lastFreeze = i
		case strings.HasPrefix(c, "zfs-snap"), strings.HasPrefix(c, "qmp-snap"):
			if i < firstSnap {
				firstSnap = i
			}
			lastSnap = i
		case strings.HasPrefix(c, "thaw"):
			thawed[strings.TrimPrefix(c, "thaw ")] = true
			if i < firstThaw {
				firstThaw = i
			}
		}
	}
	if !(lastFreeze < firstSnap && lastSnap < firstThaw) {
		t.Fatalf("freeze/snapshot/thaw order wrong: %q", calls)
	}
	if !thawed["bbbb0001-ok.qga"] || !thawed["bbbb0002-fail.qga"] || len(thawed) != 2 {
		t.Fatalf("thawed %v", thawed)
	}
	if !rec.has("qmp-snap disk0 snap-") {
		t.Errorf("running qcow2 must use the QMP internal snapshot: %q", calls)
	}
}

func TestSnapshotThawFailureDowngradesToCrash(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	rec.fail["thaw"] = errors.New("agent gone")
	mkVM(t, m, org, "cccc0001-vm", "rbd", "rbd:vms/vdx-cccc0001", true, true)
	r, err := m.TakeSnapshot("cccc0001-vm")
	if err != nil || r.Consistency != ConsistencyCrash {
		t.Fatalf("got %+v %v, want crash-consistent", r, err)
	}
}

func TestImmutableSnapshotRefusals(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	id := "dddd0001-vm"
	mkVM(t, m, org, id, "zvol", "/dev/zvol/tank/vdx-dddd0001", false, false)
	locked := record(t, m, id, SnapResult{Tag: "snap-1", Backend: "zvol", Ref: "tank/vdx-dddd0001@snap-1", Consistency: "offline"},
		SnapMeta{LockedUntil: time.Now().Add(time.Hour)})
	expired := record(t, m, id, SnapResult{Tag: "snap-2", Backend: "zvol", Ref: "tank/vdx-dddd0001@snap-2", Consistency: "offline"},
		SnapMeta{LockedUntil: time.Now().Add(-time.Hour)})

	if err := m.DeleteSnapshot(id, locked); !errors.Is(err, ErrImmutable) {
		t.Fatalf("delete locked: %v", err)
	}
	if err := m.Purge(id); !errors.Is(err, ErrLockedSnapshots) {
		t.Fatalf("purge with locked snapshot: %v", err)
	}
	if rec.has("zfs-destroy") {
		t.Fatalf("destroyed something: %q", rec.list())
	}
	if _, err := m.getAny(id); err != nil {
		t.Fatalf("VM row gone after refused purge: %v", err)
	}
	// Reverting to an OLDER snapshot can't destroy a locked newer one (ZFS).
	older := record(t, m, id, SnapResult{Tag: "snap-0", Backend: "zvol", Ref: "tank/vdx-dddd0001@snap-0", Consistency: "offline"}, SnapMeta{})
	rec.tags["tank/vdx-dddd0001"] = []string{"snap-0", "snap-1", "snap-2"}
	if err := m.RevertSnapshot(id, older, true); !errors.Is(err, ErrImmutable) {
		t.Fatalf("revert over a locked snapshot: %v", err)
	}
	if rec.has("zfs-destroy-snap") || rec.has("zfs-rollback") {
		t.Fatalf("revert destroyed/rolled back despite the lock: %q", rec.list())
	}
	// An expired lock no longer protects.
	if err := m.DeleteSnapshot(id, expired); err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if !rec.has("zfs-destroy-snap tank/vdx-dddd0001@snap-2") {
		t.Fatalf("expired snapshot not destroyed: %q", rec.list())
	}
	// An unparsable lock fails closed.
	if !(SnapRecord{LockedUntil: "garbage"}).Locked(time.Now()) {
		t.Fatal("unparsable lock must count as locked")
	}
}

func TestZvolRevertDiscardNewer(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	id, ds := "eeee0001-vm", "tank/vdx-eeee0001"
	mkVM(t, m, org, id, "zvol", "/dev/zvol/"+ds, false, false)
	var ids []int64
	for _, tg := range []string{"snap-a", "snap-b", "snap-c"} {
		ids = append(ids, record(t, m, id, SnapResult{Tag: tg, Backend: "zvol", Ref: ds + "@" + tg, Consistency: "offline"}, SnapMeta{}))
	}
	rec.tags[ds] = []string{"snap-a", "snap-b", "snap-c"}

	if err := m.RevertSnapshot(id, ids[0], false); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("revert without discard: %v", err)
	}
	// A newer snapshot we didn't create blocks the discard.
	rec.tags[ds] = []string{"snap-a", "snap-b", "foreign", "snap-c"}
	if err := m.RevertSnapshot(id, ids[0], true); err == nil || !strings.Contains(err.Error(), "not created by VXVisor") {
		t.Fatalf("foreign newer snapshot: %v", err)
	}
	if rec.has("zfs-destroy-snap") {
		t.Fatalf("destroyed before validating every newer snapshot: %q", rec.list())
	}
	rec.tags[ds] = []string{"snap-a", "snap-b", "snap-c"}
	if err := m.RevertSnapshot(id, ids[0], true); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range rec.list() {
		if strings.HasPrefix(c, "zfs-destroy-snap") || strings.HasPrefix(c, "zfs-rollback") {
			got = append(got, c)
		}
	}
	want := []string{"zfs-destroy-snap " + ds + "@snap-c", "zfs-destroy-snap " + ds + "@snap-b", "zfs-rollback " + ds + "@snap-a"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q want %q", got, want)
	}
	if left, _ := m.ListSnapshots(id); len(left) != 1 || left[0].Tag != "snap-a" {
		t.Fatalf("rows after discard: %+v", left)
	}
}

func TestRevertRequiresStoppedAndKeepsOtherSnapshots(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	mkVM(t, m, org, "ffff0001-run", "lvm", "/dev/VG0/vdx-ffff0001", true, false)
	sid := record(t, m, "ffff0001-run", SnapResult{Tag: "snap-1", Backend: "lvm", Ref: "VG0/vdx-ffff0001-snap-1"}, SnapMeta{})
	if err := m.RevertSnapshot("ffff0001-run", sid, false); err == nil || !strings.Contains(err.Error(), "stop") {
		t.Fatalf("revert of a running VM: %v", err)
	}
	mkVM(t, m, org, "ffff0002-lvm", "lvm", "/dev/VG0/vdx-ffff0002", false, false)
	a := record(t, m, "ffff0002-lvm", SnapResult{Tag: "snap-1", Backend: "lvm", Ref: "VG0/vdx-ffff0002-snap-1"}, SnapMeta{})
	record(t, m, "ffff0002-lvm", SnapResult{Tag: "snap-2", Backend: "lvm", Ref: "VG0/vdx-ffff0002-snap-2"}, SnapMeta{})
	if err := m.RevertSnapshot("ffff0002-lvm", a, false); err != nil {
		t.Fatal(err)
	}
	if !rec.has("lvm-revert VG0/vdx-ffff0002 vdx-ffff0002-snap-1") {
		t.Fatalf("calls %q", rec.list())
	}
	if l, _ := m.ListSnapshots("ffff0002-lvm"); len(l) != 2 {
		t.Fatalf("LVM revert must keep every snapshot, have %d", len(l))
	}
	// A snapshot ref pointing outside the VM's own VG is refused.
	bad := record(t, m, "ffff0002-lvm", SnapResult{Tag: "snap-x", Backend: "lvm", Ref: "OTHER/x"}, SnapMeta{})
	if err := m.RevertSnapshot("ffff0002-lvm", bad, false); err == nil {
		t.Fatal("cross-VG revert accepted")
	}
}

func TestCloneDependencyAndPromoteOnPurge(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	oid, ods := "11110000-origin", "tank/vdx-11110000"
	mkVM(t, m, org, oid, "zvol", "/dev/zvol/"+ods, false, false)
	s1 := record(t, m, oid, SnapResult{Tag: "snap-1", Backend: "zvol", Ref: ods + "@snap-1"}, SnapMeta{})
	s2 := record(t, m, oid, SnapResult{Tag: "snap-2", Backend: "zvol", Ref: ods + "@snap-2"}, SnapMeta{})
	rec.tags[ods] = []string{"snap-1", "snap-2"}

	c, err := m.CloneFromSnapshot(CloneOpts{OriginID: oid, SnapID: s1, Name: "web-clone", OwnerID: 1})
	if err != nil {
		t.Fatal(err)
	}
	o, _ := m.Get(oid)
	if c.ID == oid || c.MAC == o.MAC || c.Name != "web-clone" || c.State != "stopped" || c.Autostart {
		t.Fatalf("clone identity: %+v", c)
	}
	cds := "tank/vdx-" + c.ID[:8]
	if c.DiskPath != "/dev/zvol/"+cds || !rec.has("zfs-clone "+ods+"@snap-1 "+cds) {
		t.Fatalf("clone disk %q calls %q", c.DiskPath, rec.list())
	}
	l, ok := m.CloneLinkOf(c.ID)
	if !ok || l.SnapshotID != s1 || l.OriginID != oid || l.Method != "zfs-clone" {
		t.Fatalf("link %+v %v", l, ok)
	}
	// The snapshot the clone depends on can't be deleted.
	if err := m.DeleteSnapshot(oid, s1); !errors.Is(err, ErrHasClones) {
		t.Fatalf("delete depended-on snapshot: %v", err)
	}
	if rec.has("zfs-destroy-snap") {
		t.Fatalf("destroyed a depended-on snapshot: %q", rec.list())
	}

	// Purging the origin promotes the clone: snap-1 moves to it (row re-homed),
	// snap-2 goes with the origin, and the clone no longer depends on anything.
	rec.tags[cds] = []string{"snap-1"} // what zfs promote leaves on the clone
	if err := m.Purge(oid); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(rec.list(), "|")
	pi, di := strings.Index(calls, "zfs-promote "+cds), strings.Index(calls, "zfs-destroy "+ods)
	if pi < 0 || di < 0 || pi > di {
		t.Fatalf("want promote before destroy: %s", calls)
	}
	if _, err := m.Get(c.ID); err != nil {
		t.Fatalf("clone gone after origin purge: %v", err)
	}
	moved, ok := m.snapshotByID(s1)
	if !ok || moved.SessionID != c.ID || moved.Ref != cds+"@snap-1" {
		t.Fatalf("snap-1 not re-homed: %+v %v", moved, ok)
	}
	if _, ok := m.snapshotByID(s2); ok {
		t.Fatal("snap-2 should have been purged with the origin")
	}
	if l, ok := m.CloneLinkOf(c.ID); !ok || l.SnapshotID != 0 {
		t.Fatalf("clone still dependent after promote: %+v", l)
	}
}

func TestPurgeOriginFlattensRBDClones(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	oid := "22220000-origin"
	mkVM(t, m, org, oid, "rbd", "rbd:vms/vdx-22220000", false, false)
	s1 := record(t, m, oid, SnapResult{Tag: "snap-1", Backend: "rbd", Ref: "vms/vdx-22220000@snap-1"}, SnapMeta{})
	c, err := m.CloneFromSnapshot(CloneOpts{OriginID: oid, SnapID: s1, OwnerID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "vm-2222-clone" {
		t.Fatalf("default clone name %q", c.Name)
	}
	if err := m.DeleteSnapshot(oid, s1); !errors.Is(err, ErrHasClones) {
		t.Fatalf("delete: %v", err)
	}
	if err := m.Purge(oid); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(rec.list(), "|")
	img := "vdx-" + c.ID[:8]
	fi, ri, mi := strings.Index(calls, "rbd-flatten vms/"+img), strings.Index(calls, "rbd-snap-rm vms/vdx-22220000@snap-1"), strings.Index(calls, "rbd-rm vms/vdx-22220000")
	if fi < 0 || ri < fi || mi < ri {
		t.Fatalf("want flatten, then snapshot rm, then image rm: %s", calls)
	}
	if l, _ := m.CloneLinkOf(c.ID); l.SnapshotID != 0 {
		t.Fatalf("clone still dependent: %+v", l)
	}
}

func TestQcow2AndLVMClonesAreIndependent(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	dir := t.TempDir()
	mkVM(t, m, org, "33330000-qcow", "qcow2", filepath.Join(dir, "33330000.qcow2"), true, false)
	q := record(t, m, "33330000-qcow", SnapResult{Tag: "snap-1", Backend: "qcow2"}, SnapMeta{})
	c, err := m.CloneFromSnapshot(CloneOpts{OriginID: "33330000-qcow", SnapID: q, OwnerID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(c.DiskPath) != dir || !rec.has("img-clone "+filepath.Join(dir, "33330000.qcow2")+" snap-1 "+c.DiskPath+" true") {
		t.Fatalf("qcow2 clone %q calls %q", c.DiskPath, rec.list())
	}
	if l, _ := m.CloneLinkOf(c.ID); l.SnapshotID != 0 {
		t.Fatal("a qcow2 clone must not pin its snapshot")
	}
	if err := m.DeleteSnapshot("33330000-qcow", q); err != nil {
		t.Fatalf("delete after independent clone: %v", err)
	}

	mkVM(t, m, org, "44440000-lvm", "lvm", "/dev/VG0/vdx-44440000", false, false)
	ls := record(t, m, "44440000-lvm", SnapResult{Tag: "snap-1", Backend: "lvm", Ref: "VG0/vdx-44440000-snap-1"}, SnapMeta{})
	lc, err := m.CloneFromSnapshot(CloneOpts{OriginID: "44440000-lvm", SnapID: ls, OwnerID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if lc.DiskPath != "/dev/VG0/vdx-"+lc.ID[:8] || !rec.has("lvm-copy VG0/vdx-44440000-snap-1 vdx-"+lc.ID[:8]) {
		t.Fatalf("lvm clone %q calls %q", lc.DiskPath, rec.list())
	}
	if err := m.Purge("44440000-lvm"); err != nil {
		t.Fatal(err)
	}
	// Purge removes the snapshot LV and the disk LV, never the clone's LV.
	if !rec.has("lvm-remove VG0/vdx-44440000-snap-1") || !rec.has("lvm-remove-dev /dev/VG0/vdx-44440000") || rec.has("lvm-remove VG0/vdx-"+lc.ID[:8]) {
		t.Fatalf("purge calls %q", rec.list())
	}
}

func TestCloneFailureCleansUp(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	mkVM(t, m, org, "55550000-rbd", "rbd", "rbd:vms/vdx-55550000", false, false)
	s1 := record(t, m, "55550000-rbd", SnapResult{Tag: "snap-1", Backend: "rbd", Ref: "vms/vdx-55550000@snap-1"}, SnapMeta{})
	// Clone succeeds on the host but the DB insert fails (unknown owner FK).
	if _, err := m.CloneFromSnapshot(CloneOpts{OriginID: "55550000-rbd", SnapID: s1, OwnerID: 999}); err == nil {
		t.Fatal("expected the insert to fail")
	}
	if !rec.has("rbd-rm vms/vdx-") {
		t.Fatalf("host clone not removed after failure: %q", rec.list())
	}
	var n int
	_ = m.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 1 {
		t.Fatalf("sessions rows %d", n)
	}
}

func TestTransientBaseReleasedWhenCloneIsPurged(t *testing.T) {
	m, org := snapTestManager(t)
	rec := fakeSnapOps(t)
	oid, ods := "66660000-origin", "tank/vdx-66660000"
	mkVM(t, m, org, oid, "zvol", "/dev/zvol/"+ods, false, false)
	base := record(t, m, oid, SnapResult{Tag: "snap-b", Backend: "zvol", Ref: ods + "@snap-b"}, SnapMeta{Transient: true})
	c, err := m.CloneFromSnapshot(CloneOpts{OriginID: oid, SnapID: base, OwnerID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Purge(c.ID); err != nil {
		t.Fatal(err)
	}
	if !rec.has("zfs-destroy tank/vdx-"+c.ID[:8]) || !rec.has("zfs-destroy-snap "+ods+"@snap-b") {
		t.Fatalf("calls %q", rec.list())
	}
	if _, ok := m.snapshotByID(base); ok {
		t.Fatal("transient clone base still recorded")
	}
	if _, err := m.Get(oid); err != nil {
		t.Fatal("origin must survive its clone's purge")
	}
}
