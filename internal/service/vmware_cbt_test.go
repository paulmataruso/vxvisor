package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"vdxclone/internal/auth"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/storage"
	"vdxclone/internal/store"
	"vdxclone/internal/vmware"
)

// ---- a fake vSphere VM with CBT ----------------------------------------------
//
// vcsim has no QueryChangedDiskAreas, so the orchestration is tested against
// this model of one VM: disks with content, a snapshot tree that freezes the
// content, and CBT as generations — a change id names the generation at a
// snapshot, and a query returns the 4 KiB blocks written after it. Turning CBT
// off invalidates every change id (a new epoch), like the real thing.

const fakeBlock = 4096

type fakeSnap struct {
	moref, name string
	frozen      map[int32][]byte
	gen, epoch  int
	active      bool // CBT was active at the snapshot (it has change ids)
}

type fakeWrite struct {
	key        int32
	off, n     int64
	gen, epoch int
}

type fakeVC struct {
	mu         sync.Mutex
	moid, name string
	power      string
	tools      bool
	cbt        bool // config.changeTrackingEnabled
	active     bool // CBT live (after a stun cycle)
	epoch, gen int
	keys       []int32
	data       map[int32][]byte
	snaps      []*fakeSnap
	writes     []fakeWrite
	seq        int
	calls      []string // every source-mutating call, in order
	queryErr   error
	onShutdown func() // runs inside ShutdownGuestOS (e.g. the guest's last writes)
	opened     []string
}

func newFakeVC(sizes ...int64) *fakeVC {
	f := &fakeVC{moid: "vm-42", name: "app01", power: "poweredOn", tools: true, data: map[int32][]byte{}}
	for i, sz := range sizes {
		k := int32(2000 + i)
		f.keys = append(f.keys, k)
		f.data[k] = make([]byte, sz)
	}
	return f
}

func (f *fakeVC) consent(c vmware.CBTConsent) error {
	if c.MOID() != f.moid {
		return fmt.Errorf("consent for %q does not cover %s", c.MOID(), f.moid)
	}
	return nil
}

// write is a guest write to the running VM.
func (f *fakeVC) write(key int32, off int64, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeLocked(key, off, b)
}

func (f *fakeVC) writeLocked(key int32, off int64, b []byte) {
	f.gen++
	copy(f.data[key][off:], b)
	if f.active {
		f.writes = append(f.writes, fakeWrite{key, off, int64(len(b)), f.gen, f.epoch})
	}
}

func (f *fakeVC) snapshot(moref, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps = append(f.snaps, &fakeSnap{moref: moref, name: name, frozen: map[int32][]byte{}})
}

func (f *fakeVC) snapNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, s := range f.snaps {
		out = append(out, s.name)
	}
	sort.Strings(out)
	return out
}

func (f *fakeVC) current(key int32) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.data[key]...)
}

func (f *fakeVC) findSnap(moref string) *fakeSnap {
	for _, s := range f.snaps {
		if s.moref == moref {
			return s
		}
	}
	return nil
}

func (f *fakeVC) CBTState(ctx context.Context, moid string) (vmware.CBTVMState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if moid != f.moid {
		return vmware.CBTVMState{}, fmt.Errorf("no VM %s", moid)
	}
	st := vmware.CBTVMState{Name: f.name, PowerState: f.power, CBTEnabled: f.cbt, ToolsOK: f.tools && f.power == "poweredOn"}
	for _, s := range f.snaps {
		st.Snapshots = append(st.Snapshots, vmware.SnapshotInfo{MOREF: s.moref, Name: s.name})
	}
	return st, nil
}

func (f *fakeVC) SetChangeTracking(ctx context.Context, c vmware.CBTConsent, on bool) error {
	if err := f.consent(c); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("cbt=%v", on))
	f.cbt = on
	if !on {
		f.active = false
		f.epoch++
	}
	return nil
}

func (f *fakeVC) CreateCBTSnapshot(ctx context.Context, c vmware.CBTConsent, name, desc string) (string, error) {
	if err := f.consent(c); err != nil {
		return "", err
	}
	if !strings.HasPrefix(name, vmware.SnapshotPrefix) {
		return "", fmt.Errorf("bad name %q", name)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	if f.cbt {
		f.active = true // the snapshot is the stun cycle that activates CBT
	}
	s := &fakeSnap{moref: fmt.Sprintf("snapshot-%d", f.seq), name: name, frozen: map[int32][]byte{}, gen: f.gen, epoch: f.epoch, active: f.active}
	for k, d := range f.data {
		s.frozen[k] = append([]byte(nil), d...)
	}
	f.snaps = append(f.snaps, s)
	f.calls = append(f.calls, "create "+name)
	return s.moref, nil
}

func (f *fakeVC) RemoveCBTSnapshot(ctx context.Context, c vmware.CBTConsent, moref, name string) (bool, error) {
	if err := f.consent(c); err != nil {
		return false, err
	}
	if !strings.HasPrefix(name, vmware.SnapshotPrefix) {
		return false, vmware.ErrNotOurSnapshot
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.snaps {
		if s.moref != moref {
			continue
		}
		if s.name != name {
			return false, fmt.Errorf("%w: named %q", vmware.ErrNotOurSnapshot, s.name)
		}
		f.snaps = append(f.snaps[:i], f.snaps[i+1:]...)
		f.calls = append(f.calls, "remove "+name)
		return true, nil
	}
	return false, nil
}

func (f *fakeVC) ShutdownGuestOS(ctx context.Context, c vmware.CBTConsent) error {
	if err := f.consent(c); err != nil {
		return err
	}
	if f.onShutdown != nil {
		f.onShutdown()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.power != "poweredOn" {
		return fmt.Errorf("not powered on")
	}
	f.calls = append(f.calls, "shutdown")
	f.power = "poweredOff"
	return nil
}

func (f *fakeVC) SnapshotDisks(ctx context.Context, moid, moref string) ([]vmware.CBTDisk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.findSnap(moref)
	if s == nil || moid != f.moid {
		return nil, fmt.Errorf("no snapshot %s", moref)
	}
	var out []vmware.CBTDisk
	for i, k := range f.keys {
		d := vmware.CBTDisk{Key: k, Label: fmt.Sprintf("Hard disk %d", i+1), FileName: fmt.Sprintf("[ds1] app01/app01_%d.vmdk", i), Capacity: int64(len(s.frozen[k]))}
		if s.active {
			d.ChangeID = fmt.Sprintf("e%d-g%d", s.epoch, s.gen)
		}
		out = append(out, d)
	}
	return out, nil
}

func (f *fakeVC) QueryChangedAreas(ctx context.Context, moid, moref string, key int32, capacity int64, changeID string) ([]vmware.ChangedArea, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	s := f.findSnap(moref)
	if s == nil {
		return nil, fmt.Errorf("no snapshot %s", moref)
	}
	data := s.frozen[key]
	dirty := make([]bool, (len(data)+fakeBlock-1)/fakeBlock)
	if changeID == "*" {
		for b := range dirty {
			end := min((b+1)*fakeBlock, len(data))
			dirty[b] = !bytes.Equal(data[b*fakeBlock:end], make([]byte, end-b*fakeBlock))
		}
	} else {
		var e, g int
		if _, err := fmt.Sscanf(changeID, "e%d-g%d", &e, &g); err != nil || e != s.epoch || !s.active {
			return nil, fmt.Errorf("FileFault: invalid change id %q", changeID)
		}
		for _, w := range f.writes {
			if w.key == key && w.epoch == e && w.gen > g && w.gen <= s.gen {
				for b := w.off / fakeBlock; b*fakeBlock < w.off+w.n; b++ {
					dirty[b] = true
				}
			}
		}
	}
	var out []vmware.ChangedArea
	for b := 0; b < len(dirty); b++ {
		if !dirty[b] {
			continue
		}
		start := b
		for b < len(dirty) && dirty[b] {
			b++
		}
		out = append(out, vmware.ChangedArea{Start: int64(start * fakeBlock), Length: int64(min(b*fakeBlock, len(data)) - start*fakeBlock)})
	}
	return out, nil
}

func (f *fakeVC) GetVM(ctx context.Context, moid string) (vmware.VMInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if moid != f.moid {
		return vmware.VMInfo{}, fmt.Errorf("no VM %s", moid)
	}
	vm := vmware.VMInfo{MOID: f.moid, Name: f.name, PowerState: f.power, Firmware: "bios", NumCPU: 2, MemMB: 2048, Importable: true}
	for _, k := range f.keys {
		vm.Disks = append(vm.Disks, vmware.DiskInfo{CapacityGB: int64(len(f.data[k])) >> 30})
	}
	return vm, nil
}

func (f *fakeVC) Close(context.Context) {}

// open serves a disk as the snapshot froze it — refusing a removed snapshot,
// like VDDK would.
func (f *fakeVC) open(ctx context.Context, src cbtSource, r *cbtImport, pass string, d vmware.CBTDisk, snap string) (*cbtDisk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.findSnap(snap)
	if s == nil {
		return nil, fmt.Errorf("snapshot %s is gone", snap)
	}
	if pass != "s3cret" {
		return nil, fmt.Errorf("VDDK got the wrong password")
	}
	f.opened = append(f.opened, snap)
	rd := bytes.NewReader(s.frozen[d.Key])
	return &cbtDisk{readers: []io.ReaderAt{rd, rd, rd}, close: func() {}}, nil
}

// ---- harness -------------------------------------------------------------------

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type finishRec struct {
	calls   int
	matched bool // staging matched the source at the moment of the call
	err     error
}

var cbtAdmin = &Principal{User: &auth.User{ID: 1, Username: "root"}, IsAdmin: true, OrgID: 1, OrgRole: "owner"}

func cbtTestService(t *testing.T, f *fakeVC) (*Service, *finishRec, *testClock) {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := &config.Config{}
	cfg.Paths.DataDir = dir
	cfg.Paths.ImageDir = filepath.Join(dir, "images")
	s := &Service{cfg: cfg, db: d, store: store.New(d), stg: storage.New(cfg, d), vmwimp: newVmwImportTracker()}
	fin := &finishRec{}
	clk := &testClock{t: time.Now()}
	s.cbt = &cbtRuntime{
		dial:  func(context.Context, vmware.Creds) (cbtSource, error) { return f, nil },
		open:  f.open,
		ready: func(*Principal) bool { return true },
		now:   clk.Now,
		finish: func(id string, lg *importLogger, vm vmware.VMInfo, disks []string, r *cbtImport, p *Principal, ip string) (string, string, error) {
			fin.calls++
			if fin.err != nil {
				return "", "", fin.err
			}
			fin.matched = len(disks) == len(f.keys)
			for i, k := range f.keys {
				b, err := os.ReadFile(disks[i])
				fin.matched = fin.matched && err == nil && bytes.Equal(b, f.current(k))
			}
			return "vmware-app01", "sess-1", nil
		},
		pollEvery: time.Millisecond,
	}
	t.Cleanup(s.cbtWait)
	return s, fin, clk
}

func startCBT(t *testing.T, s *Service, f *fakeVC) string {
	t.Helper()
	id, err := s.VMwareImportCBT(cbtAdmin, vmware.Creds{URL: "vc.example", User: "svc", Pass: "s3cret"}, f.moid, "linux", 0, 30, "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	return id
}

func mustLoad(t *testing.T, s *Service, id string) *cbtImport {
	t.Helper()
	r, err := s.cbtLoad(id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// stagingMatches reports whether every staging file equals the source's disk.
func stagingMatches(t *testing.T, s *Service, id string, f *fakeVC) bool {
	t.Helper()
	disks, _ := s.cbtDisks(id)
	if len(disks) != len(f.keys) {
		return false
	}
	for i, d := range disks {
		b, err := os.ReadFile(d.Staging)
		if err != nil || !bytes.Equal(b, f.current(f.keys[i])) {
			return false
		}
	}
	return true
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i%251)
	}
	return b
}

func (f *fakeVC) callsWith(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// ---- tests ------------------------------------------------------------------------

// TestCBTWarmImportLifecycle: base copy while running, delta passes (on demand
// and on schedule), cut-over with a guest shutdown — the instance is made from
// staging that matches the source exactly, every snapshot WE took is gone, the
// operator's own snapshot is untouched, CBT is back off, staging is deleted and
// the stored password is wiped.
func TestCBTWarmImportLifecycle(t *testing.T) {
	f := newFakeVC(1<<20, 512<<10)
	f.write(2000, 0, pattern(64<<10, 1))
	f.write(2001, 100<<10, pattern(8<<10, 2))
	s, fin, _ := cbtTestService(t, f)

	id := startCBT(t, s, f)
	r := mustLoad(t, s, id)
	if r.State != cbtSyncing || r.Passes != 1 || r.CBTOrig != 0 || !r.CBTByUs || r.VMName != "app01" {
		t.Fatalf("after base copy: %+v", r)
	}
	if !stagingMatches(t, s, id, f) {
		t.Fatal("staging must equal the source after the base copy")
	}
	if n := len(f.snapNames()); n != 0 {
		t.Fatalf("the base-copy snapshot must be removed, %d left", n)
	}
	if r.BaseBytes != 64<<10+8<<10 {
		t.Fatalf("base copy moved %d bytes, want only the allocated %d", r.BaseBytes, 64<<10+8<<10)
	}

	// The guest keeps writing; the operator takes their own snapshot.
	f.write(2000, 300<<10, pattern(5000, 3))
	f.write(2001, 0, make([]byte, 4096)) // zeroing must reach staging too
	f.write(2000, 0, pattern(4096, 9))
	f.snapshot("snapshot-user", "nightly-backup")
	if err := s.CBTSyncNow(cbtAdmin, id, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	if r = mustLoad(t, s, id); r.Passes != 2 || r.LastErr != "" || !stagingMatches(t, s, id, f) {
		t.Fatalf("after Sync now: passes=%d err=%q match=%v", r.Passes, r.LastErr, stagingMatches(t, s, id, f))
	}
	if h := s.cbtHistory(id, 8); len(h) != 2 || h[0].Kind != "delta" || h[0].Bytes != 8192+4096+4096 {
		t.Fatalf("history %+v: the delta must carry only the changed blocks", h)
	}

	// A scheduled pass, driven by the tick.
	f.write(2001, 200<<10, pattern(12000, 4))
	s.cbtExec(`UPDATE vmware_cbt_imports SET next_run_at=0 WHERE id=?`, id)
	s.CBTTick()
	s.cbtWait()
	if r = mustLoad(t, s, id); r.Passes != 3 || !stagingMatches(t, s, id, f) {
		t.Fatalf("after a scheduled pass: passes=%d", r.Passes)
	}

	// Cut over: writes before and during the shutdown must all land.
	f.write(2000, 700<<10, pattern(3000, 5))
	f.onShutdown = func() { f.write(2001, 400<<10, pattern(4096, 6)) }
	if err := s.CBTCutover(cbtAdmin, id, true, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r = mustLoad(t, s, id)
	if r.State != cbtDone || fin.calls != 1 || !fin.matched {
		t.Fatalf("cut-over: state=%s step=%q err=%q finish calls=%d staging matched=%v", r.State, r.Step, r.LastErr, fin.calls, fin.matched)
	}
	if r.ResultImage != "vmware-app01" || r.ResultSession != "sess-1" || r.PassEnc != "" || r.FinishedAt == "" {
		t.Fatalf("done row: image=%q session=%q pass wiped=%v", r.ResultImage, r.ResultSession, r.PassEnc == "")
	}
	if got := f.snapNames(); len(got) != 1 || got[0] != "nightly-backup" {
		t.Fatalf("only the operator's snapshot may remain, got %v", got)
	}
	if f.cbt || f.callsWith("cbt=true") != 1 || f.callsWith("cbt=false") != 1 || f.callsWith("shutdown") != 1 {
		t.Fatalf("CBT must be back off (on once, off once) and one guest shutdown: cbt=%v calls=%v", f.cbt, f.calls)
	}
	if f.callsWith("create ") != f.callsWith("remove ") {
		t.Fatalf("every snapshot we created must be removed: %v", f.calls)
	}
	disks, _ := s.cbtDisks(id)
	for _, d := range disks {
		if _, err := os.Stat(d.Staging); !os.IsNotExist(err) {
			t.Fatalf("staging %s must be deleted", d.Staging)
		}
	}
	if pend, _ := s.cbtPendingSnaps(id); len(pend) != 0 {
		t.Fatalf("pending snapshot records after done: %+v", pend)
	}
	var audits int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'vmware.cbt%'`).Scan(&audits)
	if audits < 10 {
		t.Fatalf("expected the source mutations to be audited, got %d rows", audits)
	}
}

// TestCBTLeavesCBTOnWhenItWasOn: we only ever switch CBT back off if WE turned
// it on.
func TestCBTLeavesCBTOnWhenItWasOn(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.cbt, f.active = true, true
	f.write(2000, 0, pattern(8192, 1))
	s, _, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	f.power = "poweredOff"
	if err := s.CBTCutover(cbtAdmin, id, false, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r := mustLoad(t, s, id)
	if r.State != cbtDone || r.CBTOrig != 1 || r.CBTByUs {
		t.Fatalf("state=%s cbt_orig=%d by_us=%v", r.State, r.CBTOrig, r.CBTByUs)
	}
	if !f.cbt || f.callsWith("cbt=") != 0 {
		t.Fatalf("CBT was already on: it must stay on and never be reconfigured: %v", f.calls)
	}
}

// TestCBTCancel: cancel removes our snapshots, restores CBT, deletes staging.
func TestCBTCancel(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.write(2000, 0, pattern(8192, 1))
	s, fin, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	disks, _ := s.cbtDisks(id)
	if err := s.CBTCancel(cbtAdmin, id, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r := mustLoad(t, s, id)
	if r.State != cbtCancelled || r.PassEnc != "" || fin.calls != 0 {
		t.Fatalf("cancel: state=%s pass wiped=%v finish=%d", r.State, r.PassEnc == "", fin.calls)
	}
	if f.cbt || len(f.snapNames()) != 0 {
		t.Fatalf("cancel must restore CBT and leave no snapshot: cbt=%v snaps=%v", f.cbt, f.snapNames())
	}
	if _, err := os.Stat(disks[0].Staging); !os.IsNotExist(err) {
		t.Fatal("cancel must delete staging")
	}
	if err := s.CBTCancel(cbtAdmin, id, "ip"); err == nil {
		t.Fatal("a cancelled import can't be cancelled again")
	}
	if err := s.CBTSyncNow(cbtAdmin, id, "ip"); err == nil {
		t.Fatal("a cancelled import can't sync")
	}
	// The VM is free for a new warm import now.
	if _, err := s.VMwareImportCBT(cbtAdmin, vmware.Creds{URL: "vc.example", User: "svc", Pass: "s3cret"}, f.moid, "linux", 0, 0, "ip"); err != nil {
		t.Fatalf("a new import after cancel: %v", err)
	}
	s.cbtWait()
}

// TestCBTRecoveryRemovesOnlyRecordedSnapshots models a vdxd crash mid cut-over
// with leftovers on the source: a recorded snapshot (moref known), one whose
// create was interrupted (name only, old), one whose create may still be
// running (name only, recent, not on the VM yet) — plus the operator's own
// snapshot and an UNRECORDED one that merely uses our prefix. Recovery removes
// exactly the two recorded ones it can resolve, keeps waiting on the recent one,
// and never touches the other two.
func TestCBTRecoveryRemovesOnlyRecordedSnapshots(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.write(2000, 0, pattern(8192, 1))
	s, _, clk := cbtTestService(t, f)
	id := startCBT(t, s, f)

	now := clk.Now().Unix()
	rec := func(name, moref string, created int64) {
		if _, err := s.db.Exec(`INSERT INTO vmware_cbt_snapshots(import_id,moid,name,moref,created_at) VALUES(?,?,?,?,?)`, id, f.moid, name, moref, created); err != nil {
			t.Fatal(err)
		}
	}
	f.snapshot("snapshot-90", "vxvisor-cbt-crash-1")
	rec("vxvisor-cbt-crash-1", "snapshot-90", now-60)
	f.snapshot("snapshot-91", "vxvisor-cbt-crash-2")
	rec("vxvisor-cbt-crash-2", "", now-3600)
	rec("vxvisor-cbt-crash-3", "", now-10)
	f.snapshot("snapshot-92", "vxvisor-cbt-not-ours")
	f.snapshot("snapshot-93", "nightly-backup")
	s.cbtExec(`UPDATE vmware_cbt_imports SET state=? WHERE id=?`, cbtCutover, id) // crashed mid cut-over

	s.CBTTick() // boot: the orphaned cut-over drops back to syncing
	s.cbtWait()
	if r := mustLoad(t, s, id); r.State != cbtSyncing || !strings.Contains(r.Step, "interrupted") {
		t.Fatalf("interrupted cut-over: state=%s step=%q", r.State, r.Step)
	}
	s.CBTTick() // the due pass first removes the leftovers
	s.cbtWait()
	if got := f.snapNames(); strings.Join(got, ",") != "nightly-backup,vxvisor-cbt-not-ours" {
		t.Fatalf("snapshots left on the source: %v", got)
	}
	pend, _ := s.cbtPendingSnaps(id)
	if len(pend) != 1 || pend[0].Name != "vxvisor-cbt-crash-3" {
		t.Fatalf("pending records: %+v (the recent unresolved one must stay pending)", pend)
	}
	if r := mustLoad(t, s, id); r.Passes != 2 {
		t.Fatalf("the pass must still run after removing leftovers: passes=%d err=%q", r.Passes, r.LastErr)
	}

	// Cancel: cleanup waits for the recent record, then concludes it was never
	// created once the grace period is over.
	if err := s.CBTCancel(cbtAdmin, id, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	if r := mustLoad(t, s, id); r.State != cbtCleanup {
		t.Fatalf("cleanup must wait for the unresolved record, state=%s", r.State)
	}
	clk.Add(cbtOrphanGrace + time.Minute)
	s.CBTTick()
	s.cbtWait()
	if r := mustLoad(t, s, id); r.State != cbtCancelled {
		t.Fatalf("after the grace period: state=%s step=%q", r.State, r.Step)
	}
	if got := f.snapNames(); strings.Join(got, ",") != "nightly-backup,vxvisor-cbt-not-ours" {
		t.Fatalf("cleanup touched snapshots that aren't ours: %v", got)
	}
}

// TestCBTInterruptedBaseCopyRestarts: a base copy a restart killed starts over
// (fresh staging, leftover snapshot removed).
func TestCBTInterruptedBaseCopyRestarts(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.write(2000, 0, pattern(8192, 1))
	s, _, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	// Pretend we died mid base copy: state back, a recorded snapshot left, staging junk.
	s.cbtExec(`UPDATE vmware_cbt_imports SET state=?, passes=0, next_run_at=0 WHERE id=?`, cbtBaseCopy, id)
	f.snapshot("snapshot-77", "vxvisor-cbt-base-1")
	s.db.Exec(`INSERT INTO vmware_cbt_snapshots(import_id,moid,name,moref,created_at) VALUES(?,?,?,?,?)`, id, f.moid, "vxvisor-cbt-base-1", "snapshot-77", 1)
	disks, _ := s.cbtDisks(id)
	os.WriteFile(disks[0].Staging, pattern(256<<10, 7), 0o640)
	f.write(2000, 128<<10, pattern(4096, 8))

	s.CBTTick()
	s.cbtWait()
	r := mustLoad(t, s, id)
	if r.State != cbtSyncing || r.Passes != 1 || !stagingMatches(t, s, id, f) || len(f.snapNames()) != 0 {
		t.Fatalf("restarted base copy: state=%s passes=%d match=%v snaps=%v", r.State, r.Passes, stagingMatches(t, s, id, f), f.snapNames())
	}
}

// TestCBTLayoutChangeEndsInError: a resized source disk can't be synced — the
// import ends in error, fully cleaned up.
func TestCBTLayoutChangeEndsInError(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.write(2000, 0, pattern(8192, 1))
	s, _, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	f.mu.Lock()
	f.data[2000] = append(f.data[2000], make([]byte, 64<<10)...)
	f.mu.Unlock()
	if err := s.CBTSyncNow(cbtAdmin, id, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r := mustLoad(t, s, id)
	if r.State != cbtError || !strings.Contains(r.LastErr, "changed") || f.cbt || len(f.snapNames()) != 0 {
		t.Fatalf("state=%s err=%q cbt=%v snaps=%v", r.State, r.LastErr, f.cbt, f.snapNames())
	}
}

// TestCBTRetriesThenGivesUp: transient failures are retried; the fifth in a
// row ends the import (cleaned up).
func TestCBTRetriesThenGivesUp(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.write(2000, 0, pattern(8192, 1))
	s, _, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	f.queryErr = errors.New("vCenter hiccup")
	for i := 1; i <= cbtMaxFailures; i++ {
		s.cbtExec(`UPDATE vmware_cbt_imports SET next_run_at=0 WHERE id=?`, id)
		s.CBTTick()
		s.cbtWait()
		r := mustLoad(t, s, id)
		if i < cbtMaxFailures && (r.State != cbtSyncing || r.Fails != i || r.NextRun == 0) {
			t.Fatalf("failure %d: state=%s fails=%d", i, r.State, r.Fails)
		}
		if len(f.snapNames()) != 0 {
			t.Fatalf("a failed pass must still remove its snapshot: %v", f.snapNames())
		}
	}
	if r := mustLoad(t, s, id); r.State != cbtError {
		t.Fatalf("after %d failures: state=%s", cbtMaxFailures, r.State)
	}
}

// TestCBTCutoverFailureKeepsSyncing: a failed conversion goes back to syncing
// with staging intact, so the operator can fix it and cut over again.
func TestCBTCutoverFailureKeepsSyncing(t *testing.T) {
	f := newFakeVC(256 << 10)
	f.write(2000, 0, pattern(8192, 1))
	s, fin, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	fin.err = errors.New("convert: no space left on device")
	f.power = "poweredOff"
	if err := s.CBTCutover(cbtAdmin, id, false, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r := mustLoad(t, s, id)
	if r.State != cbtSyncing || !strings.Contains(r.LastErr, "no space") || !stagingMatches(t, s, id, f) || len(f.snapNames()) != 0 {
		t.Fatalf("state=%s err=%q", r.State, r.LastErr)
	}
	fin.err = nil
	if err := s.CBTCutover(cbtAdmin, id, false, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	if r = mustLoad(t, s, id); r.State != cbtDone || !fin.matched {
		t.Fatalf("second cut-over: state=%s", r.State)
	}
}

// TestCBTCBTSwitchedOffMidSync: someone turning CBT off on the source destroys
// the change history — the import ends in error rather than miss changes.
func TestCBTCBTSwitchedOffMidSync(t *testing.T) {
	f := newFakeVC(256 << 10)
	s, _, _ := cbtTestService(t, f)
	id := startCBT(t, s, f)
	f.mu.Lock()
	f.cbt, f.active = false, false
	f.epoch++
	f.mu.Unlock()
	if err := s.CBTSyncNow(cbtAdmin, id, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	if r := mustLoad(t, s, id); r.State != cbtError || !strings.Contains(r.LastErr, "switched off") {
		t.Fatalf("state=%s err=%q", r.State, r.LastErr)
	}
}

func TestCBTAdminOnly(t *testing.T) {
	f := newFakeVC(64 << 10)
	s, _, _ := cbtTestService(t, f)
	member := &Principal{User: &auth.User{ID: 2, Username: "m"}, OrgID: 1, OrgRole: "owner"}
	if _, err := s.VMwareImportCBT(member, vmware.Creds{}, f.moid, "linux", 0, 0, "ip"); err != ErrUnauthorized {
		t.Fatalf("start: %v", err)
	}
	if s.CBTSyncNow(member, "x", "ip") != ErrUnauthorized || s.CBTCutover(member, "x", true, "ip") != ErrUnauthorized || s.CBTCancel(member, "x", "ip") != ErrUnauthorized {
		t.Fatal("sync/cutover/cancel must be admin-only")
	}
	if s.CBTImportStates(member) != nil {
		t.Fatal("states must be admin-only")
	}
	s.cbt.ready = func(*Principal) bool { return false }
	if _, err := s.VMwareImportCBT(cbtAdmin, vmware.Creds{}, f.moid, "linux", 0, 0, "ip"); err == nil || !strings.Contains(err.Error(), "VDDK") {
		t.Fatalf("without VDDK: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused start must not touch the source: %v", f.calls)
	}
}

// TestCBTOneActiveImportPerVM: the partial unique index refuses a second
// active warm import of the same VM.
func TestCBTOneActiveImportPerVM(t *testing.T) {
	f := newFakeVC(64 << 10)
	s, _, _ := cbtTestService(t, f)
	startCBT(t, s, f)
	if _, err := s.VMwareImportCBT(cbtAdmin, vmware.Creds{URL: "vc.example", User: "svc", Pass: "s3cret"}, f.moid, "linux", 0, 0, "ip"); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("second import: %v", err)
	}
	if st := s.CBTImportStates(cbtAdmin); len(st) != 1 || !st[0].CanSync || !st[0].CanCutover || !st[0].CanCancel || st[0].CBTOrig != "off" {
		t.Fatalf("states: %+v", st)
	}
}
