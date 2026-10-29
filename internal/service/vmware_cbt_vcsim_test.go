package service

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/types"

	"vdxclone/internal/vmware"
)

// vcsimCBT is the real *vmware.Client against vcsim, with the two things vcsim
// lacks filled in: QueryChangedDiskAreas, and change ids on a snapshot's disks.
// Every source-mutating call (CBT on/off, snapshot create/remove, guest
// shutdown) is the real govmomi path in internal/vmware/cbt.go.
type vcsimCBT struct {
	*vmware.Client
}

const vcsimAllocated = 1 << 20 // the "*" query: the first MiB is allocated

func (v *vcsimCBT) SnapshotDisks(ctx context.Context, moid, snap string) ([]vmware.CBTDisk, error) {
	disks, err := v.Client.SnapshotDisks(ctx, moid, snap)
	for i := range disks {
		if disks[i].ChangeID == "" {
			disks[i].ChangeID = "vcsim-" + snap
		}
	}
	return disks, err
}

func (v *vcsimCBT) QueryChangedAreas(ctx context.Context, moid, snap string, key int32, capacity int64, changeID string) ([]vmware.ChangedArea, error) {
	if changeID == "*" {
		return []vmware.ChangedArea{{Start: 0, Length: vcsimAllocated}}, nil
	}
	return []vmware.ChangedArea{{Start: vcsimAllocated, Length: 64 << 10}}, nil
}

// patternDisk is a disk whose byte at offset o is a function of o.
type patternDisk struct{}

func (patternDisk) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		p[i] = byte((off+int64(i))%253) + 1
	}
	return len(p), nil
}

func freeBytes(dir string) int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0
	}
	return int64(st.Bavail) * st.Bsize
}

// TestCBTWarmImportAgainstVCSim runs the whole warm import through the real
// vSphere calls against vcsim: CBT goes on, our snapshots come and go, a
// snapshot the operator takes mid-sync survives, the guest is shut down via
// VMware Tools at cut-over, CBT goes back off — and no other VM is touched.
func TestCBTWarmImportAgainstVCSim(t *testing.T) {
	model := simulator.VPX()
	defer model.Remove()
	if err := model.Create(); err != nil {
		t.Fatal(err)
	}
	srv := model.Service.NewServer()
	defer srv.Close()
	ctx := context.Background()

	u, _ := url.Parse(srv.URL.String())
	u.User = url.UserPassword("u", "p")
	gc, err := govmomi.NewClient(ctx, u, true)
	if err != nil {
		t.Fatal(err)
	}
	defer gc.Logout(ctx)
	probe, err := vmware.Connect(ctx, vmware.Creds{URL: srv.URL.String(), User: "u", Pass: "p", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close(ctx)
	vms, err := probe.ListVMs(ctx)
	if err != nil || len(vms) < 2 {
		t.Fatalf("vcsim VMs: %v", err)
	}
	target := vms[0]
	before := map[string]vmware.CBTVMState{}
	for _, v := range vms[1:] {
		before[v.MOID], _ = probe.CBTState(ctx, v.MOID)
	}

	f := newFakeVC() // only for the harness; the source below is vcsim
	s, fin, _ := cbtTestService(t, f)
	var need int64
	for _, d := range target.Disks {
		need += d.CapacityGB << 31
	}
	if freeBytes(s.cfg.Paths.DataDir) < need+(1<<30) {
		big, err := os.MkdirTemp("/var/tmp", "cbt-vcsim-")
		if err != nil || freeBytes(big) < need+(1<<30) {
			t.Skipf("needs ~%d GiB free for the (sparse) staging precheck", need>>30)
		}
		defer os.RemoveAll(big)
		s.cfg.Paths.ImageDir = big
	}

	var mu sync.Mutex
	var openedGone []string
	s.cbt.dial = func(ctx context.Context, c vmware.Creds) (cbtSource, error) {
		cli, err := vmware.Connect(ctx, c)
		if err != nil {
			return nil, err
		}
		return &vcsimCBT{Client: cli}, nil
	}
	s.cbt.open = func(ctx context.Context, src cbtSource, r *cbtImport, pass string, d vmware.CBTDisk, snap string) (*cbtDisk, error) {
		st, err := src.CBTState(ctx, r.MOID)
		if err != nil {
			return nil, err
		}
		live := false
		for _, sn := range st.Snapshots {
			live = live || sn.MOREF == snap
		}
		if !live || pass != "p" {
			mu.Lock()
			openedGone = append(openedGone, snap)
			mu.Unlock()
		}
		return &cbtDisk{readers: []io.ReaderAt{patternDisk{}, patternDisk{}}, close: func() {}}, nil
	}
	s.cbt.finish = func(id string, lg *importLogger, vm vmware.VMInfo, disks []string, r *cbtImport, p *Principal, ip string) (string, string, error) {
		fin.calls++
		want := make([]byte, vcsimAllocated+64<<10)
		patternDisk{}.ReadAt(want, 0)
		b := make([]byte, len(want)+1<<20) // the copied areas, then a MiB that must still be a hole
		sf, err := os.Open(disks[0])
		if err == nil {
			_, err = sf.ReadAt(b, 0)
			sf.Close()
		}
		fin.matched = err == nil && bytes.Equal(b[:len(want)], want) && bytes.Count(b[len(want):], []byte{0}) == 1<<20
		return "vmware-" + vm.Name, "sess-vcsim", nil
	}

	id, err := s.VMwareImportCBT(cbtAdmin, vmware.Creds{URL: srv.URL.String(), User: "u", Pass: "p", Insecure: true}, target.MOID, "linux", 0, 30, "ip")
	if err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r := mustLoad(t, s, id)
	if r.State != cbtSyncing {
		t.Fatalf("base copy against vcsim: state=%s err=%q", r.State, r.LastErr)
	}
	st, _ := probe.CBTState(ctx, target.MOID)
	if !st.CBTEnabled || len(st.Snapshots) != 0 {
		t.Fatalf("after base copy: CBT=%v snapshots=%v (CBT on, our snapshot removed)", st.CBTEnabled, st.Snapshots)
	}

	// The operator takes their own snapshot mid-sync.
	task, err := object.NewVirtualMachine(gc.Client, types.ManagedObjectReference{Type: "VirtualMachine", Value: target.MOID}).CreateSnapshot(ctx, "pre-patch", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	ti, err := task.WaitForResult(ctx)
	if err != nil {
		t.Fatal(err)
	}
	userSnap := ti.Result.(types.ManagedObjectReference).Value

	if err := s.CBTSyncNow(cbtAdmin, id, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	if r = mustLoad(t, s, id); r.Passes != 2 || r.LastErr != "" {
		t.Fatalf("delta against vcsim: passes=%d err=%q", r.Passes, r.LastErr)
	}

	// If vcsim's guest has no VMware Tools, the operator powers it off instead.
	vmObj := object.NewVirtualMachine(gc.Client, types.ManagedObjectReference{Type: "VirtualMachine", Value: target.MOID})
	go func() {
		time.Sleep(2 * time.Second)
		if ps, _ := vmObj.PowerState(ctx); ps == types.VirtualMachinePowerStatePoweredOn {
			if task, err := vmObj.PowerOff(ctx); err == nil {
				_ = task.Wait(ctx)
			}
		}
	}()
	if err := s.CBTCutover(cbtAdmin, id, true, "ip"); err != nil {
		t.Fatal(err)
	}
	s.cbtWait()
	r = mustLoad(t, s, id)
	if r.State != cbtDone || fin.calls != 1 || !fin.matched {
		t.Fatalf("cut-over against vcsim: state=%s err=%q step=%q finish=%d matched=%v", r.State, r.LastErr, r.Step, fin.calls, fin.matched)
	}
	st, _ = probe.CBTState(ctx, target.MOID)
	if st.CBTEnabled || st.PowerState != "poweredOff" || len(st.Snapshots) != 1 || st.Snapshots[0].MOREF != userSnap {
		t.Fatalf("source after cut-over: %+v (CBT back off, only the operator's snapshot left)", st)
	}
	if len(openedGone) != 0 {
		t.Fatalf("a disk was read at a snapshot that no longer existed (or with the wrong password): %v", openedGone)
	}
	for moid, b := range before {
		a, _ := probe.CBTState(ctx, moid)
		if a.CBTEnabled != b.CBTEnabled || a.PowerState != b.PowerState || len(a.Snapshots) != len(b.Snapshots) {
			t.Fatalf("VM %s was touched: before %+v after %+v", moid, b, a)
		}
	}
	var snaps, removed int
	s.db.QueryRow(`SELECT COUNT(*), SUM(removed_at>0) FROM vmware_cbt_snapshots WHERE import_id=?`, id).Scan(&snaps, &removed)
	if snaps < 4 || snaps != removed {
		t.Fatalf("snapshot records: %d created, %d removed", snaps, removed)
	}
}
