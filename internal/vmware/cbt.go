package vmware

// cbt.go is the ONE file in this package allowed to change a source VM. It backs
// the opt-in CBT warm migration: the operator ticks "Use CBT (warm migration)"
// for one VM, and that explicit consent lets VXVisor, on THAT VM only:
//
//   - turn Changed Block Tracking on (and back off at the end, if it was off);
//   - create short-lived snapshots named with SnapshotPrefix, and remove them;
//   - ask VMware Tools to shut the guest down at cut-over (only if asked to).
//
// Every mutating method takes a CBTConsent, refuses a zero one, and acts only on
// the VM the consent names (TestCBTMutationsAreConsentGated enforces that
// structurally). Nothing here reverts, commits or removes a snapshot it did not
// create: RemoveCBTSnapshot only removes a snapshot whose moref AND name match
// the record the caller made before creating it, and the name must carry our
// prefix. There is no hard power-off, no revert, no disk merge of other
// snapshots. Everything else in this package stays read-only (TestReadOnlyDiscipline).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vmware/govmomi/fault"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// SnapshotPrefix starts the name of every snapshot VXVisor creates. A snapshot
// without it is never ours, and is never removed.
const SnapshotPrefix = "vxvisor-cbt-"

// ErrNotOurSnapshot is returned when a removal is refused because the snapshot
// is not exactly the one we recorded (wrong prefix, or renamed since).
var ErrNotOurSnapshot = errors.New("refusing to remove a snapshot VXVisor did not create")

// IsNotFound reports whether err is vSphere saying the object (VM or snapshot)
// no longer exists.
func IsNotFound(err error) bool {
	return err != nil && fault.Is(err, &types.ManagedObjectNotFound{})
}

// KeepAlive keeps the vSphere session from idling out (vCenter drops idle
// sessions after ~30 min) during a long copy that makes no API calls, by
// reading the server clock every interval. Read-only. Call stop when done.
func (c *Client) KeepAlive(every time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
				_, _ = methods.GetCurrentTime(rctx, c.gc.Client)
				rcancel()
			}
		}
	}()
	return cancel
}

// taskTimeout bounds one vSphere task we start. Tasks run on a context that is
// NOT cancelled with the caller's: once a snapshot create/remove or a
// reconfigure is sent we always wait for its outcome, so a cancelled import
// can't leave a snapshot behind that we never learned the moref of.
const taskTimeout = 30 * time.Minute

// CBTConsent is the operator's explicit permission to change ONE source VM for
// a warm migration (enable CBT, create/remove our own snapshots, shut the guest
// down when asked). The zero value grants nothing.
type CBTConsent struct {
	moid     string
	importID string
}

// NewCBTConsent records consent for the VM moid, given for import importID. The
// caller must only build one from an import the operator started with the CBT
// box ticked.
func NewCBTConsent(moid, importID string) (CBTConsent, error) {
	moid, importID = strings.TrimSpace(moid), strings.TrimSpace(importID)
	if moid == "" || importID == "" {
		return CBTConsent{}, fmt.Errorf("CBT consent needs a VM and an import id")
	}
	return CBTConsent{moid: moid, importID: importID}, nil
}

// MOID is the one VM this consent covers.
func (c CBTConsent) MOID() string { return c.moid }

// check refuses a zero consent. A mutating method acts ONLY on c.moid — it has
// no other VM parameter — so consent for one VM can never reach another.
func (c CBTConsent) check() error {
	if c.moid == "" || c.importID == "" {
		return fmt.Errorf("refusing to change a source VM: no CBT consent")
	}
	return nil
}

// CBTVMState is what a warm migration reads about its source before acting.
type CBTVMState struct {
	Name        string
	PowerState  string // poweredOn | poweredOff | suspended
	CBTEnabled  bool   // config.changeTrackingEnabled
	Independent bool   // a disk in an independent mode (snapshots skip it)
	ToolsOK     bool   // VMware Tools running (needed to shut the guest down)
	Snapshots   []SnapshotInfo
}

// SnapshotInfo is one node of a VM's snapshot tree.
type SnapshotInfo struct {
	MOREF string
	Name  string
}

// CBTDisk is one virtual disk as a snapshot froze it.
type CBTDisk struct {
	Key      int32
	Label    string
	FileName string // "[ds] dir/disk.vmdk" — the frozen file VDDK opens with snapshot=
	Capacity int64  // bytes
	ChangeID string // CBT change id of this disk at the snapshot ("" = CBT not active)
}

// ChangedArea is one changed (or, for change id "*", allocated) byte range.
type ChangedArea struct {
	Start, Length int64
}

func vmRef(moid string) types.ManagedObjectReference {
	return types.ManagedObjectReference{Type: "VirtualMachine", Value: moid}
}

func taskCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), taskTimeout)
}

// CBTState reads the source's power, CBT and snapshot state. Read-only.
func (c *Client) CBTState(ctx context.Context, moid string) (CBTVMState, error) {
	var vm mo.VirtualMachine
	pc := property.DefaultCollector(c.gc.Client)
	props := []string{"name", "runtime.powerState", "config.changeTrackingEnabled", "config.hardware", "guest.toolsRunningStatus", "snapshot"}
	if err := pc.RetrieveOne(ctx, vmRef(moid), props, &vm); err != nil {
		return CBTVMState{}, fmt.Errorf("read source VM %s: %w", moid, err)
	}
	st := CBTVMState{Name: vm.Name, PowerState: string(vm.Runtime.PowerState)}
	if vm.Config != nil {
		st.CBTEnabled = vm.Config.ChangeTrackingEnabled != nil && *vm.Config.ChangeTrackingEnabled
		for _, d := range vm.Config.Hardware.Device {
			if vd, ok := d.(*types.VirtualDisk); ok {
				if b, ok := vd.Backing.(*types.VirtualDiskFlatVer2BackingInfo); ok && strings.HasPrefix(b.DiskMode, "independent") {
					st.Independent = true
				}
			}
		}
	}
	if vm.Guest != nil {
		st.ToolsOK = vm.Guest.ToolsRunningStatus == string(types.VirtualMachineToolsRunningStatusGuestToolsRunning)
	}
	if vm.Snapshot != nil {
		var walk func([]types.VirtualMachineSnapshotTree)
		walk = func(l []types.VirtualMachineSnapshotTree) {
			for _, t := range l {
				st.Snapshots = append(st.Snapshots, SnapshotInfo{MOREF: t.Snapshot.Value, Name: t.Name})
				walk(t.ChildSnapshotList)
			}
		}
		walk(vm.Snapshot.RootSnapshotList)
	}
	return st, nil
}

// SetChangeTracking turns CBT on or off on the consented VM (one ReconfigVM
// that changes nothing but changeTrackingEnabled). CBT becomes active at the
// VM's next stun cycle — the first snapshot we take.
func (c *Client) SetChangeTracking(ctx context.Context, consent CBTConsent, enabled bool) error {
	if err := consent.check(); err != nil {
		return err
	}
	tctx, cancel := taskCtx(ctx)
	defer cancel()
	vm := object.NewVirtualMachine(c.gc.Client, vmRef(consent.moid))
	task, err := vm.Reconfigure(tctx, types.VirtualMachineConfigSpec{ChangeTrackingEnabled: types.NewBool(enabled)})
	if err != nil {
		return fmt.Errorf("set changeTrackingEnabled=%v on %s: %w", enabled, consent.moid, err)
	}
	if err := task.Wait(tctx); err != nil {
		return fmt.Errorf("set changeTrackingEnabled=%v on %s: %w", enabled, consent.moid, err)
	}
	return nil
}

// CreateCBTSnapshot creates one crash-consistent snapshot (no memory, no
// quiesce) of the consented VM and returns its moref. The name must start with
// SnapshotPrefix and must already be recorded by the caller, so a crash before
// the moref comes back can still find and remove it by name.
func (c *Client) CreateCBTSnapshot(ctx context.Context, consent CBTConsent, name, description string) (string, error) {
	if err := consent.check(); err != nil {
		return "", err
	}
	if !strings.HasPrefix(name, SnapshotPrefix) || len(name) <= len(SnapshotPrefix) {
		return "", fmt.Errorf("refusing snapshot name %q: VXVisor snapshots must start with %q", name, SnapshotPrefix)
	}
	tctx, cancel := taskCtx(ctx)
	defer cancel()
	vm := object.NewVirtualMachine(c.gc.Client, vmRef(consent.moid))
	task, err := vm.CreateSnapshot(tctx, name, description, false, false)
	if err != nil {
		return "", fmt.Errorf("create snapshot %s on %s: %w", name, consent.moid, err)
	}
	info, err := task.WaitForResult(tctx)
	if err != nil {
		return "", fmt.Errorf("create snapshot %s on %s: %w", name, consent.moid, err)
	}
	ref, ok := info.Result.(types.ManagedObjectReference)
	if !ok || ref.Value == "" {
		return "", fmt.Errorf("create snapshot %s on %s: no snapshot reference in the task result", name, consent.moid)
	}
	return ref.Value, nil
}

// RemoveCBTSnapshot removes ONE snapshot VXVisor created: the snapshot must be
// in the consented VM's tree under exactly the recorded moref AND name, and the
// name must carry SnapshotPrefix — otherwise it is refused. Children are kept
// (removeChildren=false), so a snapshot someone took after ours survives. A
// moref no longer in the tree is reported gone (removed=false, err=nil).
func (c *Client) RemoveCBTSnapshot(ctx context.Context, consent CBTConsent, moref, name string) (removed bool, err error) {
	if err := consent.check(); err != nil {
		return false, err
	}
	if !strings.HasPrefix(name, SnapshotPrefix) {
		return false, fmt.Errorf("%w: %q has no %q prefix", ErrNotOurSnapshot, name, SnapshotPrefix)
	}
	st, err := c.CBTState(ctx, consent.moid)
	if err != nil {
		return false, err
	}
	found := false
	for _, s := range st.Snapshots {
		if s.MOREF != moref {
			continue
		}
		if s.Name != name {
			return false, fmt.Errorf("%w: %s is named %q, not our %q", ErrNotOurSnapshot, moref, s.Name, name)
		}
		found = true
	}
	if !found {
		return false, nil
	}
	tctx, cancel := taskCtx(ctx)
	defer cancel()
	res, err := methods.RemoveSnapshot_Task(tctx, c.gc.Client, &types.RemoveSnapshot_Task{
		This:           types.ManagedObjectReference{Type: "VirtualMachineSnapshot", Value: moref},
		RemoveChildren: false,
	})
	if err != nil {
		return false, fmt.Errorf("remove snapshot %s (%s): %w", name, moref, err)
	}
	if err := object.NewTask(c.gc.Client, res.Returnval).Wait(tctx); err != nil {
		return false, fmt.Errorf("remove snapshot %s (%s): %w", name, moref, err)
	}
	return true, nil
}

// ShutdownGuestOS asks VMware Tools to shut the consented VM's guest down
// cleanly — used at cut-over only when the operator asked for it. It returns
// once the request is accepted; the caller waits for poweredOff. There is
// deliberately no hard power-off.
func (c *Client) ShutdownGuestOS(ctx context.Context, consent CBTConsent) error {
	if err := consent.check(); err != nil {
		return err
	}
	tctx, cancel := taskCtx(ctx)
	defer cancel()
	vm := object.NewVirtualMachine(c.gc.Client, vmRef(consent.moid))
	if err := vm.ShutdownGuest(tctx); err != nil {
		return fmt.Errorf("guest shutdown of %s via VMware Tools: %w", consent.moid, err)
	}
	return nil
}

// SnapshotDisks lists the virtual disks of a VM as the snapshot froze them
// (file, capacity, change id), in device order. Read-only.
func (c *Client) SnapshotDisks(ctx context.Context, moid, snapMoref string) ([]CBTDisk, error) {
	var snap mo.VirtualMachineSnapshot
	ref := types.ManagedObjectReference{Type: "VirtualMachineSnapshot", Value: snapMoref}
	if err := property.DefaultCollector(c.gc.Client).RetrieveOne(ctx, ref, []string{"config.hardware", "vm"}, &snap); err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", snapMoref, err)
	}
	if snap.Vm.Value != moid {
		return nil, fmt.Errorf("snapshot %s belongs to %s, not %s", snapMoref, snap.Vm.Value, moid)
	}
	var out []CBTDisk
	for _, d := range snap.Config.Hardware.Device {
		vd, ok := d.(*types.VirtualDisk)
		if !ok {
			continue
		}
		b, ok := vd.Backing.(*types.VirtualDiskFlatVer2BackingInfo)
		if !ok {
			return nil, fmt.Errorf("disk %d has a non-flat backing (%T) — warm migration needs flat VMDKs", vd.Key, vd.Backing)
		}
		disk := CBTDisk{Key: vd.Key, FileName: b.FileName, Capacity: vd.CapacityInBytes, ChangeID: b.ChangeId}
		if disk.Capacity == 0 {
			disk.Capacity = vd.CapacityInKB * 1024
		}
		if vd.DeviceInfo != nil {
			disk.Label = vd.DeviceInfo.GetDescription().Label
		}
		out = append(out, disk)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("snapshot %s has no disks", snapMoref)
	}
	return out, nil
}

// QueryChangedAreas returns every area of disk deviceKey that changed between
// changeID and the snapshot (QueryChangedDiskAreas, looped over the disk). With
// changeID "*" it returns the disk's allocated areas — the base copy. Read-only.
func (c *Client) QueryChangedAreas(ctx context.Context, moid, snapMoref string, deviceKey int32, capacity int64, changeID string) ([]ChangedArea, error) {
	snap := types.ManagedObjectReference{Type: "VirtualMachineSnapshot", Value: snapMoref}
	var out []ChangedArea
	for off := int64(0); off < capacity; {
		res, err := methods.QueryChangedDiskAreas(ctx, c.gc.Client, &types.QueryChangedDiskAreas{
			This: vmRef(moid), Snapshot: &snap, DeviceKey: deviceKey, StartOffset: off, ChangeId: changeID,
		})
		if err != nil {
			return nil, fmt.Errorf("QueryChangedDiskAreas(disk %d, offset %d, change %q): %w", deviceKey, off, changeID, err)
		}
		info := res.Returnval
		for _, a := range info.ChangedArea {
			out = append(out, ChangedArea{Start: a.Start, Length: a.Length})
		}
		next := info.StartOffset + info.Length
		if next <= off {
			return nil, fmt.Errorf("QueryChangedDiskAreas made no progress at offset %d", off)
		}
		off = next
	}
	return out, nil
}
