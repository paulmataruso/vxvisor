package ovirtapi

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/vmbackup"
)

// memBackend is an in-memory Backend for the handler tests. The host test
// points its VM at a real scratch QEMU (backupDisk) and keeps staged disks as
// real qcow2 files (diskDir); the unit tests leave both unset.
type memBackend struct {
	mu     sync.Mutex
	host   Host
	pools  []StoragePool
	nets   []Network
	vms    map[string]*VM
	staged map[string]*Disk
	cps    map[string][]Checkpoint
	audits []string

	diskDir    string                                    // "" = staged disks have no files
	backupDisk func(vm *VM) (vmbackup.Disk, error)       // nil = backups unsupported
	nextID     func() string                             // deterministic ids for golden output
	onStart    func(vm *VM) error                        // optional StartVM hook
	userData   map[string]string                         // vm id -> custom_script
	specs      map[string]VMSpec                         // vm id -> spec it was created with
	attachHook func(vm *VM, d *Disk, iface string) error // optional AttachDisk hook
	removeHook func(vmID, id string) error               // optional RemoveCheckpoint hook (drops the bitmap)
}

type fakeCaller struct{ user, ip string }

var created0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func newMemBackend() *memBackend {
	b := &memBackend{
		host: Host{Name: "node1", Address: "198.51.100.7", CPUModel: "Test CPU", CPUs: 8, Sockets: 1,
			MemoryMB: 32768, FreeMB: 16384, QEMUVer: "10.2.1", KernelVer: "7.0.0", OSVersion: "Test Linux", VMsRunning: 1},
		pools: []StoragePool{
			{PoolID: 0, Name: "default", Kind: "dir", Available: 100 << 30, Used: 20 << 30, Uploadable: true},
			{PoolID: 3, Name: "ceph", Kind: "rbd"},
		},
		nets: []Network{
			{NetID: 0, Name: "vxvisor-nat", OrgID: 1},
			{NetID: 5, Name: "lan", VLAN: 20, OrgID: 1},
		},
		vms:      map[string]*VM{},
		staged:   map[string]*Disk{},
		cps:      map[string][]Checkpoint{},
		userData: map[string]string{},
		specs:    map[string]VMSpec{},
	}
	n := 0
	b.nextID = func() string {
		n++
		return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
	}
	vm := &VM{ID: "11111111-1111-4111-8111-111111111111", Name: "web01", OrgID: 1, Status: "up", CPUs: 2,
		MemoryMB: 2048, Firmware: "uefi", MachineType: "q35", OSType: "linux", DiskBus: "virtio-blk",
		NICModel: "virtio", VGA: "qxl", GuestAgent: true, Created: created0, NetID: 5, MAC: "52:54:00:12:34:56"}
	vm.Disk = &Disk{ID: DiskIDForVM(vm.ID), Name: "web01_disk0", VMID: vm.ID, Path: "/var/lib/disks/web01.qcow2",
		Format: "qcow2", PoolID: 0, Provisioned: 10 << 30, Actual: 3 << 30, Incremental: true}
	b.vms[vm.ID] = vm
	return b
}

func (b *memBackend) Login(user, password, ip string) (Caller, error) {
	if user == "admin" && password == "secret" {
		return &fakeCaller{user: user, ip: ip}, nil
	}
	return nil, ErrForbidden
}

func (b *memBackend) Bind(c Caller, ip string) (Caller, error) {
	fc, ok := c.(*fakeCaller)
	if !ok {
		return nil, ErrForbidden
	}
	return &fakeCaller{user: fc.user, ip: ip}, nil
}

func (b *memBackend) Host(Caller) (Host, error)                  { return b.host, nil }
func (b *memBackend) StoragePools(Caller) ([]StoragePool, error) { return b.pools, nil }
func (b *memBackend) Networks(Caller) ([]Network, error)         { return b.nets, nil }

func (b *memBackend) VMs(Caller) ([]VM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []VM
	for _, v := range b.vms {
		out = append(out, b.copyVM(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (b *memBackend) copyVM(v *VM) VM {
	c := *v
	if v.Disk != nil {
		d := *v.Disk
		c.Disk = &d
	}
	return c
}

func (b *memBackend) VM(_ Caller, id string) (VM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.vms[id]
	if v == nil {
		return VM{}, fmt.Errorf("%w: VM %s", ErrNotFound, id)
	}
	return b.copyVM(v), nil
}

func (b *memBackend) GuestIPs(_ Caller, id string) []string {
	if v, err := b.VM(nil, id); err == nil && v.Status == "up" {
		return []string{"192.0.2.44"}
	}
	return nil
}

func (b *memBackend) BackupDisk(_ Caller, id string) (vmbackup.Disk, func(), error) {
	b.mu.Lock()
	v := b.vms[id]
	b.mu.Unlock()
	if v == nil {
		return vmbackup.Disk{}, nil, ErrNotFound
	}
	if b.backupDisk == nil {
		return vmbackup.Disk{}, nil, fmt.Errorf("%w: no backups in this test", ErrBadRequest)
	}
	d, err := b.backupDisk(v)
	return d, func() {}, err
}

func (b *memBackend) Checkpoints(_ Caller, vmID string) ([]Checkpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Checkpoint(nil), b.cps[vmID]...), nil
}

func (b *memBackend) AddCheckpoint(_ Caller, cp Checkpoint) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cps[cp.VMID] = append(b.cps[cp.VMID], cp)
	return nil
}

func (b *memBackend) RemoveCheckpoint(_ Caller, vmID, id string) error {
	if b.removeHook != nil {
		if err := b.removeHook(vmID, id); err != nil {
			return err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := b.cps[vmID]
	for i, cp := range cur {
		if cp.ID == id {
			b.cps[vmID] = append(cur[:i:i], cur[i+1:]...)
			b.audits = append(b.audits, "checkpoint.remove "+id)
			return nil
		}
	}
	return ErrNotFound
}

func (b *memBackend) Disks(Caller) ([]Disk, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Disk
	for _, d := range b.staged {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (b *memBackend) CreateDisk(_ Caller, spec DiskSpec) (Disk, error) {
	var pool *StoragePool
	for i := range b.pools {
		if b.pools[i].PoolID == spec.PoolID {
			pool = &b.pools[i]
		}
	}
	if pool == nil || !pool.Uploadable {
		return Disk{}, fmt.Errorf("%w: pool %d can't hold staged disks", ErrBadRequest, spec.PoolID)
	}
	b.mu.Lock()
	id := b.nextID()
	b.mu.Unlock()
	d := &Disk{ID: id, Name: spec.Name, Format: "qcow2", PoolID: spec.PoolID, Provisioned: spec.Provisioned, Incremental: true}
	if b.diskDir != "" {
		d.Path = filepath.Join(b.diskDir, id+".qcow2")
		out, err := exec.Command("qemu-img", "create", "-f", "qcow2", d.Path, strconv.FormatInt(spec.Provisioned, 10)).CombinedOutput()
		if err != nil {
			return Disk{}, fmt.Errorf("qemu-img create: %v: %s", err, out)
		}
	}
	b.mu.Lock()
	b.staged[id] = d
	b.audits = append(b.audits, "disk.create "+id)
	b.mu.Unlock()
	return *d, nil
}

func (b *memBackend) DeleteDisk(_ Caller, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := b.staged[id]
	if d == nil {
		return ErrNotFound
	}
	if d.Path != "" {
		_ = os.Remove(d.Path)
	}
	delete(b.staged, id)
	b.audits = append(b.audits, "disk.delete "+id)
	return nil
}

func (b *memBackend) WritableDisk(_ Caller, id string) (string, string, func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d := b.staged[id]; d != nil {
		return d.Path, d.Format, func() {}, nil
	}
	return "", "", nil, fmt.Errorf("%w: only staged disks can be uploaded to", ErrConflict)
}

func (b *memBackend) CreateVM(_ Caller, spec VMSpec) (VM, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, v := range b.vms {
		if v.Name == spec.Name {
			return VM{}, fmt.Errorf("%w: a VM named %q already exists", ErrConflict, spec.Name)
		}
	}
	id := b.nextID()
	v := &VM{ID: id, Name: spec.Name, OrgID: max(spec.OrgID, 1), Status: "down", CPUs: spec.CPUs, MemoryMB: spec.MemoryMB,
		Firmware: spec.Firmware, SecureBoot: spec.SecureBoot, MachineType: spec.MachineType, OSType: spec.OSType,
		DiskBus: spec.DiskBus, NICModel: spec.NICModel, VGA: spec.VGA, GuestAgent: spec.GuestAgent, TPM: spec.TPM,
		Created: created0.Add(time.Hour), MAC: "52:54:00:00:00:01"}
	b.vms[id] = v
	b.userData[id] = spec.UserData
	b.specs[id] = spec
	b.audits = append(b.audits, "vm.create "+id+" "+spec.Purpose)
	return b.copyVM(v), nil
}

func (b *memBackend) DeleteVM(_ Caller, id string, keepDisks bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.vms[id]
	if v == nil {
		return ErrNotFound
	}
	if keepDisks && v.Disk != nil {
		d := *v.Disk
		d.VMID = ""
		b.staged[d.ID] = &d
	}
	delete(b.vms, id)
	b.audits = append(b.audits, fmt.Sprintf("vm.delete %s keep=%v", id, keepDisks))
	return nil
}

func (b *memBackend) AttachDisk(_ Caller, vmID, diskID, iface string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, d := b.vms[vmID], b.staged[diskID]
	if v == nil || d == nil {
		return ErrNotFound
	}
	if v.Disk != nil {
		return fmt.Errorf("%w: VM already has a disk", ErrConflict)
	}
	if b.attachHook != nil {
		if err := b.attachHook(v, d, iface); err != nil {
			return err
		}
	}
	dd := *d
	dd.VMID = vmID
	v.Disk = &dd
	delete(b.staged, diskID)
	b.audits = append(b.audits, "disk.attach "+diskID+" "+iface)
	return nil
}

func (b *memBackend) DetachDisk(_ Caller, vmID, diskID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.vms[vmID]
	if v == nil || v.Disk == nil || v.Disk.ID != diskID {
		return ErrNotFound
	}
	d := *v.Disk
	d.VMID = ""
	b.staged[d.ID] = &d
	v.Disk = nil
	return nil
}

func (b *memBackend) SetNIC(_ Caller, vmID, profileID, iface string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.vms[vmID]
	if v == nil {
		return ErrNotFound
	}
	if profileID != "" {
		found := false
		for _, n := range b.nets {
			if netUUID(n.NetID) == profileID {
				v.NetID, found = n.NetID, true
			}
		}
		if !found {
			return fmt.Errorf("%w: vNIC profile %s", ErrNotFound, profileID)
		}
	}
	if iface == "e1000" {
		v.NICModel = "e1000e"
	}
	b.audits = append(b.audits, "nic.set "+vmID)
	return nil
}

func (b *memBackend) StartVM(_ Caller, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.vms[id]
	if v == nil {
		return ErrNotFound
	}
	if v.Disk == nil {
		return fmt.Errorf("%w: the VM has no disk", ErrBadRequest)
	}
	if b.onStart != nil {
		if err := b.onStart(v); err != nil {
			return err
		}
	}
	v.Status = "up"
	return nil
}

func (b *memBackend) StopVM(_ Caller, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.vms[id]
	if v == nil {
		return ErrNotFound
	}
	v.Status = "down"
	return nil
}

func (b *memBackend) Audit(_ Caller, action, targetType, targetID, _ string, _ map[string]any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.audits = append(b.audits, action+" "+targetID)
}

var _ Backend = (*memBackend)(nil)

func randomID() string { return uuid.NewString() }
