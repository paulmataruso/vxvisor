// Package vmware is a thin, READ-ONLY wrapper over govmomi for importing VMs from
// vCenter/ESXi into VXVisor. It deliberately exposes only non-mutating operations
// (connect, list inventory, read-only disk export) — there is NO code path here
// that powers, reconfigures, snapshots, or deletes a source VM. The source is
// only ever read, which is the project's hard safety requirement.
package vmware

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"strings"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

// Creds identifies a vCenter/ESXi endpoint. URL may be a bare host (we add
// https://.../sdk) or a full SDK URL. Pass/User are held in memory only.
type Creds struct {
	URL      string
	User     string
	Pass     string
	Insecure bool
}

// Client wraps a connected govmomi client.
type Client struct {
	gc *govmomi.Client
}

// DiskInfo describes one virtual disk on a source VM.
type DiskInfo struct {
	Label      string
	CapacityGB int64
	Backing    string // datastore path of the vmdk
	Thin       bool
}

// VMInfo is read-only inventory for a source VM.
type VMInfo struct {
	MOID          string
	Name          string
	PowerState    string // poweredOn | poweredOff | suspended
	GuestID       string
	GuestFullName string
	NumCPU        int32
	MemMB         int32
	Firmware      string // bios | efi
	Disks         []DiskInfo
	Nets          []string
	HasSnapshots  bool
	Importable    bool   // false → we refuse before touching anything
	ImportNote    string // why not importable, or a caveat
}

// normalizeURL turns a bare host or partial URL into an https .../sdk URL with
// the credentials attached.
func normalizeURL(raw, user, pass string) (*url.URL, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("vCenter/ESXi URL or host is required")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/sdk"
	}
	u.User = url.UserPassword(user, pass)
	return u, nil
}

// Connect opens a read-only session to vCenter/ESXi.
func Connect(ctx context.Context, c Creds) (*Client, error) {
	u, err := normalizeURL(c.URL, c.User, c.Pass)
	if err != nil {
		return nil, err
	}
	gc, err := govmomi.NewClient(ctx, u, c.Insecure)
	if err != nil {
		return nil, fmt.Errorf("connect to vSphere: %w", err)
	}
	return &Client{gc: gc}, nil
}

// Close logs out.
func (c *Client) Close(ctx context.Context) {
	if c != nil && c.gc != nil {
		_ = c.gc.Logout(ctx)
	}
}

// ListVMs returns read-only inventory for every VM reachable to the account.
func (c *Client) ListVMs(ctx context.Context) ([]VMInfo, error) {
	m := view.NewManager(c.gc.Client)
	v, err := m.CreateContainerView(ctx, c.gc.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		return nil, err
	}
	defer v.Destroy(ctx)

	var vms []mo.VirtualMachine
	props := []string{"name", "config.hardware", "config.firmware", "config.keyId", "runtime.powerState", "summary", "snapshot"}
	if err := v.Retrieve(ctx, []string{"VirtualMachine"}, props, &vms); err != nil {
		return nil, err
	}
	out := make([]VMInfo, 0, len(vms))
	for i := range vms {
		out = append(out, toVMInfo(&vms[i]))
	}
	return out, nil
}

func toVMInfo(vm *mo.VirtualMachine) VMInfo {
	info := VMInfo{
		MOID:         vm.Self.Value,
		Name:         vm.Name,
		HasSnapshots: vm.Snapshot != nil && len(vm.Snapshot.RootSnapshotList) > 0,
	}
	info.PowerState = string(vm.Runtime.PowerState)
	if vm.Summary.Config.GuestId != "" {
		info.GuestID = vm.Summary.Config.GuestId
	}
	info.GuestFullName = vm.Summary.Config.GuestFullName
	var refuse string
	if vm.Config != nil {
		info.Firmware = vm.Config.Firmware
		info.NumCPU = vm.Config.Hardware.NumCPU
		info.MemMB = vm.Config.Hardware.MemoryMB
		// Encrypted VMs cannot be plainly exported.
		if vm.Config.KeyId != nil {
			refuse = "VM is encrypted — cannot be exported without the key provider"
		}
		for _, d := range vm.Config.Hardware.Device {
			switch dev := d.(type) {
			case *types.VirtualDisk:
				di := DiskInfo{CapacityGB: dev.CapacityInKB / (1024 * 1024)}
				if dev.DeviceInfo != nil {
					di.Label = dev.DeviceInfo.GetDescription().Label
				}
				switch b := dev.Backing.(type) {
				case *types.VirtualDiskFlatVer2BackingInfo:
					di.Backing = b.FileName
					if b.ThinProvisioned != nil {
						di.Thin = *b.ThinProvisioned
					}
					if b.Sharing != "" && b.Sharing != "sharingNone" {
						refuse = "VM has a multi-writer / shared disk — not safely exportable"
					}
				case *types.VirtualDiskRawDiskMappingVer1BackingInfo, *types.VirtualDiskRawDiskVer2BackingInfo:
					refuse = "VM has a raw device mapping (RDM) disk — not exportable"
				default:
					di.Backing = "(non-flat backing)"
				}
				info.Disks = append(info.Disks, di)
			case types.BaseVirtualEthernetCard:
				card := dev.GetVirtualEthernetCard()
				if card.DeviceInfo != nil {
					info.Nets = append(info.Nets, card.DeviceInfo.GetDescription().Summary)
				}
			}
		}
	}
	if len(info.Disks) == 0 && refuse == "" {
		refuse = "VM has no exportable disks"
	}
	info.Importable = refuse == ""
	switch {
	case refuse != "":
		info.ImportNote = refuse
	case info.Firmware == "efi":
		info.ImportNote = "EFI firmware: imports as UEFI; boot entries may need a one-time fixup"
	}
	return info
}

// GetVM returns read-only inventory for a single VM by its managed-object id.
func (c *Client) GetVM(ctx context.Context, moid string) (VMInfo, error) {
	ref := types.ManagedObjectReference{Type: "VirtualMachine", Value: moid}
	var vm mo.VirtualMachine
	pc := c.gc.Client
	obj := object.NewVirtualMachine(pc, ref)
	props := []string{"name", "config.hardware", "config.firmware", "config.keyId", "runtime.powerState", "summary", "snapshot"}
	if err := obj.Properties(ctx, ref, props, &vm); err != nil {
		return VMInfo{}, err
	}
	return toVMInfo(&vm), nil
}

// ExportVM opens a READ-ONLY export lease on the (powered-off) source VM and
// downloads each virtual disk (stream-optimized VMDK) into destDir. It NEVER
// modifies the source: on any error it aborts the lease and removes its own
// partial files. Returns the local vmdk paths in device order (first = boot).
// Non-disk lease items (.ovf/.mf/.nvram) are skipped.
// ExportProgress reports live transfer stats to the caller.
//
// IMPORTANT: a vSphere export is a COMPRESSED, stream-optimized VMDK. The bytes
// actually streamed are the compressed contents of the (often thin) disk, which
// is normally far smaller than the disk's nominal capacity. NominalBytes is that
// capacity (the only "total" vCenter gives us up front); it is an upper bound, NOT
// the number of bytes we will download — a completed export of a 25 GiB thin disk
// routinely pulls only a few GiB. So DO NOT compute a percentage of NominalBytes
// and present it as import progress: it will never reach 100% and looks stuck.
type ExportProgress struct {
	DoneBytes    int64 // compressed stream bytes written so far across all disks
	NominalBytes int64 // sum of source disk CAPACITIES (upper bound, not the transfer size)
	BytesPerSec  int64 // instantaneous transfer rate
}

func (c *Client) ExportVM(ctx context.Context, moid, destDir string, logf func(string, ...any), prog func(ExportProgress)) ([]string, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ref := types.ManagedObjectReference{Type: "VirtualMachine", Value: moid}
	vm := object.NewVirtualMachine(c.gc.Client, ref)
	logf("opening read-only export lease on moid=%s", moid)
	lease, err := vm.Export(ctx)
	if err != nil {
		return nil, fmt.Errorf("open export lease: %w", err)
	}
	info, err := lease.Wait(ctx, nil)
	if err != nil {
		_ = lease.Abort(ctx, nil)
		return nil, fmt.Errorf("export lease: %w", err)
	}
	// Keepalive: the lease times out unless we report progress.
	updater := lease.StartUpdater(ctx, info)
	defer updater.Done()

	logf("export lease granted: %d item(s) in manifest", len(info.Items))
	var nominalBytes int64
	for _, item := range info.Items {
		isDisk := strings.HasSuffix(strings.ToLower(item.Path), ".vmdk")
		logf("  lease item: %s (%d MiB)%s", item.Path, item.Size/(1<<20), map[bool]string{true: "", false: " — skipped (non-disk)"}[isDisk])
		if isDisk {
			nominalBytes += item.Size
		}
	}
	logf("source disk capacity %d MiB nominal (thin+compressed stream — actual download is usually much less)", nominalBytes/(1<<20))
	var files []string
	cleanup := func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	var completedBytes int64
	for _, item := range info.Items {
		if !strings.HasSuffix(strings.ToLower(item.Path), ".vmdk") {
			continue // skip .ovf / .mf / .nvram — we only want the disks
		}
		local := filepath.Join(destDir, "."+sanitizeName(item.Path))
		logf("downloading disk %q (%d MiB) → %s", item.Path, item.Size/(1<<20), filepath.Base(local))
		diskStart := time.Now()

		// Download in a goroutine; poll the output file for bytes + rate so the UI
		// can show "X / Y GB @ Z MB/s".
		errCh := make(chan error, 1)
		go func() { errCh <- lease.DownloadFile(ctx, local, item, soap.Download{}) }()
		tick := time.NewTicker(time.Second)
		lastBytes, lastT := completedBytes, time.Now()
	poll:
		for {
			select {
			case derr := <-errCh:
				tick.Stop()
				if derr != nil {
					_ = os.Remove(local)
					cleanup()
					_ = lease.Abort(ctx, nil)
					logf("download of %q FAILED after %s: %v", item.Path, time.Since(diskStart).Round(time.Second), derr)
					return nil, fmt.Errorf("download %s: %w", item.Path, derr)
				}
				break poll
			case now := <-tick.C:
				cur := completedBytes
				if fi, e := os.Stat(local); e == nil {
					cur += fi.Size()
				}
				if prog != nil {
					dt := now.Sub(lastT).Seconds()
					var bps int64
					if dt > 0 {
						bps = int64(float64(cur-lastBytes) / dt)
					}
					prog(ExportProgress{DoneBytes: cur, NominalBytes: nominalBytes, BytesPerSec: bps})
					lastBytes, lastT = cur, now
				}
			}
		}
		var wrote int64
		if fi, e := os.Stat(local); e == nil {
			wrote = fi.Size()
			completedBytes += wrote
		}
		elapsed := time.Since(diskStart)
		var avg int64
		if s := elapsed.Seconds(); s > 0 {
			avg = int64(float64(wrote) / s)
		}
		logf("downloaded %q: %d MiB written in %s (avg %d MiB/s) — source nominal %d MiB; a thin disk exports as a smaller compressed stream, so a lower figure here is normal and complete, not truncated",
			item.Path, wrote/(1<<20), elapsed.Round(time.Second), avg/(1<<20), item.Size/(1<<20))
		files = append(files, local)
		if prog != nil {
			prog(ExportProgress{DoneBytes: completedBytes, NominalBytes: nominalBytes})
		}
	}
	logf("finalizing export lease")
	if err := lease.Complete(ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("complete export lease: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("export produced no disk files")
	}
	logf("export finished: %d disk file(s), %d MiB total", len(files), completedBytes/(1<<20))
	return files, nil
}

func sanitizeName(p string) string {
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, "..", "_")
	return "vdximport-" + p
}
