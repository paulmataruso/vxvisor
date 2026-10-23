// Package vmware is a thin, READ-ONLY wrapper over govmomi for importing VMs from
// vCenter/ESXi into VXVisor. It deliberately exposes only non-mutating operations
// (connect, list inventory, read-only disk export) — there is NO code path here
// that powers, reconfigures, snapshots, or deletes a source VM. The source is
// only ever read, which is the project's hard safety requirement.
package vmware

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/nfc"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
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
	gc       *govmomi.Client
	insecure bool
}

// DiskInfo describes one virtual disk on a source VM.
type DiskInfo struct {
	Label      string
	CapacityGB int64
	Backing    string // datastore path of the vmdk
	Thin       bool
}

// NICInfo describes one virtual NIC on a source VM, captured structurally so the
// migration wizard can show the source port-group and map it to a target network.
type NICInfo struct {
	Label     string // e.g. "Network adapter 1"
	MAC       string // source MAC (informational; not reused on import)
	Type      string // e1000 | e1000e | vmxnet3 | vmxnet2 | pcnet32 | sriov | vnic
	PortGroup string // standard-vSwitch port-group name, DVS portgroup key, or opaque net id
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
	Nets          []string  // human-readable NIC summaries (kept for display)
	NICs          []NICInfo // structured per-NIC detail (type/MAC/port-group)
	HasSnapshots  bool
	Importable    bool   // false → we refuse before touching anything
	ImportNote    string // why not importable, or a caveat
}

// nicType maps a govmomi virtual-NIC device to a short model name.
func nicType(d types.BaseVirtualDevice) string {
	switch d.(type) {
	case *types.VirtualVmxnet3:
		return "vmxnet3"
	case *types.VirtualVmxnet2:
		return "vmxnet2"
	case *types.VirtualVmxnet:
		return "vmxnet"
	case *types.VirtualE1000e:
		return "e1000e"
	case *types.VirtualE1000:
		return "e1000"
	case *types.VirtualPCNet32:
		return "pcnet32"
	case *types.VirtualSriovEthernetCard:
		return "sriov"
	default:
		return "vnic"
	}
}

// nicPortGroup resolves a NIC's backing to a port-group identifier: the standard
// vSwitch port-group name, the DVS portgroup key, or an NSX opaque-network id.
// Read-only — inspects the backing govmomi already fetched with config.hardware.
func nicPortGroup(card *types.VirtualEthernetCard) string {
	switch b := card.Backing.(type) {
	case *types.VirtualEthernetCardNetworkBackingInfo:
		return b.DeviceName
	case *types.VirtualEthernetCardDistributedVirtualPortBackingInfo:
		return b.Port.PortgroupKey
	case *types.VirtualEthernetCardOpaqueNetworkBackingInfo:
		return b.OpaqueNetworkId
	default:
		return ""
	}
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
	return &Client{gc: gc, insecure: c.Insecure}, nil
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
				n := NICInfo{MAC: card.MacAddress, Type: nicType(d)}
				if card.DeviceInfo != nil {
					n.Label = card.DeviceInfo.GetDescription().Label
					info.Nets = append(info.Nets, card.DeviceInfo.GetDescription().Summary)
				}
				n.PortGroup = nicPortGroup(card)
				info.NICs = append(info.NICs, n)
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

	// SPEED: when connected to vCenter, the disk URLs come back with host "*",
	// which govmomi rewrites to the host WE connected to — vCenter. That proxies
	// every byte through vCenter's NFC service, which is heavily throttled. Pull
	// directly from the ESXi host that owns the VM instead (what virt-v2v/Veeam
	// do): typically several times faster. Best-effort — we only switch if the
	// host is actually reachable from here, else we keep the proxied path.
	directHost := ""
	thumbs := map[string]string{} // vmdk filename -> host SSL thumbprint (for secure mode)
	if c.gc.ServiceContent.About.ApiType == "VirtualCenter" {
		if ha := c.ownerHostAddr(ctx, ref); ha != "" {
			if reachableTCP(net.JoinHostPort(ha, "443")) {
				directHost = ha
				thumbs = c.leaseThumbprints(ctx, lease)
				logf("DIRECT TRANSFER: pulling from ESXi host %s, bypassing the vCenter NFC proxy (faster)", ha)
			} else {
				logf("ESXi host %s is not reachable on :443 from here — using the slower vCenter-proxied transfer (open that path for full speed)", ha)
			}
		}
	}

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
		// Redirect this disk's transfer straight to the owning ESXi host.
		rewroteFrom := "" // non-empty if we redirected this disk to the ESXi host
		if directHost != "" && item.URL != nil {
			rewroteFrom = item.URL.Host
			if _, port, e := net.SplitHostPort(rewroteFrom); e == nil && port != "" {
				item.URL.Host = net.JoinHostPort(directHost, port)
			} else {
				item.URL.Host = directHost
			}
			if !c.insecure {
				if tp := thumbs[path.Base(item.URL.Path)]; tp != "" {
					c.gc.Client.SetThumbprint(item.URL.Host, tp)
				}
			}
			logf("  → disk %q routed direct to %s (was %s)", item.Path, item.URL.Host, rewroteFrom)
		}
		logf("downloading disk %q (%d MiB) → %s", item.Path, item.Size/(1<<20), filepath.Base(local))
		diskStart := time.Now()

		// One download attempt: stream in a goroutine while polling the output file
		// for bytes + rate so the UI can show "X downloaded @ Z MB/s".
		downloadOnce := func() error {
			_ = os.Remove(local) // drop any partial from a previous attempt
			errCh := make(chan error, 1)
			go func() { errCh <- lease.DownloadFile(ctx, local, item, soap.Download{}) }()
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			// Cumulative-average rate (total bytes this disk / total elapsed) rather
			// than an instantaneous delta: the transport writes in bursts, so a
			// per-tick delta frequently samples 0 and the UI rate flickers to "—".
			// The average is stable and always non-zero once data is flowing.
			startBytes, startT := completedBytes, time.Now()
			for {
				select {
				case derr := <-errCh:
					return derr
				case now := <-tick.C:
					cur := completedBytes
					if fi, e := os.Stat(local); e == nil {
						cur += fi.Size()
					}
					if prog != nil {
						var bps int64
						if el := now.Sub(startT).Seconds(); el > 0 {
							bps = int64(float64(cur-startBytes) / el)
						}
						prog(ExportProgress{DoneBytes: cur, NominalBytes: nominalBytes, BytesPerSec: bps})
					}
				}
			}
		}
		derr := downloadOnce()
		// If the direct-to-host transfer failed, fall back once to the original
		// (vCenter-proxied) URL so a blocked direct path never breaks the import.
		if derr != nil && rewroteFrom != "" && ctx.Err() == nil {
			logf("direct transfer of %q failed (%v) — falling back to the vCenter-proxied path", item.Path, derr)
			item.URL.Host = rewroteFrom
			directHost = "" // don't try direct for the remaining disks either
			derr = downloadOnce()
		}
		if derr != nil {
			_ = os.Remove(local)
			cleanup()
			_ = lease.Abort(ctx, nil)
			logf("download of %q FAILED after %s: %v", item.Path, time.Since(diskStart).Round(time.Second), derr)
			return nil, fmt.Errorf("download %s: %w", item.Path, derr)
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

// ExportVMDatastore downloads a powered-off VM's disks by GETting the flat VMDK
// data extents straight off the datastore over the ESXi/vCenter `/folder` HTTPS
// file service. Unlike ExportVM (NFC) there is NO stream-optimized recompression
// on the host, so the transfer is link-bound and typically several times faster
// on a LAN. It is strictly READ-ONLY on the source (plain GETs; nothing is
// powered, snapshotted, or reconfigured). It REFUSES a powered-on VM (the flat
// file is locked / inconsistent) or one with snapshots (a raw flat copy would
// miss the live delta chain), and handles single-extent flat disks (the common
// case) — a split/multi-extent disk errors so the caller can fall back to NFC.
// The downloaded extent is a raw image; the caller's existing qemu-img pipeline
// converts it to qcow2 (which also re-sparsifies the zeroed regions the flat GET
// necessarily transfers). Returns local raw-disk paths in device order.
func (c *Client) ExportVMDatastore(ctx context.Context, moid, destDir string, logf func(string, ...any), prog func(ExportProgress)) ([]string, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ref := types.ManagedObjectReference{Type: "VirtualMachine", Value: moid}
	var vm mo.VirtualMachine
	pc := property.DefaultCollector(c.gc.Client)
	if err := pc.RetrieveOne(ctx, ref, []string{"config.hardware", "runtime.powerState", "snapshot"}, &vm); err != nil {
		return nil, fmt.Errorf("read VM layout: %w", err)
	}
	if vm.Runtime.PowerState != types.VirtualMachinePowerStatePoweredOff {
		return nil, fmt.Errorf("the datastore transport requires the source powered OFF (it is %s) — power it off on vCenter, or use the NFC transport", vm.Runtime.PowerState)
	}
	if vm.Snapshot != nil && len(vm.Snapshot.RootSnapshotList) > 0 {
		return nil, fmt.Errorf("the datastore transport can't be used on a VM with snapshots (a raw flat copy would miss the delta chain) — remove snapshots on the source, or use the NFC transport")
	}
	disks, err := flatDisksOf(&vm)
	if err != nil {
		return nil, err
	}

	var nominalBytes int64
	for _, d := range disks {
		nominalBytes += d.capBytes
	}

	var files []string
	cleanup := func() {
		for _, f := range files {
			_ = os.Remove(f)
		}
	}
	var completedBytes int64
	for _, d := range disks {
		ds := object.NewDatastore(c.gc.Client, *d.ds)
		// Read the (tiny) descriptor to find the real data extent filename(s).
		rc, _, err := ds.Download(ctx, d.desc, &soap.Download{Method: "GET"})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("read descriptor %s: %w", d.desc, err)
		}
		descBytes, _ := io.ReadAll(rc)
		_ = rc.Close()
		extents := parseVMDKExtents(string(descBytes))
		if len(extents) == 0 {
			cleanup()
			return nil, fmt.Errorf("could not parse a data extent from descriptor %s", d.desc)
		}
		if len(extents) > 1 {
			cleanup()
			return nil, fmt.Errorf("disk %q is split into %d extents — the datastore transport handles single-extent disks only; use the NFC transport", d.label, len(extents))
		}
		extName := extents[0]
		extRel := extName
		if d.dir != "" {
			extRel = d.dir + "/" + extName
		}
		local := filepath.Join(destDir, "."+sanitizeName(extName))
		logf("downloading %q data extent %s (~%d MiB) direct from datastore → %s", d.label, extRel, d.capBytes/(1<<20), filepath.Base(local))
		diskStart := time.Now()

		// Stream the flat file to disk while polling its size for a live rate.
		errCh := make(chan error, 1)
		dlCtx, dlCancel := context.WithCancel(ctx)
		go func() { errCh <- ds.DownloadFile(dlCtx, extRel, local, &soap.Download{Method: "GET"}) }()
		tick := time.NewTicker(time.Second)
		lastBytes, lastT := completedBytes, time.Now()
		var derr error
	poll:
		for {
			select {
			case derr = <-errCh:
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
		tick.Stop()
		dlCancel()
		if derr != nil {
			_ = os.Remove(local)
			cleanup()
			logf("datastore download of %q FAILED after %s: %v", d.label, time.Since(diskStart).Round(time.Second), derr)
			return nil, fmt.Errorf("download %s: %w", extRel, derr)
		}
		var wrote int64
		if fi, e := os.Stat(local); e == nil {
			wrote = fi.Size()
			completedBytes += wrote
		}
		elapsed := time.Since(diskStart)
		var avg int64
		if sec := elapsed.Seconds(); sec > 0 {
			avg = int64(float64(wrote) / sec)
		}
		logf("downloaded %q: %d MiB in %s (avg %d MiB/s, raw flat) — will convert to qcow2 (zeros re-sparsified on convert)",
			d.label, wrote/(1<<20), elapsed.Round(time.Second), avg/(1<<20))
		files = append(files, local)
		if prog != nil {
			prog(ExportProgress{DoneBytes: completedBytes, NominalBytes: nominalBytes})
		}
	}
	logf("datastore export finished: %d disk file(s), %d MiB total", len(files), completedBytes/(1<<20))
	return files, nil
}

// parseVMDKExtents pulls the data-extent filename(s) out of a VMDK descriptor.
// Extent lines look like: RW 83886080 VMFS "MyVM-flat.vmdk". Returns the quoted
// names in order (usually one for a monolithicFlat disk).
func parseVMDKExtents(desc string) []string {
	var out []string
	for _, line := range strings.Split(desc, "\n") {
		line = strings.TrimSpace(line)
		if !(strings.HasPrefix(line, "RW ") || strings.HasPrefix(line, "RDONLY ") || strings.HasPrefix(line, "NOACCESS ")) {
			continue
		}
		a := strings.IndexByte(line, '"')
		if a < 0 {
			continue
		}
		b := strings.IndexByte(line[a+1:], '"')
		if b < 0 {
			continue
		}
		if name := line[a+1 : a+1+b]; name != "" {
			out = append(out, name)
		}
	}
	return out
}

// flatDisk describes one flat-backed virtual disk of a source VM, shared by the
// datastore and VDDK transports.
type flatDisk struct {
	ds       *types.ManagedObjectReference
	dir      string // datastore-relative directory of the vmdk
	desc     string // datastore-relative path of the descriptor .vmdk
	fileName string // full "[dsName] dir/x.vmdk" as VMware reports it (VDDK needs this)
	capBytes int64
	label    string
}

// flatDisksOf extracts the flat virtual disks from a retrieved VM (config.hardware
// must be populated). Errors on a non-flat backing so the caller can fall back to
// the NFC transport, which can read any backing.
func flatDisksOf(vm *mo.VirtualMachine) ([]flatDisk, error) {
	if vm.Config == nil {
		return nil, fmt.Errorf("source VM has no hardware config")
	}
	var disks []flatDisk
	for _, d := range vm.Config.Hardware.Device {
		vd, ok := d.(*types.VirtualDisk)
		if !ok {
			continue
		}
		b, ok := vd.Backing.(*types.VirtualDiskFlatVer2BackingInfo)
		if !ok {
			return nil, fmt.Errorf("disk has a non-flat backing (%T) this transport can't read — use the NFC transport", vd.Backing)
		}
		if b.Datastore == nil {
			return nil, fmt.Errorf("disk backing has no datastore reference")
		}
		rel := b.FileName // "[dsName] dir/name.vmdk"
		if i := strings.Index(rel, "] "); i >= 0 {
			rel = rel[i+2:]
		}
		dir := ""
		if i := strings.LastIndexByte(rel, '/'); i >= 0 {
			dir = rel[:i]
		}
		lbl := ""
		if vd.DeviceInfo != nil {
			lbl = vd.DeviceInfo.GetDescription().Label
		}
		disks = append(disks, flatDisk{ds: b.Datastore, dir: dir, desc: rel, fileName: b.FileName, capBytes: vd.CapacityInKB * 1024, label: lbl})
	}
	if len(disks) == 0 {
		return nil, fmt.Errorf("source VM has no flat disks")
	}
	return disks, nil
}

func sanitizeName(p string) string {
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, "..", "_")
	return "vdximport-" + p
}

// ownerHostAddr returns the management address (name/IP as vCenter knows it) of
// the ESXi host currently running the VM, or "" if it can't be determined. Used
// to pull disks directly from the host rather than via the vCenter NFC proxy.
func (c *Client) ownerHostAddr(ctx context.Context, ref types.ManagedObjectReference) string {
	pc := property.DefaultCollector(c.gc.Client)
	var vm mo.VirtualMachine
	if err := pc.RetrieveOne(ctx, ref, []string{"runtime.host"}, &vm); err != nil || vm.Runtime.Host == nil {
		return ""
	}
	var hs mo.HostSystem
	if err := pc.RetrieveOne(ctx, *vm.Runtime.Host, []string{"name"}, &hs); err != nil {
		return ""
	}
	return strings.TrimSpace(hs.Name)
}

// leaseThumbprints maps each disk's vmdk filename to the SSL thumbprint of the
// host serving it, read from the raw lease info — needed so a direct-to-host
// transfer verifies TLS when the connection is not insecure.
func (c *Client) leaseThumbprints(ctx context.Context, lease *nfc.Lease) map[string]string {
	out := map[string]string{}
	var le mo.HttpNfcLease
	if err := property.DefaultCollector(c.gc.Client).RetrieveOne(ctx, lease.Reference(), []string{"info"}, &le); err != nil || le.Info == nil {
		return out
	}
	for _, d := range le.Info.DeviceUrl {
		if d.SslThumbprint == "" {
			continue
		}
		if u, err := url.Parse(d.Url); err == nil {
			out[path.Base(u.Path)] = d.SslThumbprint
		}
	}
	return out
}

// reachableTCP reports whether a TCP connection to hostport succeeds quickly.
func reachableTCP(hostport string) bool {
	conn, err := net.DialTimeout("tcp", hostport, 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
