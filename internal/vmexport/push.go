package vmexport

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/nfc"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/ovf"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

// Target identifies a vCenter/ESXi endpoint and the placement for a pushed VM.
// Blank Datacenter/ResourcePool/Datastore/Folder fall back to the environment's
// defaults (govmomi finder .Default*), which is the right behaviour for a simple
// single-cluster target. Network is the target port-group the NIC attaches to.
type Target struct {
	URL      string
	User     string
	Pass     string
	Insecure bool

	Name         string // name for the new VM in vCenter
	Datacenter   string // "" = default
	ResourcePool string // "" = default (e.g. cluster's root pool)
	Datastore    string // "" = default
	Folder       string // "" = datacenter VM folder
	Network      string // target port-group name; "" = default finder network
}

// Progress reports upload progress for the UI.
type Progress struct {
	DoneBytes   int64
	TotalBytes  int64
	BytesPerSec int64
}

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

// Push uploads a VM into the target vCenter/ESXi via OVF import + NFC lease. hw
// describes the VM; vmdkPath is a stream-optimized VMDK whose basename equals
// hw.DiskHref. This WRITES to the target (creates a new VM there); it never
// touches any VXVisor source VM beyond reading its already-exported disk file.
func Push(ctx context.Context, t Target, hw Hardware, vmdkPath string, logf func(string, ...any), prog func(Progress)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	u, err := normalizeURL(t.URL, t.User, t.Pass)
	if err != nil {
		return err
	}
	logf("connecting to target vSphere %s", u.Hostname())
	gc, err := govmomi.NewClient(ctx, u, t.Insecure)
	if err != nil {
		return fmt.Errorf("connect to target vSphere: %w", err)
	}
	defer func() { _ = gc.Logout(context.Background()) }()

	finder := find.NewFinder(gc.Client, false)
	dc, err := pickDatacenter(ctx, finder, t.Datacenter)
	if err != nil {
		return err
	}
	finder.SetDatacenter(dc)
	logf("target datacenter: %s", dc.Name())

	rp, err := pickResourcePool(ctx, gc.Client, finder, t.ResourcePool)
	if err != nil {
		return err
	}
	ds, err := pickDatastore(ctx, gc.Client, finder, t.Datastore)
	if err != nil {
		return err
	}
	folder, err := pickFolder(ctx, finder, dc, t.Folder)
	if err != nil {
		return err
	}
	logf("placement: resourcePool=%s datastore=%s folder=%s", rp.Name(), ds.Name(), t.Folder)

	// Map the single OVF network to a target port-group.
	ovfNet := hw.NetworkName
	if ovfNet == "" {
		ovfNet = netName
	}
	netObj, err := finder.NetworkOrDefault(ctx, t.Network)
	if err != nil {
		// A blank network is ambiguous on a multi-network target. Fall back to
		// the first network in the inventory so the push still completes.
		if t.Network != "" {
			return fmt.Errorf("resolve target network %q: %w", t.Network, err)
		}
		netObj, err = firstNetwork(ctx, gc.Client)
		if err != nil {
			return fmt.Errorf("resolve target network: %w", err)
		}
	}
	netRef := netObj.Reference()

	name := t.Name
	if name == "" {
		name = hw.Name
	}
	descriptor := Descriptor(hw)
	cisp := types.OvfCreateImportSpecParams{
		DiskProvisioning: string(types.OvfCreateImportSpecParamsDiskProvisioningTypeThin),
		EntityName:       name,
		NetworkMapping:   []types.OvfNetworkMapping{{Name: ovfNet, Network: netRef}},
	}

	logf("building OVF import spec for %q", name)
	m := ovf.NewManager(gc.Client)
	spec, err := m.CreateImportSpec(ctx, descriptor, rp.Reference(), ds.Reference(), &cisp)
	if err != nil {
		return fmt.Errorf("create import spec: %w", err)
	}
	if spec.Error != nil && len(spec.Error) > 0 {
		return fmt.Errorf("import spec rejected by target: %s", spec.Error[0].LocalizedMessage)
	}
	for _, w := range spec.Warning {
		logf("import-spec warning: %s", w.LocalizedMessage)
	}

	logf("requesting NFC import lease…")
	lease, err := rp.ImportVApp(ctx, spec.ImportSpec, folder, nil)
	if err != nil {
		return fmt.Errorf("import vApp (lease): %w", err)
	}
	info, err := lease.Wait(ctx, spec.FileItem)
	if err != nil {
		return fmt.Errorf("wait for lease: %w", err)
	}
	updater := lease.StartUpdater(ctx, info)
	defer updater.Done()

	for _, item := range info.Items {
		if err := uploadItem(ctx, lease, item, vmdkPath, logf, prog); err != nil {
			_ = lease.Abort(ctx, nil)
			return err
		}
	}
	if err := lease.Complete(ctx); err != nil {
		return fmt.Errorf("complete lease: %w", err)
	}
	logf("push complete — VM %q created on %s", name, u.Hostname())
	return nil
}

func uploadItem(ctx context.Context, lease *nfc.Lease, item nfc.FileItem, vmdkPath string, logf func(string, ...any), prog func(Progress)) error {
	f, err := os.Open(vmdkPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	logf("uploading %q (%d MiB) to target over NFC…", item.Path, size/(1<<20))
	pr := &progressReader{f: f, total: size, startT: time.Now(), prog: prog}
	return lease.Upload(ctx, item, pr, soap.Upload{ContentLength: size})
}

func pickDatacenter(ctx context.Context, f *find.Finder, name string) (*object.Datacenter, error) {
	if name != "" {
		return f.Datacenter(ctx, name)
	}
	dc, err := f.DefaultDatacenter(ctx)
	if err != nil {
		return nil, fmt.Errorf("find target datacenter (set one explicitly?): %w", err)
	}
	return dc, nil
}

func pickResourcePool(ctx context.Context, c *vim25.Client, f *find.Finder, name string) (*object.ResourcePool, error) {
	if name != "" {
		return f.ResourcePool(ctx, name)
	}
	// DefaultResourcePool works on a single-cluster target but errors with
	// "no default resource pool found" on a multi-cluster vCenter (the default
	// is ambiguous). Fall back to the first resource pool in the inventory —
	// every cluster/standalone host exposes a root pool — so a blank placement
	// still lands the VM somewhere valid.
	if rp, err := f.DefaultResourcePool(ctx); err == nil {
		return rp, nil
	}
	v, err := view.NewManager(c).CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"ResourcePool"}, true)
	if err != nil {
		return nil, fmt.Errorf("find target resource pool (set a cluster/pool?): %w", err)
	}
	defer func() { _ = v.Destroy(ctx) }()
	var pools []mo.ResourcePool
	if err := v.Retrieve(ctx, []string{"ResourcePool"}, []string{"name"}, &pools); err != nil || len(pools) == 0 {
		return nil, fmt.Errorf("find target resource pool (set a cluster/pool?): none found in inventory")
	}
	return object.NewResourcePool(c, pools[0].Reference()), nil
}

func pickDatastore(ctx context.Context, c *vim25.Client, f *find.Finder, name string) (*object.Datastore, error) {
	if name != "" {
		return f.Datastore(ctx, name)
	}
	// Like the resource pool, DefaultDatastore is ambiguous on a multi-datastore
	// target. Fall back to the accessible datastore with the most free space (a
	// safe default that avoids filling a small local datastore).
	if ds, err := f.DefaultDatastore(ctx); err == nil {
		return ds, nil
	}
	v, err := view.NewManager(c).CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"Datastore"}, true)
	if err != nil {
		return nil, fmt.Errorf("find target datastore (set one explicitly?): %w", err)
	}
	defer func() { _ = v.Destroy(ctx) }()
	var stores []mo.Datastore
	if err := v.Retrieve(ctx, []string{"Datastore"}, []string{"name", "summary"}, &stores); err != nil || len(stores) == 0 {
		return nil, fmt.Errorf("find target datastore (set one explicitly?): none found in inventory")
	}
	best := stores[0]
	for _, d := range stores[1:] {
		if d.Summary.Accessible && d.Summary.FreeSpace > best.Summary.FreeSpace {
			best = d
		}
	}
	return object.NewDatastore(c, best.Reference()), nil
}

// firstNetwork returns the first network in the inventory, used as the fallback
// when a blank target network is ambiguous on a multi-network vCenter. Only the
// returned object's Reference() (which carries the correct managed-object type,
// standard port group or DVPG) is consumed by the caller.
func firstNetwork(ctx context.Context, c *vim25.Client) (object.NetworkReference, error) {
	v, err := view.NewManager(c).CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"Network"}, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Destroy(ctx) }()
	var nets []mo.Network
	if err := v.Retrieve(ctx, []string{"Network"}, []string{"name"}, &nets); err != nil || len(nets) == 0 {
		return nil, fmt.Errorf("no network found in inventory")
	}
	return object.NewNetwork(c, nets[0].Reference()), nil
}

func pickFolder(ctx context.Context, f *find.Finder, dc *object.Datacenter, name string) (*object.Folder, error) {
	if name != "" {
		return f.Folder(ctx, name)
	}
	folders, err := dc.Folders(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve datacenter VM folder: %w", err)
	}
	return folders.VmFolder, nil
}

// progressReader counts bytes read and periodically reports rate.
type progressReader struct {
	f        *os.File
	total    int64
	done     int64
	startT   time.Time
	prog     func(Progress)
	lastTick time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.f.Read(b)
	p.done += int64(n)
	now := time.Now()
	if p.prog != nil && now.Sub(p.lastTick) >= time.Second {
		// Cumulative-average rate (stable, never flickers to 0 on a bursty read).
		var bps int64
		if el := now.Sub(p.startT).Seconds(); el > 0 {
			bps = int64(float64(p.done) / el)
		}
		p.prog(Progress{DoneBytes: p.done, TotalBytes: p.total, BytesPerSec: bps})
		p.lastTick = now
	}
	return n, err
}
