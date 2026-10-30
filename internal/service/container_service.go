package service

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"vdxclone/internal/lxc"
	"vdxclone/internal/netdrv"
)

// LXC system containers. Managed alongside QEMU VMs but tracked in their own
// table. Creation downloads a rootfs (slow) so it runs asynchronously with a
// 'creating' status, mirroring the ISO-pull pattern.

type ContainerRow struct {
	ID        int64
	Name      string
	OrgID     int64
	Dist      string
	Release   string
	Arch      string
	Lxcpath   string
	Bridge    string // resolved host bridge (display / topology); never client input
	NetworkID int64  // port group (networks.id) the NIC is on; 0 = lxcbr0 NAT (Default org) / legacy
	CPUs      int
	MemoryMB  int
	Status    string // creating|stopped|error (DB)
	CreatedAt string
	Storage   string // backend + pool/target of the rootfs (from the lxc config)
	// live (from lxc-info)
	State    string
	PID      int
	IP       string
	MemBytes int64
}

func (s *Service) LXCAvailable(p *Principal) bool { return p != nil && lxc.Available() }

func (s *Service) ListContainers(p *Principal) ([]ContainerRow, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	q := `SELECT id,name,org_id,dist,release,arch,lxcpath,bridge,COALESCE(network_id,0),cpus,memory_mb,status,created_at FROM containers`
	args := []any{}
	if !p.IsAdmin {
		q += ` WHERE org_id=?`
		args = append(args, p.OrgID)
	}
	q += ` ORDER BY name`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContainerRow
	for rows.Next() {
		var c ContainerRow
		if rows.Scan(&c.ID, &c.Name, &c.OrgID, &c.Dist, &c.Release, &c.Arch, &c.Lxcpath, &c.Bridge, &c.NetworkID, &c.CPUs, &c.MemoryMB, &c.Status, &c.CreatedAt) != nil {
			continue
		}
		if c.Status != "creating" && c.Status != "error" {
			info, _ := lxc.Info(c.Name, c.Lxcpath)
			c.State, c.PID, c.IP, c.MemBytes = info.State, info.PID, info.IP, info.MemBytes
			c.Storage = lxc.StorageLabel(c.Name, c.Lxcpath)
		} else {
			c.State = c.Status
		}
		out = append(out, c)
	}
	return out, nil
}

// CreateContainerInput carries the create-container form fields.
type CreateContainerInput struct {
	Name          string
	Dist          string
	Release       string
	NetworkID     int64 // a port group of the caller's org; 0 = lxcbr0 NAT (Default org only)
	CPUs          int
	MemoryMB      int
	StoragePoolID int64
	DiskGB        int // rootfs size for an RBD-backed container (GiB; default 10)
	Copies        int // >1 creates that many independent containers with generated names
}

// maxContainerCopies caps a single multi-create request.
const maxContainerCopies = 50

func (s *Service) CreateContainer(p *Principal, in CreateContainerInput, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if !lxc.Available() {
		return fmt.Errorf("LXC is not installed on this host")
	}
	in.Name, in.Dist, in.Release = strings.TrimSpace(in.Name), strings.TrimSpace(in.Dist), strings.TrimSpace(in.Release)
	if in.Name == "" || in.Dist == "" || in.Release == "" {
		return fmt.Errorf("name, distribution and release are required")
	}
	if err := lxc.ValidTemplateArg("distribution", in.Dist); err != nil {
		return fmt.Errorf("%w — pick a distribution from the list", err)
	}
	if err := lxc.ValidTemplateArg("release", in.Release); err != nil {
		return fmt.Errorf("%w — pick a release from the list", err)
	}
	if in.CPUs <= 0 {
		in.CPUs = 1
	}
	if in.MemoryMB <= 0 {
		in.MemoryMB = 512
	}
	if err := checkContainerLimits(in.CPUs, in.MemoryMB); err != nil {
		return err
	}
	if in.DiskGB < 0 || in.DiskGB > maxContainerDiskGB {
		return fmt.Errorf("root disk must be 1-%d GB", maxContainerDiskGB)
	}
	copies := in.Copies
	if copies <= 0 {
		copies = 1
	}
	if copies > maxContainerCopies {
		return fmt.Errorf("at most %d copies at a time", maxContainerCopies)
	}
	// The NIC lands on a port group the org owns, resolved here — never a bridge
	// name from the request (that let a member pick the management bridge or
	// another tenant's bridge, or inject lxc.* keys through the value).
	nic, err := s.resolveContainerNIC(p.OrgID, in.NetworkID)
	if err != nil {
		return err
	}
	// rootfs location: a chosen storage pool decides where the rootfs lives. A
	// block pool (rbd / lvm — no filesystem directory) puts the rootfs on a volume
	// liblxc provisions via its native backing store; a dir/zfs pool uses a
	// directory under the pool's path.
	lxcpath := ""
	rbdPool, lvmVG, lvmThin := "", "", ""
	if in.StoragePoolID > 0 {
		var kind, pname, ppath string
		if err := s.db.QueryRow(`SELECT kind, name, COALESCE(path,'') FROM storage_pools WHERE id=?`, in.StoragePoolID).Scan(&kind, &pname, &ppath); err != nil {
			return fmt.Errorf("unknown storage pool — pick one from the list")
		}
		switch kind {
		case "rbd":
			rbdPool = ppath // the Ceph pool name
		case "lvm":
			// Pool name is "<vg>/<thinpool>" (same convention as the VM LVM backend).
			if vg, tp, ok := strings.Cut(pname, "/"); ok {
				lvmVG, lvmThin = vg, tp
			} else {
				lvmVG = pname
			}
		default: // dir / zfs — a real directory path
			if ppath != "" {
				lxcpath = filepath.Join(ppath, "lxc")
			}
		}
	}

	// Generate the independent names up front and refuse the whole batch if any
	// would collide with an existing container (so we never create a partial set
	// under surprising names).
	names := expandContainerNames(in.Name, copies)
	for _, n := range names {
		if err := lxc.ValidName(n); err != nil {
			return err
		}
		var exists int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM containers WHERE name=?`, n).Scan(&exists)
		if exists > 0 {
			return fmt.Errorf("a container named %q already exists", n)
		}
	}

	// Insert every row as 'creating' so the UI shows the whole batch immediately.
	type pending struct {
		id   int64
		name string
		mac  string
	}
	var batch []pending
	for _, n := range names {
		mac := netdrv.GenMAC()
		res, err := s.db.Exec(`INSERT INTO containers(name,org_id,owner_id,dist,release,arch,lxcpath,bridge,network_id,cpus,memory_mb,status)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,'creating')`,
			n, p.OrgID, p.User.ID, in.Dist, in.Release, "amd64", lxcpath, nic.Bridge, nic.NetworkID, in.CPUs, in.MemoryMB)
		if err != nil {
			// Roll back the rows we already inserted for this batch.
			for _, b := range batch {
				_, _ = s.db.Exec(`DELETE FROM containers WHERE id=?`, b.id)
			}
			return fmt.Errorf("a container named %q already exists", n)
		}
		id, _ := res.LastInsertId()
		batch = append(batch, pending{id: id, name: n, mac: mac})
		if nic.FabricLease {
			if _, err := s.FabricIPAM().Lease(nic.NetworkID, containerLeaseKey(id), mac); err != nil {
				for _, b := range batch {
					s.FabricIPAM().Release(containerLeaseKey(b.id))
					_, _ = s.db.Exec(`DELETE FROM containers WHERE id=?`, b.id)
				}
				return fmt.Errorf("container %s: %w", n, err)
			}
		}
	}
	s.audit(p, p.OrgID, "container.create", "container", in.Name, ip,
		map[string]any{"dist": in.Dist, "release": in.Release, "copies": copies, "network_id": nic.NetworkID, "bridge": nic.Bridge})

	// Build them sequentially in one goroutine: the first lxc-create downloads
	// the rootfs template, the rest reuse the cache — serial avoids concurrent
	// download races and resource spikes.
	go func() {
		for _, b := range batch {
			err := lxc.Create(lxc.CreateOpts{
				Name: b.name, Lxcpath: lxcpath, Dist: in.Dist, Release: in.Release,
				Arch: "amd64", Bridge: nic.Bridge, VLAN: nic.VLAN, MTU: nic.MTU,
				MAC: b.mac, CPUs: in.CPUs, MemMB: in.MemoryMB,
				RBDPool: rbdPool, LVMVG: lvmVG, LVMThin: lvmThin,
				BlockName: "lxc-" + b.name, SizeG: in.DiskGB,
			})
			if err != nil {
				log.Printf("container %s: create failed: %v", b.name, err)
				_, _ = s.db.Exec(`UPDATE containers SET status='error' WHERE id=?`, b.id)
				continue
			}
			_, _ = s.db.Exec(`UPDATE containers SET status='stopped' WHERE id=?`, b.id)
		}
	}()
	return nil
}

// expandContainerNames turns a base name + count into n distinct names. If the
// base ends in digits, those are incremented preserving zero-pad width
// (web01, n=3 → web01, web02, web03). Otherwise a zero-padded suffix is appended
// (web, n=3 → web-1, web-2, web-3). A single copy keeps the exact name typed.
func expandContainerNames(base string, n int) []string {
	if n <= 1 {
		return []string{base}
	}
	// Split a trailing digit run off the base.
	i := len(base)
	for i > 0 && base[i-1] >= '0' && base[i-1] <= '9' {
		i--
	}
	out := make([]string, 0, n)
	if i < len(base) {
		prefix, numStr := base[:i], base[i:]
		width := len(numStr)
		start, _ := strconv.Atoi(numStr)
		for k := 0; k < n; k++ {
			num := strconv.Itoa(start + k)
			for len(num) < width {
				num = "0" + num
			}
			out = append(out, prefix+num)
		}
		return out
	}
	// No trailing number: width scales with the count (n=10 → -01..-10).
	width := len(strconv.Itoa(n))
	for k := 1; k <= n; k++ {
		num := strconv.Itoa(k)
		for len(num) < width {
			num = "0" + num
		}
		out = append(out, base+"-"+num)
	}
	return out
}

// containerByID loads an org-scoped container row.
func (s *Service) containerByID(p *Principal, id int64) (ContainerRow, error) {
	var c ContainerRow
	q := `SELECT id,name,org_id,lxcpath,bridge,COALESCE(network_id,0),cpus,memory_mb,status FROM containers WHERE id=?`
	if err := s.db.QueryRow(q, id).Scan(&c.ID, &c.Name, &c.OrgID, &c.Lxcpath, &c.Bridge, &c.NetworkID, &c.CPUs, &c.MemoryMB, &c.Status); err != nil {
		return c, ErrNotFound
	}
	if !p.IsAdmin && c.OrgID != p.OrgID {
		return c, ErrUnauthorized
	}
	return c, nil
}

// ContainerConsole authorizes and returns the lxc-attach command to open an
// interactive shell in the container, plus its display name. Errors if the
// container isn't running. The web layer wires the command to a PTY↔websocket.
func (s *Service) ContainerConsole(p *Principal, id int64) (*exec.Cmd, string, error) {
	c, err := s.containerByID(p, id)
	if err != nil {
		return nil, "", err
	}
	info, _ := lxc.Info(c.Name, c.Lxcpath)
	if info.State != "RUNNING" {
		return nil, "", fmt.Errorf("container is not running")
	}
	return lxc.ConsoleCmd(c.Name, c.Lxcpath), c.Name, nil
}

// UpdateContainer moves a container to another of its org's port groups and
// changes its CPU/memory limits. The port group is resolved server-side to a
// bridge + VLAN (+ MTU) exactly as on create. On a running container the move
// is applied LIVE — the host-side veth is re-mastered onto the new bridge with
// the port group's VLAN as its access PVID (no restart) — and persisted to the
// config + DB. A move onto a lower-MTU bridge (e.g. a VXLAN port group) can't
// shrink the in-container NIC live, so it takes effect at the next start.
// CPU/memory are updated live via cgroup2 and persisted for next boot.
func (s *Service) UpdateContainer(p *Principal, id, networkID int64, cpus, memMB int, ip string) error {
	c, err := s.containerByID(p, id)
	if err != nil {
		return err
	}
	if c.Status == "creating" {
		return fmt.Errorf("container %s is still being created — wait for it to finish", c.Name)
	}
	if cpus < 1 {
		cpus = c.CPUs
	}
	if memMB < 1 {
		memMB = c.MemoryMB
	}
	if err := checkContainerLimits(cpus, memMB); err != nil {
		return err
	}
	// Resolve against the CONTAINER's org (an instance admin may be editing
	// another org's container), never the viewer's.
	nic, err := s.resolveContainerNIC(c.OrgID, networkID)
	if err != nil {
		return err
	}
	if nic.FabricLease && nic.NetworkID != c.NetworkID {
		mac := lxc.ConfigMAC(c.Name, c.Lxcpath)
		if mac == "" {
			return fmt.Errorf("container %s has no fixed MAC address, which a fabric port group's lease needs — recreate it on that port group", c.Name)
		}
		if _, err := s.FabricIPAM().Lease(nic.NetworkID, containerLeaseKey(id), mac); err != nil {
			return err
		}
	}
	if err := lxc.UpdateManaged(c.Name, c.Lxcpath, nic.Bridge, nic.VLAN, nic.MTU, cpus, memMB); err != nil {
		if nic.FabricLease && nic.NetworkID != c.NetworkID {
			s.FabricIPAM().ReleaseOn(containerLeaseKey(id), nic.NetworkID)
		}
		return fmt.Errorf("update container config: %w", err)
	}
	if c.NetworkID != 0 && c.NetworkID != nic.NetworkID {
		s.FabricIPAM().ReleaseOn(containerLeaseKey(id), c.NetworkID) // no-op unless it was a fabric port group
	}
	lxc.SetLimits(c.Name, c.Lxcpath, cpus, memMB)
	if _, err := s.db.Exec(`UPDATE containers SET bridge=?, network_id=?, cpus=?, memory_mb=? WHERE id=?`,
		nic.Bridge, nic.NetworkID, cpus, memMB, id); err != nil {
		return err
	}
	s.audit(p, c.OrgID, "container.update", "container", c.Name, ip,
		map[string]any{"network_id": nic.NetworkID, "bridge": nic.Bridge, "vlan": nic.VLAN, "cpus": cpus, "mem_mb": memMB})
	// Live move (the host-side veth only exists while the container runs).
	veth := lxc.VethName(c.Name)
	if !netdrv.IfaceExists(veth) {
		return nil
	}
	want := nic.MTU
	if want == 0 {
		want = 1500
	}
	if cur := netdrv.LinkMTU(veth); cur > want {
		log.Printf("container %s: moved to %s in config; MTU %d→%d applies at next start", c.Name, nic.Bridge, cur, want)
		return nil
	}
	if err := netdrv.RebindTap(veth, nic.Bridge, nic.VLAN); err != nil {
		return fmt.Errorf("saved, but moving the running container failed (%v) — restart it to apply the new network", err)
	}
	return nil
}

func (s *Service) StartContainer(p *Principal, id int64, ip string) error {
	c, err := s.containerByID(p, id)
	if err != nil {
		return err
	}
	if err := s.checkContainerAttach(&c); err != nil {
		return err
	}
	if err := lxc.Start(c.Name, c.Lxcpath); err != nil {
		return err
	}
	lxc.SetLimits(c.Name, c.Lxcpath, c.CPUs, c.MemoryMB)
	s.audit(p, p.OrgID, "container.start", "container", c.Name, ip, nil)
	return nil
}

func (s *Service) StopContainer(p *Principal, id int64, ip string) error {
	c, err := s.containerByID(p, id)
	if err != nil {
		return err
	}
	if err := lxc.Stop(c.Name, c.Lxcpath); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "container.stop", "container", c.Name, ip, nil)
	return nil
}

func (s *Service) DeleteContainer(p *Principal, id int64, ip string) error {
	c, err := s.containerByID(p, id)
	if err != nil {
		return err
	}
	_ = lxc.Destroy(c.Name, c.Lxcpath)
	if _, err := s.db.Exec(`DELETE FROM containers WHERE id=?`, id); err != nil {
		return err
	}
	s.FabricIPAM().Release(containerLeaseKey(id))
	s.audit(p, p.OrgID, "container.delete", "container", c.Name, ip, nil)
	return nil
}

func (s *Service) SnapshotContainer(p *Principal, id int64, ip string) error {
	c, err := s.containerByID(p, id)
	if err != nil {
		return err
	}
	if err := lxc.Snapshot(c.Name, c.Lxcpath); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "container.snapshot", "container", c.Name, ip, nil)
	return nil
}

func (s *Service) ContainerSnapshots(p *Principal, id int64) ([]string, error) {
	c, err := s.containerByID(p, id)
	if err != nil {
		return nil, err
	}
	return lxc.ListSnapshots(c.Name, c.Lxcpath)
}

// lxcDefaultBridge is LXC's own NAT bridge (lxc-net). Every container on the
// host can sit on it, so it is the Default (provider) org's fallback only.
const lxcDefaultBridge = "lxcbr0"

// maxContainerDiskGB bounds the RBD/LVM rootfs size a create may ask for.
const maxContainerDiskGB = 16384

var errTenantNoContainerPG = errors.New("containers in this organization must be attached to one of its own port groups (LXC's shared lxcbr0 NAT isn't available to tenant organizations) — choose one of the organization's port groups")

// containerNIC is where a container's NIC lands, resolved server-side.
type containerNIC struct {
	NetworkID int64
	Bridge    string
	VLAN      int // access VLAN on a vlan_filtering vSwitch (0 = untagged)
	MTU       int // the bridge's MTU when below 1500 (VXLAN), else 0

	FabricLease bool // a routed VXVisor Fabric port group: lease the address
}

// containerLeaseKey is a container's owner key for fabric leases.
func containerLeaseKey(id int64) string { return "container-" + strconv.FormatInt(id, 10) }

// resolveContainerNIC maps a port-group choice to the bridge (+ VLAN, MTU) a
// container of orgID attaches to. networkID 0 is LXC's lxcbr0 NAT, which every
// container on the host shares — the Default org keeps it, a tenant org must
// use one of its own vSwitch-backed port groups.
func (s *Service) resolveContainerNIC(orgID, networkID int64) (containerNIC, error) {
	if networkID == 0 {
		if s.TenantOrg(orgID) {
			return containerNIC{}, errTenantNoContainerPG
		}
		return containerNIC{Bridge: lxcDefaultBridge}, nil
	}
	n, err := s.net.GetNetwork(orgID, networkID)
	if err != nil {
		return containerNIC{}, fmt.Errorf("unknown port group — choose one of the organization's port groups")
	}
	if n.Bridge == "" {
		return containerNIC{}, fmt.Errorf("port group %q is user-mode NAT with no vSwitch — containers need a vSwitch-backed port group", n.Name)
	}
	if !netdrv.IfaceExists(n.Bridge) {
		return containerNIC{}, fmt.Errorf("port group %q's vSwitch (%s) isn't up on this host — check Networking, then try again", n.Name, n.Bridge)
	}
	// A routed fabric port group serves only fabric-wide leases (its bridge
	// guard admits only leased MAC/address pairs): the container gets one.
	nic := containerNIC{NetworkID: n.ID, Bridge: n.Bridge, VLAN: n.VLANID, FabricLease: n.Mode == "fabric" && n.CIDR != ""}
	if mtu := netdrv.LinkMTU(n.Bridge); mtu > 0 && mtu < 1500 {
		nic.MTU = mtu
	}
	return nic, nil
}

// checkContainerAttach is the start-time backstop: a tenant org's container
// must be on one of its own port groups, and that port group must still exist
// on the bridge in the container's config. A legacy tenant container (created
// before port groups, network_id 0) is adopted onto the org's untagged port
// group for its bridge when there is one; otherwise it must be edited onto a
// port group first.
func (s *Service) checkContainerAttach(c *ContainerRow) error {
	if c.NetworkID == 0 {
		if !s.TenantOrg(c.OrgID) {
			return nil
		}
		var nid int64
		if c.Bridge != "" {
			_ = s.db.QueryRow(`SELECT id FROM networks WHERE org_id=? AND bridge=? AND COALESCE(vlan_id,0)=0 ORDER BY id LIMIT 1`,
				c.OrgID, c.Bridge).Scan(&nid)
		}
		if nid == 0 {
			return fmt.Errorf("container %s isn't attached to one of its organization's port groups — edit it and choose a port group", c.Name)
		}
		if _, err := s.db.Exec(`UPDATE containers SET network_id=? WHERE id=?`, nid, c.ID); err != nil {
			return err
		}
		c.NetworkID = nid
		return nil
	}
	n, err := s.net.GetNetwork(c.OrgID, c.NetworkID)
	if err != nil || n.Bridge == "" || n.Bridge != c.Bridge {
		return fmt.Errorf("container %s's port group no longer exists or has changed — edit it and choose a port group", c.Name)
	}
	return nil
}

// checkContainerLimits bounds vCPUs (the cpuset is 0..cpus-1, so it can't
// exceed the host) and memory.
func checkContainerLimits(cpus, memMB int) error {
	if n := runtime.NumCPU(); cpus > n {
		return fmt.Errorf("this host has %d CPUs — choose at most %d vCPUs", n, n)
	}
	if memMB < 64 {
		return fmt.Errorf("memory must be at least 64 MB")
	}
	return nil
}

// ContainerPortGroups lists the port groups a container of orgID may attach to
// (vSwitch-backed ones only; LXC needs a bridge). Only an instance admin may
// list another org's.
func (s *Service) ContainerPortGroups(p *Principal, orgID int64) ([]netdrv.Network, error) {
	if !p.atLeast("member") || (!p.IsAdmin && orgID != p.OrgID) {
		return nil, ErrUnauthorized
	}
	all, err := s.net.ListNetworks(orgID)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, n := range all {
		if n.Bridge != "" {
			out = append(out, n)
		}
	}
	return out, nil
}
