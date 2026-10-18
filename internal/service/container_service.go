package service

import (
	"fmt"
	"os/exec"
	"path/filepath"
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
	Bridge    string
	CPUs      int
	MemoryMB  int
	Status    string // creating|stopped|error (DB)
	CreatedAt string
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
	q := `SELECT id,name,org_id,dist,release,arch,lxcpath,bridge,cpus,memory_mb,status,created_at FROM containers`
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
		if rows.Scan(&c.ID, &c.Name, &c.OrgID, &c.Dist, &c.Release, &c.Arch, &c.Lxcpath, &c.Bridge, &c.CPUs, &c.MemoryMB, &c.Status, &c.CreatedAt) != nil {
			continue
		}
		if c.Status != "creating" && c.Status != "error" {
			info, _ := lxc.Info(c.Name, c.Lxcpath)
			c.State, c.PID, c.IP, c.MemBytes = info.State, info.PID, info.IP, info.MemBytes
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
	Bridge        string
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
	if in.Name == "" || in.Dist == "" || in.Release == "" {
		return fmt.Errorf("name, distribution and release are required")
	}
	if in.CPUs <= 0 {
		in.CPUs = 1
	}
	if in.MemoryMB <= 0 {
		in.MemoryMB = 512
	}
	copies := in.Copies
	if copies <= 0 {
		copies = 1
	}
	if copies > maxContainerCopies {
		return fmt.Errorf("at most %d copies at a time", maxContainerCopies)
	}
	// rootfs location: a chosen storage pool decides where the rootfs lives. A
	// block pool (rbd / lvm — no filesystem directory) puts the rootfs on a volume
	// liblxc provisions via its native backing store; a dir/zfs pool uses a
	// directory under the pool's path.
	lxcpath := ""
	rbdPool, lvmVG, lvmThin := "", "", ""
	if in.StoragePoolID > 0 {
		var kind, pname, ppath string
		if err := s.db.QueryRow(`SELECT kind, name, COALESCE(path,'') FROM storage_pools WHERE id=?`, in.StoragePoolID).Scan(&kind, &pname, &ppath); err == nil {
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
	}
	bridge := in.Bridge

	// Generate the independent names up front and refuse the whole batch if any
	// would collide with an existing container (so we never create a partial set
	// under surprising names).
	names := expandContainerNames(in.Name, copies)
	for _, n := range names {
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
		res, err := s.db.Exec(`INSERT INTO containers(name,org_id,owner_id,dist,release,arch,lxcpath,bridge,cpus,memory_mb,status)
			VALUES(?,?,?,?,?,?,?,?,?,?,'creating')`,
			n, p.OrgID, p.User.ID, in.Dist, in.Release, "amd64", lxcpath, bridge, in.CPUs, in.MemoryMB)
		if err != nil {
			// Roll back the rows we already inserted for this batch.
			for _, b := range batch {
				_, _ = s.db.Exec(`DELETE FROM containers WHERE id=?`, b.id)
			}
			return fmt.Errorf("a container named %q already exists", n)
		}
		id, _ := res.LastInsertId()
		batch = append(batch, pending{id: id, name: n, mac: mac})
	}
	s.audit(p, p.OrgID, "container.create", "container", in.Name, ip,
		map[string]any{"dist": in.Dist, "release": in.Release, "copies": copies})

	// Build them sequentially in one goroutine: the first lxc-create downloads
	// the rootfs template, the rest reuse the cache — serial avoids concurrent
	// download races and resource spikes.
	go func() {
		for _, b := range batch {
			err := lxc.Create(lxc.CreateOpts{
				Name: b.name, Lxcpath: lxcpath, Dist: in.Dist, Release: in.Release,
				Arch: "amd64", Bridge: bridge, MAC: b.mac, CPUs: in.CPUs, MemMB: in.MemoryMB,
				RBDPool: rbdPool, LVMVG: lvmVG, LVMThin: lvmThin,
				BlockName: "lxc-" + b.name, SizeG: in.DiskGB,
			})
			if err != nil {
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
	q := `SELECT id,name,org_id,lxcpath,cpus,memory_mb,status FROM containers WHERE id=?`
	if err := s.db.QueryRow(q, id).Scan(&c.ID, &c.Name, &c.OrgID, &c.Lxcpath, &c.CPUs, &c.MemoryMB, &c.Status); err != nil {
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

func (s *Service) StartContainer(p *Principal, id int64, ip string) error {
	c, err := s.containerByID(p, id)
	if err != nil {
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
