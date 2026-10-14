package service

import (
	"fmt"
	"path/filepath"

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
}

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
	// rootfs location: a chosen storage pool's path (under /lxc), else default.
	lxcpath := ""
	if in.StoragePoolID > 0 {
		var ppath string
		if err := s.db.QueryRow(`SELECT COALESCE(path,'') FROM storage_pools WHERE id=?`, in.StoragePoolID).Scan(&ppath); err == nil && ppath != "" {
			lxcpath = filepath.Join(ppath, "lxc")
		}
	}
	bridge := in.Bridge
	mac := netdrv.GenMAC()
	res, err := s.db.Exec(`INSERT INTO containers(name,org_id,owner_id,dist,release,arch,lxcpath,bridge,cpus,memory_mb,status)
		VALUES(?,?,?,?,?,?,?,?,?,?,'creating')`,
		in.Name, p.OrgID, p.User.ID, in.Dist, in.Release, "amd64", lxcpath, bridge, in.CPUs, in.MemoryMB)
	if err != nil {
		return fmt.Errorf("a container named %q already exists", in.Name)
	}
	id, _ := res.LastInsertId()
	s.audit(p, p.OrgID, "container.create", "container", in.Name, ip, map[string]any{"dist": in.Dist, "release": in.Release})
	// Download + build asynchronously; flip status when done.
	go func() {
		if err := lxc.Create(in.Name, lxcpath, in.Dist, in.Release, "amd64", bridge, mac, in.CPUs, in.MemoryMB); err != nil {
			_, _ = s.db.Exec(`UPDATE containers SET status='error' WHERE id=?`, id)
			return
		}
		_, _ = s.db.Exec(`UPDATE containers SET status='stopped' WHERE id=?`, id)
	}()
	return nil
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
