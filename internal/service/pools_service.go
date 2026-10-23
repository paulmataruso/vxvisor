package service

import (
	"fmt"

	"vdxclone/internal/lvm"
	"vdxclone/internal/zfs"
)

// ResolveDiskTarget maps a chosen storage pool (by registry id) to the disk
// backend fields CreateInput/session.Create expect, deriving the backend from the
// pool's kind so a caller only has to ask "which pool?". poolID <= 0 means the
// default disk directory (a qcow2 file). Used by the vCenter/ESXi import so a VM
// can land on ANY registered storage — dir(qcow2) / ZFS zvol / LVM thin / Ceph RBD
// — exactly like the create-instance form, but as a single choice.
func (s *Service) ResolveDiskTarget(p *Principal, poolID int64) (backend, zvolPool string, err error) {
	if poolID <= 0 {
		return "qcow2", "", nil // default disk directory
	}
	pools, err := s.ListPools(p)
	if err != nil {
		return "", "", err
	}
	for _, pl := range pools {
		if pl.ID != poolID {
			continue
		}
		switch pl.Kind {
		case "zfs":
			return "zvol", pl.Name, nil // ZvolPool is the zpool/dataset name
		case "lvm":
			return "lvm", "", nil
		case "rbd":
			return "rbd", "", nil
		default: // "dir" (and anything filesystem-like): a qcow2 file in the pool dir
			return "qcow2", "", nil
		}
	}
	return "", "", fmt.Errorf("storage pool %d not found", poolID)
}

// Backend availability (for conditional UI). No side effects, admin-gated.
func (s *Service) ZFSAvailable(p *Principal) bool { return p != nil && p.IsAdmin && zfs.Available() }
func (s *Service) LVMAvailable(p *Principal) bool { return p != nil && p.IsAdmin && lvm.Available() }

// ---- ZFS -----------------------------------------------------------------

func (s *Service) ZFSPools(p *Principal) ([]zfs.Pool, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return zfs.ListPools()
}

func (s *Service) ZFSStatus(p *Principal, name string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	return zfs.Status(name)
}

// ZFSStatusTree returns a parsed vdev tree for a pool (health view).
func (s *Service) ZFSStatusTree(p *Principal, name string) (zfs.PoolStatus, error) {
	if !p.IsAdmin {
		return zfs.PoolStatus{}, ErrUnauthorized
	}
	return zfs.StatusTree(name)
}

// ZFSReplace replaces a device in a pool (e.g. a failed disk).
func (s *Service) ZFSReplace(p *Principal, pool, oldDev, newDev string, force bool, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if d, note, used := deviceInUse([]string{newDev}); used {
		return fmt.Errorf("new device %s is in use (%s) — refusing to wipe", d, note)
	}
	if err := zfs.ReplaceDevice(pool, oldDev, newDev, force); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "zfs.replace", "zpool", pool, ip, map[string]any{"old": oldDev, "new": newDev})
	return nil
}

// ZFSAddCache adds L2ARC cache device(s) to a pool.
func (s *Service) ZFSAddCache(p *Principal, pool string, devices []string, force bool, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if d, note, used := deviceInUse(devices); used {
		return fmt.Errorf("device %s is in use (%s) — refusing to wipe", d, note)
	}
	if err := zfs.AddCache(pool, devices, force); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "zfs.add_cache", "zpool", pool, ip, map[string]any{"devices": devices})
	return nil
}

// ZFSAddLog adds a SLOG log device (optionally mirrored) to a pool.
func (s *Service) ZFSAddLog(p *Principal, pool string, devices []string, mirror, force bool, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if d, note, used := deviceInUse(devices); used {
		return fmt.Errorf("device %s is in use (%s) — refusing to wipe", d, note)
	}
	if err := zfs.AddLog(pool, devices, mirror, force); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "zfs.add_log", "zpool", pool, ip, map[string]any{"devices": devices, "mirror": mirror})
	return nil
}

func (s *Service) ZFSDatasets(p *Principal, pool string) ([]zfs.Dataset, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return zfs.ListDatasets(pool)
}

// CreateZFSPool builds a zpool and registers it as a storage pool so VMs can
// place disks on it. `force` wipes the chosen devices; the UI confirms first.
func (s *Service) CreateZFSPool(p *Principal, name, raid string, devices []string, force bool, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if d, note, used := deviceInUse(devices); used {
		return fmt.Errorf("device %s is in use (%s) — refusing to wipe", d, note)
	}
	if err := zfs.CreatePool(name, raid, devices, force); err != nil {
		return err
	}
	// Register as a dir-style pool rooted at the pool mountpoint (/name).
	_ = s.stg.UpsertPool(name, "zfs", "/"+name)
	s.audit(p, p.OrgID, "zfs.pool.create", "pool", name, ip,
		map[string]any{"raid": raid, "devices": devices})
	return nil
}

func (s *Service) DestroyZFSPool(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := zfs.DestroyPool(name); err != nil {
		return err
	}
	// Drop the registry row so it doesn't linger in "Registered pools".
	_ = s.stg.DeletePoolsByPath("/" + name)
	s.audit(p, p.OrgID, "zfs.pool.destroy", "pool", name, ip, nil)
	return nil
}

func (s *Service) CreateZFSDataset(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := zfs.CreateDataset(name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "zfs.dataset.create", "dataset", name, ip, nil)
	return nil
}

func (s *Service) DestroyZFSDataset(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := zfs.DestroyDataset(name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "zfs.dataset.destroy", "dataset", name, ip, nil)
	return nil
}

// ---- LVM thin ------------------------------------------------------------

func (s *Service) LVMThinPools(p *Principal) ([]lvm.ThinPool, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return lvm.ListThinPools()
}

// CreateLVMThinPool wipes the chosen devices into a VG + thin pool and registers
// it as a storage pool. Destructive; the UI confirms first.
func (s *Service) CreateLVMThinPool(p *Principal, vg, pool string, devices []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if d, note, used := deviceInUse(devices); used {
		return fmt.Errorf("device %s is in use (%s) — refusing to wipe", d, note)
	}
	if err := lvm.CreateThinPool(vg, pool, devices); err != nil {
		return err
	}
	_ = s.stg.UpsertPool(vg+"/"+pool, "lvm", "/dev/"+vg)
	s.audit(p, p.OrgID, "lvm.pool.create", "pool", vg+"/"+pool, ip,
		map[string]any{"vg": vg, "thinpool": pool, "devices": devices})
	return nil
}

// RemoveVG drops a volume group to free its disks (e.g. repurpose "vmstore" for
// ZFS). Destructive; the UI confirms first.
func (s *Service) RemoveVG(p *Principal, vg, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := lvm.RemoveVG(vg); err != nil {
		return err
	}
	// Drop any registry rows for pools that lived on this VG.
	_ = s.stg.DeletePoolsByPath("/dev/" + vg)
	s.audit(p, p.OrgID, "lvm.vg.remove", "vg", vg, ip, nil)
	return nil
}

// DeleteStoragePool removes a registered storage pool entry (the registry row
// only; it does not touch any underlying ZFS/LVM backend). Admin only.
func (s *Service) DeleteStoragePool(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.stg.DeletePool(name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "pool.delete", "pool", name, ip, nil)
	return nil
}
