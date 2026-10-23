package service

import (
	"fmt"

	"vdxclone/internal/ceph"
)

// Hyperconverged Ceph (RBD). VXVisor stands up a Ceph cluster ON the nodes from
// native packages and backs VM disks with RBD. The SAME hard rules as the other
// storage backends apply: admin-only, the Ceph public/cluster network must ride
// the dedicated storage interface (never the mgmt NIC), and any disk consumed as
// an OSD is guarded by deviceInUse so a bootstrap can never wipe the boot disk or
// a live pool member.

const (
	cephBootstrappedKey = "ceph_bootstrapped"
	cephPoolKey         = "ceph_pool"
)

// CephAvailable reports whether the Ceph SERVER tooling is installed (admin UI gate).
func (s *Service) CephAvailable(p *Principal) bool {
	return p != nil && p.IsAdmin && ceph.Available()
}

// CephStatus returns a compact cluster snapshot for the Ceph page.
func (s *Service) CephStatus(p *Principal) (ceph.Health, error) {
	if !p.IsAdmin {
		return ceph.Health{}, ErrUnauthorized
	}
	return ceph.Status(), nil
}

// CephPool returns the name of the registered RBD pool ("" when none).
func (s *Service) CephPool() string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, cephPoolKey).Scan(&v)
	return v
}

// HasCephPool reports whether a usable RBD pool is registered (enables the "rbd"
// VM disk backend in the create UI).
func (s *Service) HasCephPool(p *Principal) bool {
	if p == nil || !p.IsAdmin {
		return false
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM storage_pools WHERE kind='rbd'`).Scan(&n)
	return n > 0
}

// BootstrapCeph stands up a single-node hyperconverged cluster: it brings up the
// first mon+mgr, consumes osdDisk as the first OSD, creates the RBD pool, wires a
// pool-scoped cephx client for QEMU, and registers the pool as a storage pool so
// VMs can place disks on it. DESTRUCTIVE on osdDisk; the UI confirms first.
func (s *Service) BootstrapCeph(p *Principal, poolName, osdDisk, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if !ceph.Available() {
		return fmt.Errorf("Ceph server tools are not installed on this host")
	}
	if poolName == "" {
		poolName = "rbd"
	}
	if osdDisk == "" {
		return fmt.Errorf("choose a disk to consume as the first OSD")
	}
	// The Ceph public/cluster network must ride the dedicated storage interface —
	// same rule as NFS/CIFS/iSCSI. storageNet() refuses when none is configured.
	_, monIP, subnet, err := s.storageNet()
	if err != nil {
		return err
	}
	// Never wipe an in-use disk (OS/boot/live pool member). A disk that is already
	// THIS cluster's OSD is exempt — otherwise a bootstrap that failed after the
	// OSD was added could never be retried (the disk now reads as "in use"), and
	// the remaining steps (pool/keyring/registration) are all idempotent anyway.
	if !ceph.DiskIsOSD(osdDisk) {
		if d, note, used := deviceInUse([]string{osdDisk}); used {
			return fmt.Errorf("disk %s is in use (%s) — refusing to wipe it for an OSD", d, note)
		}
	}
	// Single node today ⇒ replica size 1 (non-redundant until a 2nd node joins).
	size := 1
	if err := ceph.Bootstrap(ceph.BootstrapSpec{
		MonHost: monIP, PublicNetwork: subnet.String(), PoolSize: size,
	}); err != nil {
		return fmt.Errorf("bootstrap mon/mgr: %w", err)
	}
	s.audit(p, p.OrgID, "ceph.bootstrap", "ceph", "cluster", ip, map[string]any{"mon": monIP, "net": subnet.String()})

	if err := ceph.AddOSD(osdDisk); err != nil {
		return fmt.Errorf("add first OSD: %w", err)
	}
	s.audit(p, p.OrgID, "ceph.osd.add", "ceph", osdDisk, ip, nil)

	if err := ceph.CreatePool(poolName, size); err != nil {
		return fmt.Errorf("create RBD pool: %w", err)
	}
	if _, err := ceph.EnsureClientKeyring(poolName); err != nil {
		return fmt.Errorf("provision RBD client keyring: %w", err)
	}
	// Register the pool as a storage pool (path holds the Ceph pool name; usage is
	// overlaid from `ceph df` in ListPools since it is not a filesystem).
	if err := s.stg.UpsertPool(poolName, "rbd", poolName); err != nil {
		return err
	}
	_, _ = s.db.Exec(`INSERT INTO settings(key,value) VALUES(?, '1')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, cephBootstrappedKey)
	_, _ = s.db.Exec(`INSERT INTO settings(key,value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, cephPoolKey, poolName)
	s.audit(p, p.OrgID, "ceph.pool.create", "pool", poolName, ip, map[string]any{"size": size})
	return nil
}

// CephDiskReclaimable reports whether a disk can be cleared for reuse via the UI:
// it carries Ceph OSD remnants AND is not currently mounted. Returns a short note
// for the button tooltip. Works with the cluster stopped.
func (s *Service) CephDiskReclaimable(disk string) (bool, string) {
	taint, note := ceph.CephDiskRemnant(disk)
	if !taint {
		return false, ""
	}
	if m := diskMountNote(disk); m != "" {
		return false, "" // active/mounted → never offer a wipe
	}
	return true, note
}

// ClearCephDisk wipes a disk left behind by a removed Ceph OSD so it can be reused
// (tear down its LVM + wipe signatures + zap the partition table). It works even
// when Ceph is stopped, so a user is never stuck with an unusable disk. DESTRUCTIVE
// — the UI double-confirms. It refuses a mounted disk or one with no Ceph remnants,
// so it can never nuke a live pool member or the boot disk.
func (s *Service) ClearCephDisk(p *Principal, disk, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if disk == "" {
		return fmt.Errorf("choose a disk to clear")
	}
	if !validDiskPath(disk) {
		return fmt.Errorf("unknown disk %q", disk)
	}
	if m := diskMountNote(disk); m != "" {
		return fmt.Errorf("disk %s is %s — unmount/stop it before clearing", disk, m)
	}
	if taint, _ := ceph.CephDiskRemnant(disk); !taint {
		return fmt.Errorf("disk %s has no Ceph remnants to clear", disk)
	}
	if err := ceph.ZapDisk(disk); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "ceph.disk.clear", "disk", disk, ip, nil)
	return nil
}

// AddCephOSD consumes another whole disk as an OSD (grow raw capacity). Same
// deviceInUse guard as bootstrap. DESTRUCTIVE; the UI confirms first.
func (s *Service) AddCephOSD(p *Principal, disk, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if !ceph.Bootstrapped() {
		return fmt.Errorf("no Ceph cluster is running — bootstrap one first")
	}
	if d, note, used := deviceInUse([]string{disk}); used {
		return fmt.Errorf("disk %s is in use (%s) — refusing to wipe it for an OSD", d, note)
	}
	if err := ceph.AddOSD(disk); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "ceph.osd.add", "ceph", disk, ip, nil)
	return nil
}
