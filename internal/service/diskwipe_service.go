package service

import (
	"fmt"

	"vdxclone/internal/ceph"
	"vdxclone/internal/hostinfo"
)

// WipeDisk erases a whole disk so it becomes a free, usable device again. It is
// the general "initialize disk" the UI offers for a used disk swapped into the
// host that still carries an inert, foreign partition table/filesystem (an old
// Windows/data install, dead Ceph, etc.) — the case the Ceph-only "Clear for
// reuse" never covered.
//
// Guards (defense in depth; the UI only shows the button for wipeable disks):
//   - admin only;
//   - the path must be a real whole disk on this host;
//   - the disk (or a child) must NOT be mounted;
//   - the disk must NOT be part of an active LVM/RAID/LUKS stack — those must be
//     torn down through their own flow, not blind-wiped (this is what keeps the
//     OS disk and the VMSTORE/pool disks safe).
//
// The wipe itself reuses ceph.ZapDisk (wipefs -a + sgdisk --zap-all + zero the
// first/last MiB + partprobe); its Ceph/LVM-specific steps simply no-op on a
// plain foreign disk. DESTRUCTIVE and irreversible; the UI confirms twice.
func (s *Service) WipeDisk(p *Principal, disk, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if disk == "" {
		return fmt.Errorf("choose a disk to wipe")
	}
	if !validDiskPath(disk) {
		return fmt.Errorf("unknown disk %q", disk)
	}
	if m := diskMountNote(disk); m != "" {
		return fmt.Errorf("disk %s is %s — unmount it before wiping", disk, m)
	}
	devs, _ := hostinfo.BlockDevices()
	for _, d := range devs {
		if d.Path != disk {
			continue
		}
		if stack := storageStackMember(d); stack != "" {
			return fmt.Errorf("disk %s is part of %s — remove it from that first (initialize only clears inert leftover partitions)", disk, stack)
		}
	}
	if err := ceph.ZapDisk(disk); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "disk.wipe", "disk", disk, ip, nil)
	return nil
}
