package service

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"vdxclone/internal/blkfs"
	"vdxclone/internal/hostinfo"
	"vdxclone/internal/mdraid"
)

// Software RAID (mdraid) + filesystem-pool support. An md array is a plain block
// device that LVM/LVM-thin, ZFS, or an ext4/xfs filesystem pool can sit on. All
// writes are admin-gated and guard member disks via deviceInUse().

// MDArrayView is one array for the storage page.
type MDArrayView struct {
	mdraid.Array
	SizeH   string `json:"size_h"`
	InUse   bool   `json:"in_use"`
	UseNote string `json:"use_note"`
}

var reMDName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

func mdHuman(n int64) string {
	if n <= 0 {
		return "—"
	}
	u := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return strconv.FormatInt(n, 10) + " B"
	}
	if f >= 100 {
		return strconv.FormatFloat(f, 'f', 0, 64) + " " + u[i]
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + u[i]
}

// MDAvailable reports whether software RAID is usable (admin + mdadm present).
func (s *Service) MDAvailable(p *Principal) bool { return p.IsAdmin && mdraid.Available() }

// MDLevels exposes the supported RAID levels (name + min devices) for the UI.
func (s *Service) MDLevels() []mdraid.Level { return mdraid.Levels }

// FSTypes exposes the filesystem-pool filesystem choices for the UI.
func (s *Service) FSTypes() []string { return blkfs.FSTypes }

// ListMDArrays returns every assembled md array (admin only).
func (s *Service) ListMDArrays(p *Principal) []MDArrayView {
	if !p.IsAdmin {
		return nil
	}
	arrs, _ := mdraid.List()
	var out []MDArrayView
	for _, a := range arrs {
		_, note, used := deviceInUse([]string{a.Dev})
		out = append(out, MDArrayView{Array: a, SizeH: mdHuman(a.SizeBytes), InUse: used, UseNote: note})
	}
	return out
}

// MDArraysAsDisks returns md arrays shaped as block devices so they appear in the
// LVM/ZFS/filesystem disk pickers (you can build a pool on top of an array).
func (s *Service) MDArraysAsDisks(p *Principal) []hostinfo.BlockDev {
	if !p.IsAdmin {
		return nil
	}
	arrs, _ := mdraid.List()
	var out []hostinfo.BlockDev
	for _, a := range arrs {
		_, note, used := deviceInUse([]string{a.Dev})
		out = append(out, hostinfo.BlockDev{
			Name: a.Name, Path: a.Dev, Bytes: a.SizeBytes, Size: mdHuman(a.SizeBytes),
			Model: "md " + a.Level, Type: "raid", InUse: used, UseNote: note,
		})
	}
	return out
}

// CreateMDArray builds a new md array from free disks.
func (s *Service) CreateMDArray(p *Principal, name, level string, devices []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if len(devices) == 0 {
		return fmt.Errorf("select at least one device")
	}
	if path, note, used := deviceInUse(devices); used {
		return fmt.Errorf("%s is in use (%s) — pick free disks", path, note)
	}
	dev, err := mdraid.Create(name, level, devices)
	if err != nil {
		return err
	}
	mdraid.SaveConf()
	s.audit(p, p.OrgID, "mdraid.create", "mdraid", dev, ip, map[string]any{"level": level, "devices": devices})
	return nil
}

// DestroyMDArray stops an array and wipes its members' superblocks. Refuses if
// the array is still in use (backing a pool / PV / mounted filesystem).
func (s *Service) DestroyMDArray(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if !reMDName.MatchString(name) {
		return fmt.Errorf("invalid array name")
	}
	dev := "/dev/" + name
	if _, note, used := deviceInUse([]string{dev}); used {
		return fmt.Errorf("%s is in use (%s) — remove the pool/filesystem on it first", dev, note)
	}
	var members []string
	if arrs, _ := mdraid.List(); arrs != nil {
		for _, a := range arrs {
			if a.Dev == dev {
				members = a.Members
			}
		}
	}
	if err := mdraid.Stop(dev); err != nil {
		return err
	}
	mdraid.ZeroSuperblock(members)
	mdraid.SaveConf()
	s.audit(p, p.OrgID, "mdraid.destroy", "mdraid", dev, ip, map[string]any{"members": members})
	return nil
}

// CreateFilesystemPool makes an ext3/ext4/xfs filesystem on a device (disk or md
// array), mounts it, persists it in fstab, and registers it as a dir storage pool.
func (s *Service) CreateFilesystemPool(p *Principal, device, fstype, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	name = strings.TrimSpace(name)
	if !reMDName.MatchString(name) {
		return fmt.Errorf("pool name must be 1–32 chars of letters, digits, dot, dash or underscore")
	}
	if !strings.HasPrefix(device, "/dev/") {
		return fmt.Errorf("invalid device %q", device)
	}
	if path, note, used := deviceInUse([]string{device}); used {
		return fmt.Errorf("%s is in use (%s)", path, note)
	}
	if err := blkfs.Mkfs(fstype, device); err != nil {
		return err
	}
	mnt := filepath.Join("/var/lib/vdxclone/pools", name)
	if err := blkfs.Mount(device, mnt); err != nil {
		return err
	}
	_ = blkfs.PersistFstab(blkfs.UUID(device), mnt, fstype)
	if err := s.stg.UpsertPool(name, "dir", mnt); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "storage.fspool.create", "pool", name, ip, map[string]any{"device": device, "fstype": fstype, "mount": mnt})
	return nil
}
