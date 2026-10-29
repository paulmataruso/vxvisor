package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	"vdxclone/internal/cloudinit"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/qemu"
)

// Hooks for the oVirt-compatible backup API (internal/ovirtapi): a backup pin
// that keeps a VM's disk where a backup expects it, checkpoint invalidation,
// and disk-less VMs whose disk is uploaded and attached afterwards.

// ErrBackupBusy refuses a lifecycle operation while a backup holds the VM.
var ErrBackupBusy = errors.New("instance is being backed up; try again when the backup finishes")

// PinBackup marks a VM as being backed up until release is called. While
// pinned, Start (of a stopped VM), Delete, Purge, Resize, Snapshot,
// RevertSnapshot, MoveStorage and cluster migrations are refused. Stop is
// not: stopping a running VM mid-backup only fails that backup.
//
// It takes the launch lock briefly, so a Start already in flight finishes
// first and the running/stopped state the caller reads next stays true.
func (m *Manager) PinBackup(id string) (release func(), err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MigrationBusy(id) {
		return nil, fmt.Errorf("instance is migrating its storage; try again when the move finishes")
	}
	m.backupMu.Lock()
	if m.backupPins == nil {
		m.backupPins = map[string]int{}
	}
	m.backupPins[id]++
	m.backupMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.backupMu.Lock()
			if m.backupPins[id] <= 1 {
				delete(m.backupPins, id)
			} else {
				m.backupPins[id]--
			}
			m.backupMu.Unlock()
		})
	}, nil
}

// BackupBusy reports whether a backup holds the VM.
func (m *Manager) BackupBusy(id string) bool {
	m.backupMu.Lock()
	defer m.backupMu.Unlock()
	return m.backupPins[id] > 0
}

// DropCheckpoints forgets a VM's backup checkpoints. It runs whenever the disk
// changes outside the guest's own writes (snapshot revert, storage move,
// resize, a disk swap): the dirty bitmaps no longer describe what changed, so
// the next backup must be a full one. The bitmaps themselves are left; the
// next backup prunes any it has no record of.
func (m *Manager) DropCheckpoints(id string) {
	_, _ = m.db.Exec(`DELETE FROM ovirt_checkpoints WHERE vm_id=?`, id)
}

// QEMUOwner is the uid/gid a VM's QEMU runs as, for files it must open (a
// backup's fleecing image and NBD socket dir). -1 = root, leave as is.
func (m *Manager) QEMUOwner() (uid, gid int) {
	id, err := m.qemuIdentity()
	if err != nil || !id.RunAs {
		return -1, -1
	}
	return int(id.UID), int(id.GID)
}

// CreateBare provisions a stopped VM with no disk: a restore target or a backup
// worker made through the oVirt-compatible API, whose disk is uploaded on its
// own and attached with SetDisk. userData, when set, is a client-supplied
// cloud-init document delivered verbatim on a NoCloud seed (with the generated
// meta-data and network-config). Start refuses the VM until a disk is attached.
func (m *Manager) CreateBare(o CreateOpts, userData string) (*Session, error) {
	if o.Kind == "" {
		o.Kind = "server"
	}
	if o.Firmware == "" {
		o.Firmware = "uefi"
	}
	if o.Firmware == "uefi" {
		if _, _, ok := qemu.OVMF(); !ok {
			o.Firmware = "bios"
		}
	}
	netID := o.NetworkID
	if netID <= 0 {
		netID = m.defaultTenantNetwork(o.OrgID)
	}
	if err := m.CheckPortGroup(o.OrgID, netID); err != nil {
		return nil, err
	}

	id := uuid.NewString()
	var created []string
	fail := func(e error) (*Session, error) {
		m.releaseLeases(id)
		for _, f := range created {
			_ = os.Remove(f)
		}
		return nil, e
	}

	var varsPath string
	if o.Firmware == "uefi" {
		_, varsTmpl, _ := qemu.OVMF()
		if o.SecureBoot {
			if _, msTmpl, ok := qemu.OVMFSecure(); ok {
				varsTmpl = msTmpl
			}
		}
		varsPath = filepath.Join(m.cfg.Paths.DiskDir, id+".ovmf_vars.fd")
		if err := qemu.PrepareUEFIVars(varsTmpl, varsPath); err != nil {
			return fail(err)
		}
		created = append(created, varsPath)
	}

	mac := netdrv.GenMAC()
	staticIP, gw, dhcp, err := m.guestAddressing(o.OrgID, netID, id, mac)
	if err != nil {
		return fail(err)
	}
	var seedPath string
	if strings.TrimSpace(userData) != "" {
		var ns []string
		if staticIP != "" {
			ns = m.cfg.Cluster.Nameservers
			if len(ns) == 0 {
				ns = []string{"1.1.1.1", "8.8.8.8"}
			}
		}
		seedPath = filepath.Join(m.cfg.Paths.DiskDir, id+".seed.iso")
		cfg := cloudinit.Config{
			InstanceID: id, Hostname: sanitizeHostname(o.Name),
			MAC: mac, StaticIP: staticIP, Gateway: gw, Nameservers: ns, DHCP: dhcp,
			RawUserData: userData,
		}
		if err := cloudinit.BuildSeedISO(m.cfg.Paths.DiskDir, seedPath, cfg); err != nil {
			return fail(err)
		}
		created = append(created, seedPath)
	}

	display := o.Display
	if display != "spice" {
		display = "vnc"
	}
	hw := normalizeHardware(o)
	_, err = m.db.Exec(`INSERT INTO sessions
		(id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,mac,
		 cpus,memory_mb,disk_gb,state,cloud_init,seed_path,network_id,display,disk_backend,
		 machine_type,disk_bus,nic_model,vga,guest_agent,tpm,secureboot,os_type)
		VALUES(?,?,?,?,?,'',?,?,?,?,?,?,0,'stopped',?,?,?,?,'qcow2',?,?,?,?,?,?,?,?)`,
		id, o.Name, o.OrgID, o.OwnerID, isoInstallImage, o.Kind, o.Firmware, varsPath, mac,
		o.CPUs, o.MemoryMB, b2i(seedPath != ""), seedPath, nullIf0(netID), display,
		hw.MachineType, hw.DiskBus, hw.NICModel, hw.VGA, b2i(hw.GuestAgent), b2i(hw.TPM), b2i(hw.SecureBoot), hw.OSType)
	if err != nil {
		return fail(err)
	}
	return m.Get(id)
}

// SetDisk attaches (path != "") or detaches (path == "") a stopped VM's disk.
// backend is qcow2|zvol|lvm|rbd; poolID the storage pool it lives in (0 = the
// default disk dir). The disk file is handed to the run-as user on the next
// Start. Checkpoints are dropped: they described the previous disk.
func (m *Manager) SetDisk(id, path, backend string, sizeGB int, poolID int64) error {
	if m.BackupBusy(id) {
		return ErrBackupBusy
	}
	if m.MigrationBusy(id) {
		return fmt.Errorf("instance is migrating its storage; try again when the move finishes")
	}
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if m.Running(s) {
		return errors.New("stop the instance before changing its disk")
	}
	if backend == "" {
		backend = "qcow2"
	}
	if backend == "zvol" || backend == "lvm" {
		// A raw block device is always driven over virtio-blk (see normalizeHardware).
		if _, err := m.db.Exec(`UPDATE sessions SET disk_bus='virtio-blk' WHERE id=? AND disk_bus='sata'`, id); err != nil {
			return err
		}
	}
	if _, err := m.db.Exec(`UPDATE sessions SET disk_path=?, disk_backend=?, disk_gb=?, storage_pool_id=? WHERE id=?`,
		path, backend, sizeGB, nullIf0(poolID), id); err != nil {
		return err
	}
	m.DropCheckpoints(id)
	return nil
}
