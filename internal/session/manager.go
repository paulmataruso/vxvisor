// Package session manages the lifecycle of VM sessions.
package session

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/ceph"
	"vdxclone/internal/cloudinit"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/lvm"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/qemu"
	"vdxclone/internal/zfs"
)

// isoInstallImage is the reserved images(name) row referenced by VMs created
// with no base image — installed from a boot ISO onto a blank disk (migration 14).
const isoInstallImage = "(install from ISO)"

type Session struct {
	ID           string
	Name         string
	OrgID        int64
	OwnerID      int64
	ImageName    string
	GuestOS      string // detected guest OS (qemu-guest-agent) for ISO installs
	PinCPUs      bool   // pin vCPU threads 1:1 to host CPUs on start
	HugePages    bool   // back guest RAM with hugepages (when host pool allows)
	EjectVirtio  bool   // don't auto-attach the virtio-win driver CD (Windows)
	DiskPath     string
	Kind         string
	Firmware     string // "uefi" | "bios"
	OVMFVarsPath string // per-VM writable NVRAM (uefi only)
	BootISOID    int64  // optional installer ISO (isos.id), 0 = none
	MAC          string
	CPUs         int
	MemoryMB     int
	DiskGB       int
	State        string
	PID          int
	VNCPort      int
	WSPort       int
	VNCPassword  string
	QMPSocket    string
	CloudInit    bool
	CIUsername   string
	CIPassword   string
	CISSHKey     string
	SeedPath     string
	Passthrough  string
	PoolID       int64 // 0 = not a pool VM
	NetworkID    int64 // 0 = default/NAT; else the port group (networks.id) the NIC attaches to
	Display      string // vnc | spice
	SPICEPort    int    // loopback SPICE port when display=spice (0 otherwise)
	DiskBackend  string // qcow2 | zvol | lvm
	MachineType  string // q35 | pc
	DiskBus      string // virtio-blk | virtio-scsi | sata
	NICModel     string // virtio | e1000e | rtl8139
	VGA          string // qxl | virtio | std
	GuestAgent   bool   // qemu-guest-agent virtio-serial channel
	TPM          bool   // swtpm TPM 2.0 device
	SecureBoot   bool   // UEFI Secure Boot (MS-keyed OVMF)
	OSType       string // linux | windows
	Autostart    bool   // start automatically after a host reboot ("start at boot")
	CreatedAt    string

	// PortGroup is set only on a record shipped to another node by a migration
	// (see PortGroupRefFor); it is not a column. NetworkID is node-local, so the
	// destination binds the VM by this instead.
	PortGroup *qemu.PortGroupRef `json:",omitempty"`
}

// sessionCols is the canonical column list/scan order for a session row.
const sessionCols = `id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,
	COALESCE(boot_iso_id,0),mac,cpus,memory_mb,disk_gb,state,pid,vnc_port,ws_port,vnc_password,qmp_socket,
	cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,COALESCE(pool_id,0),COALESCE(network_id,0),COALESCE(display,'vnc'),COALESCE(spice_port,0),COALESCE(disk_backend,'qcow2'),
	COALESCE(machine_type,'q35'),COALESCE(disk_bus,'virtio-blk'),COALESCE(nic_model,'virtio'),COALESCE(vga,'qxl'),COALESCE(guest_agent,0),COALESCE(tpm,0),COALESCE(secureboot,0),COALESCE(os_type,'linux'),COALESCE(guest_os,''),COALESCE(perf_pin,0),COALESCE(perf_hugepages,0),COALESCE(eject_virtio,0),COALESCE(autostart,1),created_at`

func scanSession(sc interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var ci, ga, tpmI, sbI, pin, hp, ejv, as int
	err := sc.Scan(&s.ID, &s.Name, &s.OrgID, &s.OwnerID, &s.ImageName, &s.DiskPath, &s.Kind,
		&s.Firmware, &s.OVMFVarsPath, &s.BootISOID, &s.MAC, &s.CPUs, &s.MemoryMB, &s.DiskGB, &s.State, &s.PID,
		&s.VNCPort, &s.WSPort, &s.VNCPassword, &s.QMPSocket,
		&ci, &s.CIUsername, &s.CIPassword, &s.CISSHKey, &s.SeedPath, &s.Passthrough, &s.PoolID, &s.NetworkID, &s.Display, &s.SPICEPort, &s.DiskBackend,
		&s.MachineType, &s.DiskBus, &s.NICModel, &s.VGA, &ga, &tpmI, &sbI, &s.OSType, &s.GuestOS, &pin, &hp, &ejv, &as, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	s.CloudInit = ci != 0
	s.GuestAgent = ga != 0
	s.TPM = tpmI != 0
	s.SecureBoot = sbI != 0
	s.PinCPUs = pin != 0
	s.HugePages = hp != 0
	s.Autostart = as != 0
	s.EjectVirtio = ejv != 0
	return &s, nil
}

type Manager struct {
	cfg *config.Config
	db  *db.DB
	mu  sync.Mutex // serializes port allocation + launch
	// incoming tracks migration-receiver QEMU processes between LaunchReceiver and
	// the migrate commit/abort, keyed by session id, so the destination can record
	// the real pid in its DB when it adopts the migrated VM.
	incomingMu sync.Mutex
	incoming   map[string]*os.Process
	// incomingNet: the port group (and lease) each receiver was attached to on
	// THIS node, resolved before the stream started so the adopt can't fail on it.
	incomingNet map[string]receiverNet
	// coldStaged tracks files written on the destination for an in-flight COLD
	// migration (keyed by session id) so an aborted copy can be cleaned up exactly,
	// without globbing.
	coldMu     sync.Mutex
	coldStaged map[string][]string
	// blockExport/blockTarget track an in-flight block-live (NBD) migration receiver
	// on the destination: the NBD export to tear down and the dest-local target disk
	// (removed on abort, and recorded as the adopted VM's disk_path on commit).
	blockMu     sync.Mutex
	blockExport map[string]blockExportRec
	blockTarget map[string]string
	// pinMu guards pinned: vm id -> host CPUs its vCPU threads are pinned to, so
	// the allocator bin-packs new VMs onto the least-loaded cores and releases on
	// stop. In-memory (best-effort); lost on daemon restart, re-applied on next start.
	pinMu  sync.Mutex
	pinned map[string][]int
	// snapLocks: vm id -> *sync.Mutex serializing snapshot/revert/clone/purge of
	// that VM (snapshots.go lockVMs); purgeMu serializes purges, which may touch a
	// dependent clone's storage while detaching it.
	snapLocks sync.Map
	purgeMu   sync.Mutex
	// backupPins: vm id -> backups holding it (see PinBackup). In-memory: a
	// daemon restart ends every backup anyway.
	backupMu   sync.Mutex
	backupPins map[string]int
}

func NewManager(cfg *config.Config, d *db.DB) *Manager {
	return &Manager{cfg: cfg, db: d, incoming: map[string]*os.Process{}, incomingNet: map[string]receiverNet{},
		coldStaged: map[string][]string{}, blockExport: map[string]blockExportRec{}, blockTarget: map[string]string{},
		pinned: map[string][]int{}}
}

// CreateOpts describes a new instance. It is a struct rather than a long
// positional signature because M2 added firmware, disk sizing and cloud-init.
type CreateOpts struct {
	OrgID, OwnerID int64
	Name           string
	ImageName      string
	Kind           string // desktop|server
	Firmware       string // uefi|bios (default uefi when available)
	BootISOID      int64  // optional installer ISO (isos.id), 0 = none
	CPUs, MemoryMB int
	DiskGB         int    // grow the overlay to this virtual size; 0 = image default
	CloudInit      bool
	CIUsername     string
	CIPassword     string // if empty and CloudInit, a strong one is generated
	CISSHKey       string
	Passthrough    string // csv of host PCI addresses (gated on IOMMU by caller)
	NetworkID      int64  // port group (networks.id) to attach the NIC to; 0 = default/NAT
	MAC            string // pin the NIC MAC (e.g. preserved from a VMware import); "" = generate
	StoragePoolID  int64  // storage pool (storage_pools.id) for the disk; 0 = default disk dir
	Display        string // vnc | spice
	DiskBackend    string // qcow2 | zvol | lvm | rbd
	ZvolPool       string // ZFS pool/dataset name to create the zvol under (zvol backend)
	Desktop        string // "" | xfce (cloud-init installs a lightweight desktop)
	MachineType    string // q35|pc (default q35)
	DiskBus        string // virtio-blk|virtio-scsi|sata (default virtio-blk, or sata for windows)
	NICModel       string // virtio|e1000e|rtl8139 (default virtio, or e1000e for windows)
	VGA            string // qxl|virtio|std (default qxl, or std for windows)
	GuestAgent     bool   // add the qemu-guest-agent channel
	TPM            bool   // attach a swtpm TPM 2.0 device
	SecureBoot     bool   // UEFI Secure Boot (MS-keyed OVMF pair)
	OSType         string // linux|windows (drives sensible hardware defaults)
	PinCPUs        bool   // pin vCPU threads 1:1 to host CPUs
	HugePages      bool   // back guest RAM with hugepages (host pool permitting)
}

// Create provisions a new session (overlay disk, firmware NVRAM, cloud-init seed
// ISO, DB row) in the stopped state. Any artifact it creates is cleaned up if a
// later step fails, so a failed create never leaves orphan files.
func (m *Manager) Create(o CreateOpts) (*Session, error) {
	if o.Kind == "" {
		o.Kind = "server"
	}
	if o.Firmware == "" {
		o.Firmware = "uefi"
	}
	if o.Firmware == "uefi" {
		if _, _, ok := qemu.OVMF(); !ok {
			o.Firmware = "bios" // host has no OVMF; fall back rather than fail
		}
	}

	// The NIC's port group, resolved before anything is provisioned. With none
	// chosen, an org that has a default tenant network lands on its isolated
	// bridge; the Default org (no tenant network) keeps the historical global
	// fallback. A tenant org must end up on one of its own bridged port groups.
	netID := o.NetworkID
	if netID <= 0 {
		netID = m.defaultTenantNetwork(o.OrgID)
	}
	if err := m.CheckPortGroup(o.OrgID, netID); err != nil {
		return nil, err
	}

	// Two provisioning modes:
	//   • Image chosen → copy-on-write overlay over the base cloud image (instant OS).
	//   • No image     → a blank disk to install onto from a boot ISO (needs BootISOID).
	blankInstall := o.ImageName == "" || o.ImageName == isoInstallImage
	var imgPath string
	var need int64
	if blankInstall {
		if o.BootISOID == 0 {
			return nil, fmt.Errorf("choose a base image, or a boot ISO to install from")
		}
		o.ImageName = isoInstallImage // reserved row satisfies the sessions.image_name FK
		o.CloudInit = false           // an OS installer does not consume the cloud-init seed
		need = 1 << 30                // blank qcow2 is thin; just a working margin
	} else {
		err := m.db.QueryRow(`SELECT path FROM images WHERE name=? AND status='ready'`, o.ImageName).Scan(&imgPath)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("image %q not found or not ready", o.ImageName)
		}
		if err != nil {
			return nil, err
		}
		// qcow2 overlays are thin, so gate on base image size + margin, not the ceiling.
		need = imageFileSize(imgPath) + 1<<30
	}
	// Where the VM's disk lives: a chosen storage pool's path, or the default
	// disk directory. Only the disk moves; per-VM NVRAM/seed/QMP stay in DiskDir.
	diskDir := m.cfg.Paths.DiskDir
	// For the LVM-thin backend the disk is a raw thin LV, not a file in a
	// directory, so resolve the pool to its VG/thin-pool names instead of a path.
	var lvmVG, lvmPool, rbdPool string
	if o.DiskBackend == "lvm" {
		var pname string
		if err := m.db.QueryRow(`SELECT COALESCE(name,'') FROM storage_pools WHERE id=? AND kind='lvm'`, o.StoragePoolID).Scan(&pname); err != nil || pname == "" {
			return nil, fmt.Errorf("the lvm backend needs an LVM thin pool (choose one)")
		}
		parts := strings.SplitN(pname, "/", 2) // "<vg>/<thinpool>"
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed lvm pool name %q", pname)
		}
		lvmVG, lvmPool = parts[0], parts[1]
	} else if o.DiskBackend == "rbd" {
		// The Ceph pool name is stored in the storage_pools row's path (it is not a
		// filesystem directory). The disk is an RBD image in that pool, not a file.
		if err := m.db.QueryRow(`SELECT COALESCE(path,'') FROM storage_pools WHERE id=? AND kind='rbd'`, o.StoragePoolID).Scan(&rbdPool); err != nil || rbdPool == "" {
			return nil, fmt.Errorf("the rbd backend needs a Ceph RBD pool (choose one)")
		}
	} else if o.StoragePoolID > 0 {
		var ppath string
		if err := m.db.QueryRow(`SELECT COALESCE(path,'') FROM storage_pools WHERE id=?`, o.StoragePoolID).Scan(&ppath); err == nil && ppath != "" {
			diskDir = ppath
		} else {
			o.StoragePoolID = 0 // pool gone/unknown → fall back to default
		}
	}
	if free, err := freeBytes(diskDir); err == nil && free < need {
		return nil, fmt.Errorf("insufficient disk space in pool: need ~%d MiB, have %d MiB free",
			need>>20, free>>20)
	}

	id := uuid.NewString()
	var created []string
	zvolName := "" // set when the disk backend is a raw ZFS zvol
	lvPath := ""   // set when the disk backend is a raw LVM thin volume
	rbdImage := "" // set when the disk backend is a Ceph RBD image
	fail := func(e error) (*Session, error) {
		m.releaseLeases(id)
		for _, f := range created {
			_ = os.Remove(f)
		}
		if zvolName != "" {
			_ = zfs.DestroyDataset(zvolName)
		}
		if lvPath != "" {
			_ = lvm.RemoveLV(lvPath)
		}
		if rbdImage != "" {
			_ = ceph.RemoveImage(rbdPool, rbdImage)
		}
		return nil, e
	}

	diskBackend := "qcow2"
	var disk string
	if o.DiskBackend == "zvol" {
		// Raw ZFS zvol: a block device, no qcow2 overhead and no COW-on-COW. Best
		// disk performance on ZFS (what Proxmox does). Needs a ZFS pool/dataset.
		diskBackend = "zvol"
		if !zfs.Available() {
			return fail(fmt.Errorf("the zvol backend requires ZFS on the host"))
		}
		if o.ZvolPool == "" {
			return fail(fmt.Errorf("choose a ZFS pool for the zvol"))
		}
		sizeGB := o.DiskGB
		if sizeGB <= 0 {
			sizeGB = 20
		}
		if !blankInstall { // the zvol must be at least the base image's virtual size
			if vb, err := qemu.VirtualSizeBytes(imgPath); err == nil && vb > int64(sizeGB)<<30 {
				sizeGB = int(vb>>30) + 1
			}
		}
		zvolName = o.ZvolPool + "/vdx-" + id[:8]
		if err := zfs.CreateZvol(zvolName, int64(sizeGB)<<30, true); err != nil {
			zvolName = ""
			return fail(err)
		}
		disk = "/dev/zvol/" + zvolName
		if !blankInstall { // write the base cloud image onto the zvol as raw
			if err := qemu.ConvertToRaw(imgPath, disk); err != nil {
				return fail(err)
			}
		}
	} else if o.DiskBackend == "lvm" {
		// Raw LVM thin volume: one thin LV per VM at /dev/<vg>/<lv>, driven as a
		// raw block device. Thin-provisioned, so the LV's virtual size can exceed
		// the pool's free extents; data blocks are allocated on write.
		diskBackend = "lvm"
		if !lvm.Available() {
			return fail(fmt.Errorf("the lvm backend requires LVM2 on the host"))
		}
		sizeGB := o.DiskGB
		if sizeGB <= 0 {
			sizeGB = 20
		}
		if !blankInstall { // the LV must be at least the base image's virtual size
			if vb, err := qemu.VirtualSizeBytes(imgPath); err == nil && vb > int64(sizeGB)<<30 {
				sizeGB = int(vb>>30) + 1
			}
		}
		lvName := "vdx-" + id[:8]
		if err := lvm.CreateThinVolume(lvmVG, lvmPool, lvName, int64(sizeGB)<<30); err != nil {
			return fail(err)
		}
		disk = "/dev/" + lvmVG + "/" + lvName
		lvPath = disk // arm cleanup
		if !blankInstall { // write the base cloud image onto the LV as raw
			if err := qemu.ConvertToRaw(imgPath, disk); err != nil {
				return fail(err)
			}
		}
	} else if o.DiskBackend == "rbd" {
		// Ceph RBD: the disk is a raw block image in a distributed pool, shared
		// across the cluster (so a live migration can reuse the same rbd: path).
		// No COW-on-COW, no local file — the image IS the VM's disk.
		diskBackend = "rbd"
		if !ceph.Bootstrapped() {
			return fail(fmt.Errorf("the rbd backend requires a running Ceph cluster"))
		}
		sizeGB := o.DiskGB
		if sizeGB <= 0 {
			sizeGB = 20
		}
		if !blankInstall { // the image must be at least the base image's virtual size
			if vb, err := qemu.VirtualSizeBytes(imgPath); err == nil && vb > int64(sizeGB)<<30 {
				sizeGB = int(vb>>30) + 1
			}
		}
		_, _ = ceph.EnsureClientKeyring(rbdPool) // QEMU keyring (idempotent)
		imgName := "vdx-" + id[:8]
		if blankInstall {
			if err := ceph.CreateImage(rbdPool, imgName, int64(sizeGB)<<30); err != nil {
				return fail(err)
			}
		} else {
			// qemu-img convert auto-creates the rbd image and fills it as raw.
			if err := ceph.ImportImage(rbdPool, imgName, imgPath); err != nil {
				return fail(err)
			}
			if o.DiskGB > 0 { // grow to the requested size if larger than the import
				if err := ceph.ResizeImage(rbdPool, imgName, int64(sizeGB)<<30); err != nil {
					return fail(err)
				}
			}
		}
		rbdImage = imgName // arm cleanup
		disk = ceph.RBDPath(rbdPool, imgName)
	} else {
		disk = filepath.Join(diskDir, id+".qcow2")
		if blankInstall {
			if err := qemu.CreateBlank(disk, o.DiskGB); err != nil {
				return fail(err)
			}
		} else {
			if err := qemu.CreateOverlay(imgPath, disk); err != nil {
				return fail(err)
			}
			// Grow the overlay if a larger root disk was requested (cloud images ship
			// a small root; cloud-init's growpart expands the filesystem on boot).
			if o.DiskGB > 0 {
				cur, _ := qemu.VirtualSizeBytes(disk)
				if int64(o.DiskGB)<<30 > cur {
					if err := qemu.ResizeDisk(disk, o.DiskGB); err != nil {
						return fail(err)
					}
				}
			}
		}
		created = append(created, disk)
	}

	// Per-VM UEFI NVRAM (writable copy of the OVMF vars template).
	var varsPath string
	if o.Firmware == "uefi" {
		_, varsTmpl, _ := qemu.OVMF()
		// Secure Boot needs the MS-keyed vars template (ships the MS KEK/db).
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

	// MAC is pinned now so the cloud-init network-config (bridge/overlay mode)
	// can match it to the guest NIC and the address survives reboots. A caller
	// may supply one (preserved from a VMware import, so the guest keeps the same
	// L2 identity — DHCP reservations, MAC-bound licenses); otherwise generate.
	mac := netdrv.GenMAC()
	if o.MAC != "" {
		if hw, err := net.ParseMAC(strings.TrimSpace(o.MAC)); err == nil && len(hw) == 6 {
			mac = hw.String()
		}
	}

	// Guest addressing for the cloud-init seed: a static lease from the VM's OWN
	// port group pool, DHCP from its segment, or (no port group on the cluster
	// bridge) the cluster-subnet IPAM — see guestAddressing.
	staticIP, gw, dhcp, err := m.guestAddressing(o.OrgID, netID, id, mac)
	if err != nil {
		return fail(err)
	}

	// cloud-init NoCloud seed (first-boot user/password/SSH key).
	var seedPath string
	if o.CloudInit {
		if o.CIUsername == "" {
			o.CIUsername = "vdx"
		}
		if o.CIPassword == "" {
			o.CIPassword = randPassword()
		}
		seedPath = filepath.Join(m.cfg.Paths.DiskDir, id+".seed.iso")
		// A static (bridge/overlay) guest has no DHCP-provided resolver, so give it
		// DNS or its first-boot package install (desktop, guest agent) can't resolve.
		// A DHCP guest gets its resolver from the LAN, so no override is needed.
		var ns []string
		if staticIP != "" {
			ns = m.cfg.Cluster.Nameservers
			if len(ns) == 0 {
				ns = []string{"1.1.1.1", "8.8.8.8"}
			}
		}
		cfg := cloudinit.Config{
			InstanceID: id, Hostname: sanitizeHostname(o.Name),
			Username: o.CIUsername, Password: o.CIPassword, SSHKey: o.CISSHKey,
			MAC: mac, StaticIP: staticIP, Gateway: gw, Nameservers: ns, DHCP: dhcp,
			Desktop:           o.Desktop,
			InstallGuestAgent: o.GuestAgent,
		}
		if err := cloudinit.BuildSeedISO(m.cfg.Paths.DiskDir, seedPath, cfg); err != nil {
			return fail(err)
		}
		created = append(created, seedPath)
	}

	ci := 0
	if o.CloudInit {
		ci = 1
	}
	var bootISO any
	if o.BootISOID > 0 {
		bootISO = o.BootISOID
	}
	var poolID any
	if o.StoragePoolID > 0 {
		poolID = o.StoragePoolID
	}
	display := o.Display
	if display != "spice" {
		display = "vnc"
	}
	hw := normalizeHardware(o)
	ga, tpmI, sbI := b2i(hw.GuestAgent), b2i(hw.TPM), b2i(hw.SecureBoot)
	_, err = m.db.Exec(`INSERT INTO sessions
		(id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,boot_iso_id,mac,
		 cpus,memory_mb,disk_gb,state,cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,network_id,storage_pool_id,display,disk_backend,
		 machine_type,disk_bus,nic_model,vga,guest_agent,tpm,secureboot,os_type,perf_pin,perf_hugepages)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'stopped',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, o.Name, o.OrgID, o.OwnerID, o.ImageName, disk, o.Kind, o.Firmware, varsPath, bootISO, mac,
		o.CPUs, o.MemoryMB, o.DiskGB, ci, o.CIUsername, o.CIPassword, o.CISSHKey, seedPath, o.Passthrough, nullIf0(netID), poolID, display, diskBackend,
		hw.MachineType, hw.DiskBus, hw.NICModel, hw.VGA, ga, tpmI, sbI, hw.OSType, b2i(o.PinCPUs), b2i(o.HugePages))
	if err != nil {
		return fail(err)
	}
	return m.Get(id)
}

// hugepagesAvailable reports whether the host's free hugepage pool can back a
// guest of memMB (reads /proc/meminfo: HugePages_Free × Hugepagesize). Returns
// false when no pool is reserved, so the toggle degrades to normal RAM.
func hugepagesAvailable(memMB int) bool {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return false
	}
	var freePages, sizeKB int64
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			switch f[0] {
			case "HugePages_Free:":
				freePages, _ = strconv.ParseInt(f[1], 10, 64)
			case "Hugepagesize:":
				sizeKB, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	if freePages <= 0 || sizeKB <= 0 {
		return false
	}
	return freePages*sizeKB/1024 >= int64(memMB)
}

// pinVCPUs pins each guest vCPU thread 1:1 to a host CPU and parks QEMU's
// emulator/iothreads on CPU 0. The host CPUs are bin-packed across running pinned
// VMs (least-loaded first, CPU 0 reserved for the host) so VMs avoid sharing
// cores while capacity lasts. Best effort: any failure is logged, never fatal.
func (m *Manager) pinVCPUs(id, qmpSock string, pid, nCPU int) {
	if nCPU < 1 {
		nCPU = 1
	}
	host := runtime.NumCPU()
	if host <= 1 {
		return // nothing to pin to
	}
	q, err := qemu.DialQMP(qmpSock)
	if err != nil {
		log.Printf("pin %s: QMP dial: %v", id, err)
		return
	}
	defer q.Close()
	vcpus, err := q.QueryCPUsFast()
	if err != nil || len(vcpus) == 0 {
		log.Printf("pin %s: query-cpus-fast: %v", id, err)
		return
	}
	cpus := m.allocPinCPUs(id, len(vcpus), host)
	for i, c := range vcpus {
		if i >= len(cpus) {
			break
		}
		if err := exec.Command("taskset", "-pc", strconv.Itoa(cpus[i]), strconv.Itoa(c.ThreadID)).Run(); err != nil {
			log.Printf("pin %s: vcpu%d->cpu%d: %v", id, c.CPUIndex, cpus[i], err)
		}
	}
	// Emulator + iothreads: park on CPU 0 (off the vCPU cores).
	_ = exec.Command("taskset", "-pc", "0", strconv.Itoa(pid)).Run()
	log.Printf("pin %s: %d vCPUs -> host CPUs %v (emulator on cpu0)", id, len(vcpus), cpus)
}

// allocPinCPUs picks n host CPUs (from 1..host-1, reserving CPU 0) that are the
// least used by other pinned VMs, and records the assignment.
func (m *Manager) allocPinCPUs(id string, n, host int) []int {
	m.pinMu.Lock()
	defer m.pinMu.Unlock()
	load := make([]int, host) // load[c] = how many pinned VMs use host CPU c
	for vm, cs := range m.pinned {
		if vm == id {
			continue
		}
		for _, c := range cs {
			if c >= 0 && c < host {
				load[c]++
			}
		}
	}
	// Candidate CPUs: 1..host-1 (keep CPU 0 for the host/emulator); if the box has
	// only 1 extra core, fall back to allowing CPU 0 too.
	start := 1
	if host <= n {
		start = 0
	}
	cand := make([]int, 0, host)
	for c := start; c < host; c++ {
		cand = append(cand, c)
	}
	if len(cand) == 0 {
		cand = append(cand, 0)
	}
	// Stable sort by (load asc, index asc) and take the first n (round-robin wrap).
	sort.SliceStable(cand, func(i, j int) bool {
		if load[cand[i]] != load[cand[j]] {
			return load[cand[i]] < load[cand[j]]
		}
		return cand[i] < cand[j]
	})
	out := make([]int, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, cand[i%len(cand)])
	}
	m.pinned[id] = out
	return out
}

// releasePins frees a VM's pinned CPUs so the allocator can reuse them.
func (m *Manager) releasePins(id string) {
	m.pinMu.Lock()
	delete(m.pinned, id)
	m.pinMu.Unlock()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// hwSpec is the normalized per-VM hardware profile.
type hwSpec struct {
	MachineType, DiskBus, NICModel, VGA, OSType string
	GuestAgent, TPM, SecureBoot                 bool
}

// normalizeHardware resolves the requested hardware knobs into a valid profile,
// applying OS-appropriate defaults. Windows guests get installer-friendly
// defaults (SATA disk + e1000e NIC + std VGA + TPM) so an unattended install
// "just works" without side-loading virtio drivers; the virtio-win ISO is still
// mounted so the user can switch to virtio afterwards. Unknown values fall back
// to the safe default rather than erroring, so the VM always launches.
func normalizeHardware(o CreateOpts) hwSpec {
	win := o.OSType == "windows"
	h := hwSpec{OSType: "linux", GuestAgent: o.GuestAgent, TPM: o.TPM, SecureBoot: o.SecureBoot}
	if win {
		h.OSType = "windows"
	}
	h.MachineType = pick(o.MachineType, map[string]bool{"q35": true, "pc": true}, "q35")
	// virtio everywhere is fastest. Windows has no in-box virtio driver, but
	// VXVisor auto-mounts the virtio-win ISO (fetched at install) so viostor/
	// NetKVM/qxl are available during Setup (Load driver → viostor at the disk
	// step). qxl shows a basic display pre-driver, then accelerates after QXL-WDDM.
	defBus, defNIC, defVGA := "virtio-blk", "virtio", "qxl"
	if win {
		h.TPM = true // Win10/11 expect a TPM; harmless for older guests
	}
	h.DiskBus = pick(o.DiskBus, map[string]bool{"virtio-blk": true, "virtio-scsi": true, "sata": true}, defBus)
	h.NICModel = pick(o.NICModel, map[string]bool{"virtio": true, "e1000e": true, "rtl8139": true}, defNIC)
	h.VGA = pick(o.VGA, map[string]bool{"qxl": true, "virtio": true, "std": true}, defVGA)
	// A raw block device (zvol or lvm thin LV) can only be driven by a block
	// device, not the AHCI/SATA path we use for cdrom-style attach; keep
	// virtio-blk for raw backends regardless.
	if (o.DiskBackend == "zvol" || o.DiskBackend == "lvm") && h.DiskBus == "sata" {
		h.DiskBus = "virtio-blk"
	}
	return h
}

// pick returns want if it is in the allowed set, else def.
func pick(want string, allowed map[string]bool, def string) string {
	if allowed[want] {
		return want
	}
	return def
}

// SetEjectVirtio records whether the virtio-win driver CD should be withheld
// from this VM (applies on next start).
func (m *Manager) SetEjectVirtio(id string, eject bool) error {
	_, err := m.db.Exec(`UPDATE sessions SET eject_virtio=? WHERE id=?`, b2i(eject), id)
	return err
}

// SetBootISO sets (or clears, with isoID<=0) the instance's attached boot ISO.
// It takes effect the next time the instance starts.
func (m *Manager) SetBootISO(id string, isoID int64) error {
	var v any
	if isoID > 0 {
		v = isoID
	}
	_, err := m.db.Exec(`UPDATE sessions SET boot_iso_id=? WHERE id=?`, v, id)
	return err
}

// Resize changes an offline instance's CPU/memory and optionally grows its disk.
// Shrinking a disk is refused (qcow2 cannot safely shrink a live filesystem).
func (m *Manager) Resize(id string, cpus, memMB, diskGB int) error {
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if m.Running(s) {
		return errors.New("stop the instance before resizing")
	}
	if m.BackupBusy(id) {
		return ErrBackupBusy
	}
	if diskGB > 0 && diskGB < s.DiskGB {
		return fmt.Errorf("cannot shrink disk from %d GB to %d GB", s.DiskGB, diskGB)
	}
	if diskGB > 0 {
		if s.DiskBackend == "zvol" && strings.HasPrefix(s.DiskPath, "/dev/zvol/") {
			// Grow the ZFS volume (the guest expands its filesystem on next boot).
			if err := zfs.SetVolsize(strings.TrimPrefix(s.DiskPath, "/dev/zvol/"), int64(diskGB)<<30); err != nil {
				return err
			}
		} else if s.DiskBackend == "lvm" {
			// Grow the thin LV only when the disk actually gets bigger — lvextend
			// errors ("No size change") if asked to resize to the current size,
			// which would spuriously fail a CPU/RAM-only resize. The guest expands
			// its filesystem on next boot.
			if diskGB > s.DiskGB {
				if err := lvm.ExtendLV(s.DiskPath, int64(diskGB)<<30); err != nil {
					return err
				}
			}
		} else if s.DiskBackend == "rbd" {
			// Grow the RBD image (Ceph refuses to shrink). The guest expands its
			// filesystem on next boot.
			if diskGB > s.DiskGB {
				if pool, image, ok := ceph.ParseRBD(s.DiskPath); ok {
					if err := ceph.ResizeImage(pool, image, int64(diskGB)<<30); err != nil {
						return err
					}
				}
			}
		} else {
			cur, _ := qemu.VirtualSizeBytes(s.DiskPath)
			if int64(diskGB)<<30 > cur {
				if free, err := freeBytes(m.cfg.Paths.DiskDir); err == nil && free < int64(diskGB)<<30-cur {
					return errors.New("insufficient disk space to grow disk")
				}
				if err := qemu.ResizeDisk(s.DiskPath, diskGB); err != nil {
					return err
				}
			}
		}
	}
	if cpus <= 0 {
		cpus = s.CPUs
	}
	if memMB <= 0 {
		memMB = s.MemoryMB
	}
	dg := s.DiskGB
	if diskGB > 0 {
		dg = diskGB
	}
	if dg != s.DiskGB {
		m.DropCheckpoints(id) // a resized disk is backed up in full next time
	}
	_, err = m.db.Exec(`UPDATE sessions SET cpus=?, memory_mb=?, disk_gb=? WHERE id=?`, cpus, memMB, dg, id)
	return err
}

// HardwareSpec is the editable hardware profile of a stopped instance.
type HardwareSpec struct {
	Firmware    string
	OSType      string
	MachineType string
	DiskBus     string
	NICModel    string
	VGA         string
	GuestAgent  bool
	TPM         bool
	SecureBoot  bool
	PinCPUs     bool
	HugePages   bool
}

// UpdateHardware changes a stopped instance's hardware profile. These are all
// launch-time QEMU choices, so the instance must be stopped. Values are
// normalized against the same known-good option sets as Create, and a raw
// (zvol/lvm) disk is kept on virtio-blk. Firmware / Secure Boot transitions
// (re)provision the per-VM OVMF NVRAM so the change is self-consistent — and
// never touch the data disk, so the instance stays bootable.
func (m *Manager) UpdateHardware(id string, hw HardwareSpec) error {
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if m.Running(s) {
		return errors.New("stop the instance before changing its specification")
	}
	fw := pick(hw.Firmware, map[string]bool{"uefi": true, "bios": true}, "uefi")
	osType := pick(hw.OSType, map[string]bool{"linux": true, "windows": true}, "linux")
	mach := pick(hw.MachineType, map[string]bool{"q35": true, "pc": true}, "q35")
	bus := pick(hw.DiskBus, map[string]bool{"virtio-blk": true, "virtio-scsi": true, "sata": true}, "virtio-blk")
	nic := pick(hw.NICModel, map[string]bool{"virtio": true, "e1000e": true, "rtl8139": true}, "virtio")
	vga := pick(hw.VGA, map[string]bool{"qxl": true, "virtio": true, "std": true}, "qxl")
	secure := hw.SecureBoot && fw == "uefi" // Secure Boot requires UEFI

	// A raw block device (zvol/lvm thin LV) can't use the SATA path — keep it on
	// virtio-blk regardless, same rule as Create.
	if (s.DiskBackend == "zvol" || s.DiskBackend == "lvm") && bus == "sata" {
		bus = "virtio-blk"
	}

	// (Re)provision the per-VM UEFI NVRAM when switching to UEFI, toggling Secure
	// Boot, or when the vars file is missing. For BIOS we simply stop using it.
	varsPath := s.OVMFVarsPath
	if fw == "uefi" {
		need := varsPath == "" || fw != s.Firmware || secure != s.SecureBoot
		if _, statErr := os.Stat(varsPath); varsPath != "" && statErr != nil {
			need = true
		}
		if need {
			_, varsTmpl, _ := qemu.OVMF()
			if secure {
				if _, msTmpl, ok := qemu.OVMFSecure(); ok {
					varsTmpl = msTmpl
				}
			}
			varsPath = filepath.Join(m.cfg.Paths.DiskDir, id+".ovmf_vars.fd")
			if err := qemu.PrepareUEFIVars(varsTmpl, varsPath); err != nil {
				return fmt.Errorf("provision UEFI NVRAM: %w", err)
			}
		}
	} else {
		varsPath = "" // BIOS: no NVRAM
	}

	_, err = m.db.Exec(`UPDATE sessions SET firmware=?, ovmf_vars_path=?, machine_type=?, disk_bus=?,
		nic_model=?, vga=?, guest_agent=?, tpm=?, secureboot=?, os_type=?, perf_pin=?, perf_hugepages=? WHERE id=?`,
		fw, varsPath, mach, bus, nic, vga, b2i(hw.GuestAgent), b2i(hw.TPM), b2i(secure), osType, b2i(hw.PinCPUs), b2i(hw.HugePages), id)
	return err
}

// Start launches QEMU for a stopped session.
func (m *Manager) Start(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// SAFETY: never (re)start a VM that is mid storage-move. Recovery decides
	// which disk is authoritative first; starting now could boot a half-written
	// target or diverge from the source.
	if m.MigrationBusy(id) {
		return nil, fmt.Errorf("instance is migrating its storage; try again when the move finishes")
	}
	s, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if s.State == "running" && processAliveSince(s.PID, m.startTime(id)) {
		return s, nil
	}
	// A backup of the stopped VM reads its disk; a VM made through the backup
	// API has no disk until one is attached.
	if m.BackupBusy(id) {
		return nil, ErrBackupBusy
	}
	if s.DiskPath == "" {
		return nil, errors.New("the instance has no disk attached")
	}
	// Where the NIC goes (see planNIC). Decided before anything is allocated so a
	// tenant VM with no port group of its own is refused cleanly, never started
	// on the shared network.
	plan, err := m.planNIC(s)
	if err != nil {
		return nil, err
	}

	vncPort, wsPort, err := m.allocPorts()
	if err != nil {
		return nil, err
	}
	qmpSock := filepath.Join(m.cfg.Paths.DiskDir, id+".qmp")
	_ = os.Remove(qmpSock)
	serialSock := filepath.Join(m.cfg.Paths.DiskDir, id+".serial")
	_ = os.Remove(serialSock)

	// Per-launch VNC password, written to a 0600 secret file (off the cmdline).
	pw := randVNCPassword()
	pwFile := filepath.Join(m.cfg.Paths.DiskDir, id+".vncpw")
	if err := qemu.WriteSecretFile(pwFile, pw); err != nil {
		return nil, err
	}

	var base string
	if err := m.db.QueryRow(`SELECT path FROM images WHERE name=?`, s.ImageName).Scan(&base); err != nil {
		return nil, err
	}

	// Hugepage backing only when requested AND the host pool can satisfy it —
	// otherwise QEMU would refuse to start, so we fall back to normal RAM and say so.
	hugeOK := s.HugePages && hugepagesAvailable(s.MemoryMB)
	if s.HugePages && !hugeOK {
		log.Printf("session %s: hugepages requested but host pool too small for %d MB — using normal memory (reserve pages per docs/TUNING.md §B.2)", id, s.MemoryMB)
	}
	spec := qemu.Spec{
		ID:        id,
		BaseImage: base,
		DiskPath:  s.DiskPath,
		CPUs:      s.CPUs,
		MemoryMB:  s.MemoryMB,
		HugePages: hugeOK,
		VNCPort:   vncPort,
		WSPort:    wsPort,
		QMPSocket: qmpSock,
		UserNet:   plan.UserNet,
		EnableKVM: qemu.KVMAvailable(),
		VNCPwFile: pwFile,
		Firmware:  s.Firmware,
		SeedISO:   s.SeedPath,
		DiskRaw:   s.DiskBackend == "zvol" || s.DiskBackend == "lvm",
		SerialSock: serialSock,
		MachineType: s.MachineType,
		DiskBus:     s.DiskBus,
		NICModel:    s.NICModel,
		VGA:         s.VGA,
		Windows:     s.OSType == "windows",
		GuestAgent:  s.GuestAgent,
	}
	// Who QEMU runs as (the run-as user, or root tagged with the guard group) —
	// and, for a SLIRP VM, the host loopback guard must be in place first.
	if err := m.launchAs(&spec, s.DiskPath, s.OVMFVarsPath, s.SeedPath, pwFile); err != nil {
		m.setError(id)
		return nil, err
	}
	// qemu-guest-agent channel socket (loopback/unix). Removed stale first so the
	// server socket binds cleanly.
	if s.GuestAgent {
		spec.QGASocket = filepath.Join(m.cfg.Paths.DiskDir, id+".qga")
		_ = os.Remove(spec.QGASocket)
	}
	// Windows: attach the virtio-win driver ISO (if present, and not ejected) so
	// virtio devices and the guest agent can be installed inside the guest.
	if s.OSType == "windows" && !s.EjectVirtio {
		spec.ExtraISO = qemu.VirtioWinISO(m.cfg.Paths.ISODir)
	}
	// TPM 2.0: start a per-VM swtpm and attach it. Must be up BEFORE QEMU, which
	// connects to the socket at launch; failure is fatal to the start so we never
	// silently boot a Windows 11 guest without its TPM.
	if s.TPM {
		tsock, err := m.startSwtpm(id)
		if err != nil {
			m.setError(id)
			return nil, fmt.Errorf("swtpm: %w", err)
		}
		spec.TPMSock = tsock
	}
	// SPICE display: a loopback SPICE server + qxl, for a SPICE-aware client
	// gateway. VNC stays enabled so the plain noVNC console still works too.
	spicePort := 0
	if s.Display == "spice" {
		spicePort = vncPort + 3000 // unique per VM (vncPort is unique), loopback-bound
		spec.Display = "spice"
		spec.SPICEPort = spicePort
	}
	if s.Firmware == "uefi" {
		code, _, ok := qemu.OVMF()
		if s.SecureBoot {
			if sc, _, sok := qemu.OVMFSecure(); sok {
				code, ok = sc, true
			}
		}
		if ok {
			spec.OVMFCodePath = code
			spec.OVMFVarsPath = s.OVMFVarsPath
		}
	}
	if s.BootISOID > 0 {
		var isoPath string
		if err := m.db.QueryRow(`SELECT path FROM isos WHERE id=?`, s.BootISOID).Scan(&isoPath); err == nil {
			spec.BootISO = isoPath
		}
	}
	spec.MAC = s.MAC
	spec.HostFwds = m.portForwards(id)

	// Attach this VM's NIC to the fabric (see planNIC). A VM bound to a port group
	// (network_id) lands on that port group's vSwitch as an access port with the
	// port group's VLAN as PVID — exactly like a VMware port group — whatever the
	// global mode. A VM with no port group falls back to the global cluster bridge
	// (bridge/overlay mode) or SLIRP (user mode); a tenant-org VM never does.
	// The tap is owned by the run-as user so a dropped-privilege QEMU can open it,
	// and sized to its bridge, whose MTU the guest also learns via host_mtu (a
	// VXLAN-backed port group runs at 1450; at 1500 full frames would be dropped).
	if plan.Bridge != "" {
		tap := netdrv.TapName(id)
		ownerUID := 0
		if spec.RunAsUID != 0 {
			ownerUID = int(spec.RunAsUID)
		}
		if err := netdrv.SetupTapAccess(tap, plan.Bridge, plan.VLAN, ownerUID); err != nil {
			m.setError(id)
			return nil, fmt.Errorf("setup tap %s on %s: %w", tap, plan.Bridge, err)
		}
		if plan.MTU > 0 && netdrv.LinkMTU(tap) != plan.MTU {
			if err := netdrv.SetLinkMTU(tap, plan.MTU); err != nil {
				log.Printf("session %s: tap %s MTU %d (bridge %s): %v", id, tap, plan.MTU, plan.Bridge, err)
			}
		}
		if plan.MTU > 0 && plan.MTU < 1500 {
			spec.HostMTU = plan.MTU
		}
		spec.TapName = tap
	}

	if s.Passthrough != "" {
		for _, a := range strings.Split(s.Passthrough, ",") {
			if a = strings.TrimSpace(a); a != "" {
				spec.Passthrough = append(spec.Passthrough, a)
			}
		}
	}
	spec.DiskLockingOff = onCIFS(s.DiskPath) // CIFS: disable image locking (migration)
	proc, err := qemu.Launch(spec, qemu.LogPath(m.cfg.Paths.DiskDir, id))
	if err != nil {
		m.setError(id)
		return nil, err
	}
	start := procStartTime(proc.Pid)
	_, err = m.db.Exec(`UPDATE sessions SET state='running', pid=?, pid_start_time=?, vnc_port=?, ws_port=?,
		vnc_password=?, qmp_socket=?, spice_port=?, last_started_at=? WHERE id=?`,
		proc.Pid, start, vncPort, wsPort, pw, qmpSock, spicePort, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return nil, err
	}
	// Pin vCPU threads 1:1 to host CPUs (best effort; never fails the start).
	if s.PinCPUs {
		m.pinVCPUs(id, qmpSock, proc.Pid, s.CPUs)
	}
	return m.Get(id)
}

// Stop gracefully powers down a running session (ACPI via QMP), falling back to
// SIGTERM then SIGKILL so a running guest's disk is not left dirty.
func (m *Manager) Stop(id string) error {
	if m.MigrationBusy(id) {
		return fmt.Errorf("instance is migrating its storage; try again when the move finishes")
	}
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if s.PID > 0 {
		m.gracefulShutdown(s)
	}
	// Reap this VM's software-TPM (if any). The NVRAM state dir is preserved.
	m.stopSwtpm(id)
	// Remove this VM's tap from the fabric (global bridge or a port group).
	// Best effort: a missing tap is fine. The IP lease is kept so a restart
	// reuses it.
	netdrv.TeardownTap(netdrv.TapName(id))
	m.releasePins(id) // free this VM's pinned host CPUs for the allocator
	_, err = m.db.Exec(`UPDATE sessions SET state='stopped', pid=0, pid_start_time='' WHERE id=?`, id)
	return err
}

func (m *Manager) gracefulShutdown(s *Session) {
	start := m.startTime(s.ID)
	// 1. ACPI powerdown via QMP.
	if s.QMPSocket != "" {
		if err := qemu.QMPPowerdown(s.QMPSocket); err == nil {
			if waitGone(s.PID, start, 8*time.Second) {
				return
			}
		}
	}
	// 2. SIGTERM.
	if p, err := os.FindProcess(s.PID); err == nil {
		_ = p.Signal(syscall.SIGTERM)
	}
	if waitGone(s.PID, start, 5*time.Second) {
		return
	}
	// 3. SIGKILL.
	if p, err := os.FindProcess(s.PID); err == nil {
		_ = p.Signal(syscall.SIGKILL)
	}
}

// Get reads a session row. It performs NO writes — reconciliation of stale
// 'running' rows is the reconciler's job, so reads never contend on the writer.
func (m *Manager) Get(id string) (*Session, error) {
	row := m.db.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE id=? AND deleted_at IS NULL`, id)
	return scanSession(row)
}

// Running reports whether the session's process is actually alive right now.
func (m *Manager) Running(s *Session) bool {
	return s.State == "running" && processAliveSince(s.PID, m.startTime(s.ID))
}

// List returns an org's live (non-deleted) sessions in one query.
func (m *Manager) List(orgID int64) ([]*Session, error) {
	rows, err := m.db.Query(`SELECT `+sessionCols+` FROM sessions
		WHERE org_id=? AND deleted_at IS NULL ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SetAutostart sets the "start at boot" flag for a VM.
func (m *Manager) SetAutostart(id string, on bool) error {
	v := 0
	if on {
		v = 1
	}
	_, err := m.db.Exec(`UPDATE sessions SET autostart=? WHERE id=? AND deleted_at IS NULL`, v, id)
	return err
}

// idSet runs a single-column (id) query and returns the ids. Used by the boot
// autostart and shutdown-all paths, which operate across all orgs on this host.
func (m *Manager) idSet(q string) ([]string, error) {
	rows, err := m.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AutostartIDs returns every autostart-flagged VM on this host that is NOT
// currently marked running — the set to power on after a host reboot.
func (m *Manager) AutostartIDs() ([]string, error) {
	return m.idSet(`SELECT id FROM sessions
		WHERE COALESCE(autostart,1)=1 AND state!='running' AND deleted_at IS NULL`)
}

// RunningIDs returns every VM marked running on this host — the set to power
// down gracefully when the host is shutting down.
func (m *Manager) RunningIDs() ([]string, error) {
	return m.idSet(`SELECT id FROM sessions WHERE state='running' AND deleted_at IS NULL`)
}

// ShutdownAll gracefully powers down every running VM on this host, in parallel,
// bounded by timeout. Used by `vdxd shutdown-vms` at host poweroff so guests get
// a clean ACPI shutdown (flushed disks) instead of being SIGKILLed when the host
// goes down. Each VM follows the normal ACPI→SIGTERM→SIGKILL fallback; the final
// SIGKILL guarantees we return within the budget even if a guest ignores ACPI.
func (m *Manager) ShutdownAll(timeout time.Duration) int {
	ids, err := m.RunningIDs()
	if err != nil {
		return 0
	}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = m.Stop(id) // ACPI powerdown, then SIGTERM, then SIGKILL
		}(id)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
	return len(ids)
}

// Delete soft-deletes a session (moves it to Trash) after stopping it. The
// overlay disk is left in place until a purge; retention worker purges later.
// GuestAgentInfo queries the VM's qemu-guest-agent (if enabled and running) and
// returns whatever it can. Never blocks for more than ~1.5s; a VM without the
// agent enabled or not running yields an empty (non-responsive) result.
func (m *Manager) GuestAgentInfo(id string) qemu.GuestInfo {
	s, err := m.Get(id)
	if err != nil || !s.GuestAgent || !m.Running(s) {
		return qemu.GuestInfo{}
	}
	gi := qemu.QueryGuestAgent(filepath.Join(m.cfg.Paths.DiskDir, id+".qga"))
	// For a VM installed from an ISO (no base image), persist the OS the agent
	// reports so the UI can show it instead of "(install from ISO)". Only updates
	// when it actually changed, so this is cheap on the repeated UI poll.
	if gi.Responsive && gi.OS != "" && s.ImageName == isoInstallImage && s.GuestOS != gi.OS {
		_, _ = m.db.Exec(`UPDATE sessions SET guest_os=? WHERE id=?`, gi.OS, id)
	}
	return gi
}

// SetNetwork rebinds a session's NIC to a port group (0 = default/NAT). The new
// binding is persisted immediately. When the VM is running and both the target
// is a live vSwitch and the VM already has a bridged tap, the tap is MOVED live
// to the new vSwitch (no restart, guest NIC stays up). Returns live=true when it
// was applied live; live=false means it will take effect on the next start (e.g.
// switching to/from user-mode NAT, which is a QEMU netdev type that can't hot-swap,
// or when the target vSwitch isn't present). The guest keeps its IP/MAC either way.
// A move to a bridge with a SMALLER MTU than the guest's NIC (e.g. onto a VXLAN
// port group) is also deferred: the guest learns its MTU only at start.
// A tenant org's VM may not be unbound (0) or put on a bridgeless port group.
func (m *Manager) SetNetwork(id string, networkID int64) (live bool, err error) {
	cur, err := m.Get(id)
	if err != nil {
		return false, err
	}
	if err := m.CheckPortGroup(cur.OrgID, networkID); err != nil {
		return false, err
	}
	if _, err := m.db.Exec(`UPDATE sessions SET network_id=? WHERE id=?`, nullIf0(networkID), id); err != nil {
		return false, err
	}
	s, err := m.Get(id)
	if err != nil {
		return false, err
	}
	if !m.Running(s) {
		return false, nil // stopped: picked up by planNIC on next start
	}
	// Resolve the new target exactly as Start would (see planNIC).
	plan, err := m.planNIC(s)
	if err != nil {
		return false, nil // persisted; Start reports why it can't attach
	}
	tap := netdrv.TapName(id)
	// Live move is only possible when the VM currently has a bridged tap AND the
	// target is a present vSwitch. Otherwise leave it pending for next start.
	if plan.UserNet || plan.Bridge == "" || !netdrv.IfaceExists(tap) || !netdrv.IfaceExists(plan.Bridge) {
		return false, nil
	}
	if plan.MTU > 0 && plan.MTU < guestMTUOf(s.PID) {
		return false, nil
	}
	if err := netdrv.RebindTap(tap, plan.Bridge, plan.VLAN); err != nil {
		return false, err
	}
	if plan.MTU > 0 && netdrv.LinkMTU(tap) != plan.MTU {
		_ = netdrv.SetLinkMTU(tap, plan.MTU) // keep the tap from capping the bridge
	}
	return true, nil
}

// DetectGuestOS probes the guest agent of every running ISO-install VM that has
// no recorded OS yet and persists what it finds (via GuestAgentInfo's side
// effect). A VM leaves the candidate set as soon as its OS is recorded, so this
// does no work once every ISO VM is identified.
func (m *Manager) DetectGuestOS() {
	rows, err := m.db.Query(`SELECT id FROM sessions
		WHERE image_name=? AND state='running' AND COALESCE(guest_os,'')='' AND deleted_at IS NULL`,
		isoInstallImage)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_ = m.GuestAgentInfo(id) // persists guest_os as a side effect when detected
	}
}

// DisplayImage is what the UI should show in a VM's "Image" column: the base
// image it was cloned from, or — for an ISO install — the detected guest OS once
// the agent has reported it, falling back to the "(install from ISO)" label.
func (s *Session) DisplayImage() string {
	if s.ImageName != isoInstallImage && s.ImageName != "" {
		return s.ImageName
	}
	if s.GuestOS != "" {
		return s.GuestOS
	}
	return isoInstallImage
}

// StorageLabel is a short human description of where/how the VM's disk is stored
// — the storage provider plus the pool/target it lives on — for the instances
// list. Derived from the disk backend and the disk path.
func (s *Session) StorageLabel() string { return StorageLabelFor(s.DiskBackend, s.DiskPath) }

// StorageLabelFor renders a disk's storage provider + pool/target from its backend
// and disk path (shared by the Session method and the cluster aggregator).
func StorageLabelFor(backend, diskPath string) string {
	switch backend {
	case "rbd":
		pool := "rbd"
		if rest, ok := strings.CutPrefix(diskPath, "rbd:"); ok {
			if i := strings.IndexByte(rest, '/'); i > 0 {
				pool = rest[:i]
			}
		}
		return "Ceph RBD · " + pool
	case "lvm":
		if p, ok := strings.CutPrefix(diskPath, "/dev/"); ok {
			if i := strings.IndexByte(p, '/'); i > 0 {
				return "LVM thin · " + p[:i]
			}
		}
		return "LVM thin"
	case "zvol":
		if p, ok := strings.CutPrefix(diskPath, "/dev/zvol/"); ok {
			if i := strings.IndexByte(p, '/'); i > 0 {
				return "ZFS zvol · " + p[:i]
			}
		}
		return "ZFS zvol"
	default:
		return "qcow2 file"
	}
}

func (m *Manager) Delete(id string) error {
	if m.MigrationBusy(id) {
		return fmt.Errorf("instance is migrating its storage; try again when the move finishes")
	}
	if m.BackupBusy(id) {
		return ErrBackupBusy
	}
	_ = m.Stop(id)
	_, err := m.db.Exec(`UPDATE sessions SET deleted_at=? WHERE id=? AND deleted_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// Snapshots, instant clones and Purge live in snapshots.go / snaprecords.go.

// ListTrash returns an org's soft-deleted (trashed) sessions.
func (m *Manager) ListTrash(orgID int64) ([]*Session, error) {
	rows, err := m.db.Query(`SELECT `+sessionCols+` FROM sessions
		WHERE org_id=? AND deleted_at IS NOT NULL ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Restore brings a trashed session back (clears deleted_at + retention_at).
func (m *Manager) Restore(id string) error {
	_, err := m.db.Exec(`UPDATE sessions SET deleted_at=NULL, retention_at=NULL WHERE id=?`, id)
	return err
}

// AdoptRunningVMs rediscovers QEMU VMs already running on this host WITHOUT
// relying on the DB, and repairs their session rows. This is the self-heal that
// keeps a broken/restored/fresh control-plane DB from disrupting live VMs: it
// scans /proc for `qemu-system-x86_64 -name vdx-<id>`, recovers each VM's VNC/WS
// ports, QMP socket and VNC password from the live command line + on-disk files,
// and updates the row to state='running' with the real pid. A live VM with no DB
// row at all (created after the last good backup) is left running and logged —
// never killed.
func (m *Manager) AdoptRunningVMs() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue // not a pid dir
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(string(raw), "\x00")
		if len(args) == 0 || !strings.Contains(args[0], "qemu-system-x86_64") {
			continue
		}
		pid, _ := strconv.Atoi(e.Name())
		id, vncPort, wsPort, qmp := parseQemuCmdline(args)
		if id == "" {
			continue
		}
		m.adoptOne(id, pid, vncPort, wsPort, qmp)
	}
}

// parseQemuCmdline extracts the VM id and recoverable runtime handles from a
// qemu argv (split on NUL).
func parseQemuCmdline(args []string) (id string, vncPort, wsPort int, qmp string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-name":
			if i+1 < len(args) && strings.HasPrefix(args[i+1], "vdx-") {
				id = strings.TrimPrefix(args[i+1], "vdx-")
			}
		case "-vnc":
			if i+1 < len(args) {
				// e.g. 127.0.0.1:3,websocket=127.0.0.1:6903,password-secret=vncpw
				for _, f := range strings.Split(args[i+1], ",") {
					if d := strings.LastIndexByte(f, ':'); d >= 0 {
						if strings.HasPrefix(f, "websocket=") {
							wsPort = atoiSafe(f[d+1:])
						} else if strings.HasPrefix(f, "127.0.0.1:") || strings.HasPrefix(f, "[::1]:") {
							if disp := atoiSafe(f[d+1:]); disp >= 0 {
								vncPort = 5900 + disp
							}
						}
					}
				}
			}
		case "-qmp":
			if i+1 < len(args) {
				v := strings.TrimPrefix(args[i+1], "unix:")
				if c := strings.IndexByte(v, ','); c >= 0 {
					v = v[:c]
				}
				qmp = v
			}
		}
	}
	return
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}

// adoptOne repairs a single live VM's DB row (or logs an orphan it can't place).
func (m *Manager) adoptOne(id string, pid, vncPort, wsPort int, qmp string) {
	var state string
	var dbpid int
	var dbstart string
	err := m.db.QueryRow(`SELECT state,COALESCE(pid,0),COALESCE(pid_start_time,'') FROM sessions WHERE id=? AND deleted_at IS NULL`, id).
		Scan(&state, &dbpid, &dbstart)
	if err != nil {
		// No row (fresh/rolled-back DB, or the VM was created after the last
		// good backup). We cannot reconstruct org/owner/name safely — leave it
		// running and untouched, and tell the operator.
		log.Printf("adopt: live VM %s (pid %d) has no DB row — left RUNNING and unmanaged; recreate its record or stop it manually", id, pid)
		return
	}
	start := procStartTime(pid)
	if state == "running" && dbpid == pid && dbstart == start {
		return // already correct
	}
	if _, err := m.db.Exec(`UPDATE sessions SET state='running', pid=?, pid_start_time=? WHERE id=?`, pid, start, id); err != nil {
		return
	}
	if vncPort > 0 {
		_, _ = m.db.Exec(`UPDATE sessions SET vnc_port=?, ws_port=? WHERE id=?`, vncPort, wsPort, id)
	}
	if qmp != "" {
		_, _ = m.db.Exec(`UPDATE sessions SET qmp_socket=? WHERE id=?`, qmp, id)
	}
	if b, e := os.ReadFile(filepath.Join(m.cfg.Paths.DiskDir, id+".vncpw")); e == nil {
		if pw := strings.TrimSpace(string(b)); pw != "" {
			_, _ = m.db.Exec(`UPDATE sessions SET vnc_password=? WHERE id=?`, pw, id)
		}
	}
	log.Printf("adopt: re-adopted live VM %s (pid %d; db said %q) and restored its console handles", id, pid, state)
}

// Reconcile marks as 'stopped' any row claiming 'running' whose process is gone.
// This is the ONLY place stale running rows are corrected; the worker runs it.
func (m *Manager) Reconcile() {
	rows, err := m.db.Query(`SELECT id,pid,pid_start_time FROM sessions WHERE state='running' AND deleted_at IS NULL`)
	if err != nil {
		return
	}
	var toStop []string
	for rows.Next() {
		var id, start string
		var pid int
		if err := rows.Scan(&id, &pid, &start); err != nil {
			continue
		}
		if !processAliveSince(pid, start) {
			toStop = append(toStop, id)
		}
	}
	rows.Close()
	for _, id := range toStop {
		_, _ = m.db.Exec(`UPDATE sessions SET state='stopped', pid=0, pid_start_time='' WHERE id=?`, id)
	}
}

func (m *Manager) setError(id string) {
	_, _ = m.db.Exec(`UPDATE sessions SET state='error', pid=0 WHERE id=?`, id)
}

func (m *Manager) startTime(id string) string {
	var s string
	_ = m.db.QueryRow(`SELECT pid_start_time FROM sessions WHERE id=?`, id).Scan(&s)
	return s
}

// allocPorts picks a free VNC display port and its websocket port. Both are
// tracked so two VMs never collide on either. Caller holds m.mu.
func (m *Manager) allocPorts() (vnc, ws int, err error) {
	used := map[int]bool{}
	rows, err := m.db.Query(`SELECT vnc_port, ws_port FROM sessions WHERE state='running'`)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var v, w int
		if err := rows.Scan(&v, &w); err == nil {
			used[v] = true
			used[w] = true
		}
	}
	rows.Close()
	base := m.cfg.Server.VNCPortBase
	for p := base; p < base+256; p++ {
		w := p + 1000
		if !used[p] && !used[w] {
			return p, w, nil
		}
	}
	return 0, 0, errors.New("no free VNC port")
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randVNCPassword returns a per-launch VNC console password. RFB "VNC auth"
// only ever uses the first 8 characters (they are a DES key), so a hex string
// carried just 32 bits; 8 characters of a 62-symbol alphabet carry ~47.6.
func randVNCPassword() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, 0, 8)
	buf := make([]byte, 16)
	for len(out) < 8 {
		_, _ = rand.Read(buf)
		for _, b := range buf {
			if b < 248 && len(out) < 8 { // 248 = 4*62: rejection keeps it unbiased
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out)
}

// randPassword returns a readable but high-entropy first-boot password (no
// ambiguous characters), used when the caller does not supply one.
func randPassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// sanitizeHostname reduces an instance name to a DNS-safe hostname.
func sanitizeHostname(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == '_':
			b.WriteByte('-')
		}
	}
	h := strings.Trim(b.String(), "-")
	if h == "" {
		h = "vdx"
	}
	if len(h) > 63 {
		h = h[:63]
	}
	return h
}

// resolveTapTarget maps a VM's bound port group (sessions.network_id) to the
// vSwitch bridge and VLAN its tap should attach to. A port group is "attachable"
// when it names a host bridge (a vSwitch); its vlan_id becomes the access-port
// PVID. Returns attach=false when the VM has no port group, the port group is
// gone, or it is user-mode (no bridge), so planNIC can decide the fallback. A
// port group of ANOTHER org is an error, never a bridge to attach to (e.g. a
// network_id carried over from another node's DB by a migration).
func (m *Manager) resolveTapTarget(s *Session) (bridge string, vlan int, attach bool, err error) {
	if s.NetworkID == 0 {
		return "", 0, false, nil
	}
	var br string
	var vl int
	var org int64
	err = m.db.QueryRow(`SELECT org_id, COALESCE(bridge,''), COALESCE(vlan_id,0) FROM networks WHERE id=?`, s.NetworkID).Scan(&org, &br, &vl)
	if isNoRows(err) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	if org != s.OrgID {
		return "", 0, false, fmt.Errorf("this instance's port group belongs to another organization — pick one of its own port groups in the Network setting")
	}
	if br == "" {
		return "", 0, false, nil
	}
	return br, vl, true, nil
}

// ensureDefaultNetwork returns (creating if needed) an org's row for the shared
// cluster bridge, under which cluster-subnet guest leases are filed. The CIDR/
// gateway come from the cluster config so every node allocates from the same
// overlay subnet. It matches only the untagged cluster-bridge row on that subnet
// (never just "the org's first bridged port group", which filed cluster-subnet
// leases under unrelated VLAN port groups); allocLease's wide scope still counts
// any such legacy lease as taken.
func (m *Manager) ensureDefaultNetwork(orgID int64) (int64, string, string, error) {
	cidr := m.cfg.Cluster.Subnet
	gw := m.cfg.Cluster.Gateway
	if cidr == "" {
		cidr = "10.77.0.0/16"
	}
	var id int64
	err := m.db.QueryRow(`SELECT id FROM networks WHERE org_id=? AND mode IN('bridge','overlay') AND bridge=? AND vlan_id=0 AND cidr=?
		ORDER BY id LIMIT 1`, orgID, m.cfg.Cluster.Bridge, cidr).Scan(&id)
	if err == nil {
		return id, cidr, gw, nil
	}
	mode := "bridge"
	if m.cfg.Cluster.Overlay {
		mode = "overlay"
	}
	res, err := m.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr,gateway,pool_start,pool_end)
		VALUES(?,?,?,?,0,?,?,'','')`, orgID, "default-"+mode, mode, m.cfg.Cluster.Bridge, cidr, gw)
	if err != nil {
		return 0, "", "", err
	}
	id, _ = res.LastInsertId()
	return id, cidr, gw, nil
}

// ReceiverSpec builds the qemu.Spec a destination node should launch to receive
// a live migration of this session. Incoming is left to the migration
// orchestrator to set. It mirrors the source VM's hardware exactly (same disk
// path — valid only under shared storage — firmware, NVRAM, MAC and sizing) so
// the guest resumes identically on the far node.
func (m *Manager) ReceiverSpec(id string) (qemu.Spec, error) {
	s, err := m.Get(id)
	if err != nil {
		return qemu.Spec{}, err
	}
	var base string
	if err := m.db.QueryRow(`SELECT path FROM images WHERE name=?`, s.ImageName).Scan(&base); err != nil {
		return qemu.Spec{}, err
	}
	// The NIC policy a fresh start would apply (a tenant VM without a port group
	// of its own is not launched anywhere — a receiver is a launch too). The NIC
	// itself mirrors the SOURCE process exactly (netdev type, host_mtu): the
	// device config must be identical or the migration stream is rejected.
	plan, err := m.planNIC(s)
	if err != nil {
		return qemu.Spec{}, fmt.Errorf("can't migrate: %w", err)
	}
	ref, err := m.PortGroupRefFor(s)
	if err != nil {
		return qemu.Spec{}, fmt.Errorf("can't migrate: %w", err)
	}
	srcArgs := procArgs(s.PID)
	userNet := plan.UserNet
	if u, known := userNetFromArgs(srcArgs); known {
		userNet = u
	}
	spec := qemu.Spec{
		ID:        s.ID,
		BaseImage: base,
		DiskPath:  s.DiskPath,
		CPUs:      s.CPUs,
		MemoryMB:  s.MemoryMB,
		VNCPort:   s.VNCPort,
		WSPort:    s.WSPort,
		QMPSocket: s.QMPSocket,
		UserNet:   userNet,
		HostMTU:   hostMTUFromArgs(srcArgs),
		// The console password travels with the spec so the destination can put
		// it in its own 0600 secret file; without it the receiver's VNC would come
		// up with no password at all.
		VNCPassword: s.VNCPassword,
		EnableKVM:   qemu.KVMAvailable(),
		Firmware:  s.Firmware,
		SeedISO:   s.SeedPath,
		MAC:       s.MAC,
		SerialSock: filepath.Join(m.cfg.Paths.DiskDir, s.ID+".serial"),
		DiskRaw:    s.DiskBackend == "zvol" || s.DiskBackend == "lvm",
		DiskLockingOff: onCIFS(s.DiskPath), // CIFS shared disk: no image locking
		// Hardware MUST be byte-identical to the source or live migration fails
		// (or, worse, Windows reactivates/loses NICs). Mirror every knob.
		MachineType: s.MachineType,
		DiskBus:     s.DiskBus,
		NICModel:    s.NICModel,
		VGA:         s.VGA,
		Windows:     s.OSType == "windows",
		GuestAgent:  s.GuestAgent,
		// The destination attaches the NIC to its own copy of this port group.
		PortGroup: ref,
	}
	// Display backend + the shared virtio-serial controller must match the
	// source's device topology, so mirror spice/guest-agent channels.
	if s.Display == "spice" {
		spec.Display = "spice"
		spec.SPICEPort = s.VNCPort + 3000
	}
	if s.GuestAgent {
		spec.QGASocket = filepath.Join(m.cfg.Paths.DiskDir, s.ID+".qga")
		_ = os.Remove(spec.QGASocket)
	}
	if s.OSType == "windows" {
		spec.ExtraISO = qemu.VirtioWinISO(m.cfg.Paths.ISODir)
	}
	// TPM-backed VMs are refused by the migrate path (swtpm NVRAM is host-local),
	// so no TPM device is mirrored here.
	if s.Firmware == "uefi" {
		code, _, ok := qemu.OVMF()
		if s.SecureBoot {
			if sc, _, sok := qemu.OVMFSecure(); sok {
				code, ok = sc, true
			}
		}
		if ok {
			spec.OVMFCodePath = code
			spec.OVMFVarsPath = s.OVMFVarsPath
		}
	}
	return spec, nil
}

// SerialSockFor returns a running session's serial-console unix socket path (and
// whether the socket currently exists on disk — it is only present for VMs
// launched since serial support was added, i.e. after a (re)start).
func (m *Manager) SerialSockFor(id string) (string, bool, error) {
	s, err := m.Get(id)
	if err != nil {
		return "", false, err
	}
	p := filepath.Join(m.cfg.Paths.DiskDir, s.ID+".serial")
	_, statErr := os.Stat(p)
	return p, statErr == nil, nil
}

// LaunchReceiver starts a QEMU on THIS node ready to receive an inbound live
// migration. It decodes a base64-encoded qemu.Spec (shipped by the source over
// the authenticated peer API), sets its Incoming listener to the given port, and
// launches it. Replaces the old SSH-driven `vdxd migrate-recv` path — no inter-
// node SSH keys required.
func (m *Manager) LaunchReceiver(specB64 string, port int) (int, error) {
	blob, err := base64.StdEncoding.DecodeString(specB64)
	if err != nil {
		return 0, fmt.Errorf("decode receiver spec: %w", err)
	}
	var spec qemu.Spec
	if err := json.Unmarshal(blob, &spec); err != nil {
		return 0, fmt.Errorf("unmarshal receiver spec: %w", err)
	}
	// Pick an incoming port that is actually free on THIS node. The old code used
	// a single fixed port (49200) for every migration; a lingering/stuck receiver
	// from a prior migration keeps that port bound, so the new receiver failed to
	// launch ("Address already in use") while the source streamed into the stale
	// listener and wrongly reported success — leaving the VM adopted but dead.
	if port <= 0 || !portAvailable(port) {
		if fp := freeTCPPort(49200); fp > 0 {
			port = fp
		} else if port <= 0 {
			return 0, fmt.Errorf("no free incoming migration port")
		}
	}
	spec.Incoming = fmt.Sprintf("tcp:0.0.0.0:%d", port)
	// Launch identity exactly as a normal Start does (run-as user or the guard
	// group, never trusted from the wire), the console password into a local
	// secret file, and the SLIRP loopback guard for a user-mode receiver.
	if err := m.prepareReceiverSpec(&spec); err != nil {
		return 0, err
	}
	// The NIC goes on this node's copy of the VM's port group, before the
	// stream starts (a receiver with no tap resumes the guest offline).
	rn, err := m.attachReceiverNIC(&spec)
	if err != nil {
		return 0, fmt.Errorf("can't receive this instance: %w", err)
	}
	launched := false
	defer func() {
		if !launched {
			m.detachReceiverNIC(spec.ID, rn)
		}
	}()
	logPath := qemu.LogPath(m.cfg.Paths.DiskDir, "recv-"+spec.ID)
	proc, err := qemu.Launch(spec, logPath)
	if err != nil {
		return 0, fmt.Errorf("launch receiver: %w", err)
	}
	// Verify the receiver actually came up and bound its incoming port before we
	// let the source stream to it. If QEMU exited immediately (e.g. a port clash),
	// return the error with the log tail so the source aborts instead of streaming
	// into the void / a stale listener.
	time.Sleep(900 * time.Millisecond)
	if !processAliveSince(proc.Pid, procStartTime(proc.Pid)) {
		_ = proc.Kill()
		return 0, fmt.Errorf("receiver exited on launch: %s", readLogTail(logPath, 300))
	}
	// Remember the receiver process so AdoptMigrated can record its real pid when
	// the source commits the migration.
	m.trackIncoming(spec.ID, proc, rn)
	launched = true
	return port, nil
}

// portAvailable reports whether a TCP port can be bound on all interfaces now.
func portAvailable(p int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", p))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// freeTCPPort scans upward from base for a bindable port (small race window
// between the probe and QEMU's bind, acceptable for this control path).
func freeTCPPort(base int) int {
	for p := base; p < base+400; p++ {
		if portAvailable(p) {
			return p
		}
	}
	return 0
}

// readLogTail returns up to n trailing bytes of a file (for error surfacing).
func readLogTail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}

// AdoptMigrated records a freshly-migrated VM in THIS node's DB, completing the
// ownership handoff: the row is inserted (or revived, for a migrate-back) in the
// running state, bound to the receiver QEMU's real pid. Called on the destination
// when the source commits a completed live migration. Without this the migrated
// VM would be invisible to the destination's control plane (and un-migratable
// back). The runtime fields (pid/qmp/ports) come from the launched receiver and
// the shipped record.
func (m *Manager) AdoptMigrated(s *Session) error {
	proc, rn, _ := m.takeIncoming(s.ID)
	if proc == nil {
		return fmt.Errorf("no incoming migration receiver for %s", s.ID)
	}
	// The port group the receiver was attached to here (resolved before the
	// stream, so this can't fail now); the shipped id is the source node's.
	s.NetworkID = rn.NetID
	ci := 0
	if s.CloudInit {
		ci = 1
	}
	// Block-live migration: the disk lives at a DESTINATION-local path (its own disk
	// dir), which may differ from the shipped (source) path when the source disk was
	// in a pool. Record the dest path and clear pool_id so the adopted VM opens its
	// own copy.
	if t, ok := m.blockTargetPath(s.ID); ok && t != "" {
		s.DiskPath = t
		s.PoolID = 0
		m.ColdDone(s.ID) // aux files (vars/seed) are the VM's now — drop cleanup tracking
	}
	nid := m.localNodeID()
	start := procStartTime(proc.Pid)
	_, err := m.db.Exec(`INSERT INTO sessions
		(id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,boot_iso_id,mac,
		 cpus,memory_mb,disk_gb,state,cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,
		 network_id,display,disk_backend,pool_id,
		 pid,pid_start_time,vnc_port,ws_port,vnc_password,qmp_socket,spice_port,node_id,last_started_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?,?,'running',?,?,?,?,?,?, ?,?,?,?, ?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET state='running',deleted_at=NULL,
		 pid=excluded.pid,pid_start_time=excluded.pid_start_time,qmp_socket=excluded.qmp_socket,
		 vnc_port=excluded.vnc_port,ws_port=excluded.ws_port,vnc_password=excluded.vnc_password,
		 spice_port=excluded.spice_port,node_id=excluded.node_id,network_id=excluded.network_id`,
		s.ID, s.Name, s.OrgID, s.OwnerID, s.ImageName, s.DiskPath, s.Kind, s.Firmware, s.OVMFVarsPath, nullIf0(s.BootISOID), s.MAC,
		s.CPUs, s.MemoryMB, s.DiskGB, ci, s.CIUsername, s.CIPassword, s.CISSHKey, s.SeedPath, s.Passthrough,
		nullIf0(s.NetworkID), s.Display, s.DiskBackend, nullIf0(s.PoolID),
		proc.Pid, start, s.VNCPort, s.WSPort, s.VNCPassword, s.QMPSocket, s.SPICEPort, nid, time.Now().UTC().Format(time.RFC3339))
	return err
}

// AdoptColdMigrated records a COLD-migrated (stopped) VM into this node's DB.
// Unlike AdoptMigrated there is no receiver QEMU: the row is inserted (or revived
// for a migrate-back) in the STOPPED state with no runtime fields. The caller has
// placed the disk at s.DiskPath on this node (unchanged for shared storage, or a
// freshly-copied path for a local→local move). We refuse unless the disk is
// actually present and readable here — so a failed/doomed handoff never strands
// the source (which keeps its row until our 200).
func (m *Manager) AdoptColdMigrated(s *Session) error {
	if s.DiskPath == "" {
		return fmt.Errorf("cold migrate: empty disk path")
	}
	if fi, err := os.Stat(s.DiskPath); err != nil || fi.IsDir() {
		return fmt.Errorf("cold migrate: disk not present on destination (%s): %v", s.DiskPath, err)
	}
	// Bind this node's copy of the VM's port group (the shipped id is the
	// source's) and keep the guest's address; refusing leaves the source as is.
	if err := m.CheckMigrationTarget(s); err != nil {
		return fmt.Errorf("cold migrate: %w", err)
	}
	netID, _ := m.migratedNetwork(s)
	lease := ""
	if s.PortGroup != nil {
		lease = s.PortGroup.Lease
	}
	if err := m.reserveMigratedLease(netID, s.ID, s.MAC, lease); err != nil {
		return fmt.Errorf("cold migrate: %w", err)
	}
	s.NetworkID = netID
	ci := 0
	if s.CloudInit {
		ci = 1
	}
	nid := m.localNodeID()
	_, err := m.db.Exec(`INSERT INTO sessions
		(id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,boot_iso_id,mac,
		 cpus,memory_mb,disk_gb,state,cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,
		 network_id,display,disk_backend,pool_id,node_id)
		VALUES(?,?,?,?,?,?,?,?,?,?,?, ?,?,?,'stopped',?,?,?,?,?,?, ?,?,?,?, ?)
		ON CONFLICT(id) DO UPDATE SET state='stopped',deleted_at=NULL,
		 disk_path=excluded.disk_path,ovmf_vars_path=excluded.ovmf_vars_path,seed_path=excluded.seed_path,
		 pool_id=excluded.pool_id,node_id=excluded.node_id,network_id=excluded.network_id,
		 pid=NULL,pid_start_time=NULL,qmp_socket=NULL,vnc_port=NULL,ws_port=NULL,vnc_password=NULL,spice_port=NULL`,
		s.ID, s.Name, s.OrgID, s.OwnerID, s.ImageName, s.DiskPath, s.Kind, s.Firmware, s.OVMFVarsPath, nullIf0(s.BootISOID), s.MAC,
		s.CPUs, s.MemoryMB, s.DiskGB, ci, s.CIUsername, s.CIPassword, s.CISSHKey, s.SeedPath, s.Passthrough,
		nullIf0(s.NetworkID), s.Display, s.DiskBackend, nullIf0(s.PoolID), nid)
	if err != nil {
		if lease != "" {
			m.releaseLeases(s.ID)
		}
		return err
	}
	m.ColdDone(s.ID) // adopted — the staged files are the VM's now, not garbage
	return nil
}

// AbortIncoming tears down a migration receiver that will not be committed (the
// source migration failed), so a half-migrated QEMU is not left running.
func (m *Manager) AbortIncoming(id string) {
	proc, rn, ok := m.takeIncoming(id)
	if proc != nil {
		_ = proc.Kill()
	}
	if ok {
		m.detachReceiverNIC(id, rn)
	}
}

// localNodeID returns this node's row id (role='local'), or NULL when unknown.
func (m *Manager) localNodeID() any {
	var id int64
	if err := m.db.QueryRow(`SELECT id FROM nodes WHERE role='local'`).Scan(&id); err == nil {
		return id
	}
	return nil
}

func nullIf0(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// DeleteSessionRow hard-removes a session row (used on the SOURCE after a
// completed migration hands ownership to the destination).
func (m *Manager) DeleteSessionRow(id string) error {
	_, err := m.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

// QMPSocketFor returns a running session's QMP control socket path.
func (m *Manager) QMPSocketFor(id string) (string, error) {
	s, err := m.Get(id)
	if err != nil {
		return "", err
	}
	return s.QMPSocket, nil
}

// portForwards loads a session's user-mode forwards, binding them to the
// configured forward host (or loopback when unset).
func (m *Manager) portForwards(sessionID string) []qemu.HostFwd {
	rows, err := m.db.Query(`SELECT proto,host_port,guest_port FROM port_forwards WHERE session_id=?`, sessionID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []qemu.HostFwd
	for rows.Next() {
		var f qemu.HostFwd
		if err := rows.Scan(&f.Proto, &f.HostPort, &f.GuestPort); err == nil {
			f.HostIP = m.cfg.Network.ForwardHost
			out = append(out, f)
		}
	}
	return out
}

// lookupUser resolves a username to its numeric uid/gid and the full set of
// supplementary group ids (which must include kvm for /dev/kvm access, since a
// Credential replaces the process's groups wholesale).
func lookupUser(name string) (uid, gid uint32, groups []uint32, ok bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, nil, false
	}
	ui, err1 := strconv.Atoi(u.Uid)
	gi, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, nil, false
	}
	groups = []uint32{uint32(gi)}
	if gids, err := u.GroupIds(); err == nil {
		for _, g := range gids {
			if n, err := strconv.Atoi(g); err == nil && uint32(n) != uint32(gi) {
				groups = append(groups, uint32(n))
			}
		}
	}
	return uint32(ui), uint32(gi), groups, true
}

func imageFileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// freeBytes returns the bytes available to an unprivileged writer under dir.
func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// ---- process liveness (PID-reuse safe) -----------------------------------

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// processAliveSince is alive AND (when a start-time is recorded) the process
// occupying the PID is the same one we launched — defeating PID reuse after a
// daemon restart.
func processAliveSince(pid int, startTime string) bool {
	if !processAlive(pid) {
		return false
	}
	if startTime == "" {
		return true // legacy row without a recorded start-time
	}
	return procStartTime(pid) == startTime
}

// onCIFS reports whether path lives on a CIFS/SMB mount, where QEMU's image file
// locking must be disabled (the lock handoff during live migration fails). Uses
// statfs; any error → false (keep locking on).
func onCIFS(path string) bool {
	const (
		cifsMagic = 0xFF534D42 // legacy CIFS
		smb2Magic = 0xFE534D42 // SMB2/SMB3 (modern cifs.ko) — what Ubuntu mounts use
	)
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	t := int64(st.Type)
	return t == cifsMagic || t == smb2Magic
}

// procStartTime reads field 22 (starttime, in clock ticks since boot) from
// /proc/<pid>/stat. Empty string if unavailable.
func procStartTime(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	// comm (field 2) may contain spaces/parens; split after the last ')'.
	s := string(data)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+2 >= len(s) {
		return ""
	}
	fields := strings.Fields(s[rp+2:]) // fields[0] == field 3 (state)
	const starttimeIdx = 22 - 3        // 0-based within the post-comm slice
	if len(fields) <= starttimeIdx {
		return ""
	}
	return fields[starttimeIdx]
}

func waitGone(pid int, startTime string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAliveSince(pid, startTime) {
			return true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return !processAliveSince(pid, startTime)
}
