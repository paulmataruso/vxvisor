// Package session manages the lifecycle of VM sessions.
package session

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/cloudinit"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
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
	DiskBackend  string // qcow2 | zvol
	CreatedAt    string
}

// sessionCols is the canonical column list/scan order for a session row.
const sessionCols = `id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,
	COALESCE(boot_iso_id,0),mac,cpus,memory_mb,disk_gb,state,pid,vnc_port,ws_port,vnc_password,qmp_socket,
	cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,COALESCE(pool_id,0),COALESCE(network_id,0),COALESCE(display,'vnc'),COALESCE(spice_port,0),COALESCE(disk_backend,'qcow2'),created_at`

func scanSession(sc interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var ci int
	err := sc.Scan(&s.ID, &s.Name, &s.OrgID, &s.OwnerID, &s.ImageName, &s.DiskPath, &s.Kind,
		&s.Firmware, &s.OVMFVarsPath, &s.BootISOID, &s.MAC, &s.CPUs, &s.MemoryMB, &s.DiskGB, &s.State, &s.PID,
		&s.VNCPort, &s.WSPort, &s.VNCPassword, &s.QMPSocket,
		&ci, &s.CIUsername, &s.CIPassword, &s.CISSHKey, &s.SeedPath, &s.Passthrough, &s.PoolID, &s.NetworkID, &s.Display, &s.SPICEPort, &s.DiskBackend, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	s.CloudInit = ci != 0
	return &s, nil
}

type Manager struct {
	cfg *config.Config
	db  *db.DB
	mu  sync.Mutex // serializes port allocation + launch
}

func NewManager(cfg *config.Config, d *db.DB) *Manager {
	return &Manager{cfg: cfg, db: d}
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
	StoragePoolID  int64  // storage pool (storage_pools.id) for the disk; 0 = default disk dir
	Display        string // vnc | spice
	DiskBackend    string // qcow2 | zvol
	ZvolPool       string // ZFS pool/dataset name to create the zvol under (zvol backend)
	Desktop        string // "" | xfce (cloud-init installs a lightweight desktop)
}

// Create provisions a new session (overlay disk, firmware NVRAM, cloud-init seed
// ISO, DB row) in the stopped state. Any artifact it creates is cleaned up if a
// later step fails, so a failed create never leaves orphan files.
func (m *Manager) Create(o CreateOpts) (*Session, error) {
	if o.Kind == "" {
		o.Kind = "desktop"
	}
	if o.Firmware == "" {
		o.Firmware = "uefi"
	}
	if o.Firmware == "uefi" {
		if _, _, ok := qemu.OVMF(); !ok {
			o.Firmware = "bios" // host has no OVMF; fall back rather than fail
		}
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
	if o.StoragePoolID > 0 {
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
	fail := func(e error) (*Session, error) {
		for _, f := range created {
			_ = os.Remove(f)
		}
		if zvolName != "" {
			_ = zfs.DestroyDataset(zvolName)
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
		varsPath = filepath.Join(m.cfg.Paths.DiskDir, id+".ovmf_vars.fd")
		if err := qemu.PrepareUEFIVars(varsTmpl, varsPath); err != nil {
			return fail(err)
		}
		created = append(created, varsPath)
	}

	// MAC is pinned now so the cloud-init network-config (bridge/overlay mode)
	// can match it to the guest NIC and the address survives reboots.
	mac := netdrv.GenMAC()

	// Bridge/overlay networking: allocate a stable guest IP from the cluster
	// subnet so the VM comes up routable (for RDP and for migration identity).
	var staticIP, gw string
	if m.cfg.Network.Mode == "bridge" || m.cfg.Network.Mode == "overlay" {
		if netID, cidr, gateway, err := m.ensureDefaultNetwork(o.OrgID); err == nil {
			if leased, err := netdrv.New(m.db).AllocLease(netID, id, mac, cidr, gateway); err == nil {
				staticIP, gw = leased, gateway
			}
		}
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
		// Provision an xrdp desktop when the guest is routable (bridge/overlay)
		// and the gateway is configured for RDP, so "Open desktop" gives a full
		// RDP session with device redirection rather than only the VNC console.
		installRDP := staticIP != "" && m.cfg.Gateway.Protocol == "rdp"
		cfg := cloudinit.Config{
			InstanceID: id, Hostname: sanitizeHostname(o.Name),
			Username: o.CIUsername, Password: o.CIPassword, SSHKey: o.CISSHKey,
			MAC: mac, StaticIP: staticIP, Gateway: gw, InstallRDP: installRDP, Desktop: o.Desktop,
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
	var netID any
	if o.NetworkID > 0 {
		netID = o.NetworkID
	}
	var poolID any
	if o.StoragePoolID > 0 {
		poolID = o.StoragePoolID
	}
	display := o.Display
	if display != "spice" {
		display = "vnc"
	}
	_, err := m.db.Exec(`INSERT INTO sessions
		(id,name,org_id,owner_id,image_name,disk_path,kind,firmware,ovmf_vars_path,boot_iso_id,mac,
		 cpus,memory_mb,disk_gb,state,cloud_init,ci_username,ci_password,ci_ssh_key,seed_path,passthrough,network_id,storage_pool_id,display,disk_backend)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'stopped',?,?,?,?,?,?,?,?,?,?)`,
		id, o.Name, o.OrgID, o.OwnerID, o.ImageName, disk, o.Kind, o.Firmware, varsPath, bootISO, mac,
		o.CPUs, o.MemoryMB, o.DiskGB, ci, o.CIUsername, o.CIPassword, o.CISSHKey, seedPath, o.Passthrough, netID, poolID, display, diskBackend)
	if err != nil {
		return fail(err)
	}
	return m.Get(id)
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
	if diskGB > 0 && diskGB < s.DiskGB {
		return fmt.Errorf("cannot shrink disk from %d GB to %d GB", s.DiskGB, diskGB)
	}
	if diskGB > 0 {
		if s.DiskBackend == "zvol" && strings.HasPrefix(s.DiskPath, "/dev/zvol/") {
			// Grow the ZFS volume (the guest expands its filesystem on next boot).
			if err := zfs.SetVolsize(strings.TrimPrefix(s.DiskPath, "/dev/zvol/"), int64(diskGB)<<30); err != nil {
				return err
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
	_, err = m.db.Exec(`UPDATE sessions SET cpus=?, memory_mb=?, disk_gb=? WHERE id=?`, cpus, memMB, dg, id)
	return err
}

// Start launches QEMU for a stopped session.
func (m *Manager) Start(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if s.State == "running" && processAliveSince(s.PID, m.startTime(id)) {
		return s, nil
	}

	vncPort, wsPort, err := m.allocPorts()
	if err != nil {
		return nil, err
	}
	qmpSock := filepath.Join(m.cfg.Paths.DiskDir, id+".qmp")
	_ = os.Remove(qmpSock)

	// Per-launch VNC password, written to a 0600 secret file (off the cmdline).
	pw := randHex(16)
	pwFile := filepath.Join(m.cfg.Paths.DiskDir, id+".vncpw")
	if err := qemu.WriteSecretFile(pwFile, pw); err != nil {
		return nil, err
	}

	var base string
	if err := m.db.QueryRow(`SELECT path FROM images WHERE name=?`, s.ImageName).Scan(&base); err != nil {
		return nil, err
	}

	spec := qemu.Spec{
		ID:        id,
		BaseImage: base,
		DiskPath:  s.DiskPath,
		CPUs:      s.CPUs,
		MemoryMB:  s.MemoryMB,
		VNCPort:   vncPort,
		WSPort:    wsPort,
		QMPSocket: qmpSock,
		UserNet:   m.cfg.Network.Mode == "user",
		EnableKVM: qemu.KVMAvailable(),
		VNCPwFile: pwFile,
		Firmware:  s.Firmware,
		SeedISO:   s.SeedPath,
		DiskRaw:   s.DiskBackend == "zvol",
	}
	// SPICE display: a loopback SPICE server + qxl, used by the guac desktop
	// gateway. VNC stays enabled so the plain noVNC console still works too.
	spicePort := 0
	if s.Display == "spice" {
		spicePort = vncPort + 3000 // unique per VM (vncPort is unique), loopback-bound
		spec.Display = "spice"
		spec.SPICEPort = spicePort
	}
	if s.Firmware == "uefi" {
		code, _, ok := qemu.OVMF()
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

	// Attach this VM's NIC to the fabric. A VM bound to a port group (network_id)
	// lands on that port group's vSwitch as an access port with the port group's
	// VLAN as PVID — exactly like a VMware port group. A VM with no port group
	// falls back to the global cluster bridge when bridge/overlay mode is on.
	// The tap is owned by the run-as user so a dropped-privilege QEMU can open it.
	bridge, vlan, attach := m.resolveTapTarget(s)
	if !attach && (m.cfg.Network.Mode == "bridge" || m.cfg.Network.Mode == "overlay") {
		bridge, vlan, attach = m.cfg.Cluster.Bridge, 0, true
	}
	if attach {
		tap := netdrv.TapName(id)
		ownerUID := 0
		if m.cfg.VM.RunAs != "" {
			if uid, _, _, ok := lookupUser(m.cfg.VM.RunAs); ok {
				ownerUID = int(uid)
			}
		}
		if err := netdrv.SetupTapAccess(tap, bridge, vlan, ownerUID); err != nil {
			m.setError(id)
			return nil, fmt.Errorf("setup tap %s on %s: %w", tap, bridge, err)
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

	// Privilege separation: if a run-as user is configured, hand the VM's files
	// to it and launch QEMU under that uid/gid instead of as root.
	if m.cfg.VM.RunAs != "" {
		if uid, gid, groups, ok := lookupUser(m.cfg.VM.RunAs); ok {
			// The dropped-privilege QEMU must own its disk/NVRAM/seed/password
			// files, and be able to create the QMP socket in the disk dir.
			for _, f := range []string{s.DiskPath, s.OVMFVarsPath, s.SeedPath, pwFile} {
				if f != "" {
					_ = qemu.Chown(f, uid, gid)
				}
			}
			_ = qemu.Chown(m.cfg.Paths.DiskDir, uid, gid)
			spec.RunAsUID, spec.RunAsGID, spec.RunAsGroups = uid, gid, groups
		}
	}
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
	return m.Get(id)
}

// Stop gracefully powers down a running session (ACPI via QMP), falling back to
// SIGTERM then SIGKILL so a running guest's disk is not left dirty.
func (m *Manager) Stop(id string) error {
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if s.PID > 0 {
		m.gracefulShutdown(s)
	}
	// Remove this VM's tap from the fabric (global bridge or a port group).
	// Best effort: a missing tap is fine. The IP lease is kept so a restart
	// reuses it.
	netdrv.TeardownTap(netdrv.TapName(id))
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

// Delete soft-deletes a session (moves it to Trash) after stopping it. The
// overlay disk is left in place until a purge; retention worker purges later.
func (m *Manager) Delete(id string) error {
	_ = m.Stop(id)
	_, err := m.db.Exec(`UPDATE sessions SET deleted_at=? WHERE id=? AND deleted_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// ---- snapshots -----------------------------------------------------------

// Snapshot takes a qcow2 internal snapshot. If the VM is running it is a live
// snapshot (RAM+disk via QMP savevm); otherwise an offline disk snapshot. It
// returns the snapshot tag and whether it was taken online.
func (m *Manager) Snapshot(id, name string) (tag string, online bool, err error) {
	s, err := m.Get(id)
	if err != nil {
		return "", false, err
	}
	tag = "snap-" + randHex(4)
	if m.Running(s) {
		if err := qemu.QMPSnapshotSave(s.QMPSocket, tag); err != nil {
			return "", false, err
		}
		return tag, true, nil
	}
	if err := qemu.SnapshotCreate(s.DiskPath, tag); err != nil {
		return "", false, err
	}
	return tag, false, nil
}

// RevertSnapshot restores a disk to a snapshot. The VM must be stopped so the
// filesystem is quiescent.
func (m *Manager) RevertSnapshot(id, tag string) error {
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if m.Running(s) {
		return errors.New("stop the instance before reverting a snapshot")
	}
	return qemu.SnapshotApply(s.DiskPath, tag)
}

// DeleteSnapshot removes a snapshot from the disk (online or offline).
func (m *Manager) DeleteSnapshot(id, tag string, online bool) error {
	s, err := m.Get(id)
	if err != nil {
		return err
	}
	if m.Running(s) && online {
		return qemu.QMPSnapshotDelete(s.QMPSocket, tag)
	}
	return qemu.SnapshotDelete(s.DiskPath, tag)
}

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

// Purge permanently deletes a trashed session and its on-disk artifacts.
func (m *Manager) Purge(id string) error {
	s, err := m.db.Query(`SELECT disk_path,ovmf_vars_path,seed_path,COALESCE(disk_backend,'qcow2') FROM sessions WHERE id=?`, id)
	if err != nil {
		return err
	}
	var disk, vars, seed, backend string
	if s.Next() {
		_ = s.Scan(&disk, &vars, &seed, &backend)
	}
	s.Close()
	if _, err := m.db.Exec(`DELETE FROM sessions WHERE id=?`, id); err != nil {
		return err
	}
	// A zvol-backed disk is a ZFS volume, not a file — destroy it via zfs.
	if backend == "zvol" && strings.HasPrefix(disk, "/dev/zvol/") {
		_ = zfs.DestroyDataset(strings.TrimPrefix(disk, "/dev/zvol/"))
		disk = "" // don't os.Remove a device node
	}
	for _, f := range []string{disk, vars, seed,
		filepath.Join(m.cfg.Paths.DiskDir, id+".vncpw"),
		filepath.Join(m.cfg.Paths.DiskDir, id+".log"),
		filepath.Join(m.cfg.Paths.DiskDir, id+".qmp")} {
		if f != "" {
			_ = os.Remove(f)
		}
	}
	return nil
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
// PVID. Returns attach=false when the VM has no port group or the port group is
// user-mode (no bridge), so the caller can fall back to the global bridge.
func (m *Manager) resolveTapTarget(s *Session) (bridge string, vlan int, attach bool) {
	if s.NetworkID == 0 {
		return "", 0, false
	}
	var br string
	var vl int
	err := m.db.QueryRow(`SELECT COALESCE(bridge,''), COALESCE(vlan_id,0) FROM networks WHERE id=?`, s.NetworkID).Scan(&br, &vl)
	if err != nil || br == "" {
		return "", 0, false
	}
	return br, vl, true
}

// ensureDefaultNetwork returns (creating if needed) an org's default bridge/
// overlay network, from which guest IP leases are drawn. The CIDR/gateway come
// from the cluster config so every node allocates from the same overlay subnet.
func (m *Manager) ensureDefaultNetwork(orgID int64) (int64, string, string, error) {
	cidr := m.cfg.Cluster.Subnet
	gw := m.cfg.Cluster.Gateway
	if cidr == "" {
		cidr = "10.77.0.0/16"
	}
	var id int64
	err := m.db.QueryRow(`SELECT id FROM networks WHERE org_id=? AND mode IN('bridge','overlay') ORDER BY id LIMIT 1`, orgID).Scan(&id)
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
	spec := qemu.Spec{
		ID:        s.ID,
		BaseImage: base,
		DiskPath:  s.DiskPath,
		CPUs:      s.CPUs,
		MemoryMB:  s.MemoryMB,
		VNCPort:   s.VNCPort,
		WSPort:    s.WSPort,
		QMPSocket: s.QMPSocket,
		UserNet:   m.cfg.Network.Mode == "user",
		EnableKVM: qemu.KVMAvailable(),
		Firmware:  s.Firmware,
		SeedISO:   s.SeedPath,
		MAC:       s.MAC,
	}
	if s.Firmware == "uefi" {
		if code, _, ok := qemu.OVMF(); ok {
			spec.OVMFCodePath = code
			spec.OVMFVarsPath = s.OVMFVarsPath
		}
	}
	return spec, nil
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
