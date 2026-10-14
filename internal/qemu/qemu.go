// Package qemu builds QEMU command lines and manages VM processes.
//
// This is an original implementation. It encodes standard, publicly documented
// QEMU invocation (UEFI via OVMF, a qcow2 overlay backed by a base image, a
// VNC console exposed over a websocket for browser clients, and a QMP control
// socket). None of it is derived from another product's compiled code.
package qemu

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// Spec describes one VM to launch.
type Spec struct {
	ID        string
	BaseImage string // qcow2 base (read-only backing file)
	DiskPath  string // per-session overlay qcow2
	CPUs      int
	MemoryMB  int
	VNCPort   int    // TCP port for the VNC display (bound to loopback only)
	WSPort    int    // TCP port for the VNC websocket (bound to loopback only)
	QMPSocket string // unix socket path for QMP control
	UserNet   bool   // true = SLIRP user networking (no privileges)
	EnableKVM bool

	// Firmware is "uefi" or "bios" (SeaBIOS). For UEFI the caller supplies a
	// readonly OVMF code image plus a per-VM WRITABLE vars image (a copy of the
	// OVMF_VARS template) so each VM keeps its own NVRAM/boot entries.
	Firmware     string
	OVMFCodePath string // readonly pflash unit 0 (UEFI only)
	OVMFVarsPath string // writable pflash unit 1 (UEFI only, one copy per VM)

	// Optical drives. SeedISO is the cloud-init NoCloud seed (CIDATA); BootISO is
	// an optional installer image. BootISO, when set, boots first (order=dc).
	SeedISO string
	BootISO string

	// VNCPwFile, when set, is a file (mode 0600) holding the raw VNC password.
	// QEMU reads it via an -object secret so the password never appears on the
	// process command line. Combined with loopback binding this keeps the raw
	// VNC port unreachable from the network and password-gated locally.
	VNCPwFile string

	// Display selects the console protocol. "spice" adds a loopback SPICE server
	// + qxl VGA + guest-agent channel (served to the browser via the guac gateway);
	// VNC stays enabled regardless so the plain noVNC console always works.
	Display   string // "" / "vnc" | "spice"
	SPICEPort int    // loopback SPICE TCP port when Display=="spice"

	// DiskRaw marks DiskPath as a raw block device (a ZFS zvol) rather than a
	// qcow2 file: use format=raw with cache=none,aio=native (best for raw block).
	DiskRaw bool

	// Networking. MAC pins the NIC address. In user mode HostFwds publish guest
	// ports on the host (hostfwd). In bridge/vlan mode TapName names a host tap.
	MAC      string
	TapName  string
	HostFwds []HostFwd

	// Privilege separation: when RunAsUID is non-zero QEMU is launched under
	// this uid/gid (via the launcher's Credential) instead of as root.
	// RunAsGroups MUST include the kvm group, or /dev/kvm is inaccessible —
	// Credential replaces the process's supplementary groups entirely.
	RunAsUID    uint32
	RunAsGID    uint32
	RunAsGroups []uint32

	// Passthrough holds host PCI addresses (e.g. 0000:01:00.0) assigned to the
	// guest via vfio-pci. Only populated when the host pre-flight confirms IOMMU.
	Passthrough []string

	// Incoming, when set, starts QEMU paused awaiting an inbound live migration
	// stream (e.g. "tcp:0.0.0.0:49200"). The destination node launches with this;
	// the source then streams its RAM/device state in over QMP migrate.
	Incoming string
}

// HostFwd is a user-mode port forward: host_ip:host_port → guest_port.
type HostFwd struct {
	Proto     string // tcp|udp
	HostIP    string // "" binds 127.0.0.1
	HostPort  int
	GuestPort int
}

// CreateOverlay creates a copy-on-write qcow2 overlay backed by the base image,
// so launching a session never mutates the shared base.
func CreateOverlay(base, overlay string) error {
	if _, err := os.Stat(overlay); err == nil {
		return nil // already created
	}
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2",
		"-F", "qcow2", "-b", base, overlay)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create: %v: %s", err, out)
	}
	return nil
}

// CreateBlank creates a fresh empty qcow2 disk of the given size (GiB), for
// installing an OS from a boot ISO (no base image). Idempotent.
func CreateBlank(path string, gib int) error {
	if _, err := os.Stat(path); err == nil {
		return nil // already created
	}
	if gib <= 0 {
		gib = 20
	}
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", path, fmt.Sprintf("%dG", gib))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create (blank): %v: %s", err, out)
	}
	return nil
}

// ConvertToRaw writes a base image onto a raw target (e.g. a ZFS zvol device).
func ConvertToRaw(src, dst string) error {
	cmd := exec.Command("qemu-img", "convert", "-O", "raw", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img convert to raw: %v: %s", err, out)
	}
	return nil
}

// Args renders the QEMU argument vector for the spec.
func (s Spec) Args() []string {
	// Bind VNC and its websocket to loopback ONLY. The raw VNC protocol has no
	// transport encryption and QEMU would otherwise bind 0.0.0.0, exposing every
	// VM's framebuffer to the whole LAN and bypassing the app's login. The sole
	// external path to a console is the authenticated websocket proxy on the app
	// port, which dials these loopback ports.
	ws := s.WSPort
	if ws == 0 {
		ws = s.VNCPort + 1000
	}
	vnc := fmt.Sprintf("127.0.0.1:%d,websocket=127.0.0.1:%d", s.VNCPort-5900, ws)
	if s.VNCPwFile != "" {
		vnc += ",password-secret=vncpw"
	}
	a := []string{
		"-name", "vdx-" + s.ID,
		"-machine", "q35",
		"-smp", strconv.Itoa(s.CPUs),
		"-m", strconv.Itoa(s.MemoryMB),
	}
	// UEFI firmware: readonly code (unit 0) + per-VM writable vars (unit 1). The
	// pflash drives must come before the OS disk so unit ordering is stable.
	if s.Firmware == "uefi" && s.OVMFCodePath != "" && s.OVMFVarsPath != "" {
		a = append(a,
			"-drive", "if=pflash,format=raw,readonly=on,file="+s.OVMFCodePath,
			"-drive", "if=pflash,format=raw,file="+s.OVMFVarsPath,
		)
	}
	// Disk I/O: a dedicated IOThread + io_uring is the single biggest throughput
	// win (Proxmox-documented), and io_uring is the right AIO for file/ZFS-backed
	// qcow2 (aio=native can block on ZFS/NFS). writeback uses the host page cache
	// for speed; discard/detect-zeroes keep the thin qcow2 small.
	diskOpts := "file=" + s.DiskPath + ",if=none,id=disk0,discard=unmap,detect-zeroes=unmap"
	if s.DiskRaw {
		// Raw block (zvol): O_DIRECT + native AIO is fastest for real block devices.
		diskOpts += ",format=raw,cache=none,aio=native"
	} else {
		// qcow2 file (incl. on ZFS datasets): io_uring + writeback.
		diskOpts += ",format=qcow2,cache=writeback,aio=io_uring"
	}
	// num-queues = vCPUs gives a 1:1 virtqueue↔vCPU mapping so completion IRQs land
	// on the submitting vCPU (RH/QEMU benchmark: ~78k→104k IOPS).
	blkQ := s.CPUs
	if blkQ < 1 {
		blkQ = 1
	}
	a = append(a,
		"-object", "iothread,id=iothread0",
		"-drive", diskOpts,
		"-device", fmt.Sprintf("virtio-blk-pci,drive=disk0,iothread=iothread0,num-queues=%d", blkQ),
	)
	// Optical drives (cloud-init seed and/or an installer ISO), attached to the
	// q35 SATA bus by default. Seed media is never booted; only BootISO changes
	// the boot order.
	if s.SeedISO != "" {
		a = append(a, "-drive", "file="+s.SeedISO+",media=cdrom")
	}
	if s.BootISO != "" {
		a = append(a, "-drive", "file="+s.BootISO+",media=cdrom")
		a = append(a, "-boot", "order=dc")
	} else {
		a = append(a, "-boot", "order=c")
	}
	if s.VNCPwFile != "" {
		// Secret read from a 0600 file, so it never lands on the command line.
		a = append(a, "-object", "secret,id=vncpw,file="+s.VNCPwFile+",format=raw")
	}
	dev := "virtio-net-pci,netdev=n0"
	if s.MAC != "" {
		dev += ",mac=" + s.MAC
	}
	// virtio-net multiqueue on bridged (tap) NICs: one queue per vCPU (capped 8),
	// vectors = 2*queues + 2. Lets RX/TX scale across vCPUs (guest still needs
	// `ethtool -L <nic> combined N`). SLIRP user-net doesn't support multiqueue.
	if nq := s.netQueues(); nq > 1 {
		dev += fmt.Sprintf(",mq=on,vectors=%d", 2*nq+2)
	}
	a = append(a,
		// qxl gives the guest a real KMS/DRM GPU. The default (std/VGA) makes
		// GNOME/GDM black-screen and crawl; qxl renders cleanly over both VNC and
		// SPICE and has broad Linux/Windows driver support.
		"-vga", "qxl",
		"-vnc", vnc,
		// QMP control socket for lifecycle operations (shutdown, query).
		"-qmp", "unix:"+s.QMPSocket+",server=on,wait=off",
		"-device", dev,
		// USB tablet = ABSOLUTE pointer (the VNC/SPICE cursor lines up with the
		// guest and clicks land where expected); usb-kbd is a reliable USB keyboard.
		// Without these the guest sees only a relative PS/2 mouse, which is janky or
		// dead over a remote console — especially under GNOME/Wayland.
		"-device", "qemu-xhci,id=xhci",
		"-device", "usb-tablet",
		"-device", "usb-kbd",
		// virtio-rng feeds the guest entropy (stops boot stalling on randomness);
		// virtio-balloon lets the host reclaim unused guest RAM.
		"-device", "virtio-rng-pci",
		"-device", "virtio-balloon-pci",
	)
	// SPICE display (loopback only): a SPICE server + the guest-agent virtio
	// channel for clipboard/resolution (qxl VGA is already set above). The guac
	// gateway dials this loopback port; it is never exposed to the network.
	if s.Display == "spice" && s.SPICEPort > 0 {
		a = append(a,
			"-spice", fmt.Sprintf("port=%d,addr=127.0.0.1,disable-ticketing=on", s.SPICEPort),
			"-device", "virtio-serial-pci",
			"-chardev", "spicevmc,id=vdagent,name=vdagent",
			"-device", "virtserialport,chardev=vdagent,name=com.redhat.spice.0",
		)
	}
	if s.EnableKVM {
		a = append(a, "-enable-kvm", "-cpu", "host")
	} else {
		a = append(a, "-cpu", "max")
	}
	a = append(a, "-netdev", s.netdev())
	// Destination of a live migration: start paused, receiving state on this URI.
	if s.Incoming != "" {
		a = append(a, "-incoming", s.Incoming)
	}
	// PCI passthrough (vfio-pci). Requires IOMMU; the caller gates on that.
	for _, addr := range s.Passthrough {
		if addr != "" {
			a = append(a, "-device", "vfio-pci,host="+addr)
		}
	}
	return a
}

// netdev renders the -netdev argument for the configured networking mode.
func (s Spec) netdev() string {
	if s.UserNet {
		nd := "user,id=n0"
		for _, f := range s.HostFwds {
			proto := f.Proto
			if proto == "" {
				proto = "tcp"
			}
			ip := f.HostIP
			if ip == "" {
				ip = "127.0.0.1"
			}
			nd += fmt.Sprintf(",hostfwd=%s:%s:%d-:%d", proto, ip, f.HostPort, f.GuestPort)
		}
		return nd
	}
	// vhost=on moves the virtio-net dataplane into the kernel for far higher
	// throughput + lower CPU than userspace virtio. queues=N enables multiqueue.
	nd := "tap,id=n0,script=no,downscript=no,vhost=on"
	if s.TapName != "" {
		nd = "tap,id=n0,ifname=" + s.TapName + ",script=no,downscript=no,vhost=on"
	}
	if nq := s.netQueues(); nq > 1 {
		nd += fmt.Sprintf(",queues=%d", nq)
	}
	return nd
}

// netQueues is the virtio-net queue count: one per vCPU (capped at 8) for bridged
// tap NICs, 1 for SLIRP user networking (which doesn't support multiqueue).
func (s Spec) netQueues() int {
	if s.UserNet || s.CPUs <= 1 {
		return 1
	}
	if s.CPUs > 8 {
		return 8
	}
	return s.CPUs
}

// Launch starts QEMU detached and returns the running process.
func Launch(s Spec, logPath string) (*os.Process, error) {
	logf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("qemu-system-x86_64", s.Args()...)
	cmd.Stdout = logf
	cmd.Stderr = logf
	// Privilege separation: launch the VM under a dedicated unprivileged uid/gid
	// when configured, so a QEMU compromise does not run as root.
	if s.RunAsUID != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: s.RunAsUID, Gid: s.RunAsGID, Groups: s.RunAsGroups},
		}
	}
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	return cmd.Process, nil
}

// Chown changes ownership of a VM runtime file to the run-as user so the
// dropped-privilege QEMU process can still open it.
func Chown(path string, uid, gid uint32) error {
	return os.Chown(path, int(uid), int(gid))
}

// ovmfPairs lists candidate (code, vars-template) firmware pairs, newest first.
// Code and vars must come from the same build (both 4MB, or both legacy) or the
// firmware will not initialize its variable store.
var ovmfPairs = [][2]string{
	{"/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"},
	{"/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"},
}

// OVMF returns a matched (code, varsTemplate) OVMF pair and whether UEFI is
// available on this host. code is mounted readonly; varsTemplate is copied per
// VM via PrepareUEFIVars so each VM gets its own writable NVRAM.
func OVMF() (code, varsTemplate string, ok bool) {
	for _, p := range ovmfPairs {
		if fileExists(p[0]) && fileExists(p[1]) {
			return p[0], p[1], true
		}
	}
	return "", "", false
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// PrepareUEFIVars copies the OVMF vars template to a per-VM writable image if it
// does not already exist, so a VM keeps its own boot entries across restarts.
func PrepareUEFIVars(template, dest string) error {
	if fileExists(dest) {
		return nil
	}
	b, err := os.ReadFile(template)
	if err != nil {
		return fmt.Errorf("read OVMF vars template: %w", err)
	}
	return os.WriteFile(dest, b, 0o644)
}

// ResizeDisk grows a qcow2 overlay's virtual size to gib gigabytes. Growing a
// qcow2 is non-destructive; shrinking is refused by qemu-img for safety, so
// callers must guard against requesting a smaller size.
func ResizeDisk(overlay string, gib int) error {
	cmd := exec.Command("qemu-img", "resize", overlay, strconv.Itoa(gib)+"G")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img resize: %v: %s", err, out)
	}
	return nil
}

// VirtualSizeBytes reports a qcow2's virtual (guest-visible) size.
func VirtualSizeBytes(path string) (int64, error) {
	out, err := exec.Command("qemu-img", "info", "--output=json", path).Output()
	if err != nil {
		return 0, err
	}
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return 0, err
	}
	return info.VirtualSize, nil
}

// KVMAvailable reports whether /dev/kvm is usable.
func KVMAvailable() bool {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// LogPath returns the conventional log path for a session's disk dir.
func LogPath(diskDir, id string) string { return filepath.Join(diskDir, id+".log") }

// WriteSecretFile writes secret bytes to a 0600 file for QEMU's -object secret.
func WriteSecretFile(path, secret string) error {
	return os.WriteFile(path, []byte(secret), 0o600)
}

// ---- snapshots (offline, qcow2 internal) ---------------------------------

// SnapshotCreate records a qcow2 internal snapshot on a stopped disk.
func SnapshotCreate(disk, tag string) error { return imgSnapshot("-c", tag, disk) }

// SnapshotApply reverts a stopped disk to a snapshot.
func SnapshotApply(disk, tag string) error { return imgSnapshot("-a", tag, disk) }

// SnapshotDelete removes a snapshot from a stopped disk.
func SnapshotDelete(disk, tag string) error { return imgSnapshot("-d", tag, disk) }

func imgSnapshot(flag, tag, disk string) error {
	cmd := exec.Command("qemu-img", "snapshot", flag, tag, disk)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img snapshot %s: %v: %s", flag, err, out)
	}
	return nil
}

// ConvertStandaloneCopy copies a disk to a standalone qcow2 (collapsing the
// backing chain) so it can be backed up or restored independently. It does NOT
// compress — the backup pipeline applies a fast external compressor afterwards,
// which is far quicker than qemu-img's built-in zlib (-c).
func ConvertStandaloneCopy(src, dst string) error {
	cmd := exec.Command("qemu-img", "convert", "-O", "qcow2", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img convert: %v: %s", err, out)
	}
	return nil
}
