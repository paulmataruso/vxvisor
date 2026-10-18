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
	// HugePages backs guest RAM with hugepages (memory-backend-memfd + hugetlb).
	// The caller only sets this when the host has a reserved hugepage pool big
	// enough for MemoryMB (otherwise QEMU would refuse to start).
	HugePages bool
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

	// DiskLockingOff disables QEMU's image file locking (file.locking=off). Needed
	// for disks on filesystems that don't coordinate OFD/byte-range locks across
	// hosts (CIFS/SMB): there the migration source→destination lock handoff fails
	// ("Failed to get write lock"). The control plane guarantees a single writer,
	// so the lock is redundant on shared storage. NFS/CephFS coordinate locks and
	// keep it on.
	DiskLockingOff bool

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

	// SerialSock, when set, exposes the guest's first serial port (ttyS0) on a
	// loopback unix socket so the browser serial console (xterm.js) can attach.
	// Cloud images and cirros put their login/getty on ttyS0, so this is the
	// text console that actually accepts input for headless guests. Loopback/
	// unix only — the sole external path is the authenticated websocket proxy.
	SerialSock string

	// ---- Hardware profile (per-VM knobs; empty => safe default) ----
	MachineType string // q35 (default) | pc (i440fx)
	DiskBus     string // virtio-blk (default) | virtio-scsi | sata
	NICModel    string // virtio (default) | e1000e | rtl8139
	VGA         string // qxl (default) | virtio | std
	Windows     bool   // apply Windows tweaks: localtime RTC + Hyper-V enlightenments

	// GuestAgent adds a qemu-guest-agent virtio-serial channel
	// (org.qemu.guest_agent.0) over QGASocket. The channel shares the single
	// virtio-serial-pci controller with the SPICE vdagent when both are on.
	GuestAgent bool
	QGASocket  string // unix socket for the guest agent (loopback/unix only)

	// TPMSock, when set, is the control socket of a per-VM swtpm instance the
	// caller has already started; QEMU attaches it as a TPM 2.0 CRB device.
	TPMSock string

	// ExtraISO is an optional second cdrom (e.g. the virtio-win driver ISO for
	// Windows guests), attached read-only after the seed/boot ISOs.
	ExtraISO string
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
// ConvertToQcow2 copies any-format source to a new qcow2 at dst (used by offline
// storage vMotion). The source is only READ; dst is created fresh.
func ConvertToQcow2(src, dst string) error {
	// -m 16: up to 16 coroutines copying in parallel; -W: out-of-order writes
	// (both markedly faster for a large convert); -t none / -T none: skip the host
	// page cache so the convert doesn't evict the running VMs' working set.
	cmd := exec.Command("qemu-img", "convert", "-m", "16", "-W",
		"-t", "none", "-T", "none", "-O", "qcow2", src, dst)
	if _, err := cmd.CombinedOutput(); err != nil {
		// Older qemu-img / some inputs reject -T/-t; retry with a safe subset.
		cmd = exec.Command("qemu-img", "convert", "-m", "16", "-W", "-O", "qcow2", src, dst)
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			return fmt.Errorf("qemu-img convert to qcow2: %v: %s", err2, out2)
		}
	}
	return nil
}

// CreateQcow2Sized creates an empty qcow2 of an exact virtual byte size. Used to
// pre-create a drive-mirror target so a dropped-privilege QEMU can open an
// already-owned file (mode=existing) instead of creating one in a root-owned dir.
func CreateQcow2Sized(path string, bytes int64) error {
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", path, strconv.FormatInt(bytes, 10))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img create sized: %v: %s", err, out)
	}
	return nil
}

// ImageOK runs `qemu-img check` and returns nil only if the image passes. Used
// to verify a freshly-written vMotion target before trusting it. Raw images have
// no consistency structure, so a successful check is qcow2-only; callers verify
// raw targets by size instead.
func ImageOK(path string) error {
	cmd := exec.Command("qemu-img", "check", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img check: %v: %s", err, out)
	}
	return nil
}

// ProbeReadable runs `qemu-img info` and returns an error if qemu-img can't read
// the image (e.g. an unsupported/corrupt source). Used before converting an
// imported VMware disk so we fail fast with a clear message.
func ProbeReadable(path string) error {
	cmd := exec.Command("qemu-img", "info", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img info: %v: %s", err, out)
	}
	return nil
}

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
	mach := s.MachineType
	if mach == "" {
		mach = "q35"
	}
	// Disable the legacy HPET: modern guests keep time with kvm-clock (Linux) or
	// the Hyper-V reference TSC (Windows), so an emulated HPET only adds timer
	// VM-exits. Removing it is a standard, guest-safe win.
	mach += ",hpet=off"
	// Hugepage-backed RAM is wired through a memory-backend object referenced by
	// the machine; the object itself is appended right after -m below.
	if s.HugePages {
		mach += ",memory-backend=mem0"
	}
	// CPU topology: one socket with one core per vCPU (threads=1). A bare "-smp N"
	// presents N *sockets*, which Windows client editions silently cap (wasting
	// cores) and which hands every guest a bogus cache/NUMA topology; one socket ×
	// N cores is the portable, scheduler-friendly layout.
	cpus := s.CPUs
	if cpus < 1 {
		cpus = 1
	}
	a := []string{
		"-name", "vdx-" + s.ID,
		"-machine", mach,
		"-smp", fmt.Sprintf("%d,sockets=1,cores=%d,threads=1", cpus, cpus),
		"-m", strconv.Itoa(s.MemoryMB),
	}
	if s.HugePages {
		// Prealloc'd hugetlb-backed anonymous RAM: fewer TLB misses + no page-fault
		// jitter once running. mem0 is referenced by -machine memory-backend above.
		a = append(a, "-object",
			fmt.Sprintf("memory-backend-memfd,id=mem0,size=%dM,hugetlb=on,prealloc=on", s.MemoryMB))
	}
	// Clock discipline. The host is NTP-disciplined (chrony), and the guest's
	// paravirt kvm-clock (automatic with -cpu host) follows it closely. We also
	// pin the emulated RTC to the host clock and slew (not jump) recovered ticks
	// so the wall clock stays monotonic and accurate across pauses/migration.
	// Windows keeps its hardware clock in LOCAL time; Linux/other expect UTC —
	// getting this wrong offsets the guest by the UTC offset on every boot.
	if s.Windows {
		a = append(a, "-rtc", "base=localtime,clock=host,driftfix=slew")
	} else {
		a = append(a, "-rtc", "base=utc,clock=host,driftfix=slew")
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
	if s.DiskLockingOff {
		diskOpts += ",file.locking=off"
	}
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
	// Disk controller selected by DiskBus. virtio-blk (default) and virtio-scsi
	// get the dedicated IOThread; AHCI/SATA (used for Windows installs, which have
	// no in-box virtio driver) does not support iothread, so it is omitted there.
	switch s.DiskBus {
	case "virtio-scsi":
		a = append(a,
			"-object", "iothread,id=iothread0",
			"-drive", diskOpts,
			"-device", "virtio-scsi-pci,id=scsi0,iothread=iothread0,packed=on",
			"-device", "scsi-hd,bus=scsi0.0,drive=disk0",
		)
	case "sata":
		a = append(a,
			"-drive", diskOpts,
			"-device", "ich9-ahci,id=ahci0",
			"-device", "ide-hd,bus=ahci0.0,drive=disk0",
		)
	default: // virtio-blk
		a = append(a,
			"-object", "iothread,id=iothread0",
			"-drive", diskOpts,
			// packed=on uses virtio-1.1 packed virtqueues (fewer cache-line bounces
			// than split rings); negotiated, so guests without support fall back.
			"-device", fmt.Sprintf("virtio-blk-pci,drive=disk0,iothread=iothread0,num-queues=%d,packed=on", blkQ),
		)
	}
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
	// Extra read-only ISO (e.g. virtio-win drivers for a Windows guest), on its
	// own cdrom so the installer/user can load drivers or the guest agent.
	if s.ExtraISO != "" {
		a = append(a, "-drive", "file="+s.ExtraISO+",media=cdrom,readonly=on")
	}
	if s.VNCPwFile != "" {
		// Secret read from a 0600 file, so it never lands on the command line.
		a = append(a, "-object", "secret,id=vncpw,file="+s.VNCPwFile+",format=raw")
	}
	// NIC model. virtio (default) is fastest but needs a guest driver (built into
	// Linux; from virtio-win on Windows). e1000e/rtl8139 have in-box drivers on
	// most OSes, so they are the installer-friendly fallback (e.g. Windows setup).
	nicDev := "virtio-net-pci"
	switch s.NICModel {
	case "e1000e":
		nicDev = "e1000e"
	case "rtl8139":
		nicDev = "rtl8139"
	}
	dev := nicDev + ",netdev=n0"
	if s.MAC != "" {
		dev += ",mac=" + s.MAC
	}
	// virtio-net multiqueue on bridged (tap) NICs: one queue per vCPU (capped 8),
	// vectors = 2*queues + 2. Lets RX/TX scale across vCPUs (guest still needs
	// `ethtool -L <nic> combined N`). SLIRP user-net doesn't support multiqueue.
	// Only virtio-net supports multiqueue; emulated NICs ignore it.
	if nicDev == "virtio-net-pci" {
		// Packed virtqueues are negotiated (safe fallback for guests without them).
		// A deeper RX ring (default 256) absorbs bursts and cuts drops under load.
		// (tx_queue_size>256 is only accepted once vhost negotiates it, which is
		// fragile to rely on at launch, so the TX ring is left at its default.)
		dev += ",packed=on,rx_queue_size=1024"
		if nq := s.netQueues(); nq > 1 {
			dev += fmt.Sprintf(",mq=on,vectors=%d", 2*nq+2)
		}
	}
	// VGA adapter. qxl (default) gives the guest a real KMS/DRM GPU and renders
	// cleanly over VNC and SPICE; std is the safe choice for Windows (in-box
	// driver, no black screen before the QXL/virtio driver is installed); virtio
	// (virtio-gpu) is the modern Linux option.
	vgaModel := s.VGA
	switch vgaModel {
	case "std", "virtio", "qxl":
	default:
		vgaModel = "qxl"
	}
	a = append(a,
		"-vga", vgaModel,
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
		// virtio-balloon lets the host reclaim unused guest RAM — free-page-reporting
		// hands back pages the guest frees without waiting on a balloon inflate.
		"-device", "virtio-rng-pci",
		"-device", "virtio-balloon-pci,free-page-reporting=on",
	)
	// A SINGLE virtio-serial controller carries both the SPICE vdagent channel
	// (clipboard/resolution) and the qemu-guest-agent channel. Emitting two
	// controllers is wrong, so build one and attach whichever ports are enabled.
	spiceOn := s.Display == "spice" && s.SPICEPort > 0
	if spiceOn || s.GuestAgent {
		a = append(a, "-device", "virtio-serial-pci,id=vserial0")
	}
	if spiceOn {
		a = append(a,
			"-spice", fmt.Sprintf("port=%d,addr=127.0.0.1,disable-ticketing=on", s.SPICEPort),
			"-chardev", "spicevmc,id=vdagent,name=vdagent",
			"-device", "virtserialport,bus=vserial0.0,chardev=vdagent,name=com.redhat.spice.0",
		)
	}
	// qemu-guest-agent channel on a loopback unix socket. The guest's agent
	// (qemu-ga; from virtio-win on Windows) connects to org.qemu.guest_agent.0;
	// vdxd queries it over this socket for IPs/OS/filesystem info. If no agent is
	// installed in the guest the socket simply never answers — harmless.
	if s.GuestAgent && s.QGASocket != "" {
		a = append(a,
			"-chardev", "socket,id=qga0,path="+s.QGASocket+",server=on,wait=off",
			"-device", "virtserialport,bus=vserial0.0,chardev=qga0,name=org.qemu.guest_agent.0",
		)
	}
	// TPM 2.0 via a per-VM swtpm the caller already started on TPMSock. tpm-crb is
	// the modern CRB interface Windows 11 expects on q35/UEFI.
	if s.TPMSock != "" {
		a = append(a,
			"-chardev", "socket,id=chrtpm,path="+s.TPMSock,
			"-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
			"-device", "tpm-crb,tpmdev=tpm0",
		)
	}
	// Serial console on a loopback unix socket (server mode, non-blocking) so the
	// browser xterm.js console can attach to the guest's ttyS0. Nothing boots
	// differently; it just surfaces the serial line that cloud images/cirros use.
	if s.SerialSock != "" {
		a = append(a,
			"-chardev", "socket,id=serial0,path="+s.SerialSock+",server=on,wait=off",
			"-serial", "chardev:serial0",
		)
	}
	if s.EnableKVM {
		cpu := "host"
		// Hyper-V enlightenments make Windows guests substantially faster and more
		// stable under KVM (they teach Windows it is virtualized). Harmless to add
		// only for Windows guests.
		if s.Windows {
			// Base enlightenments PLUS paravirt TLB-shootdown (hv_tlbflush) and IPIs
			// (hv_ipi) — major wins on contended/overcommitted hosts — direct synthetic
			// timers (hv_stimer_direct), vCPU run-time (hv_runtime) and re-enlightenment
			// (hv_reenlightenment, keeps the TSC sane across live migration). hv_ipi/
			// hv_tlbflush require hv_vpindex, which is included.
			cpu += ",hv_relaxed,hv_vapic,hv_time,hv_vpindex,hv_runtime,hv_synic,hv_stimer,hv_stimer_direct,hv_tlbflush,hv_ipi,hv_frequencies,hv_reenlightenment,hv_spinlocks=0x1fff"
		}
		// Discard (don't replay) PIT ticks lost while a vCPU was descheduled — avoids
		// time-drift catch-up storms under CPU contention.
		a = append(a, "-enable-kvm", "-cpu", cpu, "-global", "kvm-pit.lost_tick_policy=discard")
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

// ovmfSecurePairs are the Microsoft-keyed OVMF pairs required for UEFI Secure
// Boot (the vars template ships with the MS KEK/db so Windows boots SB-enabled).
var ovmfSecurePairs = [][2]string{
	{"/usr/share/OVMF/OVMF_CODE_4M.ms.fd", "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"},
	{"/usr/share/OVMF/OVMF_CODE.secboot.fd", "/usr/share/OVMF/OVMF_VARS.ms.fd"},
}

// OVMFSecure returns a Secure-Boot-capable (MS-keyed) OVMF pair if present.
func OVMFSecure() (code, varsTemplate string, ok bool) {
	for _, p := range ovmfSecurePairs {
		if fileExists(p[0]) && fileExists(p[1]) {
			return p[0], p[1], true
		}
	}
	return "", "", false
}

// VirtioWinISO returns the path to the virtio-win driver ISO if one is present
// in isoDir (looked up by the caller), or "" if none. Checked at launch time so
// a freshly-downloaded ISO is picked up without restarting vdxd.
func VirtioWinISO(isoDir string) string {
	for _, name := range []string{"virtio-win.iso", "virtio-win-latest.iso"} {
		if p := isoDir + "/" + name; fileExists(p) {
			return p
		}
	}
	return ""
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
	// -U (force-share) so this works on an image currently OPEN by a running VM
	// (storage vMotion reads the virtual size of a live source); without it
	// qemu-img fails to take the image lock and exits non-zero.
	out, err := exec.Command("qemu-img", "info", "-U", "--output=json", path).Output()
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
