package qemu

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestArgsBindLoopback is the regression guard for the B1 security fix: QEMU
// must never expose a VM's VNC/websocket on a routable address, and the VNC
// password must be read from a file rather than placed on the command line.
func TestArgsBindLoopback(t *testing.T) {
	s := Spec{
		ID: "abc", DiskPath: "/d.qcow2", CPUs: 2, MemoryMB: 2048,
		VNCPort: 5901, WSPort: 6901, QMPSocket: "/q.sock", UserNet: true,
		VNCPwFile: "/run/x.vncpw",
	}
	a := strings.Join(s.Args(), " ")

	if !strings.Contains(a, "127.0.0.1:1,websocket=127.0.0.1:6901") {
		t.Errorf("VNC not bound to loopback: %s", a)
	}
	if strings.Contains(a, "0.0.0.0") || strings.Contains(a, "-vnc :") {
		t.Errorf("VNC exposed on a routable address: %s", a)
	}
	if !strings.Contains(a, "secret,id=vncpw,file=/run/x.vncpw,format=raw") {
		t.Errorf("VNC secret not read from file: %s", a)
	}
	if !strings.Contains(a, "password-secret=vncpw") {
		t.Errorf("VNC password secret not referenced: %s", a)
	}
	// The raw password must never appear inline.
	if strings.Contains(a, "password=on") || strings.Contains(a, ",password,") {
		t.Errorf("inline password on command line: %s", a)
	}
}

// TestArgsSPICETicketed: SPICE stays on loopback and requires the console
// password (the same vncpw secret) instead of disable-ticketing.
func TestArgsSPICETicketed(t *testing.T) {
	s := Spec{
		ID: "abc", DiskPath: "/d.qcow2", CPUs: 2, MemoryMB: 2048,
		VNCPort: 5901, WSPort: 6901, QMPSocket: "/q.sock", UserNet: true,
		VNCPwFile: "/run/x.vncpw", Display: "spice", SPICEPort: 8901,
	}
	a := strings.Join(s.Args(), " ")
	if !strings.Contains(a, "-spice port=8901,addr=127.0.0.1,password-secret=vncpw ") {
		t.Errorf("SPICE not loopback + ticketed: %s", a)
	}
	if strings.Contains(a, "disable-ticketing") {
		t.Errorf("SPICE must not disable ticketing when a console password is set: %s", a)
	}
}

// TestArgsUEFI checks the firmware pflash ordering: readonly code before the
// writable per-VM vars, both before the OS disk.
func TestArgsUEFI(t *testing.T) {
	s := Spec{
		ID: "u", DiskPath: "/d.qcow2", CPUs: 2, MemoryMB: 2048, VNCPort: 5900,
		Firmware: "uefi", OVMFCodePath: "/ovmf/code.fd", OVMFVarsPath: "/vm/vars.fd",
	}
	a := strings.Join(s.Args(), " ")
	code := strings.Index(a, "readonly=on,file=/ovmf/code.fd")
	vars := strings.Index(a, "if=pflash,format=raw,file=/vm/vars.fd")
	disk := strings.Index(a, "file=/d.qcow2,if=none,id=disk0")
	if code < 0 || vars < 0 || disk < 0 {
		t.Fatalf("missing pflash/disk args: %s", a)
	}
	if !(code < vars && vars < disk) {
		t.Errorf("pflash ordering wrong (code=%d vars=%d disk=%d): %s", code, vars, disk, a)
	}
	// Writable vars must NOT be readonly.
	if strings.Contains(a, "readonly=on,file=/vm/vars.fd") {
		t.Errorf("OVMF vars mounted readonly: %s", a)
	}
}

// TestArgsBIOSNoPflash verifies the BIOS path adds no firmware pflash drives.
func TestArgsBIOSNoPflash(t *testing.T) {
	s := Spec{ID: "b", DiskPath: "/d.qcow2", CPUs: 1, MemoryMB: 512, VNCPort: 5900, Firmware: "bios"}
	if strings.Contains(strings.Join(s.Args(), " "), "pflash") {
		t.Errorf("BIOS firmware should not emit pflash")
	}
}

// TestArgsSeedAndBootISO checks the cloud-init seed is attached as a cdrom and a
// boot ISO flips the boot order to cdrom-first.
func TestArgsSeedAndBootISO(t *testing.T) {
	a := strings.Join(Spec{ID: "s", DiskPath: "/d", CPUs: 1, MemoryMB: 512, VNCPort: 5900,
		SeedISO: "/seed.iso"}.Args(), " ")
	if !strings.Contains(a, "file=/seed.iso,media=cdrom") {
		t.Errorf("seed not attached as cdrom: %s", a)
	}
	if !strings.Contains(a, "-boot order=c") {
		t.Errorf("expected disk-first boot order without boot iso: %s", a)
	}
	b := strings.Join(Spec{ID: "s", DiskPath: "/d", CPUs: 1, MemoryMB: 512, VNCPort: 5900,
		BootISO: "/boot.iso"}.Args(), " ")
	if !strings.Contains(b, "-boot order=dc") {
		t.Errorf("expected cdrom-first boot order with boot iso: %s", b)
	}
}

// TestArgsHostFwdAndMAC checks user-mode port forwards render into the netdev
// and the NIC MAC pins onto the device.
func TestArgsHostFwdAndMAC(t *testing.T) {
	s := Spec{
		ID: "n", DiskPath: "/d", CPUs: 1, MemoryMB: 512, VNCPort: 5900, UserNet: true,
		MAC: "52:54:00:ab:cd:ef",
		HostFwds: []HostFwd{
			{Proto: "tcp", HostIP: "172.16.1.67", HostPort: 20022, GuestPort: 22},
			{Proto: "", HostPort: 20389, GuestPort: 3389}, // defaults to tcp + loopback
		},
	}
	a := strings.Join(s.Args(), " ")
	if !strings.Contains(a, "hostfwd=tcp:172.16.1.67:20022-:22") {
		t.Errorf("explicit hostfwd missing: %s", a)
	}
	if !strings.Contains(a, "hostfwd=tcp:127.0.0.1:20389-:3389") {
		t.Errorf("defaulted hostfwd missing: %s", a)
	}
	if !strings.Contains(a, "virtio-net-pci,netdev=n0,mac=52:54:00:ab:cd:ef") {
		t.Errorf("MAC not pinned: %s", a)
	}
}

func TestArgsNoPasswordWhenUnset(t *testing.T) {
	s := Spec{ID: "x", DiskPath: "/d", CPUs: 1, MemoryMB: 512, VNCPort: 5900, UserNet: true}
	a := strings.Join(s.Args(), " ")
	if strings.Contains(a, "password-secret") {
		t.Errorf("unexpected password-secret with no VNCPwFile: %s", a)
	}
	if !strings.Contains(a, "127.0.0.1:0,websocket=127.0.0.1:6900") {
		t.Errorf("default websocket port wrong: %s", a)
	}
}

// TestLaunchReapsExitedChild guards the zombie leak: when QEMU exits, Launch's
// child must be reaped so /proc/<pid> disappears. A zombie keeps its /proc entry
// and still answers kill(pid, 0), which made dead VMs look alive forever.
func TestLaunchReapsExitedChild(t *testing.T) {
	old := qemuBinary
	qemuBinary = "true" // exits immediately, ignores QEMU's argv
	defer func() { qemuBinary = old }()

	s := Spec{ID: "z", DiskPath: "/d", CPUs: 1, MemoryMB: 512, VNCPort: 5900, UserNet: true}
	proc, err := Launch(s, filepath.Join(t.TempDir(), "z.log"))
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	stat := "/proc/" + strconv.Itoa(proc.Pid) + "/stat"
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(stat); os.IsNotExist(err) {
			return // reaped
		}
	}
	data, _ := os.ReadFile(stat)
	t.Fatalf("exited child %d was never reaped (zombie): %s", proc.Pid, data)
}

// TestArgsHostMTU: a port group MTU below 1500 (VXLAN) is advertised to the
// guest on the virtio NIC; emulated NICs and the unset case get no host_mtu.
func TestArgsHostMTU(t *testing.T) {
	s := Spec{ID: "m", DiskPath: "/d", CPUs: 2, MemoryMB: 512, VNCPort: 5900,
		TapName: "vdxtabc", HostMTU: 1450}
	if a := strings.Join(s.Args(), " "); !strings.Contains(a, "virtio-net-pci,netdev=n0,packed=on,rx_queue_size=1024,mq=on,vectors=6,host_mtu=1450") {
		t.Errorf("host_mtu missing on virtio NIC: %s", a)
	}
	s.NICModel = "e1000e"
	if a := strings.Join(s.Args(), " "); strings.Contains(a, "host_mtu") {
		t.Errorf("host_mtu on an emulated NIC: %s", a)
	}
	s.NICModel, s.HostMTU = "", 0
	if a := strings.Join(s.Args(), " "); strings.Contains(a, "host_mtu") {
		t.Errorf("unexpected host_mtu when unset: %s", a)
	}
}

// TestArgsNoVNCPasswordInline: the migration-carried console password must never
// reach the command line (only the 0600 secret file does).
func TestArgsNoVNCPasswordInline(t *testing.T) {
	s := Spec{ID: "p", DiskPath: "/d", CPUs: 1, MemoryMB: 512, VNCPort: 5900,
		VNCPassword: "S3cretPw", VNCPwFile: "/run/p.vncpw"}
	if a := strings.Join(s.Args(), " "); strings.Contains(a, "S3cretPw") {
		t.Errorf("VNC password leaked onto the command line: %s", a)
	}
}
