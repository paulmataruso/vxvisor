// Package lxc wraps the liblxc CLI tools (lxc-create/start/stop/destroy/info/
// snapshot) to run system containers alongside QEMU VMs. All operations shell
// out; the service layer gates on membership/org and records containers in the
// database. A container's rootfs lives under an lxcpath (default /var/lib/lxc or
// a chosen storage pool), its NIC is a veth into a chosen bridge, and CPU/memory
// limits are written to the container config (cgroup2).
package lxc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Available() bool { _, err := exec.LookPath("lxc-create"); return err == nil }

// VethName is the deterministic host-side veth name for a container. LXC would
// otherwise name the host end randomly (vethXXXXXX), which the topology diagram
// can't match back to the container. Pinning it to a hash of the name lets the
// diagram draw each container → its own veth → the switch. Linux caps interface
// names at 15 chars, so this is "vdx" + 10 hex of sha256(name) = 13 chars.
func VethName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "vdx" + hex.EncodeToString(sum[:])[:10]
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func pathArgs(lxcpath string) []string {
	if lxcpath != "" {
		return []string{"-P", lxcpath}
	}
	return nil
}

func basePath(lxcpath string) string {
	if lxcpath != "" {
		return lxcpath
	}
	return "/var/lib/lxc"
}

// Container is the live state of one container (from lxc-info).
type Container struct {
	Name     string `json:"name"`
	State    string `json:"state"` // RUNNING | STOPPED | FROZEN | ...
	PID      int    `json:"pid"`
	IP       string `json:"ip"`
	MemBytes int64  `json:"mem_bytes"`
}

// CreateOpts parameterises a new container. RBDPool or LVMVG select a block
// backing store, where liblxc puts the rootfs on a device it provisions
// (-B rbd: a Ceph image mapped as a kernel block device; -B lvm: an LVM thin
// volume) — it creates the volume, lays down a filesystem and mounts it as the
// rootfs, (un)mapping/activating on start/stop. Otherwise the rootfs is a plain
// directory under Lxcpath (default /var/lib/lxc). A block pool's path is NOT a
// filesystem directory, so it must never be used as Lxcpath.
type CreateOpts struct {
	Name      string
	Lxcpath   string
	Dist      string
	Release   string
	Arch      string
	Bridge    string
	MAC       string
	CPUs      int
	MemMB     int
	RBDPool   string // Ceph pool name — non-empty ⇒ rootfs on RBD (-B rbd)
	RBDUser   string // cephx id used for map/auth (defaults to "admin")
	LVMVG     string // LVM volume group — non-empty ⇒ rootfs on an LVM LV (-B lvm)
	LVMThin   string // optional LVM thin pool within the VG
	BlockName string // rbd image / lv name (defaults to "lxc-"+Name)
	SizeG     int    // rootfs size in GiB for a block backing store (defaults to 10)
}

// Create builds a container from the download template (dist/release/arch), then
// applies NIC + CPU/memory limits to its config.
func Create(o CreateOpts) error {
	if o.Arch == "" {
		o.Arch = "amd64"
	}
	tmpl := []string{"-t", "download", "--", "--dist", o.Dist, "--release", o.Release, "--arch", o.Arch}
	var args []string
	switch {
	case o.RBDPool != "" || o.LVMVG != "":
		// Block backing store: liblxc owns the rootfs device, so the container's
		// config lives under the default lxcpath and Lxcpath is not used here.
		vol := o.BlockName
		if vol == "" {
			vol = "lxc-" + o.Name
		}
		size := o.SizeG
		if size <= 0 {
			size = 10
		}
		if o.RBDPool != "" {
			user := o.RBDUser
			if user == "" {
				user = "admin"
			}
			args = []string{"-n", o.Name, "-B", "rbd",
				"--rbdpool", o.RBDPool, "--rbdname", vol, "--rbduser", user,
				"--fstype", "ext4", "--fssize", fmt.Sprintf("%dG", size)}
		} else {
			args = []string{"-n", o.Name, "-B", "lvm", "--vgname", o.LVMVG, "--lvname", vol,
				"--fstype", "ext4", "--fssize", fmt.Sprintf("%dG", size)}
			if o.LVMThin != "" {
				args = append(args, "--thinpool", o.LVMThin)
			}
		}
		args = append(args, tmpl...)
	default:
		if o.Lxcpath != "" {
			if err := os.MkdirAll(o.Lxcpath, 0o755); err != nil {
				return err
			}
		}
		args = append(append(pathArgs(o.Lxcpath), "-n", o.Name), tmpl...)
	}
	if _, err := run(600*time.Second, "lxc-create", args...); err != nil {
		return err
	}
	return applyConfig(o.Name, o.Lxcpath, o.Bridge, o.MAC, o.CPUs, o.MemMB)
}

// applyConfig appends vdxd-managed NIC + limit settings to the container config.
func applyConfig(name, lxcpath, bridge, mac string, cpus, memMB int) error {
	cfgPath := filepath.Join(basePath(lxcpath), name, "config")
	var b strings.Builder
	b.WriteString("\n# --- managed by vdxd ---\n")
	if bridge != "" {
		b.WriteString("lxc.net.0.type = veth\n")
		b.WriteString("lxc.net.0.link = " + bridge + "\n")
		// Pin the host-side veth name so the topology diagram can match this
		// container's cable back to it (LXC would otherwise pick a random name).
		b.WriteString("lxc.net.0.veth.pair = " + VethName(name) + "\n")
		b.WriteString("lxc.net.0.flags = up\n")
		if mac != "" {
			b.WriteString("lxc.net.0.hwaddr = " + mac + "\n")
		}
	}
	if memMB > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.memory.max = %d\n", int64(memMB)<<20)
	}
	if cpus > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.cpuset.cpus = 0-%d\n", cpus-1)
	}
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

// SetLimits updates CPU/memory limits live (if running) and rewrites nothing on
// disk beyond what the caller persists; best-effort for a running container.
func SetLimits(name, lxcpath string, cpus, memMB int) {
	if memMB > 0 {
		_, _ = run(10*time.Second, "lxc-cgroup", append(pathArgs(lxcpath), "-n", name, "memory.max", strconv.FormatInt(int64(memMB)<<20, 10))...)
	}
	if cpus > 0 {
		_, _ = run(10*time.Second, "lxc-cgroup", append(pathArgs(lxcpath), "-n", name, "cpuset.cpus", "0-"+strconv.Itoa(cpus-1))...)
	}
}

func Start(name, lxcpath string) error {
	_, err := run(60*time.Second, "lxc-start", append(pathArgs(lxcpath), "-n", name, "-d")...)
	return err
}

func Stop(name, lxcpath string) error {
	_, err := run(60*time.Second, "lxc-stop", append(pathArgs(lxcpath), "-n", name)...)
	return err
}

func Destroy(name, lxcpath string) error {
	_, _ = run(30*time.Second, "lxc-stop", append(pathArgs(lxcpath), "-n", name, "-k")...)
	_, err := run(60*time.Second, "lxc-destroy", append(pathArgs(lxcpath), "-n", name, "-f")...)
	return err
}

// Info parses lxc-info for one container.
func Info(name, lxcpath string) (Container, error) {
	c := Container{Name: name, State: "STOPPED"}
	out, err := run(10*time.Second, "lxc-info", append(pathArgs(lxcpath), "-n", name)...)
	if err != nil {
		return c, nil // treat unknown as stopped rather than hard error
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "State":
			c.State = v
		case "PID":
			c.PID, _ = strconv.Atoi(v)
		case "IP":
			if c.IP == "" {
				c.IP = v
			}
		case "Memory use":
			c.MemBytes = parseHuman(v)
		}
	}
	return c, nil
}

// Snapshot creates a snapshot of a (stopped) container.
func Snapshot(name, lxcpath string) error {
	_, err := run(120*time.Second, "lxc-snapshot", append(pathArgs(lxcpath), "-n", name)...)
	return err
}

// ListSnapshots returns snapshot names for a container.
func ListSnapshots(name, lxcpath string) ([]string, error) {
	out, err := run(15*time.Second, "lxc-snapshot", append(pathArgs(lxcpath), "-n", name, "-L")...)
	if err != nil {
		return nil, err
	}
	var snaps []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "snap") {
			snaps = append(snaps, f[0])
		}
	}
	return snaps, nil
}

// Restore reverts a container to a snapshot.
func Restore(name, lxcpath, snap string) error {
	_, err := run(120*time.Second, "lxc-snapshot", append(pathArgs(lxcpath), "-n", name, "-r", snap)...)
	return err
}

// parseHuman parses lxc-info memory like "123.45 MiB" into bytes.
func parseHuman(s string) int64 {
	f := strings.Fields(s)
	if len(f) < 1 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	mult := 1.0
	if len(f) >= 2 {
		switch strings.ToUpper(f[1]) {
		case "KIB", "KB":
			mult = 1 << 10
		case "MIB", "MB":
			mult = 1 << 20
		case "GIB", "GB":
			mult = 1 << 30
		}
	}
	return int64(v * mult)
}
