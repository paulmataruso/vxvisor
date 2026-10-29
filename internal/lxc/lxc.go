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

// StorageLabel describes where a container's rootfs lives — the backing store
// plus its pool/target — read from the container config's lxc.rootfs.path. Used
// for the containers list UI (parallel to a VM's StorageLabel).
func StorageLabel(name, lxcpath string) string {
	b, err := os.ReadFile(filepath.Join(basePath(lxcpath), name, "config"))
	if err != nil {
		if lxcpath != "" {
			return "Directory · " + lxcpath
		}
		return "Directory"
	}
	rootfs := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "lxc.rootfs.path") {
			if i := strings.IndexByte(line, '='); i >= 0 {
				rootfs = strings.TrimSpace(line[i+1:])
			}
		}
	}
	switch {
	case strings.HasPrefix(rootfs, "rbd:"): // rbd:/dev/rbd/<pool>/<image>
		p := strings.TrimPrefix(strings.TrimPrefix(rootfs, "rbd:"), "/dev/rbd/")
		pool := p
		if i := strings.IndexByte(p, '/'); i > 0 {
			pool = p[:i]
		}
		return "Ceph RBD · " + pool
	case strings.HasPrefix(rootfs, "lvm:"): // lvm:/dev/<vg>/<lv>
		p := strings.TrimPrefix(rootfs, "lvm:/dev/")
		vg := p
		if i := strings.IndexByte(p, '/'); i > 0 {
			vg = p[:i]
		}
		return "LVM thin · " + vg
	case strings.HasPrefix(rootfs, "zfs:"):
		return "ZFS"
	default: // dir:/path or a bare directory path
		if lxcpath != "" {
			return "Directory · " + lxcpath
		}
		return "Directory"
	}
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
	Bridge    string // host bridge the veth joins (resolved server-side, never client text)
	VLAN      int    // port group VLAN: the veth's untagged PVID on a vlan_filtering vSwitch (0 = untagged)
	MTU       int    // NIC MTU when the bridge runs below 1500 (a VXLAN segment's 1450); 0 = default
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
	// Backstop: the name is a path component and an lxc-* argument; dist/release/
	// arch become template cache + image URL path components (lxc-create runs as
	// root), whatever the caller already checked.
	if err := ValidName(o.Name); err != nil {
		return err
	}
	for _, a := range [][2]string{{"distribution", o.Dist}, {"release", o.Release}, {"architecture", o.Arch}} {
		if err := ValidTemplateArg(a[0], a[1]); err != nil {
			return err
		}
	}
	// Render the managed block BEFORE creating anything, so a bad NIC value is
	// refused without leaving a half-configured container behind.
	managed, err := managedBlock(o.Name, o.Bridge, o.MAC, o.VLAN, o.MTU, o.CPUs, o.MemMB)
	if err != nil {
		return err
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
	return appendConfig(o.Name, o.Lxcpath, managed)
}

// managedBlock renders the vdxd-managed NIC + limit settings appended to a new
// container's config. Every NIC value is validated (see nicLines): the bridge
// must be an interface name and nothing may break out of its line.
func managedBlock(name, bridge, mac string, vlan, mtu, cpus, memMB int) (string, error) {
	var b strings.Builder
	b.WriteString("\n# --- managed by vdxd ---\n")
	if bridge != "" {
		// Pin the host-side veth name so the topology diagram can match this
		// container's cable back to it (LXC would otherwise pick a random name).
		nic, err := nicLines(0, bridge, VethName(name), "", mac, vlan, mtu)
		if err != nil {
			return "", err
		}
		b.WriteString(nic)
	}
	if memMB > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.memory.max = %d\n", int64(memMB)<<20)
	}
	if cpus > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.cpuset.cpus = 0-%d\n", cpus-1)
	}
	return b.String(), nil
}

// appendConfig appends a rendered managed block to the container config.
func appendConfig(name, lxcpath, block string) error {
	cfgPath := filepath.Join(basePath(lxcpath), name, "config")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(block)
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
