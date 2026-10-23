package lxc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NetLeg is one virtual-router NIC: a veth whose host end lands on Bridge and
// whose in-container name is pinned to Name (eth0, eth1, …) for deterministic
// ordering. Used by the vRouter LXC backend; distinct from the single-NIC
// container create path (applyConfig).
type NetLeg struct {
	Bridge string
	Name   string // in-container interface name, e.g. "eth0"
	MAC    string
}

const vdxManagedMarker = "# --- managed by vdxd ---"

// LegVethName is the deterministic host-side veth name for leg idx of a
// container. "vdx" + 8 hex of sha256(name) + idx stays within IFNAMSIZ (15).
func LegVethName(name string, idx int) string {
	sum := sha256.Sum256([]byte(name))
	return "vdx" + hex.EncodeToString(sum[:])[:8] + strconv.Itoa(idx)
}

// ConfigPath / RootfsPath expose the container's on-disk config + rootfs so the
// vRouter backend can write frr.conf directly when the container is stopped
// (dir-backed rootfs only — block-backed rootfs is unmapped while stopped).
func ConfigPath(name, lxcpath string) string { return filepath.Join(basePath(lxcpath), name, "config") }
func RootfsPath(name, lxcpath string) string {
	return filepath.Join(basePath(lxcpath), name, "rootfs")
}

// WriteLegs REWRITES the vdxd-managed block of a container config with N NIC
// legs plus CPU/memory limits and lxc.start.auto so the container returns after
// a host reboot. Unlike applyConfig (which appends a single net.0), this owns
// the whole managed block: it truncates everything from the marker onward and
// rewrites it, so repeated calls (provision → swap to real legs) are idempotent.
func WriteLegs(name, lxcpath string, legs []NetLeg, cpus, memMB int) error {
	cfgPath := ConfigPath(name, lxcpath)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	// Drop any existing managed block.
	head := string(raw)
	if i := strings.Index(head, vdxManagedMarker); i >= 0 {
		head = strings.TrimRight(head[:i], "\n")
	} else {
		head = strings.TrimRight(head, "\n")
	}

	var b strings.Builder
	b.WriteString(head)
	b.WriteString("\n\n" + vdxManagedMarker + "\n")
	// Do NOT autostart via the lxc service: its veth legs need their host bridges
	// to exist first, which vdxd ensures (ReensureVRouters) before starting the
	// container at boot. Autostarting here would race the bridge creation.
	b.WriteString("lxc.start.auto = 0\n")
	for i, l := range legs {
		if l.Bridge == "" {
			continue
		}
		p := "lxc.net." + strconv.Itoa(i)
		fmt.Fprintf(&b, "%s.type = veth\n", p)
		fmt.Fprintf(&b, "%s.link = %s\n", p, l.Bridge)
		fmt.Fprintf(&b, "%s.veth.pair = %s\n", p, LegVethName(name, i))
		name := l.Name
		if name == "" {
			name = "eth" + strconv.Itoa(i)
		}
		fmt.Fprintf(&b, "%s.name = %s\n", p, name)
		fmt.Fprintf(&b, "%s.flags = up\n", p)
		if l.MAC != "" {
			fmt.Fprintf(&b, "%s.hwaddr = %s\n", p, l.MAC)
		}
	}
	if memMB > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.memory.max = %d\n", int64(memMB)<<20)
	}
	if cpus > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.cpuset.cpus = 0-%d\n", cpus-1)
	}
	return os.WriteFile(cfgPath, []byte(b.String()), 0o644)
}

// UpdateManaged rewrites the single-NIC container's vdxd-managed settings in
// place — the NIC's bridge (lxc.net.0.link) and the CPU/memory cgroup limits —
// preserving everything else (MAC, veth pair name, rootfs). Used by "edit
// container". Keys not already present are appended inside the managed block.
func UpdateManaged(name, lxcpath, bridge string, cpus, memMB int) error {
	cfgPath := ConfigPath(name, lxcpath)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	want := map[string]string{}
	if bridge != "" {
		want["lxc.net.0.link"] = "lxc.net.0.link = " + bridge
	}
	if memMB > 0 {
		want["lxc.cgroup2.memory.max"] = "lxc.cgroup2.memory.max = " + strconv.FormatInt(int64(memMB)<<20, 10)
	}
	if cpus > 0 {
		want["lxc.cgroup2.cpuset.cpus"] = "lxc.cgroup2.cpuset.cpus = 0-" + strconv.Itoa(cpus-1)
	}
	lines := strings.Split(string(raw), "\n")
	seen := map[string]bool{}
	for i, l := range lines {
		t := strings.TrimSpace(l)
		for k, v := range want {
			if strings.HasPrefix(t, k+" ") || strings.HasPrefix(t, k+"=") || t == k {
				lines[i] = v
				seen[k] = true
			}
		}
	}
	// Append any key not already present (keep it inside the config; order is fine).
	for k, v := range want {
		if !seen[k] {
			lines = append(lines, v)
		}
	}
	return os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")), 0o644)
}

// AttachRun runs a command inside a (running) container via lxc-attach and
// returns its combined output.
func AttachRun(name, lxcpath string, timeout time.Duration, args ...string) (string, error) {
	a := append(pathArgs(lxcpath), "-n", name, "--")
	a = append(a, args...)
	return run(timeout, "lxc-attach", a...)
}

// WriteRootfsFile writes a file into a stopped dir-backed container's rootfs
// (creating parent dirs). Used to drop /etc/frr/frr.conf before first start.
func WriteRootfsFile(name, lxcpath, rel string, data []byte, mode os.FileMode) error {
	full := filepath.Join(RootfsPath(name, lxcpath), filepath.Clean("/"+rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, data, mode)
}
