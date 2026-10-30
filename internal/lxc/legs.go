package lxc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// NetLeg is one virtual-router NIC: a veth whose host end lands on Bridge and
// whose in-container name is pinned to Name (eth0, eth1, …) for deterministic
// ordering. Used by the vRouter LXC backend; distinct from the single-NIC
// container create path (managedBlock).
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

// ConfigMAC is the MAC of a container's first NIC as its config pins it ("" =
// none, the NIC gets a random one at each start).
func ConfigMAC(name, lxcpath string) string {
	raw, err := os.ReadFile(ConfigPath(name, lxcpath))
	if err != nil {
		return ""
	}
	return configMAC(string(raw))
}

func configMAC(cfg string) string {
	for _, l := range strings.Split(cfg, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.TrimSpace(k) != "lxc.net.0.hwaddr" {
			continue
		}
		if hw, err := net.ParseMAC(strings.TrimSpace(v)); err == nil && len(hw) == 6 {
			return hw.String()
		}
	}
	return ""
}
func RootfsPath(name, lxcpath string) string {
	return filepath.Join(basePath(lxcpath), name, "rootfs")
}

// WriteLegs REWRITES the vdxd-managed block of a container config with N NIC
// legs plus CPU/memory limits and lxc.start.auto so the container returns after
// a host reboot. Unlike managedBlock (which appends a single net.0), this owns
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
		ifname := l.Name
		if ifname == "" {
			ifname = "eth" + strconv.Itoa(i)
		}
		// Validated rendering: bridge/ifname must be interface names, MAC a MAC,
		// and no value may break out of its line (lxc.* injection backstop).
		nic, err := nicLines(i, l.Bridge, LegVethName(name, i), ifname, l.MAC, 0, 0)
		if err != nil {
			return err
		}
		b.WriteString(nic)
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
// place — the NIC's bridge (lxc.net.0.link), its port group VLAN
// (lxc.net.0.veth.vlan.id) and MTU (lxc.net.0.mtu), and the CPU/memory cgroup
// limits — preserving everything else (MAC, veth pair name, rootfs). Used by
// "edit container". A zero VLAN / MTU removes that key; an empty bridge leaves
// the NIC alone. Keys not already present are appended.
func UpdateManaged(name, lxcpath, bridge string, vlan, mtu, cpus, memMB int) error {
	cfgPath := ConfigPath(name, lxcpath)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	want := map[string]string{}
	drop := map[string]bool{}
	if bridge != "" {
		// Same validation as a fresh create (interface name, VLAN/MTU ranges,
		// single-line values) — the lxc.* injection backstop.
		if _, err := nicLines(0, bridge, VethName(name), "", "", vlan, mtu); err != nil {
			return err
		}
		want["lxc.net.0.link"] = "lxc.net.0.link = " + bridge
		if vlan > 0 {
			want["lxc.net.0.veth.vlan.id"] = "lxc.net.0.veth.vlan.id = " + strconv.Itoa(vlan)
		} else {
			drop["lxc.net.0.veth.vlan.id"] = true
		}
		if mtu > 0 {
			want["lxc.net.0.mtu"] = "lxc.net.0.mtu = " + strconv.Itoa(mtu)
		} else {
			drop["lxc.net.0.mtu"] = true
		}
	}
	if memMB > 0 {
		want["lxc.cgroup2.memory.max"] = "lxc.cgroup2.memory.max = " + strconv.FormatInt(int64(memMB)<<20, 10)
	}
	if cpus > 0 {
		want["lxc.cgroup2.cpuset.cpus"] = "lxc.cgroup2.cpuset.cpus = 0-" + strconv.Itoa(cpus-1)
	}
	var lines []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(raw), "\n") {
		k := configKey(l)
		if drop[k] {
			continue
		}
		if v, ok := want[k]; ok {
			l = v
			seen[k] = true
		}
		lines = append(lines, l)
	}
	// Append any key not already present (keep it inside the config; order is fine).
	for _, k := range []string{"lxc.net.0.link", "lxc.net.0.veth.vlan.id", "lxc.net.0.mtu", "lxc.cgroup2.memory.max", "lxc.cgroup2.cpuset.cpus"} {
		if v, ok := want[k]; ok && !seen[k] {
			lines = append(lines, v)
		}
	}
	return os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")), 0o644)
}

// configKey returns the key of a "key = value" config line ("" for comments,
// blanks and anything without '=').
func configKey(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	k, _, ok := strings.Cut(t, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(k)
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
