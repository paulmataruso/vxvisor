// Package lxc wraps the liblxc CLI tools (lxc-create/start/stop/destroy/info/
// snapshot) to run system containers alongside QEMU VMs. All operations shell
// out; the service layer gates on membership/org and records containers in the
// database. A container's rootfs lives under an lxcpath (default /var/lib/lxc or
// a chosen storage pool), its NIC is a veth into a chosen bridge, and CPU/memory
// limits are written to the container config (cgroup2).
package lxc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Available() bool { _, err := exec.LookPath("lxc-create"); return err == nil }

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

// Create builds a container from the download template (dist/release/arch) under
// lxcpath, then applies NIC + CPU/memory limits to its config.
func Create(name, lxcpath, dist, release, arch, bridge, mac string, cpus, memMB int) error {
	if arch == "" {
		arch = "amd64"
	}
	if lxcpath != "" {
		if err := os.MkdirAll(lxcpath, 0o755); err != nil {
			return err
		}
	}
	args := append(pathArgs(lxcpath), "-n", name, "-t", "download", "--",
		"--dist", dist, "--release", release, "--arch", arch)
	if _, err := run(600*time.Second, "lxc-create", args...); err != nil {
		return err
	}
	return applyConfig(name, lxcpath, bridge, mac, cpus, memMB)
}

// applyConfig appends vdxd-managed NIC + limit settings to the container config.
func applyConfig(name, lxcpath, bridge, mac string, cpus, memMB int) error {
	cfgPath := filepath.Join(basePath(lxcpath), name, "config")
	var b strings.Builder
	b.WriteString("\n# --- managed by vdxd ---\n")
	if bridge != "" {
		b.WriteString("lxc.net.0.type = veth\n")
		b.WriteString("lxc.net.0.link = " + bridge + "\n")
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
