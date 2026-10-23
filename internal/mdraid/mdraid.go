// Package mdraid manages Linux software RAID (md) arrays via mdadm. An array is
// a plain block device (/dev/mdN) that any pool backend can sit on — LVM /
// LVM-thin, ZFS, or a plain ext4/xfs filesystem. READ ops parse /proc/mdstat +
// `mdadm --detail`; WRITE ops (create/stop) are admin-gated by the caller and
// guarded against in-use member disks at the service layer.
package mdraid

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Array is one md device.
type Array struct {
	Name      string   `json:"name"`  // md0
	Dev       string   `json:"dev"`   // /dev/md0
	Level     string   `json:"level"` // raid0|raid1|raid5|raid6|raid10|linear
	State     string   `json:"state"` // clean|active|degraded|resyncing|…
	SizeBytes int64    `json:"size_bytes"`
	Members   []string `json:"members"` // component devices (/dev/sdX)
	Degraded  bool     `json:"degraded"`
	Sync      string   `json:"sync"` // resync/recovery progress line, if any
}

// Level is a supported RAID level with its minimum device count.
type Level struct {
	Name string
	Min  int
}

// Levels are the RAID levels the UI offers.
var Levels = []Level{
	{"raid1", 2}, {"raid0", 2}, {"raid5", 3}, {"raid6", 4}, {"raid10", 4}, {"linear", 2},
}

func run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Available reports whether mdadm is installed.
func Available() bool {
	_, err := exec.LookPath("mdadm")
	return err == nil
}

var reMdLine = regexp.MustCompile(`^(md\d+)\s*:\s*(\S+)\s+(\S+)\s+(.*)$`)
var reMember = regexp.MustCompile(`^([a-zA-Z0-9]+)\[\d+\]`)

// List returns every assembled md array by reading /proc/mdstat (for the member
// list + sync status) and `mdadm --detail` (for level/state/size).
func List() ([]Array, error) {
	f, err := os.Open("/proc/mdstat")
	if err != nil {
		return nil, nil // no md subsystem loaded = no arrays
	}
	defer f.Close()
	var out []Array
	sc := bufio.NewScanner(f)
	var cur *Array
	for sc.Scan() {
		line := sc.Text()
		if m := reMdLine.FindStringSubmatch(line); m != nil {
			if cur != nil {
				out = append(out, *cur)
			}
			a := Array{Name: m[1], Dev: "/dev/" + m[1], State: m[2]}
			for _, tok := range strings.Fields(m[4]) {
				if mm := reMember.FindStringSubmatch(tok); mm != nil {
					a.Members = append(a.Members, "/dev/"+mm[1])
				}
			}
			cur = &a
			continue
		}
		if cur != nil {
			if strings.Contains(line, "recovery") || strings.Contains(line, "resync") {
				cur.Sync = strings.TrimSpace(line)
			}
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	// Enrich each with mdadm --detail (level, state, size).
	for i := range out {
		detail(&out[i])
	}
	return out, sc.Err()
}

var (
	reDetLevel = regexp.MustCompile(`Raid Level\s*:\s*(\S+)`)
	reDetState = regexp.MustCompile(`State\s*:\s*(.+)`)
	reDetSize  = regexp.MustCompile(`Array Size\s*:\s*(\d+)`)
)

func detail(a *Array) {
	b, err := run(10*time.Second, "mdadm", "--detail", a.Dev)
	if err != nil {
		return
	}
	s := string(b)
	if m := reDetLevel.FindStringSubmatch(s); m != nil {
		a.Level = m[1]
	}
	if m := reDetState.FindStringSubmatch(s); m != nil {
		a.State = strings.TrimSpace(m[1])
		a.Degraded = strings.Contains(a.State, "degraded")
	}
	if m := reDetSize.FindStringSubmatch(s); m != nil { // first number is KiB
		if kib, e := strconv.ParseInt(m[1], 10, 64); e == nil {
			a.SizeBytes = kib * 1024
		}
	}
}

var reName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// validLevel returns the min device count for a level, or an error.
func validLevel(level string, n int) error {
	for _, l := range Levels {
		if l.Name == level {
			if n < l.Min {
				return fmt.Errorf("%s needs at least %d devices", level, l.Min)
			}
			if level == "raid10" && n%2 != 0 {
				return fmt.Errorf("raid10 needs an even number of devices")
			}
			return nil
		}
	}
	return fmt.Errorf("unsupported RAID level %q", level)
}

// nextMD returns the lowest /dev/mdN not currently present.
func nextMD() string {
	for n := 0; n < 128; n++ {
		if _, err := os.Stat(fmt.Sprintf("/dev/md%d", n)); os.IsNotExist(err) {
			return fmt.Sprintf("md%d", n)
		}
	}
	return "md127"
}

// Create builds a new array from the given component devices and returns its
// /dev path. The caller must have confirmed the devices are free (this wipes
// their superblocks via mdadm --create). name is a cosmetic array name.
func Create(name, level string, devices []string) (string, error) {
	if !Available() {
		return "", fmt.Errorf("mdadm is not installed on this host")
	}
	if !reName.MatchString(name) {
		return "", fmt.Errorf("array name must be 1–32 chars of letters, digits, dot, dash or underscore")
	}
	if err := validLevel(level, len(devices)); err != nil {
		return "", err
	}
	for _, d := range devices {
		if !strings.HasPrefix(d, "/dev/") {
			return "", fmt.Errorf("invalid device %q", d)
		}
	}
	md := nextMD()
	dev := "/dev/" + md
	args := []string{"--create", dev, "--name=" + name, "--level=" + level,
		"--raid-devices=" + strconv.Itoa(len(devices)), "--metadata=1.2", "--run", "--force"}
	args = append(args, devices...)
	if out, err := run(60*time.Second, "mdadm", args...); err != nil {
		return "", fmt.Errorf("mdadm --create: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return dev, nil
}

// Stop stops (deactivates) an array. Members are left intact unless ZeroSuperblock
// is also called.
func Stop(dev string) error {
	if out, err := run(30*time.Second, "mdadm", "--stop", dev); err != nil {
		return fmt.Errorf("mdadm --stop %s: %v: %s", dev, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ZeroSuperblock wipes the md superblock from component devices so they become
// free disks again (best-effort per device).
func ZeroSuperblock(devices []string) {
	for _, d := range devices {
		_, _ = run(20*time.Second, "mdadm", "--zero-superblock", d)
	}
}

// SaveConf persists the current array set to mdadm.conf and refreshes initramfs
// so arrays re-assemble on boot. Best-effort; a failure is non-fatal (udev
// auto-assembles 1.2-metadata arrays by UUID anyway).
func SaveConf() {
	conf := "/etc/mdadm/mdadm.conf"
	if _, err := os.Stat("/etc/mdadm"); err != nil {
		conf = "/etc/mdadm.conf"
	}
	scan, err := run(10*time.Second, "mdadm", "--detail", "--scan")
	if err != nil {
		return
	}
	// Rewrite only the ARRAY lines, preserving any non-ARRAY config.
	var keep []string
	if b, err := os.ReadFile(conf); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(ln), "ARRAY") {
				keep = append(keep, ln)
			}
		}
	}
	body := strings.TrimRight(strings.Join(keep, "\n"), "\n") + "\n" + string(scan)
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		return
	}
	_, _ = run(120*time.Second, "update-initramfs", "-u")
}
