// Package zfs wraps the zpool/zfs CLIs to create and manage ZFS pools and
// datasets from the UI. All operations shell out to the host tools (zfsutils);
// nothing here is destructive unless the caller asks (CreatePool/DestroyPool).
// The service layer gates every call on admin.
package zfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Available reports whether the host has the ZFS tools installed.
func Available() bool {
	_, err := exec.LookPath("zpool")
	return err == nil
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

// Pool is one zpool as the UI shows it.
type Pool struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	AllocBytes int64  `json:"alloc_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	Health     string `json:"health"`      // ONLINE | DEGRADED | FAULTED | ...
	CapPercent int    `json:"cap_percent"` // used %
	FragPct    int    `json:"frag_pct"`
}

// ListPools returns all imported zpools.
func ListPools() ([]Pool, error) {
	if !Available() {
		return nil, nil
	}
	// -Hp: script mode, parseable exact bytes. Fields in fixed order.
	out, err := run(10*time.Second, "zpool", "list", "-Hp", "-o",
		"name,size,alloc,free,health,capacity,fragmentation")
	if err != nil {
		return nil, err
	}
	var pools []Pool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		pools = append(pools, Pool{
			Name:       f[0],
			SizeBytes:  atoi64(f[1]),
			AllocBytes: atoi64(f[2]),
			FreeBytes:  atoi64(f[3]),
			Health:     f[4],
			CapPercent: atoiPct(f[5]),
			FragPct:    atoiPct(f[6]),
		})
	}
	return pools, nil
}

// Status returns `zpool status` text for one pool (for the detail/health view).
func Status(name string) (string, error) {
	if err := validName(name); err != nil {
		return "", err
	}
	return run(10*time.Second, "zpool", "status", name)
}

// CreatePool creates a zpool named `name` over `devices` with an optional raid
// layout ("" | "mirror" | "raidz" | "raidz2" | "raidz3"). force wipes existing
// signatures on the devices (zpool create -f) — the caller must have confirmed.
func CreatePool(name, raid string, devices []string, force bool) error {
	if err := validName(name); err != nil {
		return err
	}
	if len(devices) == 0 {
		return errors.New("no devices selected for the pool")
	}
	// The UI already confirms "selected disks will be WIPED", so clear any
	// residual signatures (stale GPT/EFI labels, old LVM/mdraid) first. This is
	// what makes zpool create reliable on a just-freed disk without forcing.
	for _, d := range devices {
		if d != "" {
			_, _ = run(30*time.Second, "wipefs", "-a", d)
		}
	}
	args := []string{"create"}
	if force {
		args = append(args, "-f")
	}
	// Default mountpoint under /<name>; set ashift=12 for modern 4K disks.
	args = append(args, "-o", "ashift=12", name)
	switch raid {
	case "", "stripe":
		// plain stripe / single disk: devices as-is
	case "mirror", "raidz", "raidz2", "raidz3":
		args = append(args, raid)
	default:
		return fmt.Errorf("unknown raid layout %q", raid)
	}
	for _, d := range devices {
		if d == "" {
			return errors.New("empty device path")
		}
		args = append(args, d)
	}
	_, err := run(120*time.Second, "zpool", args...)
	return err
}

// DestroyPool exports+destroys a pool. Destructive; caller confirms.
func DestroyPool(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	_, err := run(60*time.Second, "zpool", "destroy", "-f", name)
	return err
}

// VdevLine is one row of a pool's vdev tree, for the status view.
type VdevLine struct {
	Indent  int    `json:"indent"`  // hierarchy depth (0 = pool root)
	Name    string `json:"name"`    // device / vdev name or a section header
	State   string `json:"state"`   // ONLINE/DEGRADED/... ("" for a section header)
	Read    string `json:"read"`
	Write   string `json:"write"`
	Cksum   string `json:"cksum"`
	Section string `json:"section"` // "" data | cache | logs | spares | special | dedup
}

// PoolStatus is a parsed `zpool status` for structured display.
type PoolStatus struct {
	Name    string     `json:"name"`
	State   string     `json:"state"`
	Scan    string     `json:"scan"`
	Status  string     `json:"status"`
	Action  string     `json:"action"`
	Errors  string     `json:"errors"`
	Devices []VdevLine `json:"devices"`
}

// StatusTree parses `zpool status <name>` into a structured tree.
func StatusTree(name string) (PoolStatus, error) {
	var ps PoolStatus
	if err := validName(name); err != nil {
		return ps, err
	}
	out, err := run(10*time.Second, "zpool", "status", name)
	if err != nil {
		return ps, err
	}
	ps.Name = name
	section := ""     // current vdev section inside config:
	inConfig := false // past the "config:" header
	tableStarted := false
	sectionWords := map[string]bool{"cache": true, "logs": true, "log": true, "spares": true, "special": true, "dedup": true}
	for _, raw := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(raw)
		if !inConfig {
			switch {
			case strings.HasPrefix(trimmed, "state:"):
				ps.State = strings.TrimSpace(strings.TrimPrefix(trimmed, "state:"))
			case strings.HasPrefix(trimmed, "scan:"):
				ps.Scan = strings.TrimSpace(strings.TrimPrefix(trimmed, "scan:"))
			case strings.HasPrefix(trimmed, "status:"):
				ps.Status = strings.TrimSpace(strings.TrimPrefix(trimmed, "status:"))
			case strings.HasPrefix(trimmed, "action:"):
				ps.Action = strings.TrimSpace(strings.TrimPrefix(trimmed, "action:"))
			case strings.HasPrefix(trimmed, "errors:"):
				ps.Errors = strings.TrimSpace(strings.TrimPrefix(trimmed, "errors:"))
			case strings.HasPrefix(trimmed, "config:"):
				inConfig = true
			}
			continue
		}
		if strings.HasPrefix(trimmed, "errors:") {
			ps.Errors = strings.TrimSpace(strings.TrimPrefix(trimmed, "errors:"))
			inConfig = false
			continue
		}
		if trimmed == "" {
			continue
		}
		f := strings.Fields(trimmed)
		if !tableStarted {
			if len(f) >= 2 && f[0] == "NAME" { // header row
				tableStarted = true
			}
			continue
		}
		// indentation: strip one leading tab, count leading spaces.
		body := strings.TrimPrefix(raw, "\t")
		indent := len(body) - len(strings.TrimLeft(body, " "))
		if sectionWords[f[0]] && len(f) == 1 {
			section = f[0]
			ps.Devices = append(ps.Devices, VdevLine{Name: f[0], Section: f[0], Indent: 0})
			continue
		}
		v := VdevLine{Indent: indent, Name: f[0], Section: section}
		if len(f) >= 5 {
			v.State, v.Read, v.Write, v.Cksum = f[1], f[2], f[3], f[4]
		} else if len(f) >= 2 {
			v.State = f[1]
		}
		ps.Devices = append(ps.Devices, v)
	}
	return ps, nil
}

// ReplaceDevice swaps a faulted/old device for a new one (`zpool replace`). The
// new device is wiped first (caller confirmed). force passes -f.
func ReplaceDevice(pool, old, newDev string, force bool) error {
	if err := validName(pool); err != nil {
		return err
	}
	if err := validDevice(old); err != nil {
		return fmt.Errorf("old device: %w", err)
	}
	if err := validDevice(newDev); err != nil {
		return fmt.Errorf("new device: %w", err)
	}
	_, _ = run(30*time.Second, "wipefs", "-a", newDev)
	args := []string{"replace"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, pool, old, newDev)
	_, err := run(120*time.Second, "zpool", args...)
	return err
}

// AddCache adds L2ARC cache device(s) to a pool (`zpool add pool cache ...`).
func AddCache(pool string, devices []string, force bool) error {
	return addAux(pool, "cache", "", devices, force)
}

// AddLog adds SLOG log device(s) to a pool (`zpool add pool log [mirror] ...`).
// With mirror=true and 2+ devices, the log is mirrored (recommended for a SLOG).
func AddLog(pool string, devices []string, mirror, force bool) error {
	layout := ""
	if mirror && len(devices) >= 2 {
		layout = "mirror"
	}
	return addAux(pool, "log", layout, devices, force)
}

func addAux(pool, class, layout string, devices []string, force bool) error {
	if err := validName(pool); err != nil {
		return err
	}
	if len(devices) == 0 {
		return errors.New("no devices selected")
	}
	for _, d := range devices {
		if err := validDevice(d); err != nil {
			return err
		}
		_, _ = run(30*time.Second, "wipefs", "-a", d)
	}
	args := []string{"add"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, pool, class)
	if layout != "" {
		args = append(args, layout)
	}
	args = append(args, devices...)
	_, err := run(120*time.Second, "zpool", args...)
	return err
}

// SetVolsize grows (or sets) a zvol's volume size.
func SetVolsize(name string, sizeBytes int64) error {
	if err := validDatasetName(name); err != nil {
		return err
	}
	if sizeBytes <= 0 {
		return errors.New("volsize must be positive")
	}
	_, err := run(30*time.Second, "zfs", "set", "volsize="+strconv.FormatInt(sizeBytes, 10), name)
	return err
}

// validDevice is a light guard for /dev paths coming from the admin disk picker.
func validDevice(d string) error {
	if d == "" || !strings.HasPrefix(d, "/dev/") || strings.ContainsAny(d, " \t;|&") {
		return fmt.Errorf("invalid device path %q", d)
	}
	return nil
}

// Dataset is a zfs filesystem/volume.
type Dataset struct {
	Name       string `json:"name"`
	UsedBytes  int64  `json:"used_bytes"`
	AvailBytes int64  `json:"avail_bytes"`
	Mountpoint string `json:"mountpoint"`
	Type       string `json:"type"` // filesystem | volume
}

// ListDatasets lists datasets under a pool (recursively).
func ListDatasets(pool string) ([]Dataset, error) {
	if err := validName(pool); err != nil {
		return nil, err
	}
	out, err := run(10*time.Second, "zfs", "list", "-Hp", "-r", "-o",
		"name,used,avail,mountpoint,type", pool)
	if err != nil {
		return nil, err
	}
	var ds []Dataset
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		ds = append(ds, Dataset{
			Name: f[0], UsedBytes: atoi64(f[1]), AvailBytes: atoi64(f[2]),
			Mountpoint: f[3], Type: f[4],
		})
	}
	return ds, nil
}

// CreateDataset creates a filesystem dataset (e.g. pool/vms).
func CreateDataset(name string) error {
	if err := validDatasetName(name); err != nil {
		return err
	}
	_, err := run(30*time.Second, "zfs", "create", "-p", name)
	return err
}

// DestroyDataset recursively destroys a dataset. Destructive; caller confirms.
func DestroyDataset(name string) error {
	if err := validDatasetName(name); err != nil {
		return err
	}
	_, err := run(60*time.Second, "zfs", "destroy", "-r", name)
	return err
}

// CreateZvol creates a block volume (zvol) of sizeBytes, for use as a raw VM
// disk at /dev/zvol/<name>. sparse makes it thin-provisioned.
func CreateZvol(name string, sizeBytes int64, sparse bool) error {
	if err := validDatasetName(name); err != nil {
		return err
	}
	if sizeBytes <= 0 {
		return errors.New("zvol size must be positive")
	}
	args := []string{"create", "-p"}
	if sparse {
		args = append(args, "-s")
	}
	args = append(args, "-V", strconv.FormatInt(sizeBytes, 10), name)
	if _, err := run(30*time.Second, "zfs", args...); err != nil {
		return err
	}
	// The /dev/zvol/<name> symlink is created by udev AFTER `zfs create` returns,
	// so wait for it (settle + poll) before callers open the device.
	_, _ = run(10*time.Second, "udevadm", "settle")
	dev := "/dev/zvol/" + name
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(dev); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("zvol device %s did not appear", dev)
}

// ---- validation (names flow into shell args; keep them strict) -----------

func validName(name string) error {
	if name == "" {
		return errors.New("pool name required")
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || r == '.' || r == ':' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("invalid pool name %q", name)
		}
	}
	return nil
}

func validDatasetName(name string) error {
	if name == "" {
		return errors.New("dataset name required")
	}
	// datasets allow '/' separators between valid name segments
	for _, seg := range strings.Split(name, "/") {
		if err := validName(seg); err != nil {
			return err
		}
	}
	return nil
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func atoiPct(s string) int {
	s = strings.TrimSuffix(strings.TrimSpace(s), "%")
	n, _ := strconv.Atoi(s)
	return n
}
