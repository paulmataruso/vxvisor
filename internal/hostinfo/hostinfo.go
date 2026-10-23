// Package hostinfo introspects the host: network interfaces, block devices,
// mounts, and directory listings. It backs the UI's interface picker, mount-path
// autocomplete, ZFS/LVM disk picker, and the network topology diagram.
//
// Everything here is READ-ONLY and parses the JSON output of standard tools
// (iproute2 `ip -j`, util-linux `lsblk -J`/`findmnt -J`) plus /sys and statfs.
// Callers must gate these behind an admin check — the data describes the host.
package hostinfo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func run(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

var (
	reKmsgNvme  = regexp.MustCompile(`nvme (nvme\d+): .*(Disabling device|disable controller|reset failure|Removing after probe failure)`)
	reKmsgIOErr = regexp.MustCompile(`I/O error, dev ([a-z0-9]+)`)
)

// KernelDiskErrors scans the kernel ring buffer for block-device failure markers
// — an NVMe controller disabled after a failed reset (a drive that dropped off
// the bus), or logged I/O errors — and returns a map of device name (sda,
// nvme0n1) OR NVMe controller name (nvme0) → a human reason. Best-effort and
// bounded by run()'s timeout; an empty map on any error. READ-ONLY.
func KernelDiskErrors() map[string]string {
	out := map[string]string{}
	b, err := run("dmesg")
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 256*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := reKmsgNvme.FindStringSubmatch(line); m != nil {
			out[m[1]] = "NVMe controller " + m[1] + " was disabled after a reset failure — the drive dropped off the bus"
			continue
		}
		if m := reKmsgIOErr.FindStringSubmatch(line); m != nil {
			if dev := m[1]; !strings.HasPrefix(dev, "dm-") {
				if _, ok := out[dev]; !ok {
					out[dev] = "the kernel logged I/O errors on this device"
				}
			}
		}
	}
	return out
}

// ---- interfaces ----------------------------------------------------------

// Iface is one host network interface as the UI needs it.
type Iface struct {
	Name      string   `json:"name"`
	State     string   `json:"state"`     // up | down | unknown
	MAC       string   `json:"mac"`
	Addrs     []string `json:"addrs"`     // CIDRs, e.g. 172.16.0.157/24
	SpeedMbps int      `json:"speed_mbps"`// 0 if unknown (virtual/down)
	Type      string   `json:"type"`      // physical | bridge | vxlan | tap | bond | vlan | loopback | other
	Master    string   `json:"master"`    // bridge/bond this iface is enslaved to, if any
	Carrier   bool     `json:"carrier"`   // link detected
	Group     string   `json:"group"`     // UI grouping label, filled by the service layer (DB-aware); empty here
}

// ipLink mirrors the fields we read from `ip -j -d link`.
type ipLink struct {
	IfName    string `json:"ifname"`
	Address   string `json:"address"`
	OperState string `json:"operstate"`
	Master    string `json:"master"`
	LinkType  string `json:"link_type"`
	Flags     []string `json:"flags"`
	LinkInfo  struct {
		InfoKind string `json:"info_kind"` // bridge, vxlan, tun, bond, vlan...
	} `json:"linkinfo"`
}

type ipAddr struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Family    string `json:"family"`
	} `json:"addr_info"`
}

// Interfaces returns every host interface with state, addressing and type.
func Interfaces() ([]Iface, error) {
	linkOut, err := run("ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, err
	}
	var links []ipLink
	if err := json.Unmarshal(linkOut, &links); err != nil {
		return nil, err
	}
	// Addresses are a separate call.
	addrByIf := map[string][]string{}
	if addrOut, err := run("ip", "-j", "addr", "show"); err == nil {
		var addrs []ipAddr
		if json.Unmarshal(addrOut, &addrs) == nil {
			for _, a := range addrs {
				for _, ai := range a.AddrInfo {
					addrByIf[a.IfName] = append(addrByIf[a.IfName], ai.Local+"/"+strconv.Itoa(ai.PrefixLen))
				}
			}
		}
	}
	out := make([]Iface, 0, len(links))
	for _, l := range links {
		it := Iface{
			Name:    l.IfName,
			State:   strings.ToLower(l.OperState),
			MAC:     l.Address,
			Addrs:   addrByIf[l.IfName],
			Master:  l.Master,
			Type:    classifyIface(l),
			Carrier: hasFlag(l.Flags, "LOWER_UP"),
		}
		if it.State == "" {
			it.State = "unknown"
		}
		it.SpeedMbps = ifaceSpeed(l.IfName)
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func classifyIface(l ipLink) string {
	switch {
	case l.IfName == "lo":
		return "loopback"
	case l.LinkInfo.InfoKind == "bridge":
		return "bridge"
	case l.LinkInfo.InfoKind == "vxlan":
		return "vxlan"
	case l.LinkInfo.InfoKind == "tun":
		return "tap"
	case l.LinkInfo.InfoKind == "bond":
		return "bond"
	case l.LinkInfo.InfoKind == "vlan":
		return "vlan"
	case l.LinkInfo.InfoKind == "veth":
		return "veth" // one half of a veth pair — a container's NIC, never an uplink
	case l.LinkInfo.InfoKind == "":
		return "physical"
	default:
		return "other"
	}
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

func ifaceSpeed(name string) int {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "speed"))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// ---- block devices -------------------------------------------------------

// BlockDev is a whole disk or partition, with enough context to decide whether
// it is safe to hand to zpool/pvcreate (InUse true = has a mount, holder, or
// filesystem and must not be wiped without an explicit override).
// SmartAvailable reports whether smartctl is installed for disk health checks.
func SmartAvailable() bool {
	_, err := exec.LookPath("smartctl")
	return err == nil
}

// SmartHealth returns a disk's SMART overall-health ("PASSED"/"FAILED"/"unknown")
// via `smartctl -H`. Best-effort: devices behind controllers that need an
// explicit -d type, or without SMART, report "unknown" rather than erroring.
func SmartHealth(dev string) string {
	if dev == "" || !strings.HasPrefix(dev, "/dev/") {
		return "unknown"
	}
	out, _ := run("smartctl", "-H", dev) // ignore exit code; SMART failure sets bits
	s := string(out)
	switch {
	case strings.Contains(s, "PASSED"), strings.Contains(s, "OK"):
		return "PASSED"
	case strings.Contains(s, "FAILED"), strings.Contains(s, "FAILING"):
		return "FAILED"
	default:
		return "unknown"
	}
}

type BlockDev struct {
	Name     string     `json:"name"`      // e.g. sdc
	Path     string     `json:"path"`      // /dev/sdc
	Size     string     `json:"size"`      // human, e.g. 447.1G
	Bytes    int64      `json:"bytes"`     // raw size; 0 = offline/dropped device
	Model    string     `json:"model"`
	Type     string     `json:"type"`      // disk | part | lvm | ...
	FSType   string     `json:"fstype"`
	Mount    string     `json:"mountpoint"`
	InUse    bool       `json:"in_use"`
	UseNote  string     `json:"use_note"`  // why it's in use (for the UI warning)
	Children []BlockDev `json:"children,omitempty"`
}

type lsblkDev struct {
	Name       string      `json:"name"`
	Path       string      `json:"path"`
	Size       json.Number `json:"size"` // bytes (lsblk -b emits a JSON number)
	Model      string      `json:"model"`
	Type       string      `json:"type"`
	FSType     string      `json:"fstype"`
	MountPoint string      `json:"mountpoint"`
	Children   []lsblkDev  `json:"children"`
}

// BlockDevices returns whole disks and their partitions/holders. Disks with any
// mount, filesystem, or child holder are marked InUse with a human note so the
// UI can warn before a destructive pool-create wipes them.
func BlockDevices() ([]BlockDev, error) {
	out, err := run("lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,MODEL,TYPE,FSTYPE,MOUNTPOINT")
	if err != nil {
		return nil, err
	}
	var top struct {
		BlockDevices []lsblkDev `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, err
	}
	var devs []BlockDev
	for _, d := range top.BlockDevices {
		if d.Type != "disk" {
			continue
		}
		devs = append(devs, toBlockDev(d))
	}
	return devs, nil
}

func toBlockDev(d lsblkDev) BlockDev {
	nbytes, _ := d.Size.Int64()
	bd := BlockDev{
		Name: d.Name, Path: d.Path, Size: humanSize(d.Size.String()), Bytes: nbytes, Model: strings.TrimSpace(d.Model),
		Type: d.Type, FSType: d.FSType, Mount: d.MountPoint,
	}
	note := ""
	if d.MountPoint != "" {
		note = "mounted at " + d.MountPoint
	} else if d.FSType != "" {
		note = "has " + d.FSType + " filesystem"
	}
	for _, c := range d.Children {
		cb := toBlockDev(c)
		if cb.InUse && note == "" {
			note = "in use by " + c.Name + " (" + cb.UseNote + ")"
		} else if note == "" {
			note = "partitioned (" + c.Name + ")"
		}
		bd.Children = append(bd.Children, cb)
	}
	bd.UseNote = note
	bd.InUse = note != ""
	return bd
}

func humanSize(bytesStr string) string {
	n, err := strconv.ParseInt(bytesStr, 10, 64)
	if err != nil {
		return bytesStr
	}
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	return strconv.FormatFloat(val, 'f', 1, 64) + string("KMGTPE"[exp]) + "B"
}

// ---- mounts & directory browsing -----------------------------------------

// Mount is a mounted filesystem with capacity, for the storage UI.
type Mount struct {
	Target     string `json:"target"`
	Source     string `json:"source"`
	FSType     string `json:"fstype"`
	SizeBytes  int64  `json:"size_bytes"`
	AvailBytes int64  `json:"avail_bytes"`
}

// Mounts lists real (non-pseudo) mounted filesystems with free space.
func Mounts() ([]Mount, error) {
	out, err := run("findmnt", "-J", "-b", "-o", "TARGET,SOURCE,FSTYPE")
	if err != nil {
		return nil, err
	}
	var top struct {
		Filesystems []struct {
			Target     string `json:"target"`
			Source     string `json:"source"`
			FSType     string `json:"fstype"`
			Children   []struct {
				Target string `json:"target"`
				Source string `json:"source"`
				FSType string `json:"fstype"`
			} `json:"children"`
		} `json:"filesystems"`
	}
	if err := json.Unmarshal(out, &top); err != nil {
		return nil, err
	}
	var ms []Mount
	add := func(target, source, fstype string) {
		if isPseudoFS(fstype) {
			return
		}
		size, avail := fsSpace(target)
		ms = append(ms, Mount{Target: target, Source: source, FSType: fstype, SizeBytes: size, AvailBytes: avail})
	}
	for _, f := range top.Filesystems {
		add(f.Target, f.Source, f.FSType)
		for _, c := range f.Children {
			add(c.Target, c.Source, c.FSType)
		}
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Target < ms[j].Target })
	return ms, nil
}

func isPseudoFS(fstype string) bool {
	switch fstype {
	case "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
		"pstore", "securityfs", "debugfs", "tracefs", "mqueue", "hugetlbfs",
		"bpf", "configfs", "fusectl", "autofs", "ramfs", "squashfs", "overlay",
		"binfmt_misc", "efivarfs", "fuse.gvfsd-fuse":
		return true
	}
	return false
}

func fsSpace(dir string) (size, avail int64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0
	}
	return int64(st.Blocks) * int64(st.Bsize), int64(st.Bavail) * int64(st.Bsize)
}

// DirEntry is one subdirectory under a browsed path.
type DirEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsMount bool   `json:"is_mount"`
}

// BrowseDir lists immediate SUBDIRECTORIES of dir (never files, never contents),
// for mount-path autocomplete. It is bounded and admin-only by the caller. An
// empty or relative dir is treated as "/". Results are capped.
func BrowseDir(dir string) (string, []DirEntry, error) {
	if dir == "" {
		dir = "/"
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) {
		dir = "/"
	}
	// If the path doesn't exist yet (user still typing), browse its parent so the
	// box can still suggest siblings of the partial segment.
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return dir, nil, err
	}
	mounts := map[string]bool{}
	if ms, err := Mounts(); err == nil {
		for _, m := range ms {
			mounts[m.Target] = true
		}
	}
	const cap = 200
	var out []DirEntry
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue // hide dotdirs from the picker
		}
		p := filepath.Join(dir, e.Name())
		out = append(out, DirEntry{Name: e.Name(), Path: p, IsMount: mounts[p]})
		if len(out) >= cap {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return dir, out, nil
}
