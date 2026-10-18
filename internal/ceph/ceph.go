// Package ceph stands up and manages a HYPERCONVERGED Ceph cluster ON the
// VXVisor nodes themselves (native Ubuntu packages, no containers) and drives
// the RBD images that back VM disks. Every operation shells out to the host
// ceph / rbd / ceph-volume / ceph-authtool tools. vdxd owns /etc/ceph/ceph.conf
// the way the routing subsystem owns frr.conf.
//
// The service layer is responsible for authz, for enforcing the dedicated
// storage NIC (the Ceph public/cluster network never rides the mgmt NIC), and
// for guarding any disk an OSD would wipe (deviceInUse). This package assumes it
// runs as root (the vdxd host daemon) and chowns Ceph's own state to the `ceph`
// service user that the packages create.
package ceph

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	ConfPath      = "/etc/ceph/ceph.conf"
	adminKeyring  = "/etc/ceph/ceph.client.admin.keyring"
	monKeyring    = "/etc/ceph/ceph.mon.keyring" // transient bootstrap keyring
	bootOSDKey    = "/var/lib/ceph/bootstrap-osd/ceph.keyring"
	monmapPath    = "/etc/ceph/monmap.initial"
	cephUser      = "ceph"
	ClientName    = "vdx" // the cephx identity QEMU uses for RBD
	ClientKeyring = "/etc/ceph/ceph.client.vdx.keyring"
)

func has(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

// Available reports whether the Ceph SERVER tooling is installed (not just the
// ceph-common client that ships mount.ceph / the rbd CLI).
func Available() bool {
	return has("ceph") && has("ceph-mon") && has("ceph-volume") && has("rbd") && has("ceph-authtool")
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

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// chownCeph hands a path (recursively) to the ceph service user so the
// unprivileged mon/mgr/osd daemons can read their own state.
func chownCeph(path string) error {
	if _, err := run(15*time.Second, "chown", "-R", cephUser+":"+cephUser, path); err != nil {
		return err
	}
	return nil
}

// Bootstrapped reports whether a cluster already exists and answers on this host.
func Bootstrapped() bool {
	if !exists(ConfPath) || !exists(adminKeyring) {
		return false
	}
	_, err := run(10*time.Second, "ceph", "-s")
	return err == nil
}

// BootstrapSpec parameterises a single-node native bootstrap. The caller resolves
// MonHost/PublicNetwork from the dedicated storage interface.
type BootstrapSpec struct {
	FSID          string // generated when empty
	MonHost       string // the mon's IP (the storage-NIC address)
	PublicNetwork string // storage subnet CIDR, e.g. 10.10.0.0/24
	Hostname      string // short hostname → ceph-mon@<hostname> / ceph-mgr@<hostname>
	PoolSize      int    // default replica size (1 on a single node)
}

// Bootstrap brings up the FIRST mon + mgr of a brand-new cluster from native
// packages. It is idempotent at the step level: a step whose artifact already
// exists is skipped, so a partial/retried bootstrap converges rather than erroring.
func Bootstrap(s BootstrapSpec) error {
	if s.Hostname == "" {
		h, _ := os.Hostname()
		s.Hostname = strings.Split(h, ".")[0]
	}
	if s.MonHost == "" || s.PublicNetwork == "" {
		return fmt.Errorf("bootstrap needs a mon host IP and public network (set the storage interface first)")
	}
	if s.PoolSize < 1 {
		s.PoolSize = 1
	}
	if s.FSID == "" {
		out, err := run(5*time.Second, "uuidgen")
		if err != nil {
			return fmt.Errorf("generate fsid: %w", err)
		}
		s.FSID = strings.TrimSpace(out)
	}

	// 1. ceph.conf — vdxd owns this file. On a single node we set the CRUSH
	// failure domain to OSD and min_size 1 so PGs can reach active+clean without
	// a second host.
	if !exists(ConfPath) {
		conf := fmt.Sprintf(`# Managed by VXVisor (vdxd). Do not edit by hand.
[global]
    fsid = %s
    mon initial members = %s
    mon host = %s
    public network = %s
    cluster network = %s
    auth cluster required = cephx
    auth service required = cephx
    auth client required = cephx
    osd pool default size = %d
    osd pool default min size = 1
    osd crush chooseleaf type = 0
    osd journal size = 1024
`, s.FSID, s.Hostname, s.MonHost, s.PublicNetwork, s.PublicNetwork, s.PoolSize)
		if err := os.WriteFile(ConfPath, []byte(conf), 0o644); err != nil {
			return fmt.Errorf("write ceph.conf: %w", err)
		}
	}

	// 2. Keyrings: mon., client.admin, bootstrap-osd — merged into the mon keyring.
	if !exists(monKeyring) {
		if _, err := run(10*time.Second, "ceph-authtool", "--create-keyring", monKeyring,
			"--gen-key", "-n", "mon.", "--cap", "mon", "allow *"); err != nil {
			return fmt.Errorf("mon keyring: %w", err)
		}
	}
	if !exists(adminKeyring) {
		if _, err := run(10*time.Second, "ceph-authtool", "--create-keyring", adminKeyring,
			"--gen-key", "-n", "client.admin",
			"--cap", "mon", "allow *", "--cap", "osd", "allow *",
			"--cap", "mds", "allow *", "--cap", "mgr", "allow *"); err != nil {
			return fmt.Errorf("admin keyring: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(bootOSDKey), 0o755); err != nil {
		return fmt.Errorf("bootstrap-osd dir: %w", err)
	}
	if !exists(bootOSDKey) {
		if _, err := run(10*time.Second, "ceph-authtool", "--create-keyring", bootOSDKey,
			"--gen-key", "-n", "client.bootstrap-osd",
			"--cap", "mon", "profile bootstrap-osd", "--cap", "mgr", "allow r"); err != nil {
			return fmt.Errorf("bootstrap-osd keyring: %w", err)
		}
	}
	// Import admin + bootstrap-osd into the mon keyring (idempotent).
	_, _ = run(10*time.Second, "ceph-authtool", monKeyring, "--import-keyring", adminKeyring)
	_, _ = run(10*time.Second, "ceph-authtool", monKeyring, "--import-keyring", bootOSDKey)
	_ = chownCeph(adminKeyring)
	_ = chownCeph(bootOSDKey)
	_ = chownCeph(monKeyring)

	// 3. monmap with this mon.
	if !exists(monmapPath) {
		if _, err := run(10*time.Second, "monmaptool", "--create",
			"--add", s.Hostname, s.MonHost, "--fsid", s.FSID, monmapPath); err != nil {
			return fmt.Errorf("monmap: %w", err)
		}
		_ = chownCeph(monmapPath)
	}

	// 4. mon data dir + mkfs (run as root, then hand the store to the ceph user so
	// the ceph-mon@ unit, which drops to ceph, can open it).
	monDir := "/var/lib/ceph/mon/ceph-" + s.Hostname
	if !exists(filepath.Join(monDir, "kv_backend")) {
		if err := os.MkdirAll(monDir, 0o755); err != nil {
			return fmt.Errorf("mon dir: %w", err)
		}
		_ = chownCeph(monDir)
		if _, err := run(30*time.Second, "ceph-mon", "--mkfs", "-i", s.Hostname,
			"--monmap", monmapPath, "--keyring", monKeyring); err != nil {
			return fmt.Errorf("ceph-mon --mkfs: %w", err)
		}
		if err := chownCeph(monDir); err != nil {
			return fmt.Errorf("chown mon dir: %w", err)
		}
	}

	// 5. Start the mon, enable msgr2.
	if _, err := run(30*time.Second, "systemctl", "enable", "--now", "ceph-mon@"+s.Hostname); err != nil {
		return fmt.Errorf("start ceph-mon: %w", err)
	}
	if err := waitForMon(45 * time.Second); err != nil {
		return err
	}
	_, _ = run(15*time.Second, "ceph", "mon", "enable-msgr2")

	// 6. mgr: its own cephx key under its data dir, then start.
	mgrDir := "/var/lib/ceph/mgr/ceph-" + s.Hostname
	if !exists(filepath.Join(mgrDir, "keyring")) {
		if err := os.MkdirAll(mgrDir, 0o755); err != nil {
			return fmt.Errorf("mgr dir: %w", err)
		}
		if _, err := run(15*time.Second, "ceph", "auth", "get-or-create", "mgr."+s.Hostname,
			"mon", "allow profile mgr", "osd", "allow *", "mds", "allow *",
			"-o", filepath.Join(mgrDir, "keyring")); err != nil {
			return fmt.Errorf("mgr key: %w", err)
		}
		_ = chownCeph(mgrDir)
	}
	if _, err := run(30*time.Second, "systemctl", "enable", "--now", "ceph-mgr@"+s.Hostname); err != nil {
		return fmt.Errorf("start ceph-mgr: %w", err)
	}
	return nil
}

func waitForMon(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, err := run(10*time.Second, "ceph", "-s"); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("mon did not reach quorum in time: %v", last)
}

// DiskIsOSD reports whether disk is already consumed as a Ceph OSD on this host.
// A resumed/retried bootstrap uses this to skip re-adding the OSD (and to skip
// the caller's in-use guard, which is meant for foreign disks) instead of
// failing on the now-consumed disk.
func DiskIsOSD(disk string) bool {
	if disk == "" {
		return false
	}
	// `ceph-volume lvm list <disk>` prints a "====== osd.N ======" block per OSD
	// backed by the device, and nothing (exit 0) when the disk is not an OSD.
	out, err := run(30*time.Second, "ceph-volume", "lvm", "list", disk)
	if err != nil {
		return false
	}
	return strings.Contains(out, "====== osd")
}

// AddOSD consumes a whole disk as a BlueStore OSD. DESTRUCTIVE — the caller must
// have already verified the disk is not in use (service.deviceInUse). It is
// idempotent: a disk that is already an OSD on this host is left untouched so a
// retried bootstrap converges rather than erroring on the consumed disk.
func AddOSD(disk string) error {
	if disk == "" {
		return fmt.Errorf("no disk specified")
	}
	if DiskIsOSD(disk) {
		return nil
	}
	// ceph-volume reads the bootstrap-osd keyring to self-register the OSD.
	if _, err := run(5*time.Minute, "ceph-volume", "lvm", "create", "--data", disk); err != nil {
		return fmt.Errorf("create OSD on %s: %w", disk, err)
	}
	return nil
}

// CreatePool creates an RBD pool, initialises it for rbd, and pins its replica
// size (1 on a single node — non-redundant until a second node joins).
func CreatePool(name string, size int) error {
	if name == "" {
		return fmt.Errorf("pool name required")
	}
	if size < 1 {
		size = 1
	}
	// pg_num 32 is a sane small-cluster default; the mgr pg autoscaler tunes it.
	if _, err := run(60*time.Second, "ceph", "osd", "pool", "create", name, "32"); err != nil {
		// "already exists" is fine (idempotent).
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	if _, err := run(30*time.Second, "rbd", "pool", "init", name); err != nil {
		return err
	}
	// A replica size of 1 (single-node, intentionally non-redundant) is refused by
	// default in modern Ceph — it must be explicitly allowed and confirmed.
	sizeArgs := []string{"osd", "pool", "set", name, "size", fmt.Sprint(size)}
	if size == 1 {
		if _, err := run(15*time.Second, "ceph", "config", "set", "global", "mon_allow_pool_size_one", "true"); err != nil {
			return err
		}
		sizeArgs = append(sizeArgs, "--yes-i-really-mean-it")
	}
	if _, err := run(30*time.Second, "ceph", sizeArgs...); err != nil {
		return err
	}
	if _, err := run(30*time.Second, "ceph", "osd", "pool", "set", name, "min_size", "1"); err != nil {
		return err
	}
	return nil
}

// EnsureClientKeyring creates (idempotently) the `client.vdx` cephx identity that
// QEMU uses for RBD, scoped to the given pool, and writes a keyring file readable
// by the QEMU run-as user. Returns the keyring path. The key is never placed on a
// command line — QEMU references the keyring file via :id=vdx:keyring=...
func EnsureClientKeyring(pool string) (string, error) {
	caps := []string{
		"mon", "profile rbd",
		"osd", "profile rbd pool=" + pool,
	}
	args := append([]string{"auth", "get-or-create", "client." + ClientName}, caps...)
	args = append(args, "-o", ClientKeyring)
	// get-or-create is idempotent; retry briefly because the mon/mgr can be
	// momentarily busy right after a fresh pool is created and initialised.
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}
		if _, err = run(15*time.Second, "ceph", args...); err == nil {
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("client.%s keyring: %w", ClientName, err)
	}
	// World-readable: it only grants pool-scoped RBD access, and the QEMU run-as
	// user (non-root) must open it. Ownership stays root; mode 0644.
	_ = os.Chmod(ClientKeyring, 0o644)
	return ClientKeyring, nil
}

// ---- RBD image lifecycle (VM disks) --------------------------------------

// RBDPath is the QEMU/qemu-img URI for an image, authenticated as client.vdx via
// the keyring file (no secret on the command line).
func RBDPath(pool, image string) string {
	return fmt.Sprintf("rbd:%s/%s:id=%s:keyring=%s:conf=%s", pool, image, ClientName, ClientKeyring, ConfPath)
}

// ParseRBD splits an "rbd:pool/image[:opts]" disk path back into pool + image.
func ParseRBD(diskPath string) (pool, image string, ok bool) {
	if !strings.HasPrefix(diskPath, "rbd:") {
		return "", "", false
	}
	body := strings.TrimPrefix(diskPath, "rbd:")
	if i := strings.IndexByte(body, ':'); i >= 0 { // strip :id=...:keyring=...
		body = body[:i]
	}
	parts := strings.SplitN(body, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// CreateImage provisions a blank RBD image of the given size (bytes).
func CreateImage(pool, image string, bytes int64) error {
	mb := bytes >> 20
	if mb < 1 {
		mb = 1
	}
	_, err := run(60*time.Second, "rbd", "create", "--size", fmt.Sprintf("%dM", mb), pool+"/"+image)
	return err
}

// ImportImage writes a source disk image (a cloud base image) onto a NEW RBD
// image, expanding it to raw. qemu-img speaks the rbd: transport directly.
func ImportImage(pool, image, srcPath string) error {
	dst := RBDPath(pool, image)
	if _, err := run(30*time.Minute, "qemu-img", "convert", "-p", "-O", "raw", srcPath, dst); err != nil {
		return fmt.Errorf("import to rbd %s/%s: %w", pool, image, err)
	}
	return nil
}

// RemoveImage deletes an RBD image (best-effort; used on VM purge).
func RemoveImage(pool, image string) error {
	_, err := run(60*time.Second, "rbd", "rm", pool+"/"+image)
	return err
}

// ResizeImage grows an RBD image to the given size (bytes). Ceph refuses to
// shrink without --allow-shrink, which we never pass.
func ResizeImage(pool, image string, bytes int64) error {
	mb := bytes >> 20
	if mb < 1 {
		mb = 1
	}
	_, err := run(60*time.Second, "rbd", "resize", "--size", fmt.Sprintf("%dM", mb), pool+"/"+image)
	return err
}

// ---- status --------------------------------------------------------------

// Health is a compact snapshot of cluster state for the UI.
type Health struct {
	Available  bool   `json:"available"`
	Configured bool   `json:"configured"`
	Status     string `json:"status"` // HEALTH_OK | HEALTH_WARN | HEALTH_ERR
	NumMons    int    `json:"num_mons"`
	NumOSDs    int    `json:"num_osds"`
	OSDsUp     int    `json:"osds_up"`
	OSDsIn     int    `json:"osds_in"`
	TotalBytes int64  `json:"total_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	AvailBytes int64  `json:"avail_bytes"`
	Summary    string `json:"summary"` // first health check message, if any
}

// Status parses `ceph -s -f json` into a Health. Returns Configured=false when no
// cluster is bootstrapped.
func Status() Health {
	h := Health{Available: Available()}
	if !Bootstrapped() {
		return h
	}
	h.Configured = true
	out, err := run(15*time.Second, "ceph", "-s", "-f", "json")
	if err != nil {
		h.Status = "unknown"
		h.Summary = err.Error()
		return h
	}
	var s struct {
		Health struct {
			Status string `json:"status"`
			Checks map[string]struct {
				Summary struct {
					Message string `json:"message"`
				} `json:"summary"`
			} `json:"checks"`
		} `json:"health"`
		MonMap struct {
			NumMons int `json:"num_mons"`
		} `json:"monmap"`
		OSDMap struct {
			NumOSDs   int `json:"num_osds"`
			NumUpOSDs int `json:"num_up_osds"`
			NumInOSDs int `json:"num_in_osds"`
		} `json:"osdmap"`
		PGMap struct {
			BytesTotal int64 `json:"bytes_total"`
			BytesUsed  int64 `json:"bytes_used"`
			BytesAvail int64 `json:"bytes_avail"`
		} `json:"pgmap"`
	}
	if json.Unmarshal([]byte(out), &s) == nil {
		h.Status = s.Health.Status
		h.NumMons = s.MonMap.NumMons
		h.NumOSDs = s.OSDMap.NumOSDs
		h.OSDsUp = s.OSDMap.NumUpOSDs
		h.OSDsIn = s.OSDMap.NumInOSDs
		h.TotalBytes = s.PGMap.BytesTotal
		h.UsedBytes = s.PGMap.BytesUsed
		h.AvailBytes = s.PGMap.BytesAvail
		for _, c := range s.Health.Checks {
			if c.Summary.Message != "" {
				h.Summary = c.Summary.Message
				break
			}
		}
	}
	return h
}

// PoolUsage returns used/total bytes for one RBD pool (for the storage-pool
// usage overlay). Zero values when unavailable.
func PoolUsage(pool string) (used, total int64) {
	out, err := run(15*time.Second, "ceph", "df", "-f", "json")
	if err != nil {
		return 0, 0
	}
	var df struct {
		Pools []struct {
			Name  string `json:"name"`
			Stats struct {
				BytesUsed int64 `json:"bytes_used"`
				MaxAvail  int64 `json:"max_avail"`
			} `json:"stats"`
		} `json:"pools"`
	}
	if json.Unmarshal([]byte(out), &df) != nil {
		return 0, 0
	}
	for _, p := range df.Pools {
		if p.Name == pool {
			return p.Stats.BytesUsed, p.Stats.BytesUsed + p.Stats.MaxAvail
		}
	}
	return 0, 0
}
