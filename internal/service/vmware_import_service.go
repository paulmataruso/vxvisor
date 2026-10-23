package service

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/qemu"
	"vdxclone/internal/vmware"
)

// importTempPrefix is the leading marker on the transient per-disk download
// files ExportVM writes into the image dir. Anything with this prefix is a
// work-in-progress artifact that is safe to delete when no import owns it.
const importTempPrefix = ".vdximport-"

// Direct vCenter/ESXi import. The source VM is ONLY ever read: we connect, list
// inventory, and open a read-only export lease. No code path powers, snapshots,
// reconfigures, or deletes a source VM (enforced by a test in internal/vmware).
// Honest promise: the source is never modified; an import either completes or
// cleans up its own target artifacts. It is NOT "no-fail" — networks, space, or
// unsupported disks can fail it, always leaving the source intact.
//
// Experimental: validated against the govmomi simulator for connect+list; the
// export+convert pipeline needs a real vCenter/ESXi to exercise end-to-end.

// VMwareImportState is the live status of one import (JSON for the poller).
type VMwareImportState struct {
	ID         string `json:"id"`
	VMName     string `json:"vm"`
	Status     string `json:"status"` // connecting|exporting|converting|registering|done|failed
	Step       string `json:"step"`
	Pct        int    `json:"pct"`
	DoneBytes  int64  `json:"done_bytes"`
	TotalBytes int64  `json:"total_bytes"` // 0 = unknown (true for the compressed export stream)
	Nominal    int64  `json:"nominal"`     // sum of source disk capacities — an upper bound for context, NOT the download size
	Rate       int64  `json:"rate"`        // bytes/sec during export
	Image      string `json:"image,omitempty"`
	Err        string `json:"err,omitempty"`
	StartedAt  int64  `json:"started"`
	FinishedAt int64  `json:"finished,omitempty"`
	// HasLog is true once a durable per-import log file exists; the UI can then
	// offer a link to GET /api/vmware-import/{id}/log for the full detail. The log
	// outlives this in-memory tracker entry (which is pruned 10 min after finish).
	HasLog  bool     `json:"has_log,omitempty"`
	LogTail []string `json:"log_tail,omitempty"` // last lines, populated on failure
}

type vmwImportTracker struct {
	mu sync.Mutex
	m  map[string]*VMwareImportState
}

func newVmwImportTracker() *vmwImportTracker {
	return &vmwImportTracker{m: map[string]*VMwareImportState{}}
}

func (t *vmwImportTracker) set(id string, fn func(*VMwareImportState)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[id]
	if st == nil {
		st = &VMwareImportState{ID: id, StartedAt: time.Now().UnixMilli()}
		t.m[id] = st
	}
	fn(st)
}

func (t *vmwImportTracker) snapshot() []VMwareImportState {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute).UnixMilli()
	var out []VMwareImportState
	for id, st := range t.m {
		if st.FinishedAt != 0 && st.FinishedAt < cutoff {
			delete(t.m, id)
			continue
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt > out[j].StartedAt })
	return out
}

// importLogDir is where durable per-import logs live (one file per import). They
// outlive the in-memory tracker so a failed import left overnight can still be
// diagnosed — by the admin via the UI/API, or over SSH in the journal mirror.
func (s *Service) importLogDir() string { return filepath.Join(s.cfg.Paths.DataDir, "import-logs") }

// importLogger mirrors every line to (a) the systemd journal via log.Printf and
// (b) a durable file, and keeps the recent tail in memory for the UI.
type importLogger struct {
	id   string
	mu   sync.Mutex
	f    *os.File
	tail []string
}

func (s *Service) newImportLogger(id string) *importLogger {
	return newFileLogger(id, s.importLogDir(), "vmware-")
}

// newFileLogger opens a durable per-job log file <dir>/<prefix><id>.log, degrading
// to journal-only if the file can't be opened. Shared by import and export.
func newFileLogger(id, dir, prefix string) *importLogger {
	lg := &importLogger{id: id}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("%s%s: cannot create log dir %s: %v (journal-only)", prefix, id, dir, err)
		return lg
	}
	f, err := os.OpenFile(filepath.Join(dir, prefix+id+".log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		log.Printf("%s%s: cannot open log file: %v (journal-only)", prefix, id, err)
		return lg
	}
	lg.f = f
	return lg
}

// logf records one timestamped line to the journal, the durable file, and the
// in-memory tail. Safe for concurrent use (the export progress callback runs on
// its own goroutine).
func (lg *importLogger) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("vmware-import %s: %s", lg.id, msg)
	line := time.Now().Format("2006-01-02 15:04:05") + "  " + msg
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if lg.f != nil {
		fmt.Fprintln(lg.f, line)
	}
	lg.tail = append(lg.tail, line)
	if len(lg.tail) > 400 {
		lg.tail = lg.tail[len(lg.tail)-400:]
	}
}

func (lg *importLogger) tailLines(n int) []string {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if n > len(lg.tail) {
		n = len(lg.tail)
	}
	out := make([]string, n)
	copy(out, lg.tail[len(lg.tail)-n:])
	return out
}

func (lg *importLogger) close() {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if lg.f != nil {
		_ = lg.f.Close()
		lg.f = nil
	}
}

// VMwareImportLog returns the full durable log for one import (admin only).
func (s *Service) VMwareImportLog(p *Principal, id string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	// Guard against path traversal — ids are uuids, but be strict.
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return "", fmt.Errorf("invalid import id")
	}
	b, err := os.ReadFile(filepath.Join(s.importLogDir(), "vmware-"+id+".log"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no log for import %s (it may have been pruned)", id)
		}
		return "", err
	}
	return string(b), nil
}

// pruneImportLogs removes import log files older than 14 days. Called at boot
// alongside SweepImportTemps — cheap bookkeeping, never touches a live import.
func (s *Service) pruneImportLogs() {
	dir := s.importLogDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-14 * 24 * time.Hour)
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "vmware-") {
			continue
		}
		fi, serr := e.Info()
		if serr != nil || fi.ModTime().After(cutoff) {
			continue
		}
		if rerr := os.Remove(filepath.Join(dir, e.Name())); rerr == nil {
			log.Printf("vmware-import: pruned old log %s", e.Name())
		}
	}
}

// VMwareImportStates returns in-flight + recent imports (admin only).
func (s *Service) VMwareImportStates(p *Principal) []VMwareImportState {
	if !p.IsAdmin || s.vmwimp == nil {
		return nil
	}
	return s.vmwimp.snapshot()
}

// VMwareConnectList connects read-only and returns the inventory. The vCenter
// password is used in memory only and never audited.
func (s *Service) VMwareConnectList(p *Principal, c vmware.Creds, ip string) ([]vmware.VMInfo, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cli, err := vmware.Connect(ctx, c)
	if err != nil {
		return nil, err
	}
	defer cli.Close(ctx)
	vms, err := cli.ListVMs(ctx)
	if err != nil {
		return nil, err
	}
	s.audit(p, p.OrgID, "vmware.connect", "vmware", vcHost(c.URL), ip, map[string]any{"user": c.User, "vms": len(vms)})
	return vms, nil
}

// VMwareImport runs an import asynchronously and returns a tracking id. The
// imported instance's disk lands on targetPoolID (0 = default disk directory);
// the backend is derived from that pool's kind, so a VM can be imported onto any
// registered storage — dir(qcow2) / ZFS zvol / LVM thin / Ceph RBD.
func (s *Service) VMwareImport(p *Principal, c vmware.Creds, moid, osType, transport string, targetPoolID int64, ip string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	if strings.TrimSpace(moid) == "" {
		return "", fmt.Errorf("select a VM to import")
	}
	switch transport {
	case "", "nfc":
		transport = "nfc"
	case "datastore", "vddk":
		// ok
	default:
		return "", fmt.Errorf("unknown transfer method %q", transport)
	}
	// Validate the target pool up front so the user gets an immediate error
	// instead of a failure 40 minutes into the transfer.
	backend, zvolPool, err := s.ResolveDiskTarget(p, targetPoolID)
	if err != nil {
		return "", err
	}
	id := uuid.NewString()
	s.vmwimp.set(id, func(st *VMwareImportState) { st.Status = "connecting"; st.Step = "queued" })
	s.audit(p, p.OrgID, "vmware.import_start", "vmware", moid, ip, map[string]any{"host": vcHost(c.URL), "user": c.User, "pool_id": targetPoolID, "backend": backend, "transport": transport})
	go s.runVMwareImport(id, c, moid, osType, transport, backend, zvolPool, targetPoolID, importOverride{}, p, ip)
	return id, nil
}

// importOverride carries per-VM settings from the migration wizard that replace
// the source-derived defaults. Zero/empty fields mean "keep as source".
type importOverride struct {
	Name      string
	CPUs      int
	MemMB     int
	Firmware  string // "" | bios | uefi
	NetworkID int64  // target port group; 0 = default/NAT
}

// VDDKLibDir / SetVDDKLibDir read and write the operator-supplied path to the
// (proprietary, non-bundleable) VMware VDDK library tree used by the fastest
// import transport. Stored in the settings kv table.
const vddkLibDirKey = "vddk_libdir"

func (s *Service) VDDKLibDir() string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, vddkLibDirKey).Scan(&v)
	return v
}

func (s *Service) SetVDDKLibDir(p *Principal, dir, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	dir = strings.TrimSpace(dir)
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, vddkLibDirKey, dir)
	if err == nil {
		s.audit(p, p.OrgID, "vmware.vddk_libdir", "setting", vddkLibDirKey, ip, map[string]any{"dir": dir})
	}
	return err
}

// UploadVDDK takes the operator-supplied VMware VDDK archive (vmware-vix-disklib
// .tar.gz, proprietary and not bundleable), unpacks it into a managed directory
// under DataDir, locates the vix-disklib "distrib" tree (the dir holding
// lib64/libvixDiskLib.so*), and records it as the VDDK libdir — so the operator
// can enable the fastest import transport by uploading the tarball through the UI
// instead of unpacking it on the host by hand. Admin only. Returns the resolved
// libdir on success. The archive is trusted operator input but is still extracted
// into an isolated, freshly-emptied directory.
func (s *Service) UploadVDDK(p *Principal, src io.Reader, ip string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	base := filepath.Join(s.cfg.Paths.DataDir, "vddk")
	// Fresh each time: a re-upload fully replaces the previous tree.
	_ = os.RemoveAll(base)
	tree := filepath.Join(base, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		return "", err
	}
	tgz := filepath.Join(base, ".upload.tar.gz")
	f, err := os.Create(tgz)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		_ = os.RemoveAll(base)
		return "", fmt.Errorf("receive VDDK upload: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.RemoveAll(base)
		return "", err
	}
	defer os.Remove(tgz)
	// GNU tar auto-detects gzip/bzip2/xz on read, so -xf handles .tar.gz and .tar.
	cmd := exec.Command("tar", "-xf", tgz, "-C", tree)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(base)
		return "", fmt.Errorf("extract VDDK archive (expected a vmware-vix-disklib .tar.gz): %v: %s", err, strings.TrimSpace(string(out)))
	}
	dir, err := findVDDKDistrib(tree)
	if err != nil {
		_ = os.RemoveAll(base)
		return "", err
	}
	if err := s.SetVDDKLibDir(p, dir, ip); err != nil {
		return "", err
	}
	s.audit(p, p.OrgID, "vmware.vddk_upload", "setting", vddkLibDirKey, ip, map[string]any{"dir": dir})
	return dir, nil
}

// findVDDKDistrib walks an unpacked VDDK tree and returns the directory that
// contains lib64/libvixDiskLib.so* — that parent directory is what nbdkit's VDDK
// plugin wants as libdir=.
func findVDDKDistrib(root string) (string, error) {
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found != "" {
			return nil
		}
		if d.IsDir() && d.Name() == "lib64" {
			if m, _ := filepath.Glob(filepath.Join(path, "libvixDiskLib.so*")); len(m) > 0 {
				found = filepath.Dir(path)
				return filepath.SkipAll
			}
		}
		return nil
	})
	if found == "" {
		return "", fmt.Errorf("that archive does not look like a VMware VDDK distribution (no lib64/libvixDiskLib.so found) — download the vmware-vix-disklib .tar.gz matching your vSphere version")
	}
	return found, nil
}

// VDDKReady reports whether the VDDK "fastest" transport can be offered: nbdkit +
// plugin installed AND the operator has set a libdir.
func (s *Service) VDDKReady(p *Principal) bool {
	return p != nil && p.IsAdmin && vmware.VDDKAvailable() && strings.TrimSpace(s.VDDKLibDir()) != ""
}

// VDDKInstalled reports whether the nbdkit VDDK wrapper is present (regardless of
// whether a libdir is set) — for the Storage-page hint.
func (s *Service) VDDKInstalled(p *Principal) bool {
	return p != nil && p.IsAdmin && vmware.VDDKAvailable()
}

func (s *Service) runVMwareImport(id string, c vmware.Creds, moid, osType, transport, diskBackend, zvolPool string, targetPoolID int64, ov importOverride, p *Principal, ip string) {
	lg := s.newImportLogger(id)
	defer lg.close()
	hasLog := lg.f != nil
	s.vmwimp.set(id, func(st *VMwareImportState) { st.HasLog = hasLog })

	fail := func(step, msg string) {
		lg.logf("FAILED at %s: %s", step, msg)
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.Status = "failed"
			st.Step = step
			st.Err = msg
			st.FinishedAt = time.Now().UnixMilli()
			st.LogTail = lg.tailLines(30)
		})
		s.audit(p, p.OrgID, "vmware.import_failed", "vmware", moid, ip, map[string]any{"step": step, "error": msg})
	}
	lg.logf("import %s starting: moid=%s host=%s user=%s insecure=%v os_hint=%s",
		id, moid, vcHost(c.URL), c.User, c.Insecure, osType)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	lg.logf("connecting to vSphere (read-only)…")
	cli, err := vmware.Connect(ctx, c)
	if err != nil {
		fail("connect", err.Error())
		return
	}
	defer cli.Close(ctx)
	lg.logf("connected; inspecting source VM %s", moid)

	vm, err := cli.GetVM(ctx, moid)
	if err != nil {
		fail("inspect", err.Error())
		return
	}
	s.vmwimp.set(id, func(st *VMwareImportState) { st.VMName = vm.Name })
	lg.logf("source: name=%q power=%s firmware=%s guest=%q cpu=%d memMB=%d disks=%d snapshots=%v importable=%v",
		vm.Name, vm.PowerState, vm.Firmware, vm.GuestFullName, vm.NumCPU, vm.MemMB, len(vm.Disks), vm.HasSnapshots, vm.Importable)
	for i, d := range vm.Disks {
		lg.logf("  disk[%d]: %q %d GiB thin=%v backing=%s", i, d.Label, d.CapacityGB, d.Thin, d.Backing)
	}
	// SOURCE SAFETY: cold only. We never change the source's power — refuse if on.
	if vm.PowerState != "poweredOff" {
		fail("precheck", "source VM is "+vm.PowerState+" — power it OFF on vCenter first (VXVisor never changes the source)")
		return
	}
	if !vm.Importable {
		fail("precheck", vm.ImportNote)
		return
	}

	destDir := s.stg.ImageDir()
	if err := os.MkdirAll(destDir, 0o750); err != nil {
		fail("precheck", err.Error())
		return
	}
	// Free-space precheck: need the source-allocated size plus the converted copy.
	var need int64
	for _, d := range vm.Disks {
		need += d.CapacityGB * 1024 * 1024 * 1024
	}
	free := s.stg.FreeBytes(destDir)
	lg.logf("target image dir %s: free=%d GiB, need ~%d GiB (incl. transient copy)", destDir, free/(1<<30), need*2/(1<<30))
	if free > 0 && free < need*2 {
		fail("precheck", fmt.Sprintf("not enough free space in image storage (need ~%d GiB incl. transient, have %d GiB)", need*2/(1<<30), free/(1<<30)))
		return
	}

	transportLabel := map[string]string{
		"nfc":       "NFC export (compressed stream)",
		"datastore": "datastore direct download (fast, raw flat)",
		"vddk":      "VDDK over NBD (fastest, allocated blocks)",
	}[transport]
	lg.logf("exporting %q (%d disk(s), ~%d GiB) read-only via %s", vm.Name, len(vm.Disks), need/(1<<30), transportLabel)
	s.vmwimp.set(id, func(st *VMwareImportState) {
		st.Status = "exporting"
		st.Step = "downloading disks (read-only) — " + transportLabel
	})
	var lastLog time.Time
	progFn := func(ep vmware.ExportProgress) {
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.DoneBytes = ep.DoneBytes
			// A stream-optimized export is compressed: the true total is unknown
			// until it finishes, and the nominal capacity is NOT it. Report total
			// as unknown (0) so the UI shows "X downloaded @ rate" instead of a
			// fraction of a number we'll never reach. Nominal is kept for context.
			st.TotalBytes = 0
			st.Nominal = ep.NominalBytes
			st.Rate = ep.BytesPerSec
			st.Pct = 0
		})
		// Throttle periodic progress to one line every ~15s (per-disk start/finish
		// lines come from the transport itself).
		if time.Since(lastLog) >= 15*time.Second {
			lastLog = time.Now()
			lg.logf("export progress: %d MiB pulled @ %d MiB/s (source nominal %d MiB; total unknown until done)",
				ep.DoneBytes/(1<<20), ep.BytesPerSec/(1<<20), ep.NominalBytes/(1<<20))
		}
	}
	var vmdks []string
	switch transport {
	case "datastore":
		vmdks, err = cli.ExportVMDatastore(ctx, moid, destDir, lg.logf, progFn)
	case "vddk":
		vmdks, err = cli.ExportVMVDDK(ctx, moid, destDir, s.VDDKLibDir(), c.User, c.Pass, lg.logf, progFn)
	default:
		vmdks, err = cli.ExportVM(ctx, moid, destDir, lg.logf, progFn)
	}
	if err != nil {
		fail("export", err.Error())
		return
	}
	lg.logf("export complete, %d disk file(s)", len(vmdks))
	// Cleanup helper for the transient vmdks.
	defer func() {
		for _, f := range vmdks {
			_ = os.Remove(f)
		}
	}()

	s.vmwimp.set(id, func(st *VMwareImportState) {
		st.Status = "converting"
		st.Step = "qemu-img convert → qcow2"
		st.Pct = 0
	})
	base := sanitizeImageName(vm.Name)
	var firstImage string
	var registered []string
	for i, vmdk := range vmdks {
		if err := qemu.ProbeReadable(vmdk); err != nil {
			s.rollbackImages(registered)
			fail("convert", "source disk not readable by qemu-img: "+err.Error())
			return
		}
		name := base
		if len(vmdks) > 1 {
			name = fmt.Sprintf("%s-disk%d", base, i)
		}
		dst := filepath.Join(destDir, name+".qcow2")
		lg.logf("converting disk %d/%d (%s) → %s.qcow2 via qemu-img", i+1, len(vmdks), filepath.Base(vmdk), name)
		if err := qemu.ConvertToQcow2(vmdk, dst); err != nil {
			_ = os.Remove(dst)
			s.rollbackImages(registered)
			fail("convert", err.Error())
			return
		}
		lg.logf("registering base image %q", name)
		if err := s.stg.RegisterImage(name, dst, "vmware:"+vm.Name); err != nil {
			_ = os.Remove(dst)
			s.rollbackImages(registered)
			fail("register", err.Error())
			return
		}
		registered = append(registered, dst)
		if i == 0 {
			firstImage = name
		}
		s.vmwimp.set(id, func(st *VMwareImportState) { st.Pct = (i + 1) * 100 / len(vmdks) })
	}

	s.vmwimp.set(id, func(st *VMwareImportState) {
		st.Status = "registering"
		st.Step = "creating instance from imported disk"
		st.Image = firstImage
		st.Pct = 100
	})
	s.audit(p, p.OrgID, "vmware.import", "image", firstImage, ip, map[string]any{
		"vm": vm.Name, "disks": len(vmdks), "firmware": vm.Firmware, "guest": vm.GuestFullName, "os_type": osType,
	})

	// Auto-create a ready-to-run instance from the imported boot disk, mirroring
	// the source VM's shape (firmware/CPU/memory/disk-bus), so the user doesn't
	// have to build one by hand. This is the whole point of a direct import.
	//
	// Best-effort: the base image is already registered, so if instance creation
	// fails (quota, licensing, a host constraint) we still finish "done" with the
	// image and tell the user exactly why no instance was made and how to add one.
	firmware := "bios"
	if vm.Firmware == "efi" {
		firmware = "uefi"
	}
	cpus := int(vm.NumCPU)
	if cpus < 1 {
		cpus = 1
	}
	mem := int(vm.MemMB)
	if mem < 512 {
		mem = 1024
	}
	// Apply per-VM wizard overrides (empty/zero = keep source value).
	instName := vm.Name
	if n := strings.TrimSpace(ov.Name); n != "" {
		instName = n
	}
	if ov.CPUs > 0 {
		cpus = ov.CPUs
	}
	if ov.MemMB > 0 {
		mem = ov.MemMB
	}
	if ov.Firmware == "bios" || ov.Firmware == "uefi" {
		firmware = ov.Firmware
	}
	diskBus := "" // default (virtio-blk)
	busNote := ""
	if osType == "windows" {
		// Windows won't boot off virtio without drivers; SATA for first boot,
		// then the user installs virtio-win and can switch the bus.
		diskBus = "sata"
		busNote = " Disk bus set to SATA for first boot — install virtio-win drivers, then switch to virtio."
	}
	// Preserve the source VM's primary NIC MAC so the migrated guest keeps its
	// L2 identity (DHCP reservations, MAC-bound licenses). VXVisor models one NIC
	// per instance, so only the first adapter's MAC carries over; any additional
	// source NICs are noted below. Reusing the MAC is safe because the source is
	// powered off for this migration — leaving it running would duplicate the MAC.
	srcMAC := ""
	if len(vm.NICs) > 0 {
		srcMAC = strings.TrimSpace(vm.NICs[0].MAC)
	}
	if srcMAC != "" {
		lg.logf("preserving source MAC %s on the primary NIC", srcMAC)
	}
	if len(vm.NICs) > 1 {
		lg.logf("note: source has %d NICs; VXVisor instances have one NIC, so only the primary MAC (%s) is preserved — add extra NICs manually if needed", len(vm.NICs), srcMAC)
	}
	in := CreateInput{
		Name:     instName,
		Image:    firstImage,
		Kind:     "server",
		Firmware: firmware,
		CPUs:     cpus,
		MemoryMB: mem,
		DiskGB:   0, // inherit the image's virtual size (the source disk capacity)
		OSType:   osType,
		DiskBus:  diskBus,
		Display:  "vnc",
		MAC:       srcMAC,       // preserve the source primary-NIC MAC
		NetworkID: ov.NetworkID, // target port group (wizard); 0 = default/NAT
		// Place the instance's boot disk on the chosen storage pool (backend
		// derived from the pool kind). The base image stays a qcow2 template in
		// the image dir; CreateSession converts it onto the target backend.
		StoragePoolID: targetPoolID,
		DiskBackend:   diskBackend,
		ZvolPool:      zvolPool,
	}
	busLog := diskBus
	if busLog == "" {
		busLog = "virtio-blk (default)"
	}
	storeLog := diskBackend
	if targetPoolID <= 0 {
		storeLog = "qcow2 (default disk dir)"
	}
	lg.logf("creating instance %q from image %q (kind=server firmware=%s cpu=%d memMB=%d disk-bus=%s storage=%s net=default/NAT, stopped)",
		instName, firstImage, firmware, cpus, mem, busLog, storeLog)

	extra := ""
	if len(vmdks) > 1 {
		extra = fmt.Sprintf(" The other %d disk(s) were imported as base images (%s-disk1…) — attach them to the instance if needed.", len(vmdks)-1, base)
	}
	efiNote := ""
	if firmware == "uefi" {
		efiNote = " UEFI boot entries may need a one-time fixup on first boot."
	}

	sess, cerr := s.CreateSession(p, in, ip)
	if cerr != nil {
		lg.logf("instance creation FAILED: %v (the base image %q is registered and ready; create an instance from it manually)", cerr, firstImage)
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.Status = "done"
			st.Step = fmt.Sprintf("image %q ready, but auto-creating the instance failed: %v — create one from this image on the Instances page.", firstImage, cerr)
			st.FinishedAt = time.Now().UnixMilli()
			st.LogTail = lg.tailLines(30)
		})
		return
	}
	s.vmwimp.set(id, func(st *VMwareImportState) {
		st.Status = "done"
		st.Step = fmt.Sprintf("instance %q created (%d vCPU, %d MiB, %s) from image %q — stopped, ready to start.%s%s",
			instName, cpus, mem, firmware, firstImage, efiNote, busNote) + extra
		st.FinishedAt = time.Now().UnixMilli()
	})
	lg.logf("DONE → instance %q (id=%s) created from image %q (%d disk(s))", instName, sess.ID, firstImage, len(vmdks))
	s.audit(p, p.OrgID, "vmware.import_instance", "session", sess.ID, ip, map[string]any{
		"vm": vm.Name, "image": firstImage, "cpus": cpus, "memory_mb": mem, "firmware": firmware,
	})
}

// PlanItem is one row of a migration plan: a source VM plus the per-VM target
// settings chosen in the wizard. Order in the slice is the import order.
type PlanItem struct {
	MOID         string
	Name         string // target instance name ("" = keep source)
	OSType       string // linux | windows
	Transport    string // nfc | datastore | vddk ("" = nfc)
	TargetPoolID int64  // storage pool (0 = default disk dir)
	NetworkID    int64  // target port group (0 = default/NAT)
	CPUs         int    // 0 = keep source
	MemMB        int    // 0 = keep source
	Firmware     string // "" = keep source
}

// MigratePlan starts a batch import of several VMs in the given order. Each VM
// becomes its own entry in the import progress tracker (so the existing progress
// table shows them all). Imports run SEQUENTIALLY — the link/host is the
// bottleneck, so running them in parallel would only thrash the same pipe — and
// the batch CONTINUES past a failed VM rather than aborting the whole plan. Admin
// only. Returns a plan id (for audit/flash); progress is polled via the import
// states endpoint.
func (s *Service) MigratePlan(p *Principal, c vmware.Creds, items []PlanItem, ip string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	if len(items) == 0 {
		return "", fmt.Errorf("select at least one VM to migrate")
	}
	// Validate transports + target pools up front so the user gets an immediate
	// error instead of one surfacing mid-batch.
	for i := range items {
		if strings.TrimSpace(items[i].MOID) == "" {
			return "", fmt.Errorf("plan row %d has no VM selected", i+1)
		}
		switch items[i].Transport {
		case "", "nfc":
			items[i].Transport = "nfc"
		case "datastore", "vddk":
		default:
			return "", fmt.Errorf("plan row %d: unknown transfer method %q", i+1, items[i].Transport)
		}
		if _, _, err := s.ResolveDiskTarget(p, items[i].TargetPoolID); err != nil {
			return "", fmt.Errorf("plan row %d: %w", i+1, err)
		}
	}
	planID := uuid.NewString()
	s.audit(p, p.OrgID, "vmware.migrate_plan_start", "vmware", planID, ip, map[string]any{
		"host": vcHost(c.URL), "user": c.User, "count": len(items),
	})
	go s.runMigratePlan(planID, c, items, p, ip)
	return planID, nil
}

func (s *Service) runMigratePlan(planID string, c vmware.Creds, items []PlanItem, p *Principal, ip string) {
	log.Printf("vmware-migrate: plan %s started: %d VM(s), sequential", planID, len(items))
	for i, it := range items {
		backend, zvolPool, err := s.ResolveDiskTarget(p, it.TargetPoolID)
		id := uuid.NewString()
		display := it.Name
		if strings.TrimSpace(display) == "" {
			display = it.MOID
		}
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.VMName = display
			st.Status = "connecting"
			st.Step = fmt.Sprintf("queued — migration plan (%d/%d)", i+1, len(items))
		})
		if err != nil {
			// Pool vanished between validation and run — mark this one failed, go on.
			s.vmwimp.set(id, func(st *VMwareImportState) {
				st.Status = "failed"
				st.Step = "precheck"
				st.Err = err.Error()
				st.FinishedAt = time.Now().UnixMilli()
			})
			continue
		}
		ov := importOverride{Name: it.Name, CPUs: it.CPUs, MemMB: it.MemMB, Firmware: it.Firmware, NetworkID: it.NetworkID}
		// Synchronous: one VM at a time, in order. A failure is recorded in the
		// tracker by runVMwareImport itself and does not stop the plan.
		s.runVMwareImport(id, c, it.MOID, it.OSType, it.Transport, backend, zvolPool, it.TargetPoolID, ov, p, ip)
	}
	log.Printf("vmware-migrate: plan %s finished", planID)
}

// SweepImportTemps removes orphaned transient export files from the image dir.
// An import downloads each disk to a ".vdximport-*" temp file and only cleans it
// up when the goroutine finishes; if vdxd is restarted or crashes mid-export the
// goroutine dies and the partial file is leaked. No import survives a restart (the
// tracker is in-memory), so on startup any such file is dead weight — we log and
// remove it. Called once at boot, when no import can possibly own these files.
func (s *Service) SweepImportTemps() {
	s.pruneImportLogs()
	if s.stg == nil {
		return
	}
	dir := s.stg.ImageDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), importTempPrefix) {
			continue
		}
		full := filepath.Join(dir, e.Name())
		sz := int64(0)
		if fi, serr := e.Info(); serr == nil {
			sz = fi.Size()
		}
		if rerr := os.Remove(full); rerr != nil {
			log.Printf("vmware-import: could not remove orphaned export temp %s: %v", full, rerr)
		} else {
			log.Printf("vmware-import: removed orphaned export temp %s (%d MiB, from an interrupted import)", full, sz/(1<<20))
		}
	}
}

func (s *Service) rollbackImages(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

func sanitizeImageName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if r == ' ' || r == '_' || r == '.' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "import"
	}
	return "vmware-" + out
}

func vcHost(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	return s
}
