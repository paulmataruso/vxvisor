package service

import (
	"context"
	"fmt"
	"log"
	"os"
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
	lg := &importLogger{id: id}
	dir := s.importLogDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		log.Printf("vmware-import %s: cannot create log dir %s: %v (journal-only)", id, dir, err)
		return lg
	}
	f, err := os.OpenFile(filepath.Join(dir, "vmware-"+id+".log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		log.Printf("vmware-import %s: cannot open log file: %v (journal-only)", id, err)
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

// VMwareImport runs an import asynchronously and returns a tracking id.
func (s *Service) VMwareImport(p *Principal, c vmware.Creds, moid, osType string, ip string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	if strings.TrimSpace(moid) == "" {
		return "", fmt.Errorf("select a VM to import")
	}
	id := uuid.NewString()
	s.vmwimp.set(id, func(st *VMwareImportState) { st.Status = "connecting"; st.Step = "queued" })
	s.audit(p, p.OrgID, "vmware.import_start", "vmware", moid, ip, map[string]any{"host": vcHost(c.URL), "user": c.User})
	go s.runVMwareImport(id, c, moid, osType, p, ip)
	return id, nil
}

func (s *Service) runVMwareImport(id string, c vmware.Creds, moid, osType string, p *Principal, ip string) {
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

	lg.logf("exporting %q (%d disk(s), ~%d GiB) read-only", vm.Name, len(vm.Disks), need/(1<<30))
	s.vmwimp.set(id, func(st *VMwareImportState) { st.Status = "exporting"; st.Step = "downloading disks (read-only)" })
	var lastLog time.Time
	vmdks, err := cli.ExportVM(ctx, moid, destDir, lg.logf, func(ep vmware.ExportProgress) {
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
		// lines come from ExportVM itself).
		if time.Since(lastLog) >= 15*time.Second {
			lastLog = time.Now()
			lg.logf("export progress: %d MiB pulled @ %d MiB/s (source nominal %d MiB; compressed, total unknown until done)",
				ep.DoneBytes/(1<<20), ep.BytesPerSec/(1<<20), ep.NominalBytes/(1<<20))
		}
	})
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

	note := ""
	if vm.Firmware == "efi" {
		note = " (UEFI — launch with UEFI firmware; boot entries may need a one-time fixup)"
	}
	if osType == "windows" {
		note += " — Windows: launch with a SATA disk bus for first boot, then install virtio drivers"
	}
	s.vmwimp.set(id, func(st *VMwareImportState) {
		st.Status = "done"
		st.Step = "registered image " + firstImage + note
		st.Image = firstImage
		st.Pct = 100
		st.FinishedAt = time.Now().UnixMilli()
	})
	lg.logf("DONE → image %q (%d disk(s))", firstImage, len(vmdks))
	s.audit(p, p.OrgID, "vmware.import", "image", firstImage, ip, map[string]any{
		"vm": vm.Name, "disks": len(vmdks), "firmware": vm.Firmware, "guest": vm.GuestFullName, "os_type": osType,
	})
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
