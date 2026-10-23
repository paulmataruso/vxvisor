package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/qemu"
	"vdxclone/internal/vmexport"
)

// VM export: produce a portable copy of a VXVisor VM. Three targets —
//   - download-image : a single disk image (qcow2 | raw | vmdk) to download
//   - download-ova   : an OVA (OVF + stream-optimized VMDK) to download
//   - push           : upload the VM straight into a target vCenter/ESXi
//
// The VM must be STOPPED (for a consistent image). Export only ever READS the
// VXVisor VM's disk; it never modifies the source instance. The push target is a
// DIFFERENT VMware environment — all vCenter-write code lives in internal/vmexport
// (a separate package), keeping internal/vmware strictly read-only.

// VMExportState is the live status of one export (JSON for the poller).
type VMExportState struct {
	ID         string `json:"id"`
	VMName     string `json:"vm"`
	Target     string `json:"target"` // download-image | download-ova | push
	Format     string `json:"format"` // qcow2 | raw | vmdk (download-image)
	Status     string `json:"status"` // preparing|converting|packing|uploading|done|failed
	Step       string `json:"step"`
	DoneBytes  int64  `json:"done_bytes"`
	TotalBytes int64  `json:"total_bytes"`
	Rate       int64  `json:"rate"`
	File       string `json:"file,omitempty"` // download filename once ready (download-* targets)
	Err        string `json:"err,omitempty"`
	StartedAt  int64  `json:"started"`
	FinishedAt int64  `json:"finished,omitempty"`
	HasLog     bool   `json:"has_log,omitempty"`
	LogTail    []string `json:"log_tail,omitempty"`

	filePath string // full path to the produced download file (not serialized)
}

type vmExportTracker struct {
	mu sync.Mutex
	m  map[string]*VMExportState
}

func newVMExportTracker() *vmExportTracker { return &vmExportTracker{m: map[string]*VMExportState{}} }

func (t *vmExportTracker) set(id string, fn func(*VMExportState)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[id]
	if st == nil {
		st = &VMExportState{ID: id, StartedAt: time.Now().UnixMilli()}
		t.m[id] = st
	}
	fn(st)
}

func (t *vmExportTracker) remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, id)
}

func (t *vmExportTracker) get(id string) (VMExportState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.m[id]
	if !ok {
		return VMExportState{}, false
	}
	return *st, true
}

func (t *vmExportTracker) snapshot() []VMExportState {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-30 * time.Minute).UnixMilli()
	out := make([]VMExportState, 0, len(t.m))
	for id, st := range t.m {
		if st.FinishedAt != 0 && st.FinishedAt < cutoff && st.Target == "push" {
			delete(t.m, id) // push leaves no downloadable file, so prune aggressively
			continue
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt > out[j].StartedAt })
	return out
}

func (s *Service) exportDir() string    { return filepath.Join(s.cfg.Paths.DataDir, "exports") }
func (s *Service) exportLogDir() string  { return filepath.Join(s.cfg.Paths.DataDir, "export-logs") }
func (s *Service) newExportLogger(id string) *importLogger {
	return newFileLogger(id, s.exportLogDir(), "export-")
}

// reloadExports repopulates the in-memory tracker from files already present in
// exportDir, so exports produced before a daemon restart stay visible (and thus
// downloadable/deletable) in the UI instead of silently orphaning on disk.
func (s *Service) reloadExports() {
	if s.vmwexp == nil {
		return
	}
	ents, err := os.ReadDir(s.exportDir())
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		name := e.Name()
		full := filepath.Join(s.exportDir(), name)
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
		sum := sha256.Sum256([]byte(name))
		id := "disk-" + hex.EncodeToString(sum[:8]) // stable, path-safe id from the filename
		target, format := "download-image", ext
		if ext == "ova" {
			target, format = "download-ova", "vmdk"
		}
		mtime := fi.ModTime().UnixMilli()
		sz := fi.Size()
		s.vmwexp.set(id, func(st *VMExportState) {
			st.Status = "done"
			st.Target = target
			st.Format = format
			st.File = name
			st.filePath = full
			st.DoneBytes = sz
			st.TotalBytes = sz
			st.Step = "ready to download"
			st.VMName = strings.TrimSuffix(name, filepath.Ext(name))
			st.StartedAt = mtime
			st.FinishedAt = mtime
		})
	}
}

// ExportStates returns live/recent export progress for the poller.
func (s *Service) ExportStates(p *Principal) []VMExportState {
	if s.vmwexp == nil {
		return nil
	}
	return s.vmwexp.snapshot()
}

// VMExportLog returns the durable per-export log.
func (s *Service) VMExportLog(p *Principal, id string) (string, error) {
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return "", fmt.Errorf("invalid export id")
	}
	b, err := os.ReadFile(filepath.Join(s.exportLogDir(), "export-"+id+".log"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no log for export %s (it may have been pruned)", id)
		}
		return "", err
	}
	return string(b), nil
}

// ExportDownload returns the full path + suggested filename of a finished
// download-* export, for the streaming download handler. Errors if the export is
// unknown, not finished, failed, or was a push (nothing to download).
func (s *Service) ExportDownload(p *Principal, id string) (path, filename string, err error) {
	st, ok := s.vmwexp.get(id)
	if !ok {
		return "", "", fmt.Errorf("unknown export %s", id)
	}
	if st.Status != "done" || st.filePath == "" {
		return "", "", fmt.Errorf("export %s is not ready to download", id)
	}
	if _, serr := os.Stat(st.filePath); serr != nil {
		return "", "", fmt.Errorf("exported file is gone — re-run the export")
	}
	return st.filePath, st.File, nil
}

// DeleteExport removes a finished download export's file from disk (and its log)
// and drops the tracker entry, so exported images don't linger after download.
// Only download-* exports have a file; a running export can't be deleted. Any
// member who can reach the export page may delete one (the file is a transient
// artifact, not an org-scoped resource).
func (s *Service) DeleteExport(p *Principal, id, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if s.vmwexp == nil {
		return fmt.Errorf("unknown export %s", id)
	}
	st, ok := s.vmwexp.get(id)
	if !ok {
		return fmt.Errorf("unknown export %s", id)
	}
	if st.Status != "done" && st.Status != "failed" {
		return fmt.Errorf("export %s is still running — wait for it to finish before deleting", id)
	}
	if st.filePath != "" {
		if err := os.Remove(st.filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove exported file: %w", err)
		}
	}
	// Best-effort: drop the durable log too (guard the id like VMExportLog does).
	if id != "" && !strings.ContainsAny(id, "/\\.") {
		_ = os.Remove(filepath.Join(s.exportLogDir(), "export-"+id+".log"))
	}
	s.vmwexp.remove(id)
	s.audit(p, p.OrgID, "export.delete", "export", id, ip, map[string]any{"vm": st.VMName, "file": st.File})
	return nil
}

// ExportVM validates and starts an async export of a stopped VXVisor VM. Returns
// the export id for progress polling. download-* targets require only VM access;
// push (writing into an external vCenter) requires admin.
func (s *Service) ExportVM(p *Principal, sessionID, target, format string, push vmexport.Target, ip string) (string, error) {
	sess, err := s.GetSession(p, sessionID) // enforces the caller can see this VM
	if err != nil {
		return "", err
	}
	switch target {
	case "download-image":
		switch format {
		case "qcow2", "raw", "vmdk":
		default:
			return "", fmt.Errorf("unknown image format %q (use qcow2, raw, or vmdk)", format)
		}
	case "download-ova":
		format = "vmdk"
	case "push":
		if !p.IsAdmin {
			return "", ErrUnauthorized
		}
		if strings.TrimSpace(push.URL) == "" {
			return "", fmt.Errorf("a target vCenter/ESXi URL is required to push")
		}
		format = "vmdk"
	default:
		return "", fmt.Errorf("unknown export target %q", target)
	}
	// Consistency + source safety: only export a stopped VM.
	if s.mgr.Running(sess) {
		return "", fmt.Errorf("stop the VM before exporting — a running VM's disk is not crash-consistent")
	}
	if strings.TrimSpace(sess.DiskPath) == "" {
		return "", fmt.Errorf("this VM has no disk to export")
	}
	id := uuid.NewString()
	s.vmwexp.set(id, func(st *VMExportState) {
		st.VMName = sess.Name
		st.Target = target
		st.Format = format
		st.Status = "preparing"
		st.Step = "queued"
	})
	s.audit(p, p.OrgID, "vm.export_start", "session", sess.ID, ip, map[string]any{
		"target": target, "format": format, "push_host": vcHost(push.URL),
	})
	go s.runExport(id, sess.ID, sess.Name, sess.DiskPath, sess.DiskBackend, sess.Firmware, sess.OSType, sess.CPUs, sess.MemoryMB, target, format, push, p, ip)
	return id, nil
}

func (s *Service) runExport(id, sessID, vmName, diskPath, backend, firmware, osType string, cpus, memMB int, target, format string, push vmexport.Target, p *Principal, ip string) {
	lg := s.newExportLogger(id)
	defer lg.close()
	hasLog := lg.f != nil
	s.vmwexp.set(id, func(st *VMExportState) { st.HasLog = hasLog })

	fail := func(step, msg string) {
		lg.logf("FAILED at %s: %s", step, msg)
		s.vmwexp.set(id, func(st *VMExportState) {
			st.Status = "failed"
			st.Step = step
			st.Err = msg
			st.FinishedAt = time.Now().UnixMilli()
			st.LogTail = lg.tailLines(30)
		})
		s.audit(p, p.OrgID, "vm.export_failed", "session", sessID, ip, map[string]any{"step": step, "error": msg})
	}
	lg.logf("export %s starting: vm=%q target=%s format=%s backend=%s src=%s", id, vmName, target, format, backend, diskPath)

	dir := s.exportDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fail("prepare", err.Error())
		return
	}
	// Virtual size drives both the progress bar and the OVF capacity.
	vsize, err := qemu.VirtualSizeBytes(diskPath)
	if err != nil {
		lg.logf("could not read source virtual size (%v) — progress will be approximate", err)
	}
	// Free-space guard: a conversion needs room for the output (≈ allocated size,
	// ≤ virtual size), and OVA briefly needs the vmdk + the ova.
	if vsize > 0 {
		free := s.stg.FreeBytes(dir)
		needMul := int64(1)
		if target == "download-ova" {
			needMul = 2
		}
		if free > 0 && free < vsize*needMul {
			fail("prepare", fmt.Sprintf("not enough free space for export (need up to ~%d GiB, have %d GiB) — free space or use a smaller target", vsize*needMul/(1<<30), free/(1<<30)))
			return
		}
	}

	base := vmexport.SanitizeName(vmName)

	switch target {
	case "download-image":
		ext := map[string]string{"qcow2": "qcow2", "raw": "img", "vmdk": "vmdk"}[format]
		dst := filepath.Join(dir, base+"."+ext)
		_ = os.Remove(dst)
		s.vmwexp.set(id, func(st *VMExportState) { st.Status = "converting"; st.Step = "qemu-img convert → " + format })
		lg.logf("converting %s → %s", diskPath, filepath.Base(dst))
		if err := s.convertTracked(id, diskPath, dst, format, vsize); err != nil {
			_ = os.Remove(dst)
			fail("convert", err.Error())
			return
		}
		s.finishDownload(id, dst, lg)

	case "download-ova":
		vmdk := filepath.Join(dir, "."+base+"-disk1.vmdk")
		_ = os.Remove(vmdk)
		defer os.Remove(vmdk)
		s.vmwexp.set(id, func(st *VMExportState) { st.Status = "converting"; st.Step = "qemu-img convert → stream-optimized VMDK" })
		lg.logf("converting %s → stream-optimized VMDK", diskPath)
		if err := s.convertTracked(id, diskPath, vmdk, "vmdk", vsize); err != nil {
			fail("convert", err.Error())
			return
		}
		s.vmwexp.set(id, func(st *VMExportState) { st.Status = "packing"; st.Step = "building OVA (OVF + manifest + disk)" })
		hw := exportHardware(vmName, base, firmware, osType, cpus, memMB, vsize, vmdk, push.Network)
		out := filepath.Join(dir, base+".ova")
		_ = os.Remove(out)
		if err := vmexport.WriteOVA(hw, vmdk, out, lg.logf); err != nil {
			_ = os.Remove(out)
			fail("pack", err.Error())
			return
		}
		s.finishDownload(id, out, lg)

	case "push":
		vmdk := filepath.Join(dir, "."+base+"-push.vmdk")
		_ = os.Remove(vmdk)
		defer os.Remove(vmdk)
		s.vmwexp.set(id, func(st *VMExportState) { st.Status = "converting"; st.Step = "qemu-img convert → stream-optimized VMDK" })
		lg.logf("converting %s → stream-optimized VMDK for push", diskPath)
		if err := s.convertTracked(id, diskPath, vmdk, "vmdk", vsize); err != nil {
			fail("convert", err.Error())
			return
		}
		hw := exportHardware(vmName, base, firmware, osType, cpus, memMB, vsize, vmdk, push.Network)
		s.vmwexp.set(id, func(st *VMExportState) { st.Status = "uploading"; st.Step = "pushing to " + vcHost(push.URL) })
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		progFn := func(pr vmexport.Progress) {
			s.vmwexp.set(id, func(st *VMExportState) {
				st.DoneBytes = pr.DoneBytes
				st.TotalBytes = pr.TotalBytes
				st.Rate = pr.BytesPerSec
			})
		}
		if err := vmexport.Push(ctx, push, hw, vmdk, lg.logf, progFn); err != nil {
			fail("push", err.Error())
			return
		}
		s.vmwexp.set(id, func(st *VMExportState) {
			st.Status = "done"
			st.Step = "pushed to " + vcHost(push.URL)
			st.FinishedAt = time.Now().UnixMilli()
		})
		lg.logf("DONE → pushed %q to %s", vmName, vcHost(push.URL))
	}
	s.audit(p, p.OrgID, "vm.export", "session", sessID, ip, map[string]any{"target": target, "format": format})
}

// finishDownload marks a download-* export complete and records the file to serve.
func (s *Service) finishDownload(id, path string, lg *importLogger) {
	name := filepath.Base(path)
	size := allocatedSize(path)
	s.vmwexp.set(id, func(st *VMExportState) {
		st.Status = "done"
		st.Step = "ready to download"
		st.File = name
		st.filePath = path
		st.DoneBytes = size
		st.TotalBytes = size
		st.FinishedAt = time.Now().UnixMilli()
	})
	lg.logf("DONE → %s ready to download (%d MiB)", name, size/(1<<20))
}

// convertTracked runs qemu-img convert in the background and polls the growing
// output for a live progress bar/rate. total is the source virtual size.
func (s *Service) convertTracked(id, src, dst, format string, total int64) error {
	errCh := make(chan error, 1)
	go func() { errCh <- qemu.ConvertImage(src, dst, format) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	// Cumulative-average rate (see internal/vmware: a per-tick delta samples 0 on
	// bursty writes and the UI rate flickers to "—"); the average is stable.
	startT := time.Now()
	for {
		select {
		case err := <-errCh:
			return err
		case now := <-tick.C:
			cur := allocatedSize(dst)
			var bps int64
			if el := now.Sub(startT).Seconds(); el > 0 {
				bps = int64(float64(cur) / el)
			}
			s.vmwexp.set(id, func(st *VMExportState) {
				st.DoneBytes = cur
				st.TotalBytes = total
				st.Rate = bps
			})
		}
	}
}

// exportHardware builds the OVF hardware description from the source VM facts.
func exportHardware(name, base, firmware, osType string, cpus, memMB int, vsize int64, vmdkPath, network string) vmexport.Hardware {
	capBytes := vsize
	if capBytes <= 0 {
		capBytes = allocatedSize(vmdkPath) // last-resort estimate
	}
	fw := "bios"
	if firmware == "uefi" || firmware == "efi" {
		fw = "uefi"
	}
	if cpus < 1 {
		cpus = 1
	}
	if memMB < 256 {
		memMB = 1024
	}
	return vmexport.Hardware{
		Name:              name,
		CPUs:              cpus,
		MemMB:             memMB,
		Firmware:          fw,
		OSType:            osType,
		DiskHref:          base + "-disk1.vmdk",
		DiskCapacityBytes: capBytes,
		NetworkName:       network,
	}
}

// allocatedSize returns bytes actually allocated on disk (st_blocks×512), the
// right measure while a sparse/pre-sized qemu-img output is being written. Falls
// back to apparent size, or 0 if the file is absent.
func allocatedSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}
