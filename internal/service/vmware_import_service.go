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
	TotalBytes int64  `json:"total_bytes"`
	Rate       int64  `json:"rate"` // bytes/sec during export
	Image      string `json:"image,omitempty"`
	Err        string `json:"err,omitempty"`
	StartedAt  int64  `json:"started"`
	FinishedAt int64  `json:"finished,omitempty"`
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
	fail := func(step, msg string) {
		log.Printf("vmware-import %s: FAILED at %s: %s", id, step, msg)
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.Status = "failed"
			st.Step = step
			st.Err = msg
			st.FinishedAt = time.Now().UnixMilli()
		})
		s.audit(p, p.OrgID, "vmware.import_failed", "vmware", moid, ip, map[string]any{"step": step, "error": msg})
	}
	log.Printf("vmware-import %s: start moid=%s host=%s os=%s", id, moid, vcHost(c.URL), osType)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()

	cli, err := vmware.Connect(ctx, c)
	if err != nil {
		fail("connect", err.Error())
		return
	}
	defer cli.Close(ctx)

	vm, err := cli.GetVM(ctx, moid)
	if err != nil {
		fail("inspect", err.Error())
		return
	}
	s.vmwimp.set(id, func(st *VMwareImportState) { st.VMName = vm.Name })
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
	if free := s.stg.FreeBytes(destDir); free > 0 && free < need*2 {
		fail("precheck", fmt.Sprintf("not enough free space in image storage (need ~%d GiB incl. transient, have %d GiB)", need*2/(1<<30), free/(1<<30)))
		return
	}

	log.Printf("vmware-import %s: exporting %q (%d disk(s), ~%d GiB) read-only", id, vm.Name, len(vm.Disks), need/(1<<30))
	s.vmwimp.set(id, func(st *VMwareImportState) { st.Status = "exporting"; st.Step = "downloading disks (read-only)" })
	var lastLog time.Time
	vmdks, err := cli.ExportVM(ctx, moid, destDir, func(ep vmware.ExportProgress) {
		s.vmwimp.set(id, func(st *VMwareImportState) {
			st.DoneBytes = ep.DoneBytes
			st.TotalBytes = ep.TotalBytes
			st.Rate = ep.BytesPerSec
			if ep.TotalBytes > 0 {
				st.Pct = int(ep.DoneBytes * 100 / ep.TotalBytes)
			}
		})
		// Throttle progress to the journal: one line every ~15s.
		if time.Since(lastLog) >= 15*time.Second {
			lastLog = time.Now()
			log.Printf("vmware-import %s: export %d/%d MiB @ %d MiB/s", id,
				ep.DoneBytes/(1<<20), ep.TotalBytes/(1<<20), ep.BytesPerSec/(1<<20))
		}
	})
	if err != nil {
		fail("export", err.Error())
		return
	}
	log.Printf("vmware-import %s: export complete, %d disk file(s)", id, len(vmdks))
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
		log.Printf("vmware-import %s: converting disk %d/%d → %s.qcow2", id, i+1, len(vmdks), name)
		if err := qemu.ConvertToQcow2(vmdk, dst); err != nil {
			_ = os.Remove(dst)
			s.rollbackImages(registered)
			fail("convert", err.Error())
			return
		}
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
	log.Printf("vmware-import %s: DONE → image %q (%d disk(s))", id, firstImage, len(vmdks))
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
