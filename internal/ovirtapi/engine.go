package ovirtapi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/imageio"
	"vdxclone/internal/nbd"
	"vdxclone/internal/vmbackup"
)

// The engine's stateful parts: VM backups (oVirt "incremental backup" API) and
// image transfers. Both live in memory — like the engine's own async tasks they
// don't survive a restart: a vdxd restart fails in-flight work and the client
// retries (vmbackup.Recover cleans the QEMU side at boot). Checkpoints are the
// one durable piece and go through the Backend (DB + qcow2 bitmaps).

type backup struct {
	id, vmID    string
	from, to    string // checkpoint ids ("" = full / no new checkpoint)
	description string
	phase       string // initializing|starting|ready|finalizing|succeeded|failed
	created     time.Time
	modified    time.Time
	disk        Disk
	vdisk       vmbackup.Disk
	export      *vmbackup.Export
	release     func()
	caller      Caller
}

type transfer struct {
	id, ticket    string
	direction     string // download | upload
	format        string
	phase         string // transferring|finalizing_success|finished_success|cancelled_*|finished_failure
	diskID        string
	backupID      string
	vmID          string
	inactivity    time.Duration
	timeoutPolicy string
	created       time.Time
	ended         time.Time
	size          uint64
	transferred   uint64
	export        *vmbackup.Export // owned by the transfer (not a backup's)
	release       func()
	caller        Caller
}

type snapshot struct {
	id, description string
	created         time.Time
}

const (
	backupIdle    = 2 * time.Hour // a ready backup with no transfer activity fails after this
	keepFinished  = time.Hour     // finished backups/transfers stay queryable this long
	defaultIdle   = 60 * time.Second
	maxTicketLife = 24 * time.Hour
	reapInterval  = 15 * time.Second
)

// Run reaps idle transfers and backups until ctx is done, then fails
// everything still in flight.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.shutdown()
			return
		case <-t.C:
			s.reap()
		}
	}
}

func (s *Server) reap() {
	now := s.now()
	var expired []*transfer
	var stale []*backup
	s.mu.Lock()
	for id, t := range s.transfers {
		if t.phase != "transferring" {
			if !t.ended.IsZero() && now.Sub(t.ended) > keepFinished {
				delete(s.transfers, id)
			}
			continue
		}
		if st, ok := s.io.Status(t.ticket); !ok || st.Expired {
			expired = append(expired, t)
		} else {
			t.transferred = st.Transferred
		}
	}
	for id, b := range s.backups {
		if b.phase == "succeeded" || b.phase == "failed" {
			if now.Sub(b.modified) > keepFinished {
				delete(s.backups, id)
			}
			continue
		}
		if b.phase == "ready" && now.Sub(b.modified) > backupIdle && !s.backupBusyLocked(b.id) {
			stale = append(stale, b)
		}
	}
	s.mu.Unlock()
	for _, t := range expired {
		log.Printf("ovirtapi: image transfer %s timed out (no activity for %s)", t.id, t.inactivity)
		s.endTransfer(t, false, "finished_failure")
		s.be.Audit(t.caller, "ovirt.transfer.timeout", "image_transfer", t.id, "", map[string]any{"disk": t.diskID})
	}
	for _, b := range stale {
		log.Printf("ovirtapi: backup %s of VM %s abandoned (idle %s); failing it", b.id, b.vmID, backupIdle)
		s.endBackup(b, false)
		s.be.Audit(b.caller, "ovirt.backup.abandoned", "session", b.vmID, "", map[string]any{"backup": b.id})
	}
}

func (s *Server) shutdown() {
	s.mu.Lock()
	var ts []*transfer
	var bs []*backup
	for _, t := range s.transfers {
		if t.phase == "transferring" {
			ts = append(ts, t)
		}
	}
	for _, b := range s.backups {
		if b.phase == "ready" || b.phase == "starting" {
			bs = append(bs, b)
		}
	}
	s.mu.Unlock()
	for _, t := range ts {
		s.endTransfer(t, false, "finished_failure")
	}
	for _, b := range bs {
		s.endBackup(b, false)
	}
}

// backupBusyLocked reports whether a backup has a live transfer.
func (s *Server) backupBusyLocked(id string) bool {
	for _, t := range s.transfers {
		if t.backupID == id && t.phase == "transferring" {
			return true
		}
	}
	return false
}

// ---- backups -------------------------------------------------------------------

// startBackup implements POST /vms/{id}/backups.
func (s *Server) startBackup(c Caller, vmID string, diskIDs []string, from, description string) (*backup, error) {
	vm, err := s.be.VM(c, vmID)
	if err != nil {
		return nil, err
	}
	if vm.Disk == nil {
		return nil, fmt.Errorf("%w: the VM has no disk", ErrBadRequest)
	}
	for _, d := range diskIDs {
		if d != vm.Disk.ID {
			return nil, fmt.Errorf("%w: disk %s is not attached to VM %s", ErrBadRequest, d, vmID)
		}
	}
	s.mu.Lock()
	if other, busy := s.busyVM[vmID]; busy {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: backup %s is already running for this VM", ErrConflict, other)
	}
	b := &backup{id: uuid.NewString(), vmID: vmID, from: from, description: description,
		phase: "initializing", created: s.now(), modified: s.now(), disk: *vm.Disk, caller: c}
	s.busyVM[vmID] = b.id
	s.mu.Unlock()
	unbusy := func() { s.mu.Lock(); delete(s.busyVM, vmID); s.mu.Unlock() }

	disk, release, err := s.be.BackupDisk(c, vmID)
	if err != nil {
		unbusy()
		return nil, err
	}
	fail := func(e error) (*backup, error) { release(); unbusy(); return nil, e }

	// Only checkpoints this engine recorded (and whose bitmaps are healthy)
	// can be an incremental base; drop bitmaps left by a backup that never
	// finalized.
	cps, err := s.be.Checkpoints(c, vmID)
	if err != nil {
		return fail(err)
	}
	known := map[string]Checkpoint{}
	for _, cp := range cps {
		known[cp.ID] = cp
	}
	if onDisk, err := vmbackup.Checkpoints(disk); err == nil {
		for _, bm := range onDisk {
			if _, ok := known[bm.CheckpointID]; !ok {
				_ = vmbackup.RemoveCheckpoint(disk, bm.CheckpointID)
			}
		}
	}
	if from != "" {
		cp, ok := known[from]
		if !ok || cp.Invalid {
			return fail(fmt.Errorf("%w: checkpoint %s is invalid or does not exist; a full backup is required", ErrBadRequest, from))
		}
	}
	req := vmbackup.Request{From: from}
	if disk.Format == "qcow2" && vmbackup.SupportsCheckpoints(disk) {
		req.To = uuid.NewString()
	} else if from != "" {
		return fail(fmt.Errorf("%w: disk %s does not support incremental backup", ErrBadRequest, vm.Disk.ID))
	}
	disk.WorkRoot = s.cfg.WorkRoot
	exp, err := vmbackup.Start(disk, req)
	if errors.Is(err, vmbackup.ErrCheckpointInvalid) {
		return fail(fmt.Errorf("%w: checkpoint %s is no longer valid (the VM was not shut down cleanly or its disk changed); a full backup is required", ErrBadRequest, from))
	}
	if err != nil {
		return fail(err)
	}
	s.mu.Lock()
	b.to, b.export, b.release, b.vdisk = req.To, exp, release, disk
	b.phase, b.modified = "ready", s.now()
	s.backups[b.id] = b
	s.mu.Unlock()
	return b, nil
}

// endBackup tears a backup down. ok=true persists its new checkpoint.
func (s *Server) endBackup(b *backup, ok bool) error {
	s.mu.Lock()
	if b.phase != "ready" && b.phase != "starting" && b.phase != "initializing" {
		s.mu.Unlock()
		return nil
	}
	b.phase, b.modified = "finalizing", s.now()
	var live []*transfer
	for _, t := range s.transfers {
		if t.backupID == b.id && t.phase == "transferring" {
			live = append(live, t)
		}
	}
	s.mu.Unlock()
	for _, t := range live {
		s.endTransfer(t, false, "finished_failure")
	}
	err := b.export.Finish(ok)
	if ok && err == nil && b.to != "" {
		err = s.be.AddCheckpoint(b.caller, Checkpoint{ID: b.to, VMID: b.vmID, ParentID: b.from,
			Description: b.description, Created: b.created})
		if err != nil {
			_ = vmbackup.RemoveCheckpoint(b.vdisk, b.to)
		}
	}
	b.release()
	s.mu.Lock()
	delete(s.busyVM, b.vmID)
	b.phase, b.modified = "succeeded", s.now()
	if !ok || err != nil {
		b.phase = "failed"
	}
	s.mu.Unlock()
	return err
}

// ---- image transfers -------------------------------------------------------------

type transferSpec struct {
	diskID, backupID, direction, format, policy string
	inactivity                                  time.Duration
}

func (s *Server) startTransfer(c Caller, spec transferSpec) (*transfer, error) {
	if spec.direction == "" {
		spec.direction = "download"
	}
	if spec.direction != "download" && spec.direction != "upload" {
		return nil, fmt.Errorf("%w: invalid direction %q", ErrBadRequest, spec.direction)
	}
	if spec.format == "" {
		spec.format = "raw"
	}
	if spec.inactivity <= 0 {
		spec.inactivity = defaultIdle
	}
	if spec.policy == "" {
		spec.policy = "legacy"
	}
	t := &transfer{id: uuid.NewString(), ticket: uuid.NewString(), direction: spec.direction, format: spec.format,
		diskID: spec.diskID, backupID: spec.backupID, inactivity: spec.inactivity, timeoutPolicy: spec.policy,
		created: s.now(), caller: c, phase: "transferring"}
	tk := imageio.Ticket{ID: t.ticket, InactivityTimeout: spec.inactivity, Deadline: s.now().Add(maxTicketLife),
		ZeroContext: "base:allocation"}

	switch {
	case spec.backupID != "":
		if spec.direction != "download" {
			return nil, fmt.Errorf("%w: a backup can only be downloaded", ErrBadRequest)
		}
		s.mu.Lock()
		b := s.backups[spec.backupID]
		s.mu.Unlock()
		if b == nil {
			return nil, fmt.Errorf("%w: backup %s", ErrNotFound, spec.backupID)
		}
		if b.phase != "ready" {
			return nil, fmt.Errorf("%w: backup %s is %s, not ready", ErrConflict, b.id, b.phase)
		}
		if spec.diskID != "" && spec.diskID != b.disk.ID {
			return nil, fmt.Errorf("%w: disk %s is not part of backup %s", ErrBadRequest, spec.diskID, b.id)
		}
		t.diskID, t.vmID = b.disk.ID, b.vmID
		exp := b.export
		tk.Read, tk.Size, tk.DirtyContext = true, exp.Size, exp.DirtyContext
		tk.Dial = dialer(exp, exp.DirtyContext)
	case spec.direction == "upload":
		path, format, release, err := s.be.WritableDisk(c, spec.diskID)
		if err != nil {
			return nil, err
		}
		exp, err := vmbackup.OpenWritable(path, format, filepath.Join(s.cfg.WorkRoot, "uploads"))
		if err != nil {
			release()
			return nil, err
		}
		t.export, t.release = exp, release
		tk.Read, tk.Write, tk.Size, tk.RawOnly = true, true, exp.Size, true
		tk.Dial = dialer(exp, "")
	default:
		// A plain download (no backup) is not offered: backup clients (Veeam,
		// the SDK's backup examples) always download inside a VM backup, which
		// is what gives the read a consistent point in time.
		return nil, fmt.Errorf("%w: downloading a disk outside a backup is not supported; start a VM backup", ErrBadRequest)
	}
	t.size = tk.Size
	if err := s.io.Add(tk); err != nil {
		s.releaseTransfer(t, false)
		return nil, err
	}
	s.mu.Lock()
	s.transfers[t.id] = t
	if b := s.backups[t.backupID]; b != nil {
		b.modified = s.now()
	}
	s.mu.Unlock()
	return t, nil
}

func dialer(exp *vmbackup.Export, dirty string) func() (imageio.Backend, error) {
	return func() (imageio.Backend, error) {
		metas := []string{"base:allocation"}
		if dirty != "" {
			metas = append(metas, dirty)
		}
		c, err := nbd.Dial(exp.Addr, exp.Name, metas...)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

// endTransfer finishes (ok) or cancels a transfer and sets its final phase.
func (s *Server) endTransfer(t *transfer, ok bool, final string) {
	s.mu.Lock()
	if t.phase != "transferring" {
		s.mu.Unlock()
		return
	}
	if ok {
		t.phase = "finalizing_success"
	} else {
		t.phase = "cancelled_system"
	}
	s.mu.Unlock()
	if st, found := s.io.Status(t.ticket); found {
		t.transferred = st.Transferred
	}
	s.io.Remove(t.ticket, 30*time.Second)
	s.releaseTransfer(t, ok)
	s.mu.Lock()
	t.phase, t.ended = final, s.now()
	if b := s.backups[t.backupID]; b != nil {
		b.modified = s.now()
	}
	s.mu.Unlock()
}

func (s *Server) releaseTransfer(t *transfer, ok bool) {
	if t.export != nil {
		_ = t.export.Finish(ok)
	}
	if t.release != nil {
		t.release()
	}
}

// ---- rendering -------------------------------------------------------------------

func (s *Server) renderBackup(b *backup) *Node {
	base := api("vms", b.vmID, "backups", b.id)
	n := El("backup",
		El("actions", Link(base+"/finalize", "finalize")),
		T("phase", b.phase), T("description", b.description),
		D("creation_date", b.created), D("modification_date", b.modified),
		ListOf("disks", Ref("disk", api("disks", b.disk.ID), b.disk.ID)),
		Ref("vm", api("vms", b.vmID), b.vmID),
		Ref("host", api("hosts", s.hostID()), s.hostID()),
		Link(base+"/disks", "disks"),
	).Obj(base, b.id)
	if b.from != "" {
		n.Add(T("from_checkpoint_id", b.from))
	}
	if b.to != "" {
		n.Add(T("to_checkpoint_id", b.to))
	}
	return n
}

func (b *backup) mode() string {
	if b.from != "" {
		return "incremental"
	}
	return "full"
}

func (s *Server) renderTransfer(t *transfer) *Node {
	base := api("imagetransfers", t.id)
	active := t.phase == "transferring"
	transferred := t.transferred
	if active {
		if st, ok := s.io.Status(t.ticket); ok {
			transferred = st.Transferred
			active = st.Active
		}
	}
	proxy := httpsURL(s.cfg.PublicHost, s.cfg.APIPort, "/images/"+t.ticket)
	direct := proxy
	if s.cfg.ImageioPort > 0 {
		direct = httpsURL(s.cfg.PublicHost, s.cfg.ImageioPort, "/images/"+t.ticket)
	}
	n := El("image_transfer",
		El("actions", Link(base+"/cancel", "cancel"), Link(base+"/finalize", "finalize"),
			Link(base+"/extend", "extend"), Link(base+"/pause", "pause"), Link(base+"/resume", "resume")),
		B("active", active), T("direction", t.direction), T("format", t.format),
		I("inactivity_timeout", int64(t.inactivity/time.Second)), T("phase", t.phase),
		B("shallow", false), T("timeout_policy", t.timeoutPolicy),
		I("transferred", int64(transferred)),
		Ref("disk", api("disks", t.diskID), t.diskID),
		Ref("image", "", derive("image", t.diskID)),
		Ref("host", api("hosts", s.hostID()), s.hostID()),
	).Obj(base, t.id)
	if t.phase == "transferring" {
		n.Add(T("transfer_url", direct), T("proxy_url", proxy))
	}
	if t.backupID != "" {
		n.Add(Ref("backup", api("vms", t.vmID, "backups", t.backupID), t.backupID))
	}
	return n
}

func secondsParam(v string) time.Duration {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}
