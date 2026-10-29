// Package vmbackup is the backup data path: it exposes one VM disk as a
// read-only, point-in-time NBD export — with an optional dirty-bitmap meta
// context for incremental backup — and manages the persistent qcow2 dirty
// bitmaps that back oVirt-style checkpoints.
//
// A RUNNING VM is backed up pull-mode, the way libvirt does it: a scratch
// "fleecing" qcow2 whose backing is the live disk node is attached, and a
// blockdev-backup sync=none job copies each block the guest is about to
// overwrite into it first (copy-before-write). Reading the fleecing node
// therefore always returns the disk exactly as it was when the job started,
// while the guest keeps running. The node is exported read-only over QEMU's
// own NBD server on a private unix socket. The new checkpoint's bitmap is
// created in the SAME QMP transaction that starts the job, so the checkpoint
// and the backup's point in time are one instant.
//
// A STOPPED VM needs no fleecing: the image is static, so qemu-nbd exports it
// read-only (holding the image lock, so the VM can't start mid-backup), with
// --bitmap for an incremental.
//
// Checkpoints: every checkpoint is one persistent, enabled bitmap named
// vdxckpt-<id>, stored in the qcow2. Each bitmap records every write since its
// checkpoint, so an incremental from checkpoint C is exactly bitmap C (no chain
// merge). Only qcow2 (compat 1.1) can store persistent bitmaps: raw disks (zvol,
// LVM, RBD) get full backups only. A bitmap QEMU could not save cleanly (the
// process was killed) comes back "inconsistent"/"in-use" and is refused —
// the caller then forces a full backup.
package vmbackup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vdxclone/internal/qemu"
)

const (
	// BitmapPrefix marks the persistent bitmaps vdxd manages as checkpoints.
	BitmapPrefix = "vdxckpt-"
	tmpBitmap    = "vdxtmp-" // per-backup, disabled, non-persistent merge target
	objPrefix    = "vdxbk-"  // job / export ids
	nodePrefix   = "vdxfl-"  // fleecing node names (QEMU caps node names at 31 chars)
)

// ErrCheckpointInvalid means the incremental base checkpoint's bitmap is gone
// or was not saved cleanly. The caller must fall back to a full backup.
var ErrCheckpointInvalid = errors.New("checkpoint is missing or inconsistent; a full backup is required")

// ErrNoCheckpoints means the disk can't hold persistent bitmaps (raw, or a
// legacy qcow2 v2 image): full backups only.
var ErrNoCheckpoints = errors.New("this disk does not support checkpoints (incremental backup needs a qcow2 v3 disk)")

// BitmapName is the bitmap that backs checkpoint id.
func BitmapName(checkpointID string) string { return BitmapPrefix + checkpointID }

// Disk is the one disk of a VM being backed up.
type Disk struct {
	VMID      string
	Path      string // file, block device, or rbd: spec
	Format    string // "qcow2" | "raw"
	Running   bool
	QMPSocket string // running VMs
	Device    string // QEMU drive id; "" = "disk0"
	// WorkRoot holds per-VM work dirs (NBD sockets, fleecing scratch images).
	// It must be on local disk; the fleecing image grows with guest writes made
	// during the backup.
	WorkRoot string
	// UID/GID own the files a dropped-privilege QEMU must open (its NBD socket
	// dir and the fleecing image). Negative = leave as root.
	UID, GID int
}

func (d Disk) device() string {
	if d.Device == "" {
		return "disk0"
	}
	return d.Device
}

func (d Disk) workDir() string { return filepath.Join(d.WorkRoot, d.VMID) }

// Request selects the backup flavour. From is the incremental base checkpoint
// id ("" = full). To is the checkpoint created at this backup's point in time
// ("" = none, e.g. a raw disk).
type Request struct {
	From, To string
}

// Export is a live NBD export of one disk for the lifetime of one backup (or
// one upload, for OpenWritable). Close it with Finish.
type Export struct {
	// Addr is "unix:<socket>" — never a network address; vdxd relays it.
	Addr string
	// Name is the NBD export name.
	Name string
	// Size is the disk's virtual size in bytes.
	Size uint64
	// DirtyContext is the NBD meta context listing the blocks changed since
	// Request.From ("" for a full backup).
	DirtyContext string

	disk       Disk
	req        Request
	id         string
	running    bool
	node       string // the disk's format node (running VM)
	tmpBitmap  string
	fleeceNode string
	fleecePath string
	proc       *exec.Cmd // qemu-nbd (stopped VM / writable)
	sock       string

	mu   sync.Mutex
	done bool
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// A unix socket path must fit sockaddr_un.sun_path (108 bytes with the NUL).
// Sockets are <work root>/<vm id>/<8 hex>.nbd.sock, so with a UUID VM id the
// work root may be at most MaxWorkRootLen bytes.
const (
	maxSockPath    = 107
	MaxWorkRootLen = maxSockPath - 1 - 36 - 1 - len("01234567.nbd.sock")
)

func sockPath(dir, id string) (string, error) {
	p := filepath.Join(dir, id[:8]+".nbd.sock")
	if len(p) > maxSockPath {
		return "", fmt.Errorf("vmbackup: socket path %s is longer than %d bytes; use a shorter work directory", p, maxSockPath)
	}
	return p, nil
}

func (d Disk) ensureWorkDir() (string, error) {
	if d.WorkRoot == "" || d.VMID == "" || strings.ContainsAny(d.VMID, "/\x00") || d.VMID == "." || d.VMID == ".." {
		return "", errors.New("vmbackup: bad work dir")
	}
	if err := os.MkdirAll(d.WorkRoot, 0o711); err != nil {
		return "", err
	}
	dir := d.workDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	if d.UID >= 0 && d.GID >= 0 {
		_ = os.Chown(dir, d.UID, d.GID)
	}
	return dir, nil
}

// Start opens a point-in-time export of d for one backup.
func Start(d Disk, req Request) (*Export, error) {
	if req.From != "" && req.From == req.To {
		return nil, errors.New("vmbackup: from and to checkpoints are the same")
	}
	if (req.From != "" || req.To != "") && d.Format != "qcow2" {
		return nil, ErrNoCheckpoints
	}
	if d.Running {
		return startRunning(d, req)
	}
	return startStopped(d, req)
}

// ---- running VM: fleecing + QEMU's NBD server ---------------------------

func startRunning(d Disk, req Request) (*Export, error) {
	dir, err := d.ensureWorkDir()
	if err != nil {
		return nil, err
	}
	q, err := qemu.DialQMP(d.QMPSocket)
	if err != nil {
		return nil, fmt.Errorf("qmp: %w", err)
	}
	defer q.Close()
	dn, err := q.QueryDisk(d.device())
	if err != nil {
		return nil, err
	}
	if dn.NodeName == "" || dn.VirtualSize <= 0 {
		return nil, fmt.Errorf("vmbackup: disk %s has no node name / size", d.device())
	}
	if req.From != "" {
		ok := false
		for _, b := range dn.Bitmaps {
			if b.Name == BitmapName(req.From) {
				ok = !b.Inconsistent
			}
		}
		if !ok {
			return nil, ErrCheckpointInvalid
		}
	}
	if req.To != "" {
		for _, b := range dn.Bitmaps {
			if b.Name == BitmapName(req.To) {
				return nil, fmt.Errorf("vmbackup: checkpoint %s already exists", req.To)
			}
		}
	}

	id := newID()
	e := &Export{disk: d, req: req, id: id, running: true, node: dn.NodeName,
		Size: uint64(dn.VirtualSize), Name: objPrefix + id,
		fleeceNode: nodePrefix + id, fleecePath: filepath.Join(dir, id+".fleece.qcow2"),
		sock: filepath.Join(dir, "nbd.sock")}
	if len(e.sock) > maxSockPath {
		return nil, fmt.Errorf("vmbackup: socket path %s is longer than %d bytes; use a shorter work directory", e.sock, maxSockPath)
	}

	// The scratch image: empty, same virtual size, written only by the
	// copy-before-write job. Pre-created and chowned so a dropped-privilege
	// QEMU can open it.
	if err := qemu.CreateQcow2Sized(e.fleecePath, dn.VirtualSize); err != nil {
		return nil, err
	}
	if d.UID >= 0 && d.GID >= 0 {
		_ = os.Chown(e.fleecePath, d.UID, d.GID)
	}
	undo := func() { _ = os.Remove(e.fleecePath) }
	if err := q.BlockdevAdd(map[string]any{
		"driver":    "qcow2",
		"node-name": e.fleeceNode,
		"file":      map[string]any{"driver": "file", "filename": e.fleecePath},
		"backing":   dn.NodeName,
	}); err != nil {
		undo()
		return nil, fmt.Errorf("attach fleecing image: %w", err)
	}
	undo = func() { _ = q.BlockdevDel(e.fleeceNode); _ = os.Remove(e.fleecePath) }

	// One atomic instant: the incremental's frozen copy of the base bitmap, the
	// new checkpoint's bitmap, and the start of copy-before-write.
	var acts []map[string]any
	if req.From != "" {
		e.tmpBitmap = tmpBitmap + id
		acts = append(acts,
			qemu.TxAction("block-dirty-bitmap-add", map[string]any{
				"node": dn.NodeName, "name": e.tmpBitmap, "persistent": false, "disabled": true}),
			qemu.TxAction("block-dirty-bitmap-merge", map[string]any{
				"node": dn.NodeName, "target": e.tmpBitmap, "bitmaps": []string{BitmapName(req.From)}}))
	}
	if req.To != "" {
		acts = append(acts, qemu.TxAction("block-dirty-bitmap-add", map[string]any{
			"node": dn.NodeName, "name": BitmapName(req.To), "persistent": true}))
	}
	acts = append(acts, qemu.TxAction("blockdev-backup", map[string]any{
		"job-id": e.Name, "device": dn.NodeName, "target": e.fleeceNode, "sync": "none"}))
	if err := q.Transaction(acts...); err != nil {
		undo()
		return nil, fmt.Errorf("start backup job: %w", err)
	}
	// From here Finish(false) knows how to unwind everything.
	_ = os.Remove(e.sock)
	if err := q.NBDServerStartUnix(e.sock); err != nil {
		if !strings.Contains(err.Error(), "already running") {
			e.teardownRunning(q, false)
			return nil, fmt.Errorf("start NBD server: %w", err)
		}
		// A server left by a crashed vdxd: restart it on our socket, but only
		// when it carries no exports (never steal one in use).
		if ids, _ := q.BlockExportIDs(); len(ids) > 0 {
			e.teardownRunning(q, false)
			return nil, errors.New("vmbackup: the VM's NBD server is busy with another export")
		}
		_ = q.NBDServerStop()
		if err := q.NBDServerStartUnix(e.sock); err != nil {
			e.teardownRunning(q, false)
			return nil, fmt.Errorf("start NBD server: %w", err)
		}
	}
	var bitmaps []string
	if e.tmpBitmap != "" {
		bitmaps = []string{e.tmpBitmap}
		e.DirtyContext = "qemu:dirty-bitmap:" + e.tmpBitmap
	}
	if err := q.BlockExportAddReadOnly(e.Name, e.fleeceNode, e.Name, bitmaps); err != nil {
		e.teardownRunning(q, false)
		return nil, fmt.Errorf("export: %w", err)
	}
	e.Addr = "unix:" + e.sock
	return e, nil
}

// teardownRunning unwinds a running-VM export in reverse order. Every step is
// best effort and idempotent, so it also serves crash recovery.
func (e *Export) teardownRunning(q *qemu.QMP, ok bool) error {
	_ = q.BlockExportDelHard(e.Name)
	waitGone(func() ([]string, error) { return q.BlockExportIDs() }, e.Name)
	_ = q.NBDServerStop()
	_ = os.Remove(e.sock)
	_ = q.BlockJobCancelForce(e.Name)
	waitGone(func() ([]string, error) { return q.BlockJobIDs() }, e.Name)
	var delErr error
	for i := 0; i < 20; i++ { // the job releases the node asynchronously
		if delErr = q.BlockdevDel(e.fleeceNode); delErr == nil || strings.Contains(delErr.Error(), "not found") {
			delErr = nil
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e.tmpBitmap != "" {
		_ = q.BitmapRemove(e.node, e.tmpBitmap)
	}
	var ckErr error
	if !ok && e.req.To != "" {
		ckErr = q.BitmapRemove(e.node, BitmapName(e.req.To))
		if ckErr != nil && strings.Contains(ckErr.Error(), "not found") {
			ckErr = nil
		}
	}
	if delErr == nil {
		_ = os.Remove(e.fleecePath)
	}
	return errors.Join(delErr, ckErr)
}

// waitGone polls list until id disappears (bounded).
func waitGone(list func() ([]string, error), id string) {
	for i := 0; i < 100; i++ {
		ids, err := list()
		if err != nil {
			return
		}
		found := false
		for _, x := range ids {
			if x == id {
				found = true
			}
		}
		if !found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ---- stopped VM: qemu-nbd -------------------------------------------------

func startStopped(d Disk, req Request) (*Export, error) {
	dir, err := d.ensureWorkDir()
	if err != nil {
		return nil, err
	}
	info, err := qemu.ImageInfo(d.Path)
	if err != nil {
		return nil, err
	}
	if d.Format == "qcow2" && (req.From != "" || req.To != "") {
		if info.Compat != "" && info.Compat != "1.1" {
			return nil, ErrNoCheckpoints
		}
		if req.From != "" {
			ok := false
			for _, b := range info.Bitmaps {
				if b.Name == BitmapName(req.From) {
					ok = !b.InUse()
				}
			}
			if !ok {
				return nil, ErrCheckpointInvalid
			}
		}
		for _, b := range info.Bitmaps {
			if req.To != "" && b.Name == BitmapName(req.To) {
				return nil, fmt.Errorf("vmbackup: checkpoint %s already exists", req.To)
			}
		}
	}
	id := newID()
	sock, err := sockPath(dir, id)
	if err != nil {
		return nil, err
	}
	e := &Export{disk: d, req: req, id: id, Name: objPrefix + id, Size: uint64(info.VirtualSize), sock: sock}
	// A stopped disk is static, so the new checkpoint can be created before
	// the export: the bitmap starts empty = "nothing changed since now".
	if req.To != "" {
		if err := qemu.BitmapAddOffline(d.Path, BitmapName(req.To)); err != nil {
			return nil, err
		}
	}
	args := []string{"--read-only", "--persistent", "--shared=8", "--format=" + d.Format,
		"--socket=" + e.sock, "--export-name=" + e.Name, "--cache=none", "--aio=threads"}
	if req.From != "" {
		args = append(args, "--bitmap="+BitmapName(req.From))
		e.DirtyContext = "qemu:dirty-bitmap:" + BitmapName(req.From)
	}
	if err := e.spawnNBD(append(args, d.Path)); err != nil {
		if req.To != "" {
			_ = qemu.BitmapRemoveOffline(d.Path, BitmapName(req.To))
		}
		return nil, err
	}
	return e, nil
}

// OpenWritable exports a disk image read-write through qemu-nbd, for uploads
// (restore, worker images). No VM may be using it. workDir is a private
// directory for the socket.
func OpenWritable(path, format, workDir string) (*Export, error) {
	if format != "qcow2" && format != "raw" {
		return nil, fmt.Errorf("vmbackup: unsupported format %q", format)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	size, err := qemu.VirtualSizeBytes(path)
	if err != nil {
		return nil, err
	}
	id := newID()
	sock, err := sockPath(workDir, id)
	if err != nil {
		return nil, err
	}
	e := &Export{id: id, Name: objPrefix + id, Size: uint64(size), sock: sock}
	args := []string{"--persistent", "--shared=8", "--format=" + format, "--socket=" + e.sock,
		"--export-name=" + e.Name, "--cache=writeback", "--discard=unmap", "--detect-zeroes=unmap", path}
	if err := e.spawnNBD(args); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Export) spawnNBD(args []string) error {
	_ = os.Remove(e.sock)
	cmd := exec.Command("qemu-nbd", args...)
	// Die with vdxd: a leftover qemu-nbd would hold the image lock and keep
	// the VM from starting.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("qemu-nbd: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.After(15 * time.Second)
	for {
		if _, err := os.Stat(e.sock); err == nil {
			break
		}
		select {
		case err := <-exited:
			return fmt.Errorf("qemu-nbd exited: %v: %s", err, strings.TrimSpace(stderr.String()))
		case <-deadline:
			_ = cmd.Process.Kill()
			<-exited
			return errors.New("qemu-nbd did not create its socket")
		case <-time.After(20 * time.Millisecond):
		}
	}
	e.proc = cmd
	_ = os.WriteFile(e.sock+".pid", []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	go func() { <-exited; e.mu.Lock(); e.proc = nil; e.mu.Unlock() }()
	e.Addr = "unix:" + e.sock
	return nil
}

// Finish ends the export. ok=false (a failed or cancelled backup) also drops
// the checkpoint this backup created, so a checkpoint only ever exists for a
// backup that completed.
func (e *Export) Finish(ok bool) error {
	e.mu.Lock()
	if e.done {
		e.mu.Unlock()
		return nil
	}
	e.done = true
	proc := e.proc
	e.mu.Unlock()

	if e.running {
		q, err := qemu.DialQMP(e.disk.QMPSocket)
		if err != nil {
			// The VM is gone (stopped/crashed): QEMU took the job, export and
			// non-persistent bitmaps with it. A persistent new checkpoint was
			// flushed only if it shut down cleanly; leave it — Checkpoints()
			// reports whether it is usable.
			_ = os.Remove(e.fleecePath)
			_ = os.Remove(e.sock)
			return nil
		}
		defer q.Close()
		return e.teardownRunning(q, ok)
	}
	if proc != nil && proc.Process != nil {
		_ = proc.Process.Signal(syscall.SIGTERM)
		for i := 0; i < 100; i++ {
			e.mu.Lock()
			gone := e.proc == nil
			e.mu.Unlock()
			if gone {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		e.mu.Lock()
		if e.proc != nil {
			_ = e.proc.Process.Kill()
		}
		e.mu.Unlock()
	}
	_ = os.Remove(e.sock)
	_ = os.Remove(e.sock + ".pid")
	if !ok && e.req.To != "" && e.disk.Path != "" {
		// qemu-nbd has released the image lock once it exited.
		for i := 0; i < 20; i++ {
			err := qemu.BitmapRemoveOffline(e.disk.Path, BitmapName(e.req.To))
			if err == nil || strings.Contains(err.Error(), "not found") {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil
}

// ---- checkpoints ------------------------------------------------------------

// Bitmap is one checkpoint bitmap found on a disk.
type Bitmap struct {
	CheckpointID string
	Inconsistent bool
}

// Checkpoints lists the checkpoint bitmaps on d (running or stopped).
func Checkpoints(d Disk) ([]Bitmap, error) {
	var out []Bitmap
	if d.Running {
		q, err := qemu.DialQMP(d.QMPSocket)
		if err != nil {
			return nil, err
		}
		defer q.Close()
		dn, err := q.QueryDisk(d.device())
		if err != nil {
			return nil, err
		}
		for _, b := range dn.Bitmaps {
			if id, ok := strings.CutPrefix(b.Name, BitmapPrefix); ok {
				out = append(out, Bitmap{CheckpointID: id, Inconsistent: b.Inconsistent})
			}
		}
		return out, nil
	}
	if d.Format != "qcow2" {
		return nil, nil
	}
	info, err := qemu.ImageInfo(d.Path)
	if err != nil {
		return nil, err
	}
	for _, b := range info.Bitmaps {
		if id, ok := strings.CutPrefix(b.Name, BitmapPrefix); ok {
			out = append(out, Bitmap{CheckpointID: id, Inconsistent: b.InUse()})
		}
	}
	return out, nil
}

// SupportsCheckpoints reports whether d can hold persistent bitmaps.
func SupportsCheckpoints(d Disk) bool {
	if d.Format != "qcow2" || strings.HasPrefix(d.Path, "rbd:") {
		return false
	}
	info, err := qemu.ImageInfo(d.Path)
	if err != nil {
		return false
	}
	return info.Format == "qcow2" && (info.Compat == "" || info.Compat == "1.1")
}

// RemoveCheckpoint deletes checkpoint id's bitmap. Missing is not an error.
func RemoveCheckpoint(d Disk, id string) error {
	name := BitmapName(id)
	var err error
	if d.Running {
		var q *qemu.QMP
		if q, err = qemu.DialQMP(d.QMPSocket); err != nil {
			return err
		}
		defer q.Close()
		err = q.BitmapRemove(d.device(), name)
	} else {
		err = qemu.BitmapRemoveOffline(d.Path, name)
	}
	if err != nil && (strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "does not exist")) {
		return nil
	}
	return err
}

// Recover removes anything a crashed vdxd left inside a running VM's QEMU
// (backup jobs, exports, the NBD server, fleecing nodes, temporary bitmaps)
// and the VM's work dir. Persistent checkpoint bitmaps are kept.
func Recover(d Disk) error {
	defer os.RemoveAll(d.workDir())
	if !d.Running {
		return nil
	}
	q, err := qemu.DialQMP(d.QMPSocket)
	if err != nil {
		return err
	}
	defer q.Close()
	exports, _ := q.BlockExportIDs()
	ours := false
	for _, id := range exports {
		if strings.HasPrefix(id, objPrefix) {
			ours = true
			_ = q.BlockExportDelHard(id)
			waitGone(func() ([]string, error) { return q.BlockExportIDs() }, id)
		}
	}
	if ours {
		_ = q.NBDServerStop()
	}
	jobs, _ := q.BlockJobIDs()
	for _, id := range jobs {
		if strings.HasPrefix(id, objPrefix) {
			_ = q.BlockJobCancelForce(id)
			waitGone(func() ([]string, error) { return q.BlockJobIDs() }, id)
		}
	}
	nodes, _ := q.NodeNames()
	for _, n := range nodes {
		if strings.HasPrefix(n, nodePrefix) {
			_ = q.BlockdevDel(n)
		}
	}
	if dn, err := q.QueryDisk(d.device()); err == nil {
		for _, b := range dn.Bitmaps {
			if strings.HasPrefix(b.Name, tmpBitmap) {
				_ = q.BitmapRemove(dn.NodeName, b.Name)
			}
		}
	}
	return nil
}

// SweepStale kills qemu-nbd processes a previous vdxd left running (their pid
// files live under workRoot) and clears stopped VMs' work dirs.
func SweepStale(workRoot string) {
	_ = filepath.WalkDir(workRoot, func(p string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() || !strings.HasSuffix(p, ".nbd.sock.pid") {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 1 {
				if cmdline, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); strings.Contains(string(cmdline), "qemu-nbd") {
					_ = syscall.Kill(pid, syscall.SIGTERM)
				}
			}
		}
		_ = os.Remove(p)
		_ = os.Remove(strings.TrimSuffix(p, ".pid"))
		return nil
	})
}
