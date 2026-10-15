package session

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"vdxclone/internal/qemu"
)

// Destination side of a COLD local-disk migration: receive the VM's files, stage
// them safely, verify, and hand them to the run user. See service/coldmigrate.go
// for the orchestration and fail-safe invariant.

// ColdReceiveFile streams one incoming migration file (kind = disk|vars|seed) to
// this node's default disk directory and returns the final path. It writes to a
// <final>.incoming temp first, fsyncs, verifies a disk image, chowns to the run
// user, then atomically renames into place — so a partial transfer never leaves a
// file that could be mistaken for a good disk. Every file created is tracked for
// ColdCleanup in case the migration is aborted later.
func (m *Manager) ColdReceiveFile(id, kind, ext string, src io.Reader) (string, error) {
	dir, err := m.poolDir(0) // destination always lands in its own default disk dir
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := coldFileName(id, kind, ext)
	final := filepath.Join(dir, name)
	tmp := final + ".incoming"
	m.coldTrack(id, final, tmp)

	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("receive %s: %w", kind, err)
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	// A disk image must pass qemu-img's consistency check before we accept it —
	// never adopt a VM onto a disk that arrived corrupt.
	if kind == "disk" {
		if err := qemu.ImageOK(tmp); err != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("received disk failed integrity check: %w", err)
		}
	}
	m.chownRunAs(tmp)
	if err := os.Rename(tmp, final); err != nil {
		return "", err
	}
	fsyncFile(final)
	return final, nil
}

// coldFileName names a received file by the session id so it co-locates with how
// this node names its own disks (<id>.<ext>). Aux files get a suffix.
func coldFileName(id, kind, ext string) string {
	if ext == "" {
		switch kind {
		case "disk":
			ext = ".qcow2"
		default:
			ext = ".bin"
		}
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	switch kind {
	case "disk":
		return id + ext
	case "vars":
		return id + "-vars" + ext
	case "seed":
		return id + "-seed" + ext
	default:
		return id + "-" + kind + ext
	}
}

func (m *Manager) coldTrack(id string, paths ...string) {
	m.coldMu.Lock()
	m.coldStaged[id] = append(m.coldStaged[id], paths...)
	m.coldMu.Unlock()
}

// ColdCleanup removes every file staged for an aborted cold migration of id.
func (m *Manager) ColdCleanup(id string) {
	m.coldMu.Lock()
	paths := m.coldStaged[id]
	delete(m.coldStaged, id)
	m.coldMu.Unlock()
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// ColdDone drops the cleanup tracking for a committed cold migration (the files
// are now the adopted VM's — not garbage to remove).
func (m *Manager) ColdDone(id string) {
	m.coldMu.Lock()
	delete(m.coldStaged, id)
	m.coldMu.Unlock()
}

// RetainDiskAside keeps a source VM's files after a successful cold copy (renamed
// to *.pre-vmotion), matching the storage-vMotion fail-safe — the source is never
// hard-deleted as part of a migration.
func (m *Manager) RetainDiskAside(s *Session) {
	retainAside(s.DiskPath)
	retainAside(s.OVMFVarsPath)
	retainAside(s.SeedPath)
}
