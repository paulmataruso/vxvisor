package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"vdxclone/internal/cluster"
	"vdxclone/internal/peer"
	"vdxclone/internal/session"
)

// Cold (offline) cross-host migration. A stopped VM has no live RAM to stream, so
// migrating it is: (shared storage) a pure ownership handoff — the disk already
// lives on a filesystem both nodes mount, nothing is copied; or (local storage) a
// verified disk copy to the destination followed by the handoff.
//
// FAIL-SAFE INVARIANT (same bar as storage vMotion): the source is never put at
// risk. The source session row and its disk are removed ONLY after the
// destination has durably adopted the VM (and, for a copy, verified the disk).
// Any failure leaves the VM exactly where it started. The source disk is retained
// aside (never hard-deleted) on a successful local copy.

// coldMigrate dispatches a stopped-VM migration and runs it asynchronously behind
// the migration-status card.
func (s *Service) coldMigrate(p *Principal, sess *session.Session, src, dst cluster.Node, shared bool, ip string) error {
	if s.peerc == nil {
		return errors.New("cluster peer client not configured")
	}
	if sess.TPM {
		return errors.New("TPM-backed instances can't be migrated across hosts yet (the TPM state is host-local)")
	}
	if _, ok := s.migtr.begin(sess.ID, sess.Name, sess.Kind, src.Name, dst.Name); !ok {
		return errors.New("a migration for this instance is already in progress")
	}
	s.audit(p, p.OrgID, "session.migrate.cold.start", "session", sess.ID, ip, map[string]any{"dst_node": dst.ID, "shared": shared})
	go func() {
		s.migtr.update(sess.ID, "active", 0, 0)
		var merr error
		if shared {
			merr = s.coldHandoffShared(dst, sess)
		} else {
			merr = s.coldCopyAndHandoff(dst, sess)
		}
		if merr != nil {
			s.migtr.finish(sess.ID, "failed", merr.Error())
		} else {
			s.migtr.finish(sess.ID, "completed", "")
		}
		s.audit(p, p.OrgID, "session.migrate.cold", "session", sess.ID, ip, map[string]any{"dst_node": dst.ID, "ok": merr == nil})
	}()
	return nil
}

// coldHandoffShared migrates a stopped VM whose disk is on shared storage: the
// destination adopts it (verifying the shared disk is visible there) and only
// then is the source row removed. No data moves.
func (s *Service) coldHandoffShared(dst cluster.Node, sess *session.Session) error {
	rec, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	base := peer.BaseURL(dst.Address, peer.APIPort)
	body, code, err := s.peerc.PostBody(base, "/cluster/v1/migrate-cold-commit", rec)
	if err != nil {
		return fmt.Errorf("adopt on %s: %w", dst.Name, err)
	}
	if code != 200 {
		return fmt.Errorf("adopt on %s: HTTP %d: %s", dst.Name, code, trimErr(body))
	}
	// Ownership has moved — remove our row. (The disk stays; it is shared.)
	return s.mgr.DeleteSessionRow(sess.ID)
}

// coldCopyAndHandoff migrates a stopped VM on LOCAL storage: it streams the disk
// (and any UEFI vars / cloud-init seed) to the destination's default disk dir,
// the destination verifies + stages them, adopts the VM, and only then does the
// source remove its row and retain its disk aside (*.pre-migration, never
// hard-deleted). A failure at any step leaves the source VM intact and startable.
func (s *Service) coldCopyAndHandoff(dst cluster.Node, sess *session.Session) error {
	base := peer.BaseURL(dst.Address, peer.APIPort)

	// 1. Stream the primary disk. The destination writes <id>.<ext> into its
	//    default disk dir (pool 0), verifies it (qemu-img check for qcow2), and
	//    returns the absolute path it landed at.
	newDisk, err := s.coldSendFile(base, sess.ID, "disk", sess.DiskPath)
	if err != nil {
		return fmt.Errorf("copy disk to %s: %w", dst.Name, err)
	}

	// 2. Aux files (small, optional). UEFI NVRAM vars and the cloud-init seed must
	//    travel with the VM or it won't boot the same on the destination.
	newVars := ""
	if sess.OVMFVarsPath != "" {
		if newVars, err = s.coldSendFile(base, sess.ID, "vars", sess.OVMFVarsPath); err != nil {
			s.coldCleanupRemote(base, sess.ID)
			return fmt.Errorf("copy UEFI vars to %s: %w", dst.Name, err)
		}
	}
	newSeed := ""
	if sess.SeedPath != "" {
		if newSeed, err = s.coldSendFile(base, sess.ID, "seed", sess.SeedPath); err != nil {
			s.coldCleanupRemote(base, sess.ID)
			return fmt.Errorf("copy cloud-init seed to %s: %w", dst.Name, err)
		}
	}

	// 3. Adopt on the destination with the rewritten (destination-local) paths.
	//    The destination's disk now lives in its own pool, so pool_id is cleared.
	moved := *sess
	moved.DiskPath = newDisk
	moved.OVMFVarsPath = newVars
	moved.SeedPath = newSeed
	moved.PoolID = 0
	rec, _ := json.Marshal(&moved)
	body, code, err := s.peerc.PostBody(base, "/cluster/v1/migrate-cold-commit", rec)
	if err != nil || code != 200 {
		s.coldCleanupRemote(base, sess.ID) // roll back the staged files on dst
		if err != nil {
			return fmt.Errorf("adopt on %s: %w", dst.Name, err)
		}
		return fmt.Errorf("adopt on %s: HTTP %d: %s", dst.Name, code, trimErr(body))
	}

	// 4. Destination owns it now. Remove our row and retain the source disk aside
	//    (never hard-delete during a migration). Non-fatal if retention fails —
	//    the authoritative copy is on the destination.
	if derr := s.mgr.DeleteSessionRow(sess.ID); derr != nil {
		return fmt.Errorf("source row cleanup (VM is live on %s): %w", dst.Name, derr)
	}
	s.mgr.RetainDiskAside(sess)
	return nil
}

// coldSendFile streams one local file to the destination's cold-disk receiver and
// returns the absolute path it was written to there.
func (s *Service) coldSendFile(base, id, kind, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	ext := filepath.Ext(path)
	q := fmt.Sprintf("/cluster/v1/cold-disk-recv?id=%s&kind=%s&ext=%s", id, kind, ext)
	body, code, err := s.peerc.PostStream(base, q, f)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("HTTP %d: %s", code, trimErr(body))
	}
	var rr struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(body, &rr) != nil || rr.Path == "" {
		return "", fmt.Errorf("destination did not report a disk path")
	}
	return rr.Path, nil
}

// coldCleanupRemote asks the destination to discard any files staged for a cold
// migration that did not complete (so a failed copy leaves nothing behind).
func (s *Service) coldCleanupRemote(base, id string) {
	_, _, _ = s.peerc.Post(base, "/cluster/v1/cold-cleanup?id="+id)
}

// AdoptColdMigratedSession (destination) records a cold-migrated stopped VM into
// this node's DB. Called by the peer API on cold-commit.
func (s *Service) AdoptColdMigratedSession(body []byte) error {
	var sess session.Session
	if err := json.Unmarshal(body, &sess); err != nil {
		return fmt.Errorf("decode session record: %w", err)
	}
	return s.mgr.AdoptColdMigrated(&sess)
}

// ColdReceiveDisk (destination) streams an incoming cold-migration file to this
// node's storage and returns the final path. Delegates to the manager, which
// stages to a temp name, verifies, chowns to the run user, and renames.
func (s *Service) ColdReceiveDisk(id, kind, ext string, src io.Reader) (string, error) {
	return s.mgr.ColdReceiveFile(id, kind, ext, src)
}

// ColdCleanup (destination) discards files staged for an aborted cold migration.
func (s *Service) ColdCleanup(id string) { s.mgr.ColdCleanup(id) }

func trimErr(b []byte) string {
	if len(b) > 200 {
		return string(b[:200])
	}
	return string(b)
}
