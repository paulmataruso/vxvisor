package service

import (
	"encoding/json"
	"errors"
	"fmt"

	"vdxclone/internal/cluster"
	"vdxclone/internal/peer"
	"vdxclone/internal/qemu"
	"vdxclone/internal/session"
)

// AdoptMigratedSession records a just-migrated VM into THIS node's DB (the
// destination side of the ownership handoff). Called by the peer API on migrate
// commit. The body is the full session row shipped by the source.
func (s *Service) AdoptMigratedSession(body []byte) error {
	var sess session.Session
	if err := json.Unmarshal(body, &sess); err != nil {
		return fmt.Errorf("decode session record: %w", err)
	}
	if err := s.mgr.AdoptMigrated(&sess); err != nil {
		return err
	}
	// Pull in accounts if we're a follower so ownership/org references resolve.
	return nil
}

// AbortMigration tears down a migration receiver on this node (destination) when
// the source migration failed. Called by the peer API on migrate abort. It uses
// the block-aware teardown (a superset of AbortIncoming): it also stops any NBD
// export and removes a half-written block-live target disk, and is a no-op for the
// extra bits on a plain shared/cold receiver.
func (s *Service) AbortMigration(id string) {
	s.mgr.AbortBlockReceiver(id)
}

// Cluster entry points (M7). Node administration is instance-admin only.

func (s *Service) ListNodes(p *Principal) ([]cluster.Node, error) {
	if !p.atLeast("member") || s.cl == nil {
		return nil, nil
	}
	return s.cl.ListNodes()
}

func (s *Service) AddNode(p *Principal, name, address, sshUser, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	id, err := s.cl.AddNode(name, address, sshUser)
	if err != nil {
		return err
	}
	s.audit(p, p.OrgID, "node.add", "node", fmt.Sprint(id), ip, map[string]any{"name": name, "address": address})
	return nil
}

func (s *Service) DeleteNode(p *Principal, id int64, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	if err := s.cl.DeleteNode(id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "node.delete", "node", fmt.Sprint(id), ip, nil)
	return nil
}

func (s *Service) ProbeNode(p *Principal, id int64, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	n, err := s.cl.GetNode(id)
	if err != nil {
		return ErrNotFound
	}
	s.cl.Probe(n)
	return nil
}

// MigrateSession performs a live migration of a running VM to another node over
// the cluster overlay. It builds the receiver spec, derives the incoming port,
// and hands off to the cluster orchestrator, which runs the real QMP migration
// when the preconditions hold (two nodes + shared storage, or block migration)
// and otherwise refuses with a clear reason rather than corrupting the guest.
// Relocate is the unified entry point for the migrate dialog: it moves a VM to a
// different host and/or different storage. The dialog removes the old "shared
// storage present" checkbox — shared storage is auto-detected. Combinations:
//   - storage only (same host): live drive-mirror or offline copy (fail-safe).
//   - host only: live migration (requires shared storage; auto-detected).
//   - both at once: refused with guidance (do them as two steps) — keeps the
//     fail-safe guarantees simple and auditable.
func (s *Service) Relocate(p *Principal, sessionID string, dstNodeID, targetPoolID int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	var localID int64
	if s.cl != nil {
		if nodes, err := s.cl.ListNodes(); err == nil {
			for _, n := range nodes {
				if n.Role == "local" {
					localID = n.ID
				}
			}
		}
	}
	hostChange := dstNodeID > 0 && dstNodeID != localID
	storageChange := targetPoolID >= 0
	switch {
	case storageChange && hostChange:
		return errors.New("change host and storage in separate steps: move the storage first, then migrate the host (or vice-versa)")
	case storageChange:
		return s.MoveSessionStorage(p, sessionID, targetPoolID, ip)
	case hostChange:
		return s.MigrateSession(p, sessionID, dstNodeID, ip)
	default:
		return errors.New("pick a different destination host and/or storage")
	}
}

// MoveSessionStorage performs a (same-host) storage vMotion asynchronously,
// surfacing progress in the migration-status card.
func (s *Service) MoveSessionStorage(p *Principal, sessionID string, targetPoolID int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return err
	}
	dstLabel := "default disk dir"
	if targetPoolID > 0 {
		if pools, err := s.stg.ListPools(); err == nil {
			for _, pl := range pools {
				if pl.ID == targetPoolID {
					dstLabel = pl.Name
				}
			}
		}
	}
	if _, ok := s.migtr.begin(sessionID, sess.Name, sess.Kind, "storage", dstLabel); !ok {
		return errors.New("a migration for this instance is already in progress")
	}
	s.audit(p, p.OrgID, "session.storage.move.start", "session", sessionID, ip, map[string]any{"pool": targetPoolID})
	go func() {
		s.migtr.update(sessionID, "active", 0, 0)
		merr := s.mgr.MoveStorage(sessionID, targetPoolID, func(done, total int64) {
			s.migtr.update(sessionID, "active", total-done, total)
		})
		if merr != nil {
			s.migtr.finish(sessionID, "failed", merr.Error())
		} else {
			s.migtr.finish(sessionID, "completed", "")
		}
		s.audit(p, p.OrgID, "session.storage.move", "session", sessionID, ip, map[string]any{"pool": targetPoolID, "ok": merr == nil})
	}()
	return nil
}

func (s *Service) MigrateSession(p *Principal, sessionID string, dstNodeID int64, ip string) error {
	if !p.IsAdmin || s.cl == nil {
		return ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return err
	}
	// Resolve the source (this node) and destination nodes up front — both the
	// live and the cold paths need them.
	nodes, _ := s.cl.ListNodes()
	var src, dst cluster.Node
	for _, n := range nodes {
		if n.Role == "local" {
			src = n
		}
		if n.ID == dstNodeID {
			dst = n
		}
	}
	if dst.ID != dstNodeID || dst.Role == "local" {
		return errors.New("destination node not found (or is this node)")
	}
	// Shared storage is AUTO-DETECTED (no more checkbox): the VM's disk is on a
	// shared FS, or a cluster-wide shared dir is configured. Conservative — a
	// false "shared" would corrupt the disk, so unknown ⇒ not shared.
	shared := session.IsSharedStorage(sess.DiskPath, sess.DiskBackend) || s.cfg.Cluster.SharedStorage != ""

	// COLD migration: a stopped VM doesn't stream RAM. On shared storage it is a
	// pure ownership handoff (the disk already lives on a filesystem both nodes
	// mount); on local storage the disk is copied to the destination first. Either
	// way the source row is removed only AFTER the destination durably adopts — so
	// a failure leaves the VM exactly where it was.
	if !s.mgr.Running(sess) {
		return s.coldMigrate(p, sess, src, dst, shared, ip)
	}

	if sess.TPM {
		return errors.New("TPM-backed instances can't be live-migrated yet (the TPM state is host-local); stop it and move it instead")
	}
	spec, err := s.mgr.ReceiverSpec(sessionID)
	if err != nil {
		return err
	}
	// Running + LOCAL disk → the NBD + drive-mirror live dance (BlockLive). The
	// destination pre-creates its own target disk at the source's virtual size; the
	// source is only read. Shared disk → the plain RAM-only live path.
	blockLive := !shared
	var vsize int64
	if blockLive {
		if vsize, err = qemu.VirtualSizeBytes(sess.DiskPath); err != nil || vsize <= 0 {
			return fmt.Errorf("cannot determine disk virtual size for live block migration: %v", err)
		}
	}
	port := s.cfg.Cluster.MigratePort
	if port == 0 {
		port = 49200
	}
	// Ship the full session row so the destination can adopt the VM into its DB
	// on completion (ownership handoff → round-trip migration works).
	rec, _ := json.Marshal(sess)

	// Single-flight: refuse a second migration of the same VM while one is in
	// flight. Without this the (now async) migration would let a double-submit
	// drive two `migrate` commands at the same source QEMU → corrupt transfer and
	// orphaned/duplicate session rows.
	if _, ok := s.migtr.begin(sessionID, sess.Name, sess.Kind, src.Name, dst.Name); !ok {
		return errors.New("a migration for this instance is already in progress")
	}
	// Audit the start synchronously (the admin's action); the outcome is audited
	// from the goroutine once the transfer completes or fails.
	s.audit(p, p.OrgID, "session.migrate.start", "session", sessionID, ip, map[string]any{"dst_node": dstNodeID})

	// Run the transfer asynchronously so the browser returns immediately and the
	// migration-status card can poll progress. The migration goroutine owns the
	// source QMP connection, the ownership handoff, and the source-row delete.
	go func() {
		// For a block-live (local-disk) move the destination also needs the UEFI
		// NVRAM vars and the cloud-init seed — the disk mirror only carries the main
		// disk. Ship those small aux files to the destination (reusing the cold-file
		// channel) and point the receiver spec at the destination-local copies. The
		// seed is read-only; the NVRAM is effectively static at runtime.
		if blockLive {
			base := peer.BaseURL(dst.Address, peer.APIPort)
			if spec.OVMFVarsPath != "" {
				np, e := s.coldSendFile(base, sessionID, "vars", spec.OVMFVarsPath)
				if e != nil {
					s.migtr.finish(sessionID, "failed", "copy UEFI vars: "+e.Error())
					s.audit(p, p.OrgID, "session.migrate", "session", sessionID, ip, map[string]any{"dst_node": dstNodeID, "ok": false})
					return
				}
				spec.OVMFVarsPath = np
			}
			if spec.SeedISO != "" {
				np, e := s.coldSendFile(base, sessionID, "seed", spec.SeedISO)
				if e != nil {
					s.migtr.finish(sessionID, "failed", "copy cloud-init seed: "+e.Error())
					s.audit(p, p.OrgID, "session.migrate", "session", sessionID, ip, map[string]any{"dst_node": dstNodeID, "ok": false})
					return
				}
				spec.SeedISO = np
			}
		}
		merr := s.cl.Migrate(cluster.MigrateReq{
			Src: src, Dst: dst,
			SessionID:     sessionID,
			LocalQMP:      sess.QMPSocket,
			IncomingPort:  port,
			SharedStorage: shared,
			BlockLive:     blockLive, // running + local disk → NBD + drive-mirror
			VirtualSize:   vsize,
			ReceiverSpec:  spec,
			SessionRecord: rec,
			Progress: func(status string, remaining, total int64) {
				s.migtr.update(sessionID, status, remaining, total)
			},
		})
		if merr != nil {
			s.migtr.finish(sessionID, "failed", merr.Error())
		} else {
			s.migtr.finish(sessionID, "completed", "")
		}
		s.audit(p, p.OrgID, "session.migrate", "session", sessionID, ip, map[string]any{"dst_node": dstNodeID, "ok": merr == nil})
	}()
	return nil
}
