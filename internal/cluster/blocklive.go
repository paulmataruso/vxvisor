package cluster

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"

	"vdxclone/internal/peer"
	"vdxclone/internal/qemu"
)

// Live migration of a RUNNING VM on LOCAL storage: the NBD + drive-mirror dance.
// The guest keeps running while its disk is mirrored to the destination over NBD;
// RAM is then pre-copied and a sub-second pause-before-switchover hands the guest
// over. Reviewed adversarially (see the plan) — the critical invariants:
//
//   - The source disk is only ever READ by the mirror; it is never written and is
//     retained aside (*.pre-vmotion) on success, never destroyed.
//   - At switchover we CANCEL the ready mirror (never block-job-complete, which
//     would pivot the SOURCE onto the remote NBD — catastrophic).
//   - After migrate-continue the source's disks are INACTIVATED, so reviving the
//     source on an abort requires blockdev-set-active{active:true} THEN cont.
//   - Before migrate-continue the source is fully revivable; after it, ownership is
//     ambiguous until `completed`, so the recovery path must not blindly resume.
//   - NBD + the incoming listener bind to the CLUSTER NIC IP only.

// blockRecvInfo is what the destination reports after launching a block receiver.
type blockRecvInfo struct {
	MigratePort int    `json:"migrate_port"`
	NBDPort     int    `json:"nbd_port"`
	Export      string `json:"export"`
	BindIP      string `json:"bind_ip"`
}

const migDevice = "disk0" // the -drive id the mirror and switchover reference

func (s *Store) migrateBlockLive(req MigrateReq) error {
	if s.peerc == nil {
		return fmt.Errorf("cluster peer client not configured")
	}
	base := peer.BaseURL(req.Dst.Address, peer.APIPort)

	// 1. Launch the block receiver on the destination. It creates the target qcow2
	// at the source's virtual size, launches QEMU listening -incoming on its cluster
	// IP, starts NBD, and exports the disk node for the mirror to write.
	blob, err := json.Marshal(req.ReceiverSpec)
	if err != nil {
		return fmt.Errorf("encode receiver spec: %w", err)
	}
	q := url.Values{}
	q.Set("port", strconv.Itoa(req.IncomingPort))
	q.Set("vsize", strconv.FormatInt(req.VirtualSize, 10))
	q.Set("bind", hostOnly(req.Dst.Address))
	body, code, err := s.peerc.PostBody(base, "/cluster/v1/migrate-recv-block?"+q.Encode(),
		[]byte(base64.StdEncoding.EncodeToString(blob)))
	if err != nil {
		return fmt.Errorf("start block receiver on %s: %w", req.Dst.Name, err)
	}
	if code != 200 {
		return fmt.Errorf("start block receiver on %s: HTTP %d: %s", req.Dst.Name, code, string(body))
	}
	var ri blockRecvInfo
	if json.Unmarshal(body, &ri) != nil || ri.NBDPort == 0 {
		s.blockAbortDst(base, req.SessionID)
		return fmt.Errorf("destination did not report NBD endpoint")
	}

	// A failure anywhere after the receiver is up must tear it down, UNLESS we
	// committed (the dst now owns the guest). The defer is the backstop; revive()
	// handles restoring the source.
	committed := false
	defer func() {
		if !committed {
			s.blockAbortDst(base, req.SessionID)
		}
	}()

	srcq, err := qemu.DialQMP(req.LocalQMP)
	if err != nil {
		return fmt.Errorf("source QMP: %w", err)
	}
	defer srcq.Close()

	// revive restores the source after a pre-completion failure: cancel the mirror +
	// migration, reactivate disks if we passed migrate-continue, resume, and reset
	// the migration state. (Dst teardown is handled by the defer above.)
	pastContinue := false
	revive := func(stage string, cause error) error {
		_ = srcq.BlockJobCancel(migDevice)
		_ = srcq.MigrateCancel()
		if pastContinue {
			// Source disks were inactivated at switchover — reactivate before cont.
			_ = srcq.BlockdevSetActive("", true)
		}
		_, _ = srcq.Execute("cont", nil)
		if st, serr := srcq.Status(); serr == nil && st != "running" {
			log.Printf("blocklive %s: ABORT at %s but source status=%q (cause: %v) — NOT confirmed running", req.SessionID, stage, st, cause)
		}
		s.setMig(req.SessionID, "idle")
		return fmt.Errorf("block-live migration aborted at %s: %w", stage, cause)
	}

	s.setMig(req.SessionID, "blk-live")

	// 2. Mirror the disk to the destination over NBD (sync=full, existing target).
	// The source is only read. format=raw: the wire carries guest-visible blocks;
	// the dst stores them through its qcow2 node.
	nbdTarget := fmt.Sprintf("nbd://%s:%d/%s", ri.BindIP, ri.NBDPort, ri.Export)
	if err := srcq.DriveMirror(migDevice, nbdTarget, "raw", "existing"); err != nil {
		s.setMig(req.SessionID, "idle")
		return fmt.Errorf("start disk mirror: %w", err)
	}
	if req.Progress != nil {
		req.Progress("mirroring", 0, 0)
	}

	// 3. Wait for the mirror to reach ready (disk fully copied, now tracking dirty
	// blocks live). Abort promptly on a job error rather than waiting the deadline.
	mirrorDeadline := time.Now().Add(60 * time.Minute)
	for {
		ready, off, length, present, perr := srcq.BlockJobProgress(migDevice)
		if perr != nil {
			return revive("mirror-poll", perr)
		}
		if !present {
			return revive("mirror", fmt.Errorf("mirror job vanished before ready"))
		}
		if failed, reason, ok := srcq.BlockJobFailed(migDevice); ok && failed {
			return revive("mirror", fmt.Errorf("disk mirror failed: %s", reason))
		}
		if req.Progress != nil {
			req.Progress("mirroring", length-off, length)
		}
		if ready {
			break
		}
		if time.Now().After(mirrorDeadline) {
			return revive("mirror", fmt.Errorf("disk mirror did not reach ready in time"))
		}
		time.Sleep(time.Second)
	}

	// 4. Pre-copy RAM. pause-before-switchover lets us intercept at pre-switchover
	// (guest vCPUs already stopped) to settle the disk before device handover.
	_ = srcq.SetMigrateCapabilities(map[string]bool{"pause-before-switchover": true, "auto-converge": true})
	s.setMig(req.SessionID, "blk-ram")
	if err := srcq.Migrate(fmt.Sprintf("tcp:%s:%d", ri.BindIP, ri.MigratePort), false); err != nil {
		return revive("ram-start", err)
	}

	// 5. Poll RAM migration to the pre-switchover pause (a stable state — polling
	// cannot miss it).
	ramDeadline := time.Now().Add(30 * time.Minute)
	for {
		st, qerr := srcq.QueryMigrate()
		if qerr != nil {
			return revive("ram-poll", qerr)
		}
		if req.Progress != nil {
			req.Progress(st.Status, st.Remaining, st.Total)
		}
		switch st.Status {
		case "pre-switchover":
			// disk + guest are quiescent; finalize.
		case "failed", "cancelled":
			return revive("ram", fmt.Errorf("RAM migration %s", st.Status))
		case "completed":
			// Shouldn't reach completed before we continue (pause-before-switchover),
			// but if it did the handover already happened — go commit.
			goto committing
		default:
			if time.Now().After(ramDeadline) {
				return revive("ram", fmt.Errorf("RAM migration stalled (status=%s)", st.Status))
			}
			time.Sleep(time.Second)
			continue
		}
		break
	}

	// 6. SWITCHOVER. Cancel the READY mirror (drains in-flight writes, emits
	// COMPLETED — never block-job-complete). The dst disk now holds every block.
	if err := srcq.BlockJobCancel(migDevice); err != nil {
		return revive("switchover-cancel", err)
	}
	for i := 0; i < 60; i++ {
		if _, _, _, present, _ := srcq.BlockJobProgress(migDevice); !present {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 7. Destination removes its NBD export BEFORE it resumes (a lingering writable
	// export can block the guest device's activation at resume).
	if _, code, err := s.peerc.Post(base, "/cluster/v1/migrate-nbd-stop?id="+req.SessionID); err != nil || code != 200 {
		return revive("nbd-stop", fmt.Errorf("destination NBD teardown failed (code=%d): %v", code, err))
	}

	// 8. Finish the handover. After this the source disks are inactivated and the
	// source is NOT safely revivable except via reactivate+cont (and must not be
	// resumed at all once `completed`). Mark the ambiguous window.
	s.setMig(req.SessionID, "blk-commit")
	pastContinue = true
	if err := srcq.MigrateContinue("pre-switchover"); err != nil {
		return revive("continue", err)
	}

committing:
	// 9. Poll to completion.
	finishDeadline := time.Now().Add(10 * time.Minute)
	for {
		st, qerr := srcq.QueryMigrate()
		if qerr != nil {
			return revive("finish-poll", qerr)
		}
		if req.Progress != nil {
			req.Progress(st.Status, st.Remaining, st.Total)
		}
		switch st.Status {
		case "completed":
			// The destination is now authoritative and running the guest. Adopt it
			// into the dst DB, then quit the (paused, inactivated) source and remove
			// our row, retaining the source disk aside.
			if body, code, cerr := s.peerc.PostBody(base, "/cluster/v1/migrate-commit", req.SessionRecord); cerr != nil || code != 200 {
				// Retry a few times — the guest IS live on dst; we must not lose it.
				adopted := false
				for i := 0; i < 5; i++ {
					time.Sleep(time.Second)
					if _, c2, e2 := s.peerc.PostBody(base, "/cluster/v1/migrate-commit", req.SessionRecord); e2 == nil && c2 == 200 {
						adopted = true
						break
					}
				}
				if !adopted {
					// Leave the source row in blk-commit (disk retained, NOT started)
					// for operator/reconcile recovery; do not resume (guest is live on
					// dst). This is the acknowledged rare crash-window case.
					log.Printf("blocklive %s: migrate-commit to %s failed (code=%d err=%v body=%s) — guest LIVE on dst but un-adopted; source left paused for recovery", req.SessionID, req.Dst.Name, code, cerr, string(body))
					committed = true // don't let the defer tear down the live dst
					return fmt.Errorf("migration completed on %s but adoption failed; investigate", req.Dst.Name)
				}
			}
			committed = true
			s.retainSourceDisk(req.SessionID)
			_, _ = s.db.Exec(`DELETE FROM sessions WHERE id=?`, req.SessionID)
			_ = srcq.Quit()
			return nil
		case "failed", "cancelled":
			// Failure AFTER continue: migration did not complete, so the dst has no
			// running guest (the defer tears it down). Ownership is ambiguous on the
			// source side — leave it in blk-commit for recovery; do NOT blindly resume.
			s.setMig(req.SessionID, "blk-commit")
			return fmt.Errorf("migration %s during switchover — source left paused; verify ownership before resuming", st.Status)
		}
		if time.Now().After(finishDeadline) {
			return fmt.Errorf("migration did not complete after switchover")
		}
		time.Sleep(time.Second)
	}
}

// setMig persists the source migration_state (busy-guard + crash recovery).
func (s *Store) setMig(id, state string) {
	_, _ = s.db.Exec(`UPDATE sessions SET migration_state=? WHERE id=?`, state, id)
}

// retainSourceDisk renames the source disk + aux files aside (*.pre-vmotion) so a
// completed migration never hard-deletes them.
func (s *Store) retainSourceDisk(id string) {
	var disk, vars, seed string
	_ = s.db.QueryRow(`SELECT disk_path, COALESCE(ovmf_vars_path,''), COALESCE(seed_path,'') FROM sessions WHERE id=?`, id).
		Scan(&disk, &vars, &seed)
	for _, p := range []string{disk, vars, seed} {
		if p != "" {
			aside := p + ".pre-vmotion"
			_ = os.Remove(aside)
			_ = os.Rename(p, aside)
		}
	}
}

// blockAbortDst tells the destination to tear down a block-live receiver (kill the
// incoming QEMU, stop NBD, remove the half-written target disk).
func (s *Store) blockAbortDst(base, id string) {
	_, _, _ = s.peerc.Post(base, "/cluster/v1/migrate-abort?id="+id)
}
