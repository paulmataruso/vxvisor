package session

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/qemu"
)

// Destination side of a block-live (NBD + drive-mirror) migration. See
// cluster/blocklive.go for the orchestration and the fail-safe invariants.

// BlockReceiverInfo is reported back to the source after the destination launches
// a block-live receiver and exports its disk over NBD.
type BlockReceiverInfo struct {
	MigratePort int    `json:"migrate_port"`
	NBDPort     int    `json:"nbd_port"`
	Export      string `json:"export"`
	BindIP      string `json:"bind_ip"`
}

type blockExportRec struct {
	qmp      string // receiver QMP socket (to tear the export down / stop NBD)
	exportID string
	target   string // the dest target qcow2 (removed on abort)
}

// LaunchBlockReceiver creates the destination's target qcow2 at the source's
// virtual size, launches the incoming QEMU bound to the CLUSTER NIC IP, then
// starts NBD and exports the disk node so the source can mirror into it. The
// target disk is DESTINATION-LOCAL (its own default disk dir), never the source's
// path, so nothing on the source is touched.
func (m *Manager) LaunchBlockReceiver(specB64 string, migratePort int, bindIP string, virtualSize int64) (BlockReceiverInfo, error) {
	var out BlockReceiverInfo
	if bindIP == "" {
		return out, fmt.Errorf("no cluster bind IP for block receiver")
	}
	if virtualSize <= 0 {
		return out, fmt.Errorf("invalid source virtual size")
	}
	blob, err := base64.StdEncoding.DecodeString(specB64)
	if err != nil {
		return out, fmt.Errorf("decode receiver spec: %w", err)
	}
	var spec qemu.Spec
	if err := json.Unmarshal(blob, &spec); err != nil {
		return out, fmt.Errorf("unmarshal receiver spec: %w", err)
	}
	// The id names local files (target disk, secrets): it must be a session uuid.
	if _, err := uuid.Parse(spec.ID); err != nil {
		return out, fmt.Errorf("receiver spec: invalid instance id")
	}

	// Destination-local target. Refuse to clobber an existing file (a stale/retained
	// disk for this id) — safety: never overwrite.
	target := filepath.Join(m.cfg.Paths.DiskDir, spec.ID+".qcow2")
	if _, err := os.Stat(target); err == nil {
		return out, fmt.Errorf("target disk already exists on destination: %s", target)
	}
	if err := os.MkdirAll(m.cfg.Paths.DiskDir, 0o755); err != nil {
		return out, err
	}
	if err := qemu.CreateQcow2Sized(target, virtualSize); err != nil {
		return out, fmt.Errorf("create target disk: %w", err)
	}
	spec.DiskPath = target

	mport := migratePort
	if mport <= 0 || !portAvailable(mport) {
		if fp := freeTCPPort(49200); fp > 0 {
			mport = fp
		} else {
			_ = os.Remove(target)
			return out, fmt.Errorf("no free incoming migration port")
		}
	}
	spec.Incoming = fmt.Sprintf("tcp:%s:%d", bindIP, mport)

	// Launch identity, console secret and SLIRP guard exactly as Start/
	// LaunchReceiver do.
	if err := m.prepareReceiverSpec(&spec); err != nil {
		_ = os.Remove(target)
		return out, err
	}

	logPath := qemu.LogPath(m.cfg.Paths.DiskDir, "recv-"+spec.ID)
	proc, err := qemu.Launch(spec, logPath)
	if err != nil {
		_ = os.Remove(target)
		return out, fmt.Errorf("launch block receiver: %w", err)
	}
	time.Sleep(900 * time.Millisecond)
	if !processAliveSince(proc.Pid, procStartTime(proc.Pid)) {
		_ = proc.Kill()
		_ = os.Remove(target)
		return out, fmt.Errorf("block receiver exited on launch: %s", readLogTail(logPath, 300))
	}

	// Dial the receiver's QMP, find the disk node, start NBD on the cluster IP and
	// export the disk node writable so the source mirror can populate it.
	q, err := dialQMPRetry(spec.QMPSocket, 20, 150*time.Millisecond)
	if err != nil {
		_ = proc.Kill()
		_ = os.Remove(target)
		return out, fmt.Errorf("block receiver QMP: %w", err)
	}
	defer q.Close()
	node, err := q.BlockNodeName("disk0")
	if err != nil {
		_ = proc.Kill()
		_ = os.Remove(target)
		return out, fmt.Errorf("find dest disk node: %w", err)
	}
	nport := freeTCPPort(mport + 1)
	if nport <= 0 {
		_ = proc.Kill()
		_ = os.Remove(target)
		return out, fmt.Errorf("no free NBD port")
	}
	export := "vdx-" + spec.ID
	exportID := "exp-" + spec.ID
	if err := q.NBDServerStart(bindIP, nport); err != nil {
		_ = proc.Kill()
		_ = os.Remove(target)
		return out, fmt.Errorf("start NBD server: %w", err)
	}
	if err := q.BlockExportAddNBD(exportID, node, export); err != nil {
		_ = q.NBDServerStop()
		_ = proc.Kill()
		_ = os.Remove(target)
		return out, fmt.Errorf("export disk over NBD: %w", err)
	}

	// Track the receiver (for adopt, recording the real pid) and the export/target
	// (for teardown + abort cleanup).
	m.incomingMu.Lock()
	m.incoming[spec.ID] = proc
	m.incomingMu.Unlock()
	m.blockMu.Lock()
	m.blockExport[spec.ID] = blockExportRec{qmp: spec.QMPSocket, exportID: exportID, target: target}
	m.blockTarget[spec.ID] = target
	m.blockMu.Unlock()

	return BlockReceiverInfo{MigratePort: mport, NBDPort: nport, Export: export, BindIP: bindIP}, nil
}

// StopBlockExport removes the NBD export and stops the NBD server on the receiver
// (called at pre-switchover, BEFORE the destination resumes the guest).
func (m *Manager) StopBlockExport(id string) {
	m.blockMu.Lock()
	rec, ok := m.blockExport[id]
	m.blockMu.Unlock()
	if !ok || rec.qmp == "" {
		return
	}
	if q, err := qemu.DialQMP(rec.qmp); err == nil {
		_ = q.BlockExportDel(rec.exportID)
		_ = q.NBDServerStop()
		q.Close()
	}
}

// AbortBlockReceiver tears down a block-live receiver on the destination: stop the
// export, kill the incoming QEMU, and remove the half-written target disk (a fresh
// dest file — safe to delete). The source keeps running on its untouched disk.
func (m *Manager) AbortBlockReceiver(id string) {
	m.StopBlockExport(id)
	m.ColdCleanup(id) // remove any aux files (UEFI vars / seed) staged for this move
	m.incomingMu.Lock()
	proc := m.incoming[id]
	delete(m.incoming, id)
	m.incomingMu.Unlock()
	if proc != nil {
		_ = proc.Kill()
	}
	m.blockMu.Lock()
	rec := m.blockExport[id]
	delete(m.blockExport, id)
	delete(m.blockTarget, id)
	m.blockMu.Unlock()
	if rec.target != "" {
		_ = os.Remove(rec.target)
	}
}

// blockTargetPath returns (and clears) the dest-local target path recorded for a
// block-live receiver, so adoption records the destination disk, not the source's.
func (m *Manager) blockTargetPath(id string) (string, bool) {
	m.blockMu.Lock()
	defer m.blockMu.Unlock()
	t, ok := m.blockTarget[id]
	delete(m.blockTarget, id)
	delete(m.blockExport, id)
	return t, ok
}

// dialQMPRetry dials a QMP socket that may not exist yet (right after launch).
func dialQMPRetry(socket string, tries int, gap time.Duration) (*qemu.QMP, error) {
	var err error
	for i := 0; i < tries; i++ {
		var q *qemu.QMP
		if q, err = qemu.DialQMP(socket); err == nil {
			return q, nil
		}
		time.Sleep(gap)
	}
	return nil, err
}
