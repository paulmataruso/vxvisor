package qemu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"
)

// QMP is a minimal QEMU Machine Protocol client over the per-VM unix socket.
// It opens, negotiates capabilities, runs one or more commands, and closes.
type QMP struct {
	conn net.Conn
	r    *bufio.Reader
}

// DialQMP connects to the QMP unix socket and completes the capabilities
// handshake so the connection is ready for commands.
func DialQMP(socketPath string) (*QMP, error) {
	c, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	q := &QMP{conn: c, r: bufio.NewReader(c)}
	if _, err := q.r.ReadBytes('\n'); err != nil { // greeting
		c.Close()
		return nil, err
	}
	if _, err := q.run(map[string]any{"execute": "qmp_capabilities"}); err != nil {
		c.Close()
		return nil, err
	}
	return q, nil
}

func (q *QMP) Close() error { return q.conn.Close() }

// Quit terminates the QEMU process via QMP (used to tear down the paused source
// after a completed live migration).
func (q *QMP) Quit() error {
	_, err := q.Execute("quit", nil)
	return err
}

func (q *QMP) run(cmd map[string]any) (json.RawMessage, error) {
	// Fresh per-command deadline. The connection is reused across many commands —
	// a migration holds ONE QMP connection for minutes, polling progress — so a
	// single fixed deadline set at dial time would expire mid-operation and break
	// the socket (write: broken pipe). Resetting here bounds each command while
	// keeping a long-lived polling connection healthy indefinitely.
	_ = q.conn.SetDeadline(time.Now().Add(30 * time.Second))
	b, _ := json.Marshal(cmd)
	if _, err := q.conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	// Read lines until we see a return/error (skip async events).
	for {
		line, err := q.r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		var env struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}
		if env.Error != nil {
			return nil, fmt.Errorf("qmp %s: %s", env.Error.Class, env.Error.Desc)
		}
		if env.Event != "" {
			continue // async event, keep reading
		}
		if env.Return == nil {
			env.Return = json.RawMessage("{}")
		}
		return env.Return, nil
	}
}

// Execute runs a QMP command with optional arguments and returns the raw result.
func (q *QMP) Execute(command string, args map[string]any) (json.RawMessage, error) {
	cmd := map[string]any{"execute": command}
	if args != nil {
		cmd["arguments"] = args
	}
	return q.run(cmd)
}

// Powerdown sends an ACPI shutdown request (graceful).
func (q *QMP) Powerdown() error { _, err := q.Execute("system_powerdown", nil); return err }

// Reset performs a hard reset (like the reset button).
func (q *QMP) Reset() error { _, err := q.Execute("system_reset", nil); return err }

// Status returns the VM run state (e.g. "running", "paused").
func (q *QMP) Status() (string, error) {
	res, err := q.Execute("query-status", nil)
	if err != nil {
		return "", err
	}
	var s struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(res, &s)
	return s.Status, nil
}

// quick one-shot helpers --------------------------------------------------

// QMPPowerdown opens, sends a graceful shutdown, and closes.
func QMPPowerdown(socket string) error {
	q, err := DialQMP(socket)
	if err != nil {
		return err
	}
	defer q.Close()
	return q.Powerdown()
}

// QMPReset opens, resets, and closes.
func QMPReset(socket string) error {
	q, err := DialQMP(socket)
	if err != nil {
		return err
	}
	defer q.Close()
	return q.Reset()
}

// hmp runs a human-monitor command through QMP. QEMU 6.2 implements live
// internal snapshots only via the HMP savevm/loadvm/delvm verbs, so we tunnel
// them rather than depend on the finicky job-based snapshot-save API.
func (q *QMP) hmp(line string) (string, error) {
	res, err := q.Execute("human-monitor-command", map[string]any{"command-line": line})
	if err != nil {
		return "", err
	}
	var out string
	_ = json.Unmarshal(res, &out)
	if out != "" {
		// HMP reports errors in its text output, not as a QMP error.
		return out, fmt.Errorf("hmp %q: %s", line, out)
	}
	return out, nil
}

// QMPSnapshotSave takes a live internal snapshot (RAM + disk) named tag.
func QMPSnapshotSave(socket, tag string) error {
	q, err := DialQMP(socket)
	if err != nil {
		return err
	}
	defer q.Close()
	_, err = q.hmp("savevm " + tag)
	return err
}

// Migrate begins streaming this VM's live state to uri (e.g. tcp:HOST:PORT).
// The call returns as soon as migration starts; progress is polled separately
// with QueryMigrate.
//
// NOTE: the legacy inline block-migration parameters (`blk`/`inc`) were deprecated
// in QEMU 8.2 and REMOVED in 9.1, so they are not sent here — passing them makes
// modern QEMU reject the command. Diskless (no-shared-storage) migration now
// requires a blockdev-mirror/NBD dance, which is not implemented yet; until then
// live migration needs shared storage, and withBlock is refused with a clear error.
func (q *QMP) Migrate(uri string, withBlock bool) error {
	if withBlock {
		return fmt.Errorf("inline block migration is unsupported on this QEMU (blk/inc removed in 9.1); configure shared storage for live migration")
	}
	_, err := q.Execute("migrate", map[string]any{"uri": uri})
	return err
}

// MigrateStatus is the decoded result of query-migrate.
type MigrateStatus struct {
	Status    string `json:"status"` // setup|active|completed|failed|cancelled
	Remaining int64  // bytes of RAM still to transfer
	Total     int64  // total bytes of RAM to transfer (0 until QEMU reports it)
}

// QueryMigrate reports migration progress.
func (q *QMP) QueryMigrate() (MigrateStatus, error) {
	res, err := q.Execute("query-migrate", nil)
	if err != nil {
		return MigrateStatus{}, err
	}
	var raw struct {
		Status string `json:"status"`
		RAM    struct {
			Remaining int64 `json:"remaining"`
			Total     int64 `json:"total"`
		} `json:"ram"`
	}
	_ = json.Unmarshal(res, &raw)
	return MigrateStatus{Status: raw.Status, Remaining: raw.RAM.Remaining, Total: raw.RAM.Total}, nil
}

// SetMigrateCapabilities toggles migration capabilities (e.g. auto-converge,
// xbzrle). Best-effort: unknown capabilities are ignored by older QEMU.
func (q *QMP) SetMigrateCapabilities(caps map[string]bool) error {
	var list []map[string]any
	for k, v := range caps {
		list = append(list, map[string]any{"capability": k, "state": v})
	}
	_, err := q.Execute("migrate-set-capabilities", map[string]any{"capabilities": list})
	return err
}

// QMPSnapshotDelete removes a live snapshot named tag.
func QMPSnapshotDelete(socket, tag string) error {
	q, err := DialQMP(socket)
	if err != nil {
		return err
	}
	defer q.Close()
	_, err = q.hmp("delvm " + tag)
	return err
}

// ---- block jobs (storage vMotion) ----------------------------------------
//
// drive-mirror copies a live disk to a new target while the guest keeps running
// on the SOURCE; writes are mirrored to the target. The source is never modified
// by the mirror, so a cancel before pivot is always safe. Once the job reports
// `ready`, block-job-complete pivots the guest onto the target.

// DriveMirror starts mirroring `device` (e.g. "disk0") to `target`. For a brand
// new qcow2 file use mode="absolute-paths" (QEMU creates it) + format="qcow2";
// for a pre-created raw target (zvol) use mode="existing" + format="raw". Both
// error modes are "report" so a target failure fails the JOB, never the guest.
func (q *QMP) DriveMirror(device, target, format, mode string) error {
	args := map[string]any{
		"device":          device,
		"target":          target,
		"sync":            "full",
		"mode":            mode,
		"on-source-error": "report",
		"on-target-error": "report",
	}
	if format != "" {
		args["format"] = format
	}
	_, err := q.Execute("drive-mirror", args)
	return err
}

type blockJob struct {
	Device string `json:"device"`
	Type   string `json:"type"`
	Ready  bool   `json:"ready"`
	Len    int64  `json:"len"`
	Offset int64  `json:"offset"`
	// Status is the job's lifecycle state (running|ready|aborting|concluded|…) and
	// Error is set when a job failed with on-*-error=report. Parsing these lets the
	// poll loop abort promptly on a mirror failure instead of waiting out a
	// deadline (a failed job stays PRESENT and not-ready until dismissed).
	Status string `json:"status"`
	Error  string `json:"error"`
}

// BlockJobs returns the active block jobs.
func (q *QMP) BlockJobs() ([]blockJob, error) {
	res, err := q.Execute("query-block-jobs", nil)
	if err != nil {
		return nil, err
	}
	var jobs []blockJob
	_ = json.Unmarshal(res, &jobs)
	return jobs, nil
}

// BlockJobProgress returns (ready, offset, len) for device's mirror job. present
// is false when no job exists for the device (completed/never started).
func (q *QMP) BlockJobProgress(device string) (ready bool, offset, length int64, present bool, err error) {
	jobs, err := q.BlockJobs()
	if err != nil {
		return false, 0, 0, false, err
	}
	for _, j := range jobs {
		if j.Device == device {
			return j.Ready, j.Offset, j.Len, true, nil
		}
	}
	return false, 0, 0, false, nil
}

// BlockJobFailed reports whether device's job has errored or concluded
// abnormally (so a poll loop can abort at once). ok is false if no such job.
func (q *QMP) BlockJobFailed(device string) (failed bool, reason string, ok bool) {
	jobs, err := q.BlockJobs()
	if err != nil {
		return false, "", false
	}
	for _, j := range jobs {
		if j.Device == device {
			if j.Error != "" {
				return true, j.Error, true
			}
			switch j.Status {
			case "aborting", "concluded":
				return true, j.Status, true
			}
			return false, "", true
		}
	}
	return false, "", false
}

// BlockJobComplete pivots the guest onto the mirror target (the job must be
// ready). After this the guest writes only to the target.
func (q *QMP) BlockJobComplete(device string) error {
	_, err := q.Execute("block-job-complete", map[string]any{"device": device})
	return err
}

// BlockJobCancel aborts a mirror. Before pivot this leaves the guest on the
// untouched source; the (partial) target should then be deleted by the caller.
func (q *QMP) BlockJobCancel(device string) error {
	_, err := q.Execute("block-job-cancel", map[string]any{"device": device})
	return err
}

// InsertedFile returns the backing file currently inserted for a -drive id, via
// query-block. Used to verify a pivot actually landed on the target.
func (q *QMP) InsertedFile(device string) (string, error) {
	res, err := q.Execute("query-block", nil)
	if err != nil {
		return "", err
	}
	var devs []struct {
		Device string `json:"device"`
		Inserted struct {
			File string `json:"file"`
		} `json:"inserted"`
	}
	_ = json.Unmarshal(res, &devs)
	for _, d := range devs {
		if d.Device == device {
			return d.Inserted.File, nil
		}
	}
	return "", nil
}

// ---- cross-host block-live migration (NBD + drive-mirror) -----------------

// BlockNodeName returns the top (format) node-name currently inserted for a
// -drive id, via query-block. The destination needs this to export the disk over
// NBD (block-export-add targets a node-name, not a drive id).
func (q *QMP) BlockNodeName(device string) (string, error) {
	res, err := q.Execute("query-block", nil)
	if err != nil {
		return "", err
	}
	var devs []struct {
		Device   string `json:"device"`
		Inserted struct {
			NodeName string `json:"node-name"`
		} `json:"inserted"`
	}
	_ = json.Unmarshal(res, &devs)
	for _, d := range devs {
		if d.Device == device {
			return d.Inserted.NodeName, nil
		}
	}
	return "", fmt.Errorf("no block node for device %q", device)
}

// NBDServerStart starts the built-in NBD server bound to a SPECIFIC host:port
// (the cluster NIC — never 0.0.0.0/:: and never the mgmt NIC).
func (q *QMP) NBDServerStart(host string, port int) error {
	_, err := q.Execute("nbd-server-start", map[string]any{
		"addr": map[string]any{
			"type": "inet",
			"data": map[string]any{"host": host, "port": strconv.Itoa(port)},
		},
	})
	return err
}

// BlockExportAddNBD exports nodeName over NBD as exportName, writable (so the
// source mirror can write it). Leaving allow-inactive unset ACTIVATES the node,
// which is required for the write-ready export during an incoming migration.
func (q *QMP) BlockExportAddNBD(id, nodeName, exportName string) error {
	_, err := q.Execute("block-export-add", map[string]any{
		"type":      "nbd",
		"id":        id,
		"node-name": nodeName,
		"name":      exportName,
		"writable":  true,
	})
	return err
}

// BlockExportDel removes an NBD export by id (done at pre-switchover, before the
// destination resumes, so a lingering writable export can't block activation).
func (q *QMP) BlockExportDel(id string) error {
	_, err := q.Execute("block-export-del", map[string]any{"id": id})
	return err
}

// NBDServerStop stops the built-in NBD server.
func (q *QMP) NBDServerStop() error { _, err := q.Execute("nbd-server-stop", nil); return err }

// DriveMirrorJob is DriveMirror with an explicit job-id so the job can be
// referenced (cancel/query) unambiguously during the cross-host dance.
func (q *QMP) DriveMirrorJob(jobID, device, target, format, mode string) error {
	args := map[string]any{
		"job-id":          jobID,
		"device":          device,
		"target":          target,
		"sync":            "full",
		"mode":            mode,
		"on-source-error": "report",
		"on-target-error": "report",
	}
	if format != "" {
		args["format"] = format
	}
	_, err := q.Execute("drive-mirror", args)
	return err
}

// MigrateContinue advances a migration paused at `state` (e.g. "pre-switchover")
// to its next phase.
func (q *QMP) MigrateContinue(state string) error {
	_, err := q.Execute("migrate-continue", map[string]any{"state": state})
	return err
}

// MigrateCancel aborts an in-progress outgoing migration.
func (q *QMP) MigrateCancel() error { _, err := q.Execute("migrate_cancel", nil); return err }

// BlockdevSetActive (re)activates or inactivates block nodes. After a migration
// reaches switchover the source's disks are inactivated; reviving the source
// requires reactivating them (active=true) BEFORE `cont`. nodeName "" targets all
// nodes. Available since QEMU 10.0.
func (q *QMP) BlockdevSetActive(nodeName string, active bool) error {
	args := map[string]any{"active": active}
	if nodeName != "" {
		args["node-name"] = nodeName
	}
	_, err := q.Execute("blockdev-set-active", args)
	return err
}
