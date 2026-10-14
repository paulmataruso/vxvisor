package qemu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
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

func (q *QMP) run(cmd map[string]any) (json.RawMessage, error) {
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
// with QueryMigrate. Optional tuning enables live block migration (copy the disk
// inline) when the cluster has no shared storage.
func (q *QMP) Migrate(uri string, withBlock bool) error {
	args := map[string]any{"uri": uri}
	if withBlock {
		args["blk"] = true
	}
	_, err := q.Execute("migrate", args)
	return err
}

// MigrateStatus is the decoded result of query-migrate.
type MigrateStatus struct {
	Status    string `json:"status"` // setup|active|completed|failed|cancelled
	Remaining int64  // bytes of RAM still to transfer
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
		} `json:"ram"`
	}
	_ = json.Unmarshal(res, &raw)
	return MigrateStatus{Status: raw.Status, Remaining: raw.RAM.Remaining}, nil
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
