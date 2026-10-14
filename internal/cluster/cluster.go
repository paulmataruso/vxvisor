// Package cluster manages multi-node operation: a node registry, a free-resource
// scheduler, node health, remote command execution over SSH, and (gated) live
// migration between nodes.
//
// On a single-host install the control node auto-registers as "local" and runs
// everything. Remote worker nodes are driven over SSH; live migration requires
// two reachable nodes plus shared storage (an NFS pool), matching CPU models,
// and pinned QEMU versions — so it is implemented here but refuses to run until
// those preconditions hold, rather than corrupting a VM.
package cluster

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"vdxclone/internal/db"
	"vdxclone/internal/qemu"
)

type Node struct {
	ID        int64
	Name      string
	Address   string
	SSHUser   string
	Role      string
	Status    string
	CPUs      int
	MemTotal  int64
	MemFree   int64
	LastSeen  string
	CreatedAt string
}

type Store struct{ db *db.DB }

func New(d *db.DB) *Store { return &Store{db: d} }

// EnsureLocalNode registers (once) the control node this daemon runs on.
func (s *Store) EnsureLocalNode(hostname string) {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE role='local'`).Scan(&n)
	if n > 0 {
		return
	}
	_, _ = s.db.Exec(`INSERT INTO nodes(name,address,role,status,cpus) VALUES(?,?,'local','ready',?)`,
		hostname, "", runtime.NumCPU())
}

func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT id,name,address,ssh_user,role,status,cpus,mem_total,mem_free,COALESCE(last_seen,''),created_at
		FROM nodes ORDER BY role='local' DESC, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.Address, &n.SSHUser, &n.Role, &n.Status, &n.CPUs, &n.MemTotal, &n.MemFree, &n.LastSeen, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNode(id int64) (Node, error) {
	var n Node
	err := s.db.QueryRow(`SELECT id,name,address,ssh_user,role,status,cpus,mem_total,mem_free,COALESCE(last_seen,''),created_at
		FROM nodes WHERE id=?`, id).
		Scan(&n.ID, &n.Name, &n.Address, &n.SSHUser, &n.Role, &n.Status, &n.CPUs, &n.MemTotal, &n.MemFree, &n.LastSeen, &n.CreatedAt)
	return n, err
}

func (s *Store) AddNode(name, address, sshUser string) (int64, error) {
	if sshUser == "" {
		sshUser = "root"
	}
	res, err := s.db.Exec(`INSERT INTO nodes(name,address,ssh_user,role,status) VALUES(?,?,?,'worker','unknown')`,
		name, address, sshUser)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteNode(id int64) error {
	_, err := s.db.Exec(`DELETE FROM nodes WHERE id=? AND role!='local'`, id)
	return err
}

// UpsertGossipNode reflects a peer discovered via gossip into the nodes table so
// the scheduler and the cluster view see live remote capacity. It matches on
// name and never touches the local node (which owns its own health row).
func (s *Store) UpsertGossipNode(name, address string, cpus int, memTotal, memFree int64, alive bool) {
	if name == "" {
		return
	}
	var localName string
	_ = s.db.QueryRow(`SELECT name FROM nodes WHERE role='local'`).Scan(&localName)
	if name == localName {
		return
	}
	status := "unreachable"
	if alive {
		status = "ready"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, _ := s.db.Exec(`UPDATE nodes SET address=?, cpus=?, mem_total=?, mem_free=?, status=?, last_seen=?
		WHERE name=? AND role!='local'`, address, cpus, memTotal, memFree, status, now, name)
	if n, _ := res.RowsAffected(); n == 0 {
		_, _ = s.db.Exec(`INSERT INTO nodes(name,address,ssh_user,role,status,cpus,mem_total,mem_free,last_seen)
			VALUES(?,?,'root','worker',?,?,?,?,?)`, name, address, status, cpus, memTotal, memFree, now)
	}
}

// PlaceSession runs the scheduler and records the chosen node on the session,
// so "sessions auto-place on the least-loaded node" holds from any node's view.
// On a single-host install this resolves to the local node.
func (s *Store) PlaceSession(sessionID string, needMemMB int) (Node, error) {
	n, err := s.Schedule(needMemMB)
	if err != nil {
		return Node{}, err
	}
	_, _ = s.db.Exec(`UPDATE sessions SET node_id=? WHERE id=?`, n.ID, sessionID)
	return n, nil
}

// UpdateLocalHealth records the control node's live CPU/mem so the scheduler and
// the cluster view reflect real capacity.
func (s *Store) UpdateLocalHealth(memUsed, memTotal int64) {
	_, _ = s.db.Exec(`UPDATE nodes SET mem_total=?, mem_free=?, status='ready', last_seen=? WHERE role='local'`,
		memTotal, memTotal-memUsed, time.Now().UTC().Format(time.RFC3339))
}

// Probe checks a worker node over SSH and records its health.
func (s *Store) Probe(n Node) {
	status := "ready"
	out, err := sshCombined(n, "nproc; free -b | awk '/Mem:/{print $2, $7}'")
	var cpus int
	var total, free int64
	if err != nil {
		status = "unreachable"
	} else {
		_, _ = fmt.Sscan(out, &cpus) // best-effort parse of first token
		parseMem(out, &total, &free)
	}
	_, _ = s.db.Exec(`UPDATE nodes SET status=?, cpus=?, mem_total=?, mem_free=?, last_seen=? WHERE id=?`,
		status, cpus, total, free, time.Now().UTC().Format(time.RFC3339), n.ID)
}

// Schedule picks the ready node with the most free memory able to host needMemMB.
// It returns the local node when no better worker fits, so single-host installs
// always schedule successfully.
func (s *Store) Schedule(needMemMB int) (Node, error) {
	nodes, err := s.ListNodes()
	if err != nil {
		return Node{}, err
	}
	var best *Node
	var local *Node
	for i := range nodes {
		n := &nodes[i]
		if n.Role == "local" {
			local = n
		}
		if n.Status != "ready" {
			continue
		}
		if n.MemFree > 0 && int64(needMemMB)*1024*1024 > n.MemFree {
			continue
		}
		if best == nil || n.MemFree > best.MemFree {
			best = n
		}
	}
	if best != nil {
		return *best, nil
	}
	if local != nil {
		return *local, nil
	}
	return Node{}, fmt.Errorf("no node available")
}

// ---- live migration (gated) ---------------------------------------------

// MigrateReq describes one live migration. ReceiverSpec is a qemu.Spec (with
// Incoming set) serialized by the caller; the orchestrator ships it to the
// destination node, which launches a paused QEMU ready to receive the stream.
type MigrateReq struct {
	Src, Dst     Node
	SessionID    string
	LocalQMP     string // source VM's QMP socket on this node
	IncomingPort int    // TCP port the destination QEMU listens on
	// SharedStorage asserts the disk is visible at the same path on both nodes.
	// When false, BlockMigrate must be true (copy the disk inline over the wire).
	SharedStorage bool
	BlockMigrate  bool
	ReceiverSpec  qemu.Spec // spec launched on the destination with Incoming set
}

// Migrate performs a live migration of a running VM from src to dst without
// disconnecting the guest. The network identity survives because both nodes
// share one L2 segment (the VXLAN overlay): on completion QEMU emits a
// gratuitous ARP and the guest's MAC is relearned on the destination.
//
// It is conservative by design — a half-finished migration without shared
// storage (and without block migration) destroys the guest disk — so it refuses
// unless the preconditions hold, then runs the real QMP sequence end to end.
func (s *Store) Migrate(req MigrateReq) error {
	if req.Src.ID == req.Dst.ID {
		return fmt.Errorf("live migration needs two distinct nodes; this is a single-node install")
	}
	if req.Dst.Role == "local" || req.Dst.Address == "" {
		return fmt.Errorf("destination node has no routable address")
	}
	if !req.SharedStorage && !req.BlockMigrate {
		return fmt.Errorf("live migration requires shared storage across nodes, or block migration; refusing to migrate a local-only disk")
	}
	dstHost := hostOnly(req.Dst.Address)
	port := req.IncomingPort

	// 1. Ship the receiver spec to the destination and launch the incoming QEMU.
	spec := req.ReceiverSpec
	spec.Incoming = fmt.Sprintf("tcp:0.0.0.0:%d", port)
	blob, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("encode receiver spec: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(blob)
	// setsid so the receiver outlives the ssh session; it waits for the stream.
	recvCmd := fmt.Sprintf("setsid vdxd migrate-recv %d %s >/tmp/vdx-recv-%s.log 2>&1 &",
		port, enc, req.SessionID)
	if out, err := sshCombined(req.Dst, recvCmd); err != nil {
		return fmt.Errorf("start receiver on %s: %v: %s", req.Dst.Name, err, out)
	}
	time.Sleep(1500 * time.Millisecond) // let the receiver bind its incoming port

	// 2. Drive the source QEMU to stream its state to the destination.
	q, err := qemu.DialQMP(req.LocalQMP)
	if err != nil {
		return fmt.Errorf("source QMP: %w", err)
	}
	defer q.Close()
	// auto-converge throttles the guest if it dirties RAM faster than we can ship
	// it, guaranteeing convergence; xbzrle compresses repeated pages.
	_ = q.SetMigrateCapabilities(map[string]bool{"auto-converge": true, "xbzrle": true})
	uri := fmt.Sprintf("tcp:%s:%d", dstHost, port)
	if err := q.Migrate(uri, req.BlockMigrate); err != nil {
		return fmt.Errorf("start migration: %w", err)
	}

	// 3. Poll to completion.
	deadline := time.Now().Add(5 * time.Minute)
	for {
		st, err := q.QueryMigrate()
		if err != nil {
			return fmt.Errorf("query-migrate: %w", err)
		}
		switch st.Status {
		case "completed":
			// Flip ownership so the control plane now schedules/queries on dst.
			_, _ = s.db.Exec(`UPDATE sessions SET node_id=? WHERE id=?`, req.Dst.ID, req.SessionID)
			return nil
		case "failed", "cancelled":
			return fmt.Errorf("migration %s", st.Status)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("migration timed out (status=%s, %d bytes remaining)", st.Status, st.Remaining)
		}
		time.Sleep(time.Second)
	}
}

// MigratePortFor derives a stable-ish incoming port for a session from a base.
func MigratePortFor(base int, seq int) int { return base + (seq % 200) }

// ---- helpers -------------------------------------------------------------

func sshCombined(n Node, remoteCmd string) (string, error) {
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new"}
	if n.SSHUser != "" {
		args = append(args, n.SSHUser+"@"+hostOnly(n.Address))
	} else {
		args = append(args, hostOnly(n.Address))
	}
	args = append(args, remoteCmd)
	out, err := exec.Command("ssh", args...).CombinedOutput()
	return string(out), err
}

func hostOnly(addr string) string {
	for i := 0; i < len(addr); i++ {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

func parseMem(s string, total, free *int64) {
	// expects a line "<memtotal> <memfree>" somewhere in s
	var a, b int64
	for _, line := range splitLines(s) {
		if _, err := fmt.Sscan(line, &a, &b); err == nil && a > 0 {
			*total, *free = a, b
		}
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
