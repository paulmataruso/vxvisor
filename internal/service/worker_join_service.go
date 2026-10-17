package service

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/remoteprov"
)

// Zero-touch worker-node join: the admin supplies the new host's SSH credentials
// plus which NICs are management/cluster and their IPs. vdxd SSHes in, configures
// the network with a reboot-safe time-based rollback (remoteprov), VERIFIES the
// node is reachable on the new management IP from the control node before making
// the change permanent, then optionally installs vdxd. If verification fails for
// ANY reason the node reverts itself — it can never be stranded.

// JoinInput is the join request.
type JoinInput struct {
	Address      string // current reachable SSH address of the new node
	SSHUser      string
	SSHPass      string
	SSHKey       string // optional PEM private key (preferred over password)
	MgmtIface    string
	MgmtCIDR     string // e.g. 172.16.0.170/24
	Gateway      string
	DNS          []string
	ClusterIface string
	ClusterCIDR  string // e.g. 10.10.0.5/24
	Bootstrap    bool   // also push + start vdxd (best-effort)
}

// JoinState is the live status of one join (JSON for /api/node-join).
type JoinState struct {
	ID         string `json:"id"`
	Address    string `json:"address"`
	NewAddr    string `json:"new_addr"`
	Name       string `json:"name"`
	Status     string `json:"status"` // starting|preflight|applying|verifying|confirming|bootstrapping|done|failed
	Step       string `json:"step"`
	Err        string `json:"err,omitempty"`
	StartedAt  int64  `json:"started"`
	FinishedAt int64  `json:"finished,omitempty"`
}

type joinTracker struct {
	mu sync.Mutex
	m  map[string]*JoinState
}

func newJoinTracker() *joinTracker { return &joinTracker{m: map[string]*JoinState{}} }

func (t *joinTracker) set(id string, fn func(*JoinState)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[id]
	if st == nil {
		st = &JoinState{ID: id, StartedAt: time.Now().UnixMilli()}
		t.m[id] = st
	}
	fn(st)
}

func (t *joinTracker) snapshot() []JoinState {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute).UnixMilli()
	var out []JoinState
	for id, st := range t.m {
		if st.FinishedAt != 0 && st.FinishedAt < cutoff {
			delete(t.m, id)
			continue
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt > out[j].StartedAt })
	return out
}

// JoinStates returns in-flight + recently-finished joins (admin only).
func (s *Service) JoinStates(p *Principal) []JoinState {
	if !p.IsAdmin || s.joins == nil {
		return nil
	}
	return s.joins.snapshot()
}

// JoinNode validates the request and runs the join asynchronously, returning a
// tracking id. The SSH/sudo password is used in-memory only and never audited.
func (s *Service) JoinNode(p *Principal, in JoinInput, ip string) (string, error) {
	if !p.IsAdmin || s.cl == nil {
		return "", ErrUnauthorized
	}
	if strings.TrimSpace(in.Address) == "" {
		return "", fmt.Errorf("node address is required")
	}
	if in.SSHUser == "" {
		return "", fmt.Errorf("SSH user is required")
	}
	if in.SSHPass == "" && in.SSHKey == "" {
		return "", fmt.Errorf("an SSH password or private key is required")
	}
	if in.MgmtIface == "" || in.MgmtCIDR == "" {
		return "", fmt.Errorf("management interface and IP/CIDR are required")
	}
	if _, _, err := net.ParseCIDR(in.MgmtCIDR); err != nil {
		return "", fmt.Errorf("management IP must be CIDR (e.g. 172.16.0.170/24)")
	}
	if in.ClusterCIDR != "" {
		if _, _, err := net.ParseCIDR(in.ClusterCIDR); err != nil {
			return "", fmt.Errorf("cluster IP must be CIDR (e.g. 10.10.0.5/24)")
		}
	}
	id := uuid.NewString()
	s.joins.set(id, func(st *JoinState) {
		st.Address = in.Address
		st.NewAddr = ipOfCIDR(in.MgmtCIDR)
		st.Status = "starting"
		st.Step = "queued"
	})
	// Audit the start WITHOUT any secret material.
	s.audit(p, p.OrgID, "node.join_start", "node", in.Address, ip, map[string]any{
		"mgmt_iface": in.MgmtIface, "mgmt_cidr": in.MgmtCIDR,
		"cluster_iface": in.ClusterIface, "cluster_cidr": in.ClusterCIDR, "bootstrap": in.Bootstrap,
	})
	go s.runJoin(id, in, p, ip)
	return id, nil
}

func ipOfCIDR(cidr string) string {
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}

func (s *Service) runJoin(id string, in JoinInput, p *Principal, ip string) {
	fail := func(step, msg string) {
		s.joins.set(id, func(st *JoinState) {
			st.Status = "failed"
			st.Step = step
			st.Err = msg
			st.FinishedAt = time.Now().UnixMilli()
		})
		s.audit(p, p.OrgID, "node.join_failed", "node", in.Address, ip, map[string]any{"step": step, "error": msg})
	}
	step := func(status, step string) {
		s.joins.set(id, func(st *JoinState) { st.Status = status; st.Step = step })
	}

	// 1. Connect (TOFU: capture + pin the host key for the rest of the join).
	step("preflight", "connecting over SSH")
	r, fp, err := remoteprov.Dial(in.Address, in.SSHUser, in.SSHPass, in.SSHKey)
	if err != nil {
		fail("connect", err.Error())
		return
	}
	// 2. Preflight: sudo + interfaces.
	if err := remoteprov.Preflight(r, in.MgmtIface, in.ClusterIface); err != nil {
		r.Close()
		fail("preflight", err.Error())
		return
	}
	// Grab the node hostname for a friendly name.
	name := in.Address
	if out, _, code, e := r.Run("hostname", nil); e == nil && code == 0 && strings.TrimSpace(out) != "" {
		name = strings.TrimSpace(out)
	}
	s.joins.set(id, func(st *JoinState) { st.Name = name })

	// 3. Apply network with reboot-safe rollback. Window must exceed verify+confirm.
	const rollbackSec = 300
	content := remoteprov.RenderJoinNetplan(remoteprov.JoinConfig{
		MgmtIface: in.MgmtIface, MgmtCIDR: in.MgmtCIDR, Gateway: in.Gateway, DNS: in.DNS,
		ClusterIface: in.ClusterIface, ClusterCIDR: in.ClusterCIDR,
	})
	step("applying", "pushing network config + arming rollback")
	if err := remoteprov.ArmAndApply(r, content, rollbackSec); err != nil {
		_ = remoteprov.Restore(r)
		r.Close()
		fail("apply", err.Error())
		return
	}
	r.Close() // the mgmt IP is changing; this session will drop.

	// 4. VERIFY from the control node: the node must become reachable on the NEW
	//    mgmt IP. If not, do nothing — the remote watchdog reverts at rollbackSec.
	newAddr := ipOfCIDR(in.MgmtCIDR)
	step("verifying", "waiting for "+newAddr+" to come up")
	if !waitTCP(net.JoinHostPort(newAddr, "22"), 120*time.Second) {
		fail("verify", "node did not become reachable on "+newAddr+":22 within 120s — it auto-reverted to its original address")
		return
	}

	// 5. CONFIRM: re-connect to the new IP (host key pinned) and disarm rollback.
	step("confirming", "disarming rollback on "+newAddr)
	var r2 *remoteprov.SSHRunner
	var cerr error
	for i := 0; i < 5; i++ {
		r2, cerr = remoteprov.DialPinned(newAddr, in.SSHUser, in.SSHPass, in.SSHKey, fp)
		if cerr == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if cerr != nil {
		fail("confirm", "reached "+newAddr+" but could not SSH back to confirm: "+cerr.Error()+" (node will auto-revert)")
		return
	}
	defer r2.Close()
	if err := remoteprov.Confirm(r2); err != nil {
		fail("confirm", "could not disarm rollback: "+err.Error()+" (node will auto-revert)")
		return
	}

	// 6. Optional best-effort bootstrap of vdxd (network is already permanent).
	if in.Bootstrap {
		step("bootstrapping", "installing vdxd")
		if err := s.bootstrapVdxd(r2, in); err != nil {
			// Non-fatal: the node is configured + reachable; admin can retry install.
			s.joins.set(id, func(st *JoinState) { st.Err = "network OK; vdxd install failed: " + err.Error() })
			s.audit(p, p.OrgID, "node.bootstrap_failed", "node", newAddr, ip, map[string]any{"error": err.Error()})
		}
	}

	// 7. Register the node.
	if _, err := s.cl.AddNode(name, newAddr, in.SSHUser); err != nil {
		s.audit(p, p.OrgID, "node.register_failed", "node", newAddr, ip, map[string]any{"error": err.Error()})
	}
	s.joins.set(id, func(st *JoinState) {
		st.Status = "done"
		st.Step = "joined"
		st.NewAddr = newAddr
		st.FinishedAt = time.Now().UnixMilli()
	})
	s.audit(p, p.OrgID, "node.join", "node", newAddr, ip, map[string]any{"name": name, "mgmt": in.MgmtCIDR, "cluster": in.ClusterCIDR, "host_key": fp})
}

// bootstrapVdxd pushes this host's vdxd binary + a minimal config + a systemd unit
// to the new node and starts it. Best-effort; failures do not undo the network.
func (s *Service) bootstrapVdxd(r *remoteprov.SSHRunner, in JoinInput) error {
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("read local vdxd binary: %w", err)
	}
	if err := remoteprov.PutRoot(r, "/usr/local/bin/vdxd", self, "0755"); err != nil {
		return err
	}
	bindIP := ipOfCIDR(in.MgmtCIDR)
	cfg := fmt.Sprintf("[server]\n  listen = \"%s:8766\"\n", bindIP)
	if err := remoteprov.PutRoot(r, "/etc/vdxclone/config.toml", []byte(cfg), "0644"); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=VXVisor daemon\nAfter=network-online.target\n[Service]\nExecStart=/usr/local/bin/vdxd serve\nRestart=on-failure\nUser=root\n[Install]\nWantedBy=multi-user.target\n"
	if err := remoteprov.PutRoot(r, "/etc/systemd/system/vdxd.service", []byte(unit), "0644"); err != nil {
		return err
	}
	if _, _, code, _ := r.SudoRun("mkdir -p /var/lib/vdxclone && systemctl daemon-reload && systemctl enable --now vdxd", nil); code != 0 {
		return fmt.Errorf("enable vdxd service failed")
	}
	return nil
}

// waitTCP dials addr until it connects or the deadline passes.
func waitTCP(addr string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			c.Close()
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
