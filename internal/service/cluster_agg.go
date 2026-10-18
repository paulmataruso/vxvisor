package service

import (
	"encoding/json"
	"fmt"
	"log"

	"vdxclone/internal/peer"
	"vdxclone/internal/session"
)

// ClusterAPIPort is the fixed port the node-to-node peer API listens on (bound to
// the cluster NIC only).
const ClusterAPIPort = peer.APIPort

// ClusterVM is one VM as shown in the cluster-wide (single-pane) view, tagged
// with the node that hosts it.
type ClusterVM struct {
	Node     string `json:"node"`
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"mem"`
	Kind     string `json:"kind"`
	Owner    string `json:"owner"`
	Storage  string `json:"storage"` // disk backend + pool/target
}

// AllLocalSessions lists every VM on THIS node (all orgs), tagged with node. It
// backs the peer API's /sessions endpoint and the local half of the aggregator.
func (s *Service) AllLocalSessions(node string) ([]ClusterVM, error) {
	rows, err := s.db.Query(`SELECT s.id,s.name,s.state,s.cpus,s.memory_mb,s.kind,COALESCE(u.username,''),
		COALESCE(s.disk_backend,'qcow2'),COALESCE(s.disk_path,'')
		FROM sessions s LEFT JOIN users u ON u.id=s.owner_id
		WHERE s.deleted_at IS NULL ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClusterVM
	for rows.Next() {
		v := ClusterVM{Node: node}
		var backend, diskPath string
		if err := rows.Scan(&v.ID, &v.Name, &v.State, &v.CPUs, &v.MemoryMB, &v.Kind, &v.Owner, &backend, &diskPath); err == nil {
			v.Storage = session.StorageLabelFor(backend, diskPath)
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// ClusterVMs returns the cluster-wide VM list: this node's VMs plus every alive
// peer's, fetched over the authenticated peer API. Admin-only (the single pane is
// an instance-wide view). On a single-host install it is just the local list.
func (s *Service) ClusterVMs(p *Principal) ([]ClusterVM, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	self := "local"
	if s.role != nil {
		self = s.role.SelfName()
	}
	out, err := s.AllLocalSessions(self)
	if err != nil {
		return nil, err
	}
	if s.role == nil || s.peerc == nil {
		return out, nil
	}
	for _, pr := range s.role.Peers() {
		if pr.Self || !pr.Alive || pr.ClusterAddr == "" {
			continue
		}
		base := peer.BaseURL(pr.ClusterAddr, ClusterAPIPort)
		body, code, err := s.peerc.Get(base, "/cluster/v1/sessions")
		if err != nil || code != 200 {
			log.Printf("cluster: aggregate from %s failed (code=%d err=%v)", pr.Name, code, err)
			continue
		}
		var vms []ClusterVM
		if json.Unmarshal(body, &vms) == nil {
			out = append(out, vms...)
		}
	}
	return dedupVMs(out), nil
}

// dedupVMs collapses the brief window during a migration commit where the same
// VM id is reported by both the source (row not yet deleted) and the destination
// (just adopted): keep the more-alive copy so the single pane never shows a VM
// twice. State rank: running > paused > anything else.
func dedupVMs(in []ClusterVM) []ClusterVM {
	rank := func(st string) int {
		switch st {
		case "running":
			return 2
		case "paused":
			return 1
		default:
			return 0
		}
	}
	idx := map[string]int{}
	out := make([]ClusterVM, 0, len(in))
	for _, v := range in {
		if i, ok := idx[v.ID]; ok {
			if rank(v.State) > rank(out[i].State) {
				out[i] = v
			}
			continue
		}
		idx[v.ID] = len(out)
		out = append(out, v)
	}
	return out
}

// ClusterMigrations returns this node's in-flight/recent migrations plus every
// alive peer's, for the single-pane migration-status card served on the VIP.
// Each migration is driven by exactly one node (the source owner) and lives only
// in that node's tracker, so the union never double-counts. Admin-only.
func (s *Service) ClusterMigrations(p *Principal) ([]MigrationState, error) {
	if p == nil || !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	out := s.migtr.snapshot()
	if s.role == nil || s.peerc == nil {
		return out, nil
	}
	for _, pr := range s.role.Peers() {
		if pr.Self || !pr.Alive || pr.ClusterAddr == "" {
			continue
		}
		base := peer.BaseURL(pr.ClusterAddr, ClusterAPIPort)
		body, code, err := s.peerc.Get(base, "/cluster/v1/migrations")
		if err != nil || code != 200 {
			continue
		}
		var ms []MigrationState
		if json.Unmarshal(body, &ms) == nil {
			out = append(out, ms...)
		}
	}
	return out, nil
}

// ProxyVMAction performs a lifecycle action on a VM that lives on a remote node,
// over the peer API. Returns ErrNotFound if the node is not an alive peer.
func (s *Service) ProxyVMAction(p *Principal, node, id, action, ip string) error {
	if !p.IsAdmin || s.role == nil || s.peerc == nil {
		return ErrUnauthorized
	}
	for _, pr := range s.role.Peers() {
		if pr.Name != node || pr.Self || !pr.Alive || pr.ClusterAddr == "" {
			continue
		}
		base := peer.BaseURL(pr.ClusterAddr, ClusterAPIPort)
		_, code, err := s.peerc.Post(base, fmt.Sprintf("/cluster/v1/sessions/%s/%s", id, action))
		if err != nil {
			return fmt.Errorf("proxy %s to %s: %w", action, node, err)
		}
		if code != 200 {
			return fmt.Errorf("remote %s on %s returned %d", action, node, code)
		}
		s.audit(p, p.OrgID, "session."+action, "session", id, ip, map[string]any{"node": node, "proxied": true})
		return nil
	}
	return ErrNotFound
}

// LaunchMigrationReceiver starts an inbound-migration QEMU on this node (called
// by the peer API when this node is a migration destination).
func (s *Service) LaunchMigrationReceiver(specB64 string, port int) (int, error) {
	return s.mgr.LaunchReceiver(specB64, port)
}

// LaunchBlockMigrationReceiver starts an inbound block-live (NBD) receiver on this
// node: it creates the target disk at the source's virtual size, launches the
// incoming QEMU bound to bindIP, and exports the disk over NBD for the source to
// mirror into.
func (s *Service) LaunchBlockMigrationReceiver(specB64 string, port int, bindIP string, vsize int64) (session.BlockReceiverInfo, error) {
	return s.mgr.LaunchBlockReceiver(specB64, port, bindIP, vsize)
}

// StopBlockExport tears down the NBD export on this (destination) node at the
// pre-switchover point, before the guest resumes.
func (s *Service) StopBlockExport(id string) { s.mgr.StopBlockExport(id) }

// LocalVMAction performs a lifecycle action on a VM hosted on THIS node. It is
// invoked by the peer API on behalf of an admin who was already authenticated on
// the calling (leader) node, so it acts at admin level without a principal.
func (s *Service) LocalVMAction(id, action string) error {
	switch action {
	case "start":
		_, err := s.mgr.Start(id)
		return err
	case "stop":
		return s.mgr.Stop(id)
	case "restart":
		_ = s.mgr.Stop(id)
		_, err := s.mgr.Start(id)
		return err
	case "delete":
		// Soft-delete to Trash (same behavior as the per-host Delete button),
		// so an admin can delete a VM from the unified VIP view regardless of
		// which node owns it.
		return s.mgr.Delete(id)
	default:
		return fmt.Errorf("unknown action %q", action)
	}
}

// ClusterVMAction dispatches a lifecycle action from the single-pane view to the
// right node: performed locally if the VM is on this node, otherwise proxied to
// the owning node over the peer API. Admin-only.
func (s *Service) ClusterVMAction(p *Principal, node, id, action, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	self := "local"
	if s.role != nil {
		self = s.role.SelfName()
	}
	if node == self || node == "" || s.role == nil {
		if err := s.LocalVMAction(id, action); err != nil {
			return err
		}
		s.audit(p, p.OrgID, "session."+action, "session", id, ip, map[string]any{"node": self})
		return nil
	}
	return s.ProxyVMAction(p, node, id, action, ip)
}

// ConsoleInfo is a VM's console details, served over the peer API so the leader
// can render/relay the console of a VM hosted on another node.
type ConsoleInfo struct {
	Name        string `json:"name"`
	VNCPassword string `json:"vncpw"`
	VNCPort     int    `json:"vncport"`
}

// LocalConsoleInfo returns console details for a VM hosted on THIS node (peer API).
func (s *Service) LocalConsoleInfo(id string) (ConsoleInfo, error) {
	sess, err := s.mgr.Get(id)
	if err != nil {
		return ConsoleInfo{}, err
	}
	if !s.mgr.Running(sess) {
		return ConsoleInfo{}, fmt.Errorf("session not running")
	}
	return ConsoleInfo{Name: sess.Name, VNCPassword: sess.VNCPassword, VNCPort: sess.VNCPort}, nil
}

// nodeOwnerAddr finds the cluster-net address of the node hosting VM id by asking
// each alive peer for its session list. "" if not found on any peer.
func (s *Service) nodeOwnerAddr(id string) string {
	if s.role == nil || s.peerc == nil {
		return ""
	}
	for _, pr := range s.role.Peers() {
		if pr.Self || !pr.Alive || pr.ClusterAddr == "" {
			continue
		}
		body, code, err := s.peerc.Get(peer.BaseURL(pr.ClusterAddr, peer.APIPort), "/cluster/v1/sessions")
		if err != nil || code != 200 {
			continue
		}
		var vms []ClusterVM
		if json.Unmarshal(body, &vms) != nil {
			continue
		}
		for _, v := range vms {
			if v.ID == id {
				return pr.ClusterAddr
			}
		}
	}
	return ""
}

// ConsoleTargetCluster resolves a console target cluster-wide. If the VM is local
// it returns the full session and owner "". If it lives on another node (admin,
// cluster mode) it fetches the remote console info and returns a synthesized
// session plus the owner's cluster-net address for the WebSocket relay.
func (s *Service) ConsoleTargetCluster(p *Principal, id string) (*session.Session, string, error) {
	sess, err := s.ConsoleTarget(p, id)
	if err == nil {
		return sess, "", nil
	}
	if s.role == nil || s.peerc == nil || !p.IsAdmin {
		return nil, "", err
	}
	addr := s.nodeOwnerAddr(id)
	if addr == "" {
		return nil, "", err
	}
	body, code, gerr := s.peerc.Get(peer.BaseURL(addr, peer.APIPort), "/cluster/v1/console/"+id+"/info")
	if gerr != nil || code != 200 {
		return nil, "", fmt.Errorf("remote console info unavailable: %v (code %d)", gerr, code)
	}
	var ci ConsoleInfo
	if json.Unmarshal(body, &ci) != nil {
		return nil, "", fmt.Errorf("bad remote console info")
	}
	return &session.Session{ID: id, Name: ci.Name, VNCPassword: ci.VNCPassword}, addr, nil
}

// LocalSerialSock returns the serial-console unix socket for a VM hosted on THIS
// node, or an error if the VM isn't found/running or has no serial socket yet
// (VMs launched before serial support, or not restarted since). Peer-API safe
// (no principal) — the caller already authenticated on the leader.
func (s *Service) LocalSerialSock(id string) (string, error) {
	sess, err := s.mgr.Get(id)
	if err != nil {
		return "", err
	}
	if !s.mgr.Running(sess) {
		return "", fmt.Errorf("session not running")
	}
	sock, ok, err := s.mgr.SerialSockFor(id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("serial console not available — restart the VM to enable it")
	}
	return sock, nil
}

// SerialTargetCluster resolves a serial-console target cluster-wide. If the VM is
// local it returns the socket path and owner "". If it lives on another node
// (admin, cluster mode) it returns owner = that node's cluster-net address so the
// web layer can relay the serial websocket to it.
func (s *Service) SerialTargetCluster(p *Principal, id string) (sock string, owner string, err error) {
	sess, cerr := s.ConsoleTarget(p, id)
	if cerr == nil {
		local, lerr := s.LocalSerialSock(sess.ID)
		if lerr != nil {
			return "", "", lerr
		}
		return local, "", nil
	}
	if s.role == nil || s.peerc == nil || !p.IsAdmin {
		return "", "", cerr
	}
	addr := s.nodeOwnerAddr(id)
	if addr == "" {
		return "", "", cerr
	}
	return "", addr, nil
}

// RemoteVMOwnerMgmt reports the MGMT address of the peer that owns VM id, or
// ok=false when the VM is local (or not found on any peer). Local VMs are checked
// first (a cheap DB lookup) so the common case never touches the network.
func (s *Service) RemoteVMOwnerMgmt(id string) (mgmtAddr string, ok bool) {
	if id == "" || s.role == nil || s.peerc == nil {
		return "", false
	}
	if _, err := s.mgr.Get(id); err == nil {
		return "", false // owned locally
	}
	for _, pr := range s.role.Peers() {
		if pr.Self || !pr.Alive || pr.ClusterAddr == "" || pr.MgmtAddr == "" {
			continue
		}
		body, code, err := s.peerc.Get(peer.BaseURL(pr.ClusterAddr, peer.APIPort), "/cluster/v1/sessions")
		if err != nil || code != 200 {
			continue
		}
		var vms []ClusterVM
		if json.Unmarshal(body, &vms) != nil {
			continue
		}
		for _, v := range vms {
			if v.ID == id {
				return pr.MgmtAddr, true
			}
		}
	}
	return "", false
}

// ClusterLeader returns the current leader name and VIP for the single-pane
// banner (empty when not clustered).
func (s *Service) ClusterLeader() (name, vip string, isLeaderHere bool) {
	if s.role == nil {
		return "", "", false
	}
	n, _, v := s.role.LeaderInfo()
	return n, v, s.role.IsLeader()
}

// ClusterVIP returns the floating management VIP this node currently serves (bare
// IP), or "" if this node holds no VIP (a follower, or a single-host install).
// The web layer compares the request's destination IP against this to decide
// between the unified cluster UI (VIP) and the standalone host UI (node IP).
func (s *Service) ClusterVIP() string {
	if s.role == nil {
		return ""
	}
	return s.role.AcquiredVIP()
}

// ClusterSelfName returns this node's cluster name ("" if not clustered).
func (s *Service) ClusterSelfName() string {
	if s.role == nil {
		return ""
	}
	return s.role.SelfName()
}

// ClusterEnabledRole reports whether this node is part of a cluster (has a role).
func (s *Service) ClusterEnabledRole() bool { return s.role != nil }

// PullAccountsIfFollower pulls the account snapshot from the leader and applies it
// locally. No-op on the leader or a single-host install. Called by a worker loop.
func (s *Service) PullAccountsIfFollower() {
	if s.role == nil || s.peerc == nil || s.role.IsLeader() {
		return
	}
	addr := s.role.LeaderClusterAddr()
	if addr == "" {
		return
	}
	base := peer.BaseURL(addr, ClusterAPIPort)
	body, code, err := s.peerc.Get(base, "/cluster/v1/accounts")
	if err != nil || code != 200 {
		return
	}
	if err := s.ApplyAccountSnapshot(body); err != nil {
		log.Printf("cluster: apply account snapshot failed: %v", err)
	}
}

// guardClusterWrite refuses an account-mutating operation on a follower, so the
// leader's authoritative snapshot is never clobbered by a stray local write.
// Callers surface this to the operator ("manage accounts at the cluster VIP").
func (s *Service) guardClusterWrite() error {
	if s.role != nil && !s.role.IsLeader() {
		return fmt.Errorf("this node is a cluster follower — manage accounts at the cluster VIP (the leader)")
	}
	return nil
}
