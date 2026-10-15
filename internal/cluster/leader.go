package cluster

import (
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"vdxclone/internal/gossip"
)

// Role runs leader election over the authenticated gossip mesh and drives the
// floating management VIP through promote/demote callbacks. Exactly one node in
// a healthy cluster holds leadership (the "control node" for the single pane and
// the owner of the VIP); every node still runs its own VMs (active/active).
//
// Election policy (tuned for a 2-node cluster with no true majority quorum):
//   - Leadership is a gossiped, term-stamped lease and is NON-PREEMPTIVE: a
//     healthy visible leader is always accepted, so a recovered primary does not
//     wrest the VIP back from a secondary that took over (no double-outage
//     failback — critic M7).
//   - The PRIMARY node claims leadership whenever no leader is visible, and keeps
//     it on a cluster-link-only partition (it never sees a higher-term leader).
//   - A SECONDARY promotes ONLY when no leader is visible, no primary is alive in
//     gossip, AND a MANDATORY management-side liveness probe of the last-known
//     primary fails (critic B2). If the primary still answers on mgmt it is alive
//     but partitioned — the secondary stands down, so the VIP is never duplicated.
//
// With exactly 2 nodes there is no protection against a primary that is hung but
// still answers mgmt probes; that needs a 3rd node / witness and is documented.
type Role struct {
	g         *gossip.Cluster
	self      string
	primary   bool
	adminPort int

	mu         sync.RWMutex
	isLeader   bool
	term       uint64
	leaderName string
	leaderVIP  string
	leaderMgmt string
	leaderAddr string // leader's cluster-net address (for peer-API calls)
	vip        string // our acquired VIP (set by the VIP manager once leased)

	// seenMgmt remembers every node's mgmt address even after it drops out of the
	// live membership, so we can probe a vanished leader for real liveness.
	seenMgmt map[string]string
	// lastLeader is the most recent leader we observed (any node, incl. self). It
	// is NOT cleared when the leader vanishes, so a claim decision can probe it.
	lastLeader string

	onPromote func() // called when THIS node becomes leader (acquire VIP)
	onDemote  func() // called when THIS node loses leadership (release VIP)
}

// NewRole builds the election role. adminPort is the mgmt-UI port peers probe
// for liveness. primary marks the startup/tiebreak-preferred node.
func NewRole(g *gossip.Cluster, selfName string, primary bool, adminPort int) *Role {
	if adminPort <= 0 {
		adminPort = 8766
	}
	return &Role{
		g: g, self: selfName, primary: primary, adminPort: adminPort,
		seenMgmt: map[string]string{},
	}
}

// OnPromote/OnDemote register VIP lifecycle callbacks. Promote acquires the VIP;
// demote releases it. They run synchronously inside Tick, so keep them quick.
func (r *Role) OnPromote(f func()) { r.onPromote = f }
func (r *Role) OnDemote(f func())  { r.onDemote = f }

// IsLeader reports whether this node currently holds the lease.
func (r *Role) IsLeader() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.isLeader }

// AcquiredVIP returns the floating VIP THIS node currently holds (bare IP), or ""
// if it holds none. Only the leader holds the VIP, so a non-empty value also means
// "this node is serving the management VIP" — used to pick the unified cluster UI.
func (r *Role) AcquiredVIP() string { r.mu.RLock(); defer r.mu.RUnlock(); return r.vip }

// LeaderInfo returns the current leader's name, mgmt address and VIP (as this
// node sees them). Name is "" when no leader is visible.
func (r *Role) LeaderInfo() (name, mgmt, vip string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.leaderName, r.leaderMgmt, r.leaderVIP
}

// LeaderClusterAddr returns the current leader's cluster-net address for peer-API
// calls (account pull, etc.), or "" if we are the leader / none is visible.
func (r *Role) LeaderClusterAddr() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.isLeader {
		return ""
	}
	return r.leaderAddr
}

// PeerInfo is a cluster member as seen via gossip, for aggregation/proxying.
type PeerInfo struct {
	Name        string
	ClusterAddr string // cluster-net IP (peer-API target)
	MgmtAddr    string
	Alive       bool
	Leader      bool
	Self        bool
}

// Peers returns the current cluster view (including self) for the single-pane
// aggregator: who is alive, their cluster-net address, and who leads.
func (r *Role) Peers() []PeerInfo {
	members := r.g.Members()
	out := make([]PeerInfo, 0, len(members))
	for _, m := range members {
		out = append(out, PeerInfo{
			Name:        m.Name,
			ClusterAddr: m.Address,
			MgmtAddr:    m.MgmtAddr,
			Alive:       m.Alive,
			Leader:      m.Leader,
			Self:        m.Name == r.self,
		})
	}
	return out
}

// SelfName returns this node's name.
func (r *Role) SelfName() string { return r.self }

// SetVIP records the VIP this node acquired and re-gossips it under our lease so
// followers can display/forward to it. Called by the VIP manager after a lease.
func (r *Role) SetVIP(vip string) {
	r.mu.Lock()
	r.vip = vip
	leader, term := r.isLeader, r.term
	r.mu.Unlock()
	if leader {
		r.g.SetLeadership(true, term, vip)
	}
}

// Run drives election on a sub-second ticker until stop is closed. A tight tick
// keeps failover to a second or two rather than riding the 30s health loop.
func (r *Role) Run(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	r.tick()
	for {
		select {
		case <-stop:
			r.stepDown()
			return
		case <-t.C:
			r.tick()
		}
	}
}

func (r *Role) tick() {
	members := r.g.Members()
	self := r.g.Self()

	// Record every node's mgmt address (sticky, survives member drop-out).
	var maxTerm uint64
	var leader *gossip.Member
	var alivePrimary *gossip.Member
	aliveNames := map[string]bool{}
	for i := range members {
		m := &members[i]
		if m.MgmtAddr != "" {
			r.seenMgmt[m.Name] = m.MgmtAddr
		}
		if !m.Alive {
			continue
		}
		aliveNames[m.Name] = true
		if m.Term > maxTerm {
			maxTerm = m.Term
		}
		if m.Primary {
			alivePrimary = m
		}
		if m.Leader {
			if leader == nil || m.Term > leader.Term ||
				(m.Term == leader.Term && betterCandidate(m, leader)) {
				leader = m
			}
		}
	}
	if leader != nil {
		r.lastLeader = leader.Name // remember for liveness-probe on a later vanish
	}

	switch {
	case leader != nil && leader.Name != r.self:
		// A healthy leader exists elsewhere — accept it (non-preemptive).
		r.follow(leader.Name, leader.MgmtAddr, leader.VIP, leader.Address)
	case leader != nil && leader.Name == r.self:
		// We are the visible leader — stay (renew our advertisement).
		r.stay(self.Term, self.VIP)
	default:
		// No leader visible → decide whether to claim.
		if r.shouldClaim(alivePrimary, aliveNames) {
			r.claim(maxTerm + 1)
		} else {
			r.follow("", "", "", "")
		}
	}
}

// shouldClaim decides whether to seize leadership when none is visible. The
// MANDATORY rule that prevents a dual VIP on a cluster-link-only partition: never
// claim while the last-known leader still answers on its management interface —
// that means it is alive and merely partitioned from us on the cluster NIC, and
// claiming would bring up a SECOND copy of the VIP. This gate applies to the
// primary too (its unconditional claim was the split-brain hole).
func (r *Role) shouldClaim(alivePrimary *gossip.Member, aliveNames map[string]bool) bool {
	// If a prior leader is known, is not us, and has VANISHED from gossip, it must
	// be confirmed truly down via a mgmt probe before we take over — otherwise it
	// is alive but partitioned on the cluster NIC and claiming would dual-own the
	// VIP. If the prior leader is still alive+visible (it just stepped down), there
	// is no partition: skip the probe and run a normal election.
	if r.lastLeader != "" && r.lastLeader != r.self && !aliveNames[r.lastLeader] {
		if mgmt := r.seenMgmt[r.lastLeader]; mgmt != "" {
			if r.probeMgmt(mgmt) {
				log.Printf("cluster: last leader %s still answers on mgmt %s — standing down (partition, not a failure)", r.lastLeader, mgmt)
				return false
			}
			log.Printf("cluster: last leader %s down (gossip-dead + mgmt probe failed) — eligible to take over", r.lastLeader)
			// Fall through to the primary/secondary tiebreak below.
		}
	}
	// No prior leader known (cold start), or the prior leader is confirmed down.
	if r.primary {
		return true // primary wins the election / takes over a dead leader
	}
	// Secondary: defer to an alive primary (let it claim); only take over if the
	// primary is not alive in gossip (and, if we had a prior leader, it was just
	// confirmed down above).
	if alivePrimary != nil {
		return false
	}
	// No alive primary either. If we never saw a leader at all, wait a beat for
	// the primary rather than racing it at boot.
	if r.lastLeader == "" {
		return false
	}
	return true
}

// probeMgmt returns true if the mgmt admin port answers (primary is alive).
func (r *Role) probeMgmt(mgmt string) bool {
	host := hostOnly(mgmt)
	if host == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(r.adminPort)), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (r *Role) claim(term uint64) {
	r.mu.Lock()
	wasLeader := r.isLeader
	r.isLeader, r.term, r.leaderName = true, term, r.self
	vip := r.vip
	r.mu.Unlock()
	r.g.SetLeadership(true, term, vip)
	if !wasLeader {
		log.Printf("cluster: claiming leadership (term %d)", term)
		if r.onPromote != nil {
			r.onPromote()
		}
	}
}

func (r *Role) stay(term uint64, vip string) {
	r.mu.Lock()
	r.leaderName, r.leaderMgmt, r.leaderVIP = r.self, "", vip
	r.mu.Unlock()
}

func (r *Role) follow(name, mgmt, vip, addr string) {
	r.mu.Lock()
	wasLeader := r.isLeader
	r.isLeader = false
	r.leaderName, r.leaderMgmt, r.leaderVIP, r.leaderAddr = name, mgmt, vip, addr
	r.mu.Unlock()
	if wasLeader {
		log.Printf("cluster: yielding leadership to %q", name)
		r.g.SetLeadership(false, 0, "")
		if r.onDemote != nil {
			r.onDemote()
		}
	}
}

// Shutdown synchronously relinquishes leadership and releases the VIP. Unlike
// closing the Run stop-channel (which only signals the goroutine and races the
// process exit), this runs the demote inline so the VIP macvlan is torn down
// before the daemon exits — no stale dual-VIP after a graceful stop.
func (r *Role) Shutdown() { r.stepDown() }

func (r *Role) stepDown() {
	r.mu.Lock()
	wasLeader := r.isLeader
	r.isLeader = false
	r.mu.Unlock()
	if wasLeader {
		r.g.SetLeadership(false, 0, "")
		if r.onDemote != nil {
			r.onDemote()
		}
	}
}

// betterCandidate breaks an equal-term tie deterministically: prefer the primary,
// then the earliest start, then the lexically-lowest name.
func betterCandidate(a, b *gossip.Member) bool {
	if a.Primary != b.Primary {
		return a.Primary
	}
	if a.Started != b.Started {
		return a.Started < b.Started
	}
	return a.Name < b.Name
}
