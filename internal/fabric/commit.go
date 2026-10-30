package fabric

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Replication of the intent (docs/FABRIC.md §14 D3): a write is a UNANIMOUS
// two-phase commit across every member — every node in any fabric before or
// after the change, plus the coordinator.
//
//  1. Sync: the coordinator fetches every member's intent and adopts the highest
//     version, so it never proposes from a stale base. An unreachable member
//     refuses the write (bring it back, or evict it).
//  2. Prepare: each member checks base == its version and its own node-local
//     rules, then holds the proposal as its one pending change (it refuses a
//     second one until the first commits, aborts or expires).
//  3. Commit: each member applies the proposal it holds, by id.
//
// Two different documents can never both commit at the same version: a version
// advances only through a proposal every member prepared, and a member that
// committed refuses any proposal on the old base. A member that missed the
// commit (crash, partition) is behind, not divergent; it adopts the newer
// version on its next sync.

// Store persists one node's intent. Save replaces version base with next
// atomically and fails if the stored version isn't base.
type Store interface {
	Load() (Intent, error)
	Save(base int64, next Intent) error
}

// Proposal is one change: the whole next document.
type Proposal struct {
	ID     string `json:"id"`
	Base   int64  `json:"base"`
	Intent Intent `json:"intent"`
}

// Errors a member returns.
var (
	ErrBusy    = errors.New("another fabric change is in progress — retry in a moment")
	ErrUnknown = errors.New("this fabric change is no longer pending here (it expired or was aborted)")
)

// StaleError means the member is on another version than the proposal's base.
type StaleError struct{ Have, Base int64 }

func (e StaleError) Error() string {
	return fmt.Sprintf("fabric state changed underneath this edit (member at version %d, edit based on %d) — reload and retry", e.Have, e.Base)
}

// PendingTTL bounds how long a member holds a prepared proposal.
const PendingTTL = 30 * time.Second

// Member is one node's side of the protocol.
type Member struct {
	Store Store
	// Check is the node-local veto (an interface that isn't there, a port group
	// with instances on this node, a VNI a local VXLAN uses). nil = none.
	Check func(cur, next Intent) error
	// Applied runs after this node's intent changed (commit or adopt).
	Applied func(Intent)
	Now     func() time.Time

	mu      sync.Mutex
	pending *Proposal
	expires time.Time
}

func (m *Member) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Current returns the stored intent.
func (m *Member) Current() (Intent, error) { return m.Store.Load() }

// Prepare validates and holds p.
func (m *Member) Prepare(p Proposal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil && m.now().Before(m.expires) && m.pending.ID != p.ID {
		return ErrBusy
	}
	cur, err := m.Store.Load()
	if err != nil {
		return err
	}
	if cur.Version != p.Base || p.Intent.Version != p.Base+1 {
		return StaleError{Have: cur.Version, Base: p.Base}
	}
	next := p.Intent
	if err := next.Validate(); err != nil {
		return err
	}
	if m.Check != nil {
		if err := m.Check(cur, next); err != nil {
			return err
		}
	}
	cp := p
	m.pending, m.expires = &cp, m.now().Add(PendingTTL)
	return nil
}

// Commit applies the held proposal id.
func (m *Member) Commit(id string) error {
	m.mu.Lock()
	if m.pending == nil || m.pending.ID != id || !m.now().Before(m.expires) {
		m.mu.Unlock()
		return ErrUnknown
	}
	p := *m.pending
	m.pending = nil
	err := m.Store.Save(p.Base, p.Intent)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if m.Applied != nil {
		m.Applied(p.Intent)
	}
	return nil
}

// Abort drops the held proposal id (no-op if it isn't held).
func (m *Member) Abort(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != nil && m.pending.ID == id {
		m.pending = nil
	}
}

// Adopt replaces the local intent with a newer one from another member. It
// reports whether anything changed. A pending proposal on the old base is
// dropped (it can never commit now).
func (m *Member) Adopt(in Intent) (bool, error) {
	m.mu.Lock()
	cur, err := m.Store.Load()
	if err != nil || in.Version <= cur.Version {
		m.mu.Unlock()
		return false, err
	}
	if err := in.Validate(); err != nil {
		m.mu.Unlock()
		return false, fmt.Errorf("refusing to adopt fabric version %d: %w", in.Version, err)
	}
	if err := m.Store.Save(cur.Version, in); err != nil {
		m.mu.Unlock()
		return false, err
	}
	m.pending = nil
	m.mu.Unlock()
	if m.Applied != nil {
		m.Applied(in)
	}
	return true, nil
}

// Transport reaches the other members.
type Transport interface {
	Fetch(node string) (Intent, error)
	Prepare(node string, p Proposal) error
	Commit(node, id string) error
	Abort(node, id string)
}

// Coordinator drives a change from this node.
type Coordinator struct {
	Self  string
	Local *Member
	Net   Transport
	// Alive lists the other cluster nodes reachable right now (nil on a
	// single-host install); a member missing from it fails the write fast.
	Alive func() map[string]bool

	mu sync.Mutex // one change at a time from this node
}

// Sync adopts the newest intent among the given members (and returns it).
func (c *Coordinator) Sync(members []string) (Intent, error) {
	for _, n := range members {
		if n == c.Self {
			continue
		}
		in, err := c.Net.Fetch(n)
		if err != nil {
			return Intent{}, fmt.Errorf("fabric host %s is unreachable (%v) — bring it back, or evict it from the fabric", n, err)
		}
		if _, err := c.Local.Adopt(in); err != nil {
			return Intent{}, err
		}
	}
	return c.Local.Current()
}

// Change applies mutate to the current intent and commits it on every member.
// exclude names members that must not be asked (an evicted, dead host).
// It returns the committed intent; a member that missed only the commit phase
// is reported in lagging (it catches up on its next sync).
func (c *Coordinator) Change(exclude []string, mutate func(*Intent) error) (committed Intent, lagging []string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	skip := map[string]bool{}
	for _, n := range exclude {
		skip[n] = true
	}
	cur, err := c.Local.Current()
	if err != nil {
		return Intent{}, nil, err
	}
	members := c.members(cur, skip)
	if err := c.reachable(members); err != nil {
		return Intent{}, nil, err
	}
	if cur, err = c.Sync(members); err != nil {
		return Intent{}, nil, err
	}
	next := cur.Clone()
	if err := mutate(&next); err != nil {
		return Intent{}, nil, err
	}
	next.Version = cur.Version + 1
	if err := next.Validate(); err != nil {
		return Intent{}, nil, err
	}
	// Hosts the change adds must take part too.
	members = union(members, c.members(next, skip))
	if err := c.reachable(members); err != nil {
		return Intent{}, nil, err
	}
	p := Proposal{ID: NewUUID(), Base: cur.Version, Intent: next}
	var prepared []string
	abort := func() {
		for _, n := range prepared {
			if n == c.Self {
				c.Local.Abort(p.ID)
			} else {
				c.Net.Abort(n, p.ID)
			}
		}
	}
	for _, n := range members {
		var perr error
		if n == c.Self {
			perr = c.Local.Prepare(p)
		} else {
			perr = c.Net.Prepare(n, p)
		}
		if perr != nil {
			abort()
			if n == c.Self {
				return Intent{}, nil, perr
			}
			return Intent{}, nil, fmt.Errorf("%s refused the change: %w", n, perr)
		}
		prepared = append(prepared, n)
	}
	if err := c.Local.Commit(p.ID); err != nil {
		abort()
		return Intent{}, nil, err
	}
	for _, n := range members {
		if n == c.Self {
			continue
		}
		if err := c.Net.Commit(n, p.ID); err != nil {
			lagging = append(lagging, n)
		}
	}
	return next, lagging, nil
}

// members is every node of every fabric in in, plus self, minus skip.
func (c *Coordinator) members(in Intent, skip map[string]bool) []string {
	out := []string{c.Self}
	for _, n := range in.Nodes() {
		if n != c.Self && !skip[n] {
			out = append(out, n)
		}
	}
	return union(out, nil)
}

func (c *Coordinator) reachable(members []string) error {
	if c.Alive == nil {
		for _, n := range members {
			if n != c.Self {
				return fmt.Errorf("fabric host %s is not reachable: this node isn't in a cluster", n)
			}
		}
		return nil
	}
	alive := c.Alive()
	var down []string
	for _, n := range members {
		if n != c.Self && !alive[n] {
			down = append(down, n)
		}
	}
	if len(down) > 0 {
		return fmt.Errorf("fabric host(s) %s are down — a fabric change needs every member; bring them back or evict them", strings.Join(down, ", "))
	}
	return nil
}

// union merges and sorts, self first.
func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append(append([]string{}, a...), b...) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > 1 {
		rest := out[1:]
		sort.Strings(rest)
	}
	return out
}
