package service

import (
	"sort"
	"sync"
	"time"
)

// migTracker records in-flight and recently-finished live migrations driven by
// THIS node, so the web layer can surface a live progress card. A migration is
// always driven by the node that owns the source VM, so each migration lives in
// exactly one node's tracker (no cross-node double counting); the VIP aggregates
// every node's tracker for the single-pane view.
type migTracker struct {
	mu sync.Mutex
	m  map[string]*MigrationState
}

// MigrationState is one migration's live status (JSON-encoded for /api/migrations).
type MigrationState struct {
	SessionID  string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	SrcNode    string `json:"src"`
	DstNode    string `json:"dst"`
	Status     string `json:"status"` // starting|active|completed|failed|cancelled
	Remaining  int64  `json:"remaining"`
	Total      int64  `json:"total"`
	Pct        int    `json:"pct"`
	Err        string `json:"err,omitempty"`
	StartedAt  int64  `json:"started"`            // unix millis
	FinishedAt int64  `json:"finished,omitempty"` // unix millis, 0 while running
}

func newMigTracker() *migTracker { return &migTracker{m: map[string]*MigrationState{}} }

// retainFinishedMS keeps a finished migration visible this long after it ends,
// so the card can show the completed/failed result before it disappears.
const retainFinishedMS = 20000

// begin registers a new migration, returning (state, true). It refuses with
// (nil, false) when a migration for the same session is already in flight — the
// single-flight guard that stops a double-submit from driving two concurrent
// `migrate` commands at the same source QEMU (which would corrupt the transfer
// and can orphan/duplicate session rows).
func (t *migTracker) begin(id, name, kind, src, dst string) (*MigrationState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[id]; ok && (e.Status == "starting" || e.Status == "active") {
		return nil, false
	}
	st := &MigrationState{
		SessionID: id, Name: name, Kind: kind, SrcNode: src, DstNode: dst,
		Status: "starting", StartedAt: time.Now().UnixMilli(),
	}
	t.m[id] = st
	return st, true
}

// update records a progress tick. QEMU's fine-grained statuses (setup/device/
// pre-switchover/active…) collapse to "active"; terminal statuses pass through.
func (t *migTracker) update(id, status string, remaining, total int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[id]
	if st == nil {
		return
	}
	switch status {
	case "completed", "failed", "cancelled":
		st.Status = status
	case "":
		// leave status as-is
	default:
		st.Status = "active"
	}
	st.Remaining, st.Total = remaining, total
	if total > 0 { // guard: total is 0 during setup
		done := total - remaining
		if done < 0 {
			done = 0
		}
		st.Pct = int(done * 100 / total)
		if st.Pct > 100 {
			st.Pct = 100
		}
	}
}

// finish marks a migration terminal with an outcome and optional error.
func (t *migTracker) finish(id, status, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.m[id]
	if st == nil {
		return
	}
	st.Status = status
	st.Err = errMsg
	st.FinishedAt = time.Now().UnixMilli()
	if status == "completed" {
		st.Pct = 100
	}
}

// snapshot returns active migrations plus those finished within the retain
// window, oldest first, and garbage-collects anything older.
func (t *migTracker) snapshot() []MigrationState {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UnixMilli()
	out := make([]MigrationState, 0, len(t.m))
	for id, st := range t.m {
		if st.FinishedAt > 0 && now-st.FinishedAt > retainFinishedMS {
			delete(t.m, id)
			continue
		}
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt < out[j].StartedAt })
	return out
}

// MigrationsSnapshot is the local tracker's view (exported for the web layer).
func (s *Service) MigrationsSnapshot() []MigrationState { return s.migtr.snapshot() }
