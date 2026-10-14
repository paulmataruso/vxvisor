// Package policy defines the licensing/quota enforcement seam.
//
// The real enforcer (local signed license + optional quotas/metering) is a
// later milestone. Until then the daemon runs NoopEnforcer, which allows
// everything. Call sites in the session service already invoke this interface
// so the real implementation drops in without touching them.
package policy

import "context"

// SessionKind distinguishes ephemeral desktops from persistent server VMs.
type SessionKind string

const (
	KindDesktop SessionKind = "desktop"
	KindServer  SessionKind = "server"
)

// Counts is the current per-org usage the enforcer weighs against quota.
type Counts struct {
	RunningSessions int
	ServerVMs       int
	StorageGB       int
}

// Quota is the per-org cap set. Zero means unlimited.
type Quota struct {
	SeatCap    int
	ServerCap  int
	StorageCap int
}

// UsageSample is one metering observation, fed to OnUsage each interval.
type UsageSample struct {
	OrgID     int64
	SessionID string
	Seconds   int
}

// Decision is an allow/deny with a human-readable reason on deny.
type Decision struct {
	Allow  bool
	Reason string
}

var allow = Decision{Allow: true}

// Enforcer gates session creation/start and receives usage samples.
type Enforcer interface {
	CanStartSession(ctx context.Context, org int64, kind SessionKind, cur Counts) Decision
	CanCreateServer(ctx context.Context, org int64, cur Counts) Decision
	OnUsage(ctx context.Context, sample UsageSample)
	Quota(ctx context.Context, org int64) Quota
}

// NoopEnforcer permits everything with unlimited quota and drops usage. It is
// the MVP enforcer; the real one arrives in the licensing milestone.
type NoopEnforcer struct{}

func (NoopEnforcer) CanStartSession(context.Context, int64, SessionKind, Counts) Decision {
	return allow
}
func (NoopEnforcer) CanCreateServer(context.Context, int64, Counts) Decision { return allow }
func (NoopEnforcer) OnUsage(context.Context, UsageSample)                    {}
func (NoopEnforcer) Quota(context.Context, int64) Quota                      { return Quota{} }
