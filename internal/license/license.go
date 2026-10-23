// Package license implements the real policy.Enforcer: an offline, locally
// signed license file that caps seats / server VMs / running VMs / storage, with
// an optional operator-opt-in heartbeat.
//
// Design stance (deliberate): this replicates the *shape* of the
// decompiled vendor licensing — an HMAC-SHA256-signed payload and a /heartbeat
// envelope — but inverts its control. The license is verified **offline** with a
// key the operator holds; enforcement is OFF unless the operator turns it on;
// and the heartbeat fires only when the operator sets a URL *they* control.
// There is no vendor server, no kill-switch, and zero network calls by default.
package license

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"vdxclone/internal/policy"
)

// Payload is the signed license content.
type Payload struct {
	Licensee   string `json:"licensee"`
	Seats      int    `json:"seats"`       // max running sessions (0 = unlimited)
	Servers    int    `json:"servers"`     // max server VMs
	StorageGB  int    `json:"storage_gb"`  // max storage
	Plan       string `json:"plan"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`  // RFC3339; empty = perpetual
}

// File is the on-disk license: payload plus its HMAC signature.
type File struct {
	Payload Payload `json:"payload"`
	Sig     string  `json:"sig"`
}

// canonical returns the stable JSON used for signing/verifying.
func canonical(p Payload) ([]byte, error) { return json.Marshal(p) }

// Sign produces a signed license using the operator's symmetric key.
func Sign(p Payload, key string) (File, error) {
	b, err := canonical(p)
	if err != nil {
		return File{}, err
	}
	return File{Payload: p, Sig: mac(b, key)}, nil
}

func mac(b []byte, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// Load reads and verifies a license file against the operator's key.
func Load(path, key string) (Payload, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Payload{}, err
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return Payload{}, err
	}
	b, err := canonical(f.Payload)
	if err != nil {
		return Payload{}, err
	}
	if !hmac.Equal([]byte(mac(b, key)), []byte(f.Sig)) {
		return Payload{}, fmt.Errorf("license signature invalid")
	}
	if f.Payload.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, f.Payload.ExpiresAt); err == nil && time.Now().After(t) {
			return Payload{}, fmt.Errorf("license expired at %s", f.Payload.ExpiresAt)
		}
	}
	return f.Payload, nil
}

// Enforcer is the real policy.Enforcer backed by a verified license.
type Enforcer struct{ lic Payload }

func NewEnforcer(lic Payload) *Enforcer { return &Enforcer{lic: lic} }

func (e *Enforcer) CanStartSession(_ context.Context, _ int64, _ policy.SessionKind, cur policy.Counts) policy.Decision {
	if e.lic.Seats > 0 && cur.RunningSessions >= e.lic.Seats {
		return policy.Decision{Allow: false, Reason: fmt.Sprintf("license seat cap reached (%d running)", e.lic.Seats)}
	}
	return policy.Decision{Allow: true}
}

func (e *Enforcer) CanCreateServer(_ context.Context, _ int64, cur policy.Counts) policy.Decision {
	if e.lic.Servers > 0 && cur.ServerVMs >= e.lic.Servers {
		return policy.Decision{Allow: false, Reason: fmt.Sprintf("license server cap reached (%d)", e.lic.Servers)}
	}
	if e.lic.StorageGB > 0 && cur.StorageGB >= e.lic.StorageGB {
		return policy.Decision{Allow: false, Reason: fmt.Sprintf("license storage cap reached (%d GB)", e.lic.StorageGB)}
	}
	return policy.Decision{Allow: true}
}

func (e *Enforcer) OnUsage(context.Context, policy.UsageSample) {}

func (e *Enforcer) Quota(context.Context, int64) policy.Quota {
	return policy.Quota{SeatCap: e.lic.Seats, ServerCap: e.lic.Servers, StorageCap: e.lic.StorageGB}
}

// ---- optional opt-in heartbeat -------------------------------------------

// HeartbeatPayload mirrors the decompiled vendor envelope shape, but is sent
// only when the operator configures a URL they control. Its signature lets a
// self-hosted collector verify authenticity.
type HeartbeatPayload struct {
	Licensee  string `json:"licensee"`
	Running   int    `json:"running"`
	Servers   int    `json:"servers"`
	Timestamp string `json:"timestamp"`
}

// SignHeartbeat returns the body and its HMAC signature header value.
func SignHeartbeat(hb HeartbeatPayload, key string) ([]byte, string, error) {
	b, err := json.Marshal(hb)
	if err != nil {
		return nil, "", err
	}
	return b, mac(b, key), nil
}
