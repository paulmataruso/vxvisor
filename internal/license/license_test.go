package license

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vdxclone/internal/policy"
)

func writeLicense(t *testing.T, f File) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lic.json")
	b, _ := json.Marshal(f)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSignLoadRoundTrip(t *testing.T) {
	f, err := Sign(Payload{Licensee: "acme", Seats: 5, Servers: 3}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Load(writeLicense(t, f), "secret")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Licensee != "acme" || got.Seats != 5 || got.Servers != 3 {
		t.Errorf("payload mismatch: %+v", got)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	f, _ := Sign(Payload{Licensee: "acme", Seats: 5}, "secret")
	if _, err := Load(writeLicense(t, f), "wrong"); err == nil {
		t.Error("expected signature failure with wrong key")
	}
}

func TestTamperRejected(t *testing.T) {
	f, _ := Sign(Payload{Licensee: "acme", Seats: 1}, "secret")
	f.Payload.Seats = 9999 // tamper after signing
	if _, err := Load(writeLicense(t, f), "secret"); err == nil {
		t.Error("expected signature failure after tampering")
	}
}

func TestExpiredRejected(t *testing.T) {
	f, _ := Sign(Payload{Licensee: "acme", ExpiresAt: time.Now().Add(-time.Hour).Format(time.RFC3339)}, "secret")
	if _, err := Load(writeLicense(t, f), "secret"); err == nil {
		t.Error("expected expired license to be rejected")
	}
}

func TestEnforcerCaps(t *testing.T) {
	e := NewEnforcer(Payload{Seats: 2, Servers: 1})
	if d := e.CanStartSession(context.Background(), 1, policy.KindServer, policy.Counts{RunningSessions: 2}); d.Allow {
		t.Error("seat cap should deny the 3rd running session")
	}
	if d := e.CanStartSession(context.Background(), 1, policy.KindServer, policy.Counts{RunningSessions: 1}); !d.Allow {
		t.Error("under seat cap should allow")
	}
	if d := e.CanCreateServer(context.Background(), 1, policy.Counts{ServerVMs: 1}); d.Allow {
		t.Error("server cap should deny the 2nd server VM")
	}
	if q := e.Quota(context.Background(), 1); q.SeatCap != 2 || q.ServerCap != 1 {
		t.Errorf("quota mismatch: %+v", q)
	}
}
