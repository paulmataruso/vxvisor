package broker

import (
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	s := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	tok := s.Mint("sess-1", 7, time.Minute)
	c, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.SessionID != "sess-1" || c.UserID != 7 {
		t.Fatalf("claims mismatch: %+v", c)
	}
}

func TestTokenTamperRejected(t *testing.T) {
	s := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	tok := s.Mint("sess-1", 7, time.Minute)
	if _, err := s.Verify(tok + "x"); err == nil {
		t.Error("expected signature failure on tampered token")
	}
	// A token minted with a different secret must not verify.
	other := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))
	if _, err := s.Verify(other.Mint("sess-1", 7, time.Minute)); err == nil {
		t.Error("expected cross-secret rejection")
	}
}

func TestTokenExpiry(t *testing.T) {
	s := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	tok := s.Mint("sess-1", 7, -time.Second) // already expired
	if _, err := s.Verify(tok); err == nil {
		t.Error("expected expired token to be rejected")
	}
}
