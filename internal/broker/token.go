// Package broker implements the public-facing VDI broker: connection tokens and
// the desktop-pool lifecycle. A connection token is a short-lived, HMAC-signed
// grant that authorizes exactly one desktop WebSocket for one user and one
// session. It lets the public portal hand the browser a connect URL that cannot
// be replayed or guessed, and that the desktop endpoint can verify statelessly
// without trusting the cookie alone.
package broker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Claims is the signed content of a connection token.
type Claims struct {
	SessionID string `json:"sid"`
	UserID    int64  `json:"uid"`
	Expires   int64  `json:"exp"` // unix seconds
}

// Signer mints and verifies connection tokens with a per-install secret.
type Signer struct{ secret []byte }

// NewSigner returns a Signer over the given secret.
func NewSigner(secret []byte) *Signer { return &Signer{secret: secret} }

// LoadOrCreateSecret reads a 32-byte secret from path, creating it (0600) with
// fresh randomness on first use so tokens survive restarts but never ship as a
// hardcoded key.
func LoadOrCreateSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// Mint returns a token authorizing user uid to open session sid for ttl.
func (s *Signer) Mint(sid string, uid int64, ttl time.Duration) string {
	c := Claims{SessionID: sid, UserID: uid, Expires: time.Now().Add(ttl).Unix()}
	payload, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + s.sign(p)
}

// Verify checks a token's signature and expiry and returns its claims.
func (s *Signer) Verify(token string) (Claims, error) {
	i := strings.IndexByte(token, '.')
	if i < 0 {
		return Claims{}, fmt.Errorf("malformed token")
	}
	p, sig := token[:i], token[i+1:]
	if !hmac.Equal([]byte(sig), []byte(s.sign(p))) {
		return Claims{}, fmt.Errorf("bad token signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return Claims{}, fmt.Errorf("bad token payload")
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, err
	}
	if time.Now().Unix() > c.Expires {
		return Claims{}, fmt.Errorf("token expired")
	}
	return c, nil
}

func (s *Signer) sign(p string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(p))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
