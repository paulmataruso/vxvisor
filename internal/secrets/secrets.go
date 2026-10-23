// Package secrets provides a small helper for per-install secret key files
// (the cluster gossip/peer-API key, the AD credential-sealing key, etc.): a
// 32-byte random secret persisted at 0600 so it survives restarts but is never
// shipped as a hardcoded value.
package secrets

import (
	"crypto/rand"
	"os"
)

// LoadOrCreate reads a >=32-byte secret from path, creating it (0600) with fresh
// randomness on first use. The returned slice is the file's full contents.
func LoadOrCreate(path string) ([]byte, error) {
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
