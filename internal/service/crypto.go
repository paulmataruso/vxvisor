package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// encSeal / encOpen are a general-purpose "encrypt a secret at rest" pair, used
// for any credential we persist in the DB (e.g. a CIFS password or Ceph key for a
// backup target). They reuse the same install-wide key as the AD bind password
// (adKey: the shared cluster.key if present, else a per-install key file) and the
// same "enc:" marker + AES-256-GCM scheme, so a DB backup never carries a
// plaintext secret. A value without the marker is returned as-is (legacy/plain).
func (s *Service) encSeal(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := s.adKey()
	if err != nil {
		return "", err
	}
	blk, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

func (s *Service) encOpen(stored string) (string, error) {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored, nil // legacy / plaintext
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
	if err != nil {
		return "", err
	}
	key, err := s.adKey()
	if err != nil {
		return "", err
	}
	blk, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("sealed secret too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(pt), nil
}
