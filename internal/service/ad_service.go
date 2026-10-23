package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"vdxclone/internal/ad"
	"vdxclone/internal/config"
	"vdxclone/internal/secrets"
)

// AD (Active Directory / LDAP) settings are persisted in the DB so an admin can
// manage them from the Settings → Authentication page with no config-file edit
// and no daemon restart. The TOML [ad] block remains a fallback for installs
// that configured it before this page existed.
//
// The settings row is a JSON blob under settings.key='ad_config'. The service
// account's bind password is the one secret here, so it is encrypted at rest
// (AES-256-GCM) with a per-install key file — DB backups never contain it in
// plaintext. Everything else is non-secret directory metadata.

const adSettingsKey = "ad_config"

// encPrefix marks a BindPassword value that is AES-GCM sealed (vs. a legacy or
// TOML plaintext value). Encrypt-on-write, decrypt-on-read is keyed on it.
const encPrefix = "enc:"

var (
	adKeyOnce sync.Once
	adKeyBuf  []byte
	adKeyErr  error
)

// adKey loads the AD encryption key. It PREFERS the shared cluster secret
// (cluster.key) so a sealed bind-password blob replicated to peers decrypts on
// every node — cluster.key is byte-identical across the cluster by constraint.
// On a single-node install (no cluster.key) it falls back to a per-install
// ad.key via secrets.LoadOrCreate (a per-install 32-byte key file).
func (s *Service) adKey() ([]byte, error) {
	adKeyOnce.Do(func() {
		if path := s.cfg.ClusterSecretPath(); path != "" {
			if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
				adKeyBuf = b
				return
			}
		}
		adKeyBuf, adKeyErr = secrets.LoadOrCreate(filepath.Join(s.cfg.Paths.DataDir, "ad.key"))
	})
	return adKeyBuf, adKeyErr
}

func (s *Service) adSeal(plaintext string) (string, error) {
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

func (s *Service) adOpen(stored string) (string, error) {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored, nil // legacy / TOML plaintext
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
		return "", fmt.Errorf("ad: ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("ad: decrypt bind password: %w", err)
	}
	return string(pt), nil
}

// ADConfigStored reports whether an admin has saved AD settings in the DB (vs.
// falling back to the TOML [ad] block).
func (s *Service) ADConfigStored() bool {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, adSettingsKey).Scan(&v)
	return err == nil && v != ""
}

// ADConfig returns the effective AD configuration: the DB-persisted settings if
// present, otherwise the TOML [ad] fallback. The bind password is decrypted.
// Used at startup to seed the live provider and by the settings page to render.
func (s *Service) ADConfig() config.ADConfig {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, adSettingsKey).Scan(&v); err != nil || v == "" {
		return s.cfg.AD // TOML fallback
	}
	var c config.ADConfig
	if err := json.Unmarshal([]byte(v), &c); err != nil {
		return s.cfg.AD
	}
	if pw, err := s.adOpen(c.BindPassword); err == nil {
		c.BindPassword = pw
	} else {
		c.BindPassword = "" // undecryptable → treat as unset rather than leak ciphertext
	}
	return c
}

// SaveADConfig persists AD settings (admin only) and returns the stored config
// so the caller can push it to the live provider. An empty incoming bind
// password is treated as "keep the existing one" so an admin editing other
// fields need not re-enter the secret.
func (s *Service) SaveADConfig(p *Principal, c config.ADConfig, ip string) (config.ADConfig, error) {
	if !p.IsAdmin {
		return config.ADConfig{}, ErrUnauthorized
	}
	c.URL = strings.TrimSpace(c.URL)
	c.Domain = strings.TrimSpace(c.Domain)
	c.BindDN = strings.TrimSpace(c.BindDN)
	c.BaseDN = strings.TrimSpace(c.BaseDN)
	c.AdminGroup = strings.TrimSpace(c.AdminGroup)
	if c.Enabled && c.URL == "" {
		return config.ADConfig{}, fmt.Errorf("a directory URL is required to enable AD")
	}
	if c.Enabled && c.Domain == "" && c.BindDN == "" {
		return config.ADConfig{}, fmt.Errorf("set a domain (for UPN login) or a service account")
	}

	// Blank incoming password = keep the current secret.
	if c.BindPassword == "" {
		c.BindPassword = s.ADConfig().BindPassword
	}

	store := c // copy to persist with the password sealed
	sealed, err := s.adSeal(c.BindPassword)
	if err != nil {
		return config.ADConfig{}, err
	}
	store.BindPassword = sealed
	blob, err := json.Marshal(store)
	if err != nil {
		return config.ADConfig{}, err
	}
	if _, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, adSettingsKey, string(blob)); err != nil {
		return config.ADConfig{}, err
	}
	s.audit(p, p.OrgID, "settings.ad.save", "settings", adSettingsKey, ip, map[string]any{
		"enabled": c.Enabled, "url": c.URL, "domain": c.Domain, "admin_group": c.AdminGroup,
	})
	if s.adReload != nil {
		s.adReload(c) // live reload on this node
	}
	return c, nil
}

// TestADConfig validates a candidate config against the live directory without
// persisting it (admin only). The caller passes the form values; a blank bind
// password falls back to the saved one so "Test" works mid-edit.
func (s *Service) TestADConfig(p *Principal, c config.ADConfig) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	if c.BindPassword == "" {
		c.BindPassword = s.ADConfig().BindPassword
	}
	return ad.TestConfig(c)
}
