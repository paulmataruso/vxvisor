package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"vdxclone/internal/platform"
)

// buildVersion is the running vdxd version, injected from main at startup via
// SetBuildVersion so the Update page can report "current" and compare releases.
var buildVersion = "dev"

// SetBuildVersion records the running build version (called once from main).
func SetBuildVersion(v string) { buildVersion = v }

// BuildVersion returns the running vdxd version.
func BuildVersion() string { return buildVersion }

// UpdateAsset is a downloadable file from the latest release (for the UI).
type UpdateAsset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// UpdateStatus is the result of a (manual, admin-initiated) update check.
type UpdateStatus struct {
	Current     string        `json:"current"`
	Latest      string        `json:"latest"`
	UpToDate    bool          `json:"up_to_date"`
	Notes       string        `json:"notes"`
	PublishedAt string        `json:"published_at"`
	Source      string        `json:"source"`  // "github:owner/repo" or "feed"
	Channel     string        `json:"channel"` // "stable" or "preview"
	Assets      []UpdateAsset `json:"assets"`
}

const updateChannelKey = "update_channel"

// UpdateChannel returns the configured release channel ("stable" default, or
// "preview" for prereleases).
func (s *Service) UpdateChannel() string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, updateChannelKey).Scan(&v)
	if v == "preview" {
		return "preview"
	}
	return "stable"
}

// SetUpdateChannel persists the release channel (admin-only; audited).
func (s *Service) SetUpdateChannel(p *Principal, channel, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if channel != "stable" && channel != "preview" {
		return fmt.Errorf("invalid channel %q", channel)
	}
	if _, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, updateChannelKey, channel); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "update.channel", "host", "", ip, map[string]any{"channel": channel})
	return nil
}

// CheckForUpdate contacts the configured source (GitHub Releases by default, or
// cfg.Update.FeedURL if set) and reports whether a newer vdxd is available. This
// is the ONLY place vdxd reaches out for updates, and it runs only when an admin
// triggers it — never automatically. Admin-only; audited.
func (s *Service) CheckForUpdate(p *Principal, ip string) (UpdateStatus, error) {
	if !p.IsAdmin {
		return UpdateStatus{}, ErrUnauthorized
	}
	rel, assets, notes, publishedAt, source, err := s.latestRelease()
	if err != nil {
		s.audit(p, p.OrgID, "update.check", "host", "", ip, map[string]any{"error": err.Error()})
		return UpdateStatus{}, err
	}
	st := UpdateStatus{
		Current:     buildVersion,
		Latest:      rel.Version,
		UpToDate:    !platform.VersionLess(buildVersion, rel.Version),
		Notes:       notes,
		PublishedAt: publishedAt,
		Source:      source,
		Channel:     s.UpdateChannel(),
	}
	for _, a := range assets {
		st.Assets = append(st.Assets, UpdateAsset{Name: a.Name, Size: a.Size})
	}
	s.audit(p, p.OrgID, "update.check", "host", "", ip, map[string]any{"latest": rel.Version, "up_to_date": st.UpToDate})
	return st, nil
}

// ApplyServerUpdate downloads the latest release, verifies its checksum, swaps
// the running vdxd binary (keeping a .bak), refreshes the bundled desktop-client
// binaries in the clients dir, and schedules a service restart. Admin-only; audited.
func (s *Service) ApplyServerUpdate(p *Principal, ip string) (string, error) {
	if !p.IsAdmin {
		return "", ErrUnauthorized
	}
	rel, assets, _, _, _, err := s.latestRelease()
	if err != nil {
		return "", err
	}
	if !platform.VersionLess(buildVersion, rel.Version) {
		return "", fmt.Errorf("already up to date (%s)", buildVersion)
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate binary: %w", err)
	}
	if err := platform.ApplyUpdate(rel, self); err != nil {
		s.audit(p, p.OrgID, "update.apply", "host", rel.Version, ip, map[string]any{"error": err.Error()})
		return "", err
	}
	// Best-effort refresh of the published desktop-client binaries so clients can
	// auto-update to the matching version. Never fails the server update.
	s.refreshClientBinaries(assets)

	s.audit(p, p.OrgID, "update.apply", "host", rel.Version, ip, map[string]any{"from": buildVersion})

	// Restart shortly, after the HTTP response has flushed. systemd brings vdxd
	// back up on the new binary.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = exec.Command("systemctl", "restart", "vdxd").Start()
	}()
	return rel.Version, nil
}

// refreshClientBinaries downloads any vxconsole-* assets into the clients dir,
// verifying checksums, and removes superseded ones. Best-effort.
func (s *Service) refreshClientBinaries(assets []platform.Asset) {
	dir := filepath.Join(s.cfg.Paths.DataDir, "clients")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	sums := s.releaseSums(assets)
	var placed []string
	for _, a := range assets {
		if !strings.HasPrefix(a.Name, "vxconsole-") {
			continue
		}
		dest := filepath.Join(dir, a.Name)
		if err := platform.DownloadVerified(a.URL, dest, sums[a.Name]); err == nil {
			placed = append(placed, a.Name)
		}
	}
	if len(placed) == 0 {
		return
	}
	// Drop older vxconsole-* that weren't part of this release.
	keep := map[string]bool{}
	for _, n := range placed {
		keep[n] = true
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "vxconsole-") && !keep[n] {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
}

// releaseSums fetches the release's SHA256SUMS (if present) → name→digest.
func (s *Service) releaseSums(assets []platform.Asset) map[string]string {
	for _, a := range assets {
		if strings.EqualFold(a.Name, "SHA256SUMS") {
			if m, err := platform.FetchSHA256SUMS(a.URL); err == nil {
				return m
			}
		}
	}
	return map[string]string{}
}

// latestRelease resolves the configured update source into a Release + assets +
// notes. FeedURL (if set) wins (air-gapped manifest); otherwise GitHub Releases.
func (s *Service) latestRelease() (platform.Release, []platform.Asset, string, string, string, error) {
	if url := s.cfg.Update.FeedURL; url != "" {
		rel, err := platform.CheckUpdate(url)
		return rel, nil, "", "", "feed", err
	}
	repo := s.cfg.Update.Repo()
	ch := s.UpdateChannel()
	rel, assets, notes, publishedAt, err := platform.CheckGitHubRelease(repo, ch)
	return rel, assets, notes, publishedAt, "github:" + repo + " (" + ch + ")", err
}
