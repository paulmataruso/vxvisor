package platform

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// This file adds a GitHub Releases source for the in-place self-update. It is
// contacted ONLY on an explicit, admin-initiated "check for updates" action from
// the web UI — never automatically or in the background — so the project's
// no-outbound/telemetry guarantee holds. Nothing about the install is sent; it is
// a plain unauthenticated GET of the public releases API.

// Asset is one file attached to a GitHub release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// GitHubRelease is the subset of the releases API we use.
type GitHubRelease struct {
	TagName     string  `json:"tag_name"`
	Name        string  `json:"name"`
	Body        string  `json:"body"`
	Draft       bool    `json:"draft"`
	Prerelease  bool    `json:"prerelease"`
	PublishedAt string  `json:"published_at"`
	Assets      []Asset `json:"assets"`
}

// CheckGitHubRelease fetches the latest (non-draft) release of owner/repo and
// returns a Release describing the vdxd server binary (version, download URL,
// sha256 from the release's SHA256SUMS asset), plus the full asset list (so the
// caller can also refresh the bundled desktop-client binaries) and the release
// notes. repo is "owner/name".
// channel is "stable" (the default; uses /releases/latest, which excludes
// prereleases and drafts) or "preview" (the newest prerelease, falling back to
// the latest stable if there is no prerelease).
func CheckGitHubRelease(repo, channel string) (rel Release, assets []Asset, notes string, publishedAt string, err error) {
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	if repo == "" {
		return Release{}, nil, "", "", fmt.Errorf("no GitHub repo configured")
	}
	gr, err := releaseForChannel(repo, channel)
	if err != nil {
		return Release{}, nil, "", "", err
	}

	// Locate the server binary asset and the checksums file.
	sums := map[string]string{}
	if a := findAsset(gr.Assets, "SHA256SUMS"); a != nil {
		if m, e := FetchSHA256SUMS(a.URL); e == nil {
			sums = m
		}
	}
	vdxd := findAsset(gr.Assets, "vdxd")
	if vdxd == nil {
		return Release{}, nil, "", "", fmt.Errorf("release %s has no vdxd asset", gr.TagName)
	}
	rel = Release{
		Version: strings.TrimSpace(gr.TagName),
		URL:     vdxd.URL,
		SHA256:  sums[vdxd.Name],
	}
	return rel, gr.Assets, gr.Body, gr.PublishedAt, nil
}

// releaseForChannel resolves the release to offer for a channel.
func releaseForChannel(repo, channel string) (GitHubRelease, error) {
	base := "https://api.github.com/repos/" + repo
	if channel == "preview" {
		// Newest non-draft prerelease (list is returned newest-first).
		list, err := fetchGitHubReleases(base + "/releases?per_page=30")
		if err != nil {
			return GitHubRelease{}, err
		}
		for _, r := range list {
			if r.Prerelease && !r.Draft {
				return r, nil
			}
		}
		// No prerelease — fall back to latest stable.
	}
	return fetchGitHubRelease(base + "/releases/latest")
}

func fetchGitHubReleases(api string) ([]GitHubRelease, error) {
	resp, err := githubGET(api)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, githubStatusErr(resp.StatusCode)
	}
	var list []GitHubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

func githubGET(api string) (*http.Response, error) {
	req, _ := http.NewRequest(http.MethodGet, api, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "vdxd-selfupdate")
	return (&http.Client{Timeout: 20 * time.Second}).Do(req)
}

func githubStatusErr(code int) error {
	switch code {
	case http.StatusNotFound:
		return fmt.Errorf("no published release found")
	case http.StatusForbidden:
		return fmt.Errorf("GitHub API rate-limited; try again later")
	default:
		return fmt.Errorf("GitHub API: HTTP %d", code)
	}
}

func fetchGitHubRelease(api string) (GitHubRelease, error) {
	resp, err := githubGET(api)
	if err != nil {
		return GitHubRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return GitHubRelease{}, githubStatusErr(resp.StatusCode)
	}
	var gr GitHubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gr); err != nil {
		return GitHubRelease{}, err
	}
	if gr.TagName == "" {
		return GitHubRelease{}, fmt.Errorf("release has no tag")
	}
	return gr, nil
}

// FetchSHA256SUMS downloads a "SHA256SUMS" file and maps filename -> hex digest.
// Accepts the standard "<hex>␠␠<name>" (and "<hex> *<name>") formats.
func FetchSHA256SUMS(url string) (map[string]string, error) {
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SHA256SUMS: HTTP %d", resp.StatusCode)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*") // binary-mode marker
		out[name] = strings.ToLower(fields[0])
	}
	return out, sc.Err()
}

// DownloadVerified downloads url to dest (0644), verifying its sha256 if sha is
// non-empty, writing atomically via a temp file in the same dir.
func DownloadVerified(url, dest, sha string) error {
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	tmp := dest + ".dl"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if sha != "" && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sha) {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch for %s", filepath.Base(dest))
	}
	return os.Rename(tmp, dest)
}

// VersionLess reports whether version a is older than b. Versions look like
// "vX.Y.Z-YYYYMMDD" (the leading v and the date are optional); comparison is by
// [major, minor, patch, date]. Unparseable parts sort as 0.
func VersionLess(a, b string) bool {
	return cmpVer(parseVer(a), parseVer(b)) < 0
}

func parseVer(v string) [4]int {
	var out [4]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	sem, date := v, ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		sem, date = v[:i], v[i+1:]
	}
	for i, p := range strings.SplitN(sem, ".", 3) {
		if i > 2 {
			break
		}
		n := 0
		fmt.Sscanf(p, "%d", &n)
		out[i] = n
	}
	d := 0
	fmt.Sscanf(date, "%d", &d)
	out[3] = d
	return out
}

func cmpVer(a, b [4]int) int {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// findAsset returns the first asset whose name contains sub (case-insensitive),
// preferring an exact name match.
func findAsset(assets []Asset, sub string) *Asset {
	lsub := strings.ToLower(sub)
	for i := range assets {
		if strings.EqualFold(assets[i].Name, sub) {
			return &assets[i]
		}
	}
	for i := range assets {
		if strings.Contains(strings.ToLower(assets[i].Name), lsub) {
			return &assets[i]
		}
	}
	return nil
}
