package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"vdxclone/internal/service"
)

// clientDL is one downloadable desktop-client artifact.
type clientDL struct {
	Name     string
	Size     int64
	Platform string // "Windows", "Linux", "macOS", or "Download"
	Arch     string
}

// clientsDir is where the desktop console client binaries are placed (by the
// installer or by hand). It is served to signed-in users from the Downloads
// page.
func (s *Server) clientsDir() string {
	return filepath.Join(s.cfg.Paths.DataDir, "clients")
}

// clientsPage lists the desktop console client downloads available on this host.
func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	dir := s.clientsDir()
	var files []clientDL
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		plat, arch := platformOf(name)
		files = append(files, clientDL{Name: name, Size: fi.Size(), Platform: plat, Arch: arch})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].Platform != files[j].Platform {
			return files[i].Platform < files[j].Platform
		}
		return files[i].Name < files[j].Name
	})
	s.render(w, p, "clients.html", "clients", map[string]any{
		"Files": files,
	})
}

// clientLatest reports the newest desktop-client build available for the given
// os/arch (query params), so the running client can self-update. It returns the
// version, the download filename + URL, the sha256 (for integrity), and size.
// Response: {"version":"","filename":"","url":"","sha256":"","size":0} when none.
func (s *Server) clientLatest(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	goos := strings.ToLower(r.URL.Query().Get("os"))
	goarch := strings.ToLower(r.URL.Query().Get("arch"))

	dir := s.clientsDir()
	entries, _ := os.ReadDir(dir)
	var bestName string
	var bestVer []int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "vxconsole-") || !clientMatchesPlatform(name, goos, goarch) {
			continue
		}
		ver := parseClientVersion(name)
		if ver == nil {
			continue
		}
		if bestVer == nil || versionLess(bestVer, ver) {
			bestVer, bestName = ver, name
		}
	}

	out := map[string]any{"version": "", "filename": "", "url": "", "sha256": "", "size": int64(0)}
	if bestName != "" {
		sum, size, err := fileSHA256(filepath.Join(dir, bestName))
		if err == nil {
			out = map[string]any{
				"version":  clientVersionString(bestName),
				"filename": bestName,
				"url":      "/clients/download/" + bestName,
				"sha256":   sum,
				"size":     size,
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// clientMatchesPlatform reports whether a client filename is for the given GOOS/
// GOARCH. os/arch empty = don't filter on that dimension.
func clientMatchesPlatform(name, goos, goarch string) bool {
	plat, arch := platformOf(name)
	if goos != "" {
		want := map[string]string{"windows": "Windows", "linux": "Linux", "darwin": "macOS"}[goos]
		if want != "" && plat != want {
			return false
		}
	}
	if goarch != "" && arch != "" && arch != goarch {
		return false
	}
	return true
}

// clientVersionString extracts the version token (e.g. "v1.12.0-20261024") from a
// client filename like "vxconsole-v1.12.0-20261024-linux-amd64[.exe]".
func clientVersionString(name string) string {
	s := strings.TrimPrefix(name, "vxconsole-")
	s = strings.TrimSuffix(s, ".exe")
	// strip the trailing -<os>-<arch>
	for _, suf := range []string{"-linux-amd64", "-windows-amd64", "-darwin-amd64", "-linux-arm64", "-windows-arm64", "-darwin-arm64"} {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSuffix(s, suf)
		}
	}
	// fall back: drop the last two dash groups
	parts := strings.Split(s, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return s
}

// parseClientVersion turns a client filename's version into comparable integers:
// [major, minor, patch, yyyymmdd]. Missing date sorts as 0. nil = unparseable.
func parseClientVersion(name string) []int {
	v := clientVersionString(name)
	v = strings.TrimPrefix(v, "v")
	semver, date := v, ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		semver, date = v[:i], v[i+1:]
	}
	sp := strings.Split(semver, ".")
	if len(sp) < 3 {
		return nil
	}
	out := make([]int, 0, 4)
	for _, p := range sp[:3] {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	d, _ := strconv.Atoi(date)
	out = append(out, d)
	return out
}

// versionLess reports a < b for [major,minor,patch,date] vectors.
func versionLess(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func fileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// clientDownload streams one client artifact as an attachment.
func (s *Server) clientDownload(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	name := filepath.Base(r.PathValue("name"))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	dir := s.clientsDir()
	path := filepath.Join(dir, name)
	// Defense in depth: the resolved path must stay inside the clients dir.
	if rel, err := filepath.Rel(dir, path); err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeHeader(name)+"\"")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// platformOf guesses the OS and architecture of a client artifact from its file
// name, for display only.
func platformOf(name string) (platform, arch string) {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "windows"), strings.HasSuffix(l, ".exe"), strings.HasSuffix(l, ".msi"):
		platform = "Windows"
	case strings.Contains(l, "darwin"), strings.Contains(l, "macos"), strings.HasSuffix(l, ".dmg"):
		platform = "macOS"
	case strings.Contains(l, "linux"), strings.HasSuffix(l, ".tar.xz"), strings.HasSuffix(l, ".tar.gz"), strings.HasSuffix(l, ".appimage"):
		platform = "Linux"
	default:
		platform = "Download"
	}
	switch {
	case strings.Contains(l, "arm64"), strings.Contains(l, "aarch64"):
		arch = "arm64"
	case strings.Contains(l, "amd64"), strings.Contains(l, "x86_64"), strings.Contains(l, "x64"):
		arch = "amd64"
	}
	return platform, arch
}
