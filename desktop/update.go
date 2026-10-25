package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	wrt "github.com/wailsapp/wails/v2/pkg/runtime"
)

// Client self-update. The shell checks the server's public /clients/latest on
// connect; if a newer build exists it offers to download + self-replace +
// relaunch. The client endpoints are unauthenticated (binaries aren't secret),
// so this works before the user logs in.

type clientRelease struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// httpc talks to the user's own server; skip TLS verify (self-signed is common
// on a LAN appliance, and the webview handles the real browsing session).
var httpc = &http.Client{
	Timeout:   60 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

// CheckUpdate is bound to the frontend: the connect screen awaits it before
// navigating to the server. If an update is accepted the process relaunches and
// this never returns; otherwise it returns and the webview proceeds to connect.
func (a *App) CheckUpdate(serverURL string) {
	serverURL = strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if serverURL == "" {
		return
	}
	rel, err := fetchLatest(serverURL)
	if err != nil || rel.Version == "" || rel.Filename == "" {
		return // unreachable / no build published → just let the webview connect
	}
	if !versionNewer(rel.Version, version) {
		return
	}
	choice, _ := wrt.MessageDialog(a.ctx, wrt.MessageDialogOptions{
		Type:          wrt.QuestionDialog,
		Title:         "Update available",
		Message:       fmt.Sprintf("A newer VXVisor Console is available.\n\nInstalled:  %s\nAvailable:  %s\n\nUpdate and restart now?", version, rel.Version),
		Buttons:       []string{"Update", "Later"},
		DefaultButton: "Update",
		CancelButton:  "Later",
	})
	// IMPORTANT: Wails renders QuestionDialog as a native MessageBox on Windows,
	// which IGNORES the custom button labels above and returns "Yes"/"No"
	// (dialog.go responses map). macOS/Linux return the custom label ("Update").
	// So accept every affirmative spelling; only an explicit decline/cancel/close
	// skips the update.
	switch strings.ToLower(strings.TrimSpace(choice)) {
	case "update", "yes", "ok":
		// proceed with the update
	default:
		return
	}
	newPath, err := download(serverURL, rel)
	if err != nil {
		wrt.MessageDialog(a.ctx, wrt.MessageDialogOptions{Type: wrt.ErrorDialog, Title: "Update failed", Message: err.Error()})
		return
	}
	if err := applyUpdate(newPath); err != nil {
		os.Remove(newPath)
		wrt.MessageDialog(a.ctx, wrt.MessageDialogOptions{Type: wrt.ErrorDialog, Title: "Update failed", Message: err.Error()})
	}
}

func fetchLatest(serverURL string) (clientRelease, error) {
	var rel clientRelease
	u := fmt.Sprintf("%s/clients/latest?os=%s&arch=%s", serverURL, runtime.GOOS, runtime.GOARCH)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("latest: %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&rel)
	return rel, err
}

// download streams the new binary next to the current executable (same
// filesystem, so the swap is an atomic rename) and verifies its sha256.
func download(serverURL string, rel clientRelease) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, e := filepath.EvalSymlinks(exe); e == nil {
		exe = resolved
	}
	dst := exe + ".new"
	path := rel.URL
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req, _ := http.NewRequest(http.MethodGet, serverURL+path, nil)
	resp, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: %s", resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(dst)
		return "", err
	}
	f.Close()
	if rel.SHA256 != "" && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), rel.SHA256) {
		os.Remove(dst)
		return "", fmt.Errorf("checksum mismatch — download may be corrupt")
	}
	return dst, nil
}

// cleanupOld removes leftovers from a prior self-update: "<exe>.old" (legacy
// Windows swap scheme), and a stale "<exe>.new"/"<exe>.update.bat" if a swap was
// interrupted. Best-effort.
func (a *App) cleanupOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if r, e := filepath.EvalSymlinks(exe); e == nil {
		exe = r
	}
	for _, suffix := range []string{".old", ".new", ".update.bat"} {
		os.Remove(exe + suffix)
	}
}

// --- version comparison (vX.Y.Z-YYYYMMDD) ----------------------------------

func versionNewer(a, b string) bool { return cmpVer(parseVer(a), parseVer(b)) > 0 }

func parseVer(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	var nums []int
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' }) {
		n, _ := strconv.Atoi(part)
		nums = append(nums, n)
	}
	return nums
}

func cmpVer(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}
