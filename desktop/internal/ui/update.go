package ui

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// checkForUpdate asks the server (not GitHub — that's the server's job) whether a
// newer client build exists for this OS/arch and, if so, offers to self-update.
// Runs in a goroutine after the shell is shown; any failure is silent (the app
// keeps running on the current version).
func (sh *shell) checkForUpdate() {
	rel, err := sh.app.client.LatestClient(runtime.GOOS, runtime.GOARCH)
	if err != nil || rel.Version == "" || rel.URL == "" {
		return
	}
	if !versionNewer(rel.Version, Version) {
		return
	}
	fyne.Do(func() { sh.promptUpdate(rel) })
}

func (sh *shell) promptUpdate(rel client.ClientRelease) {
	msg := fmt.Sprintf("A newer version of VXVisor Console is available.\n\nInstalled:  %s\nAvailable:  %s\n\nDownload and restart now?", Version, rel.Version)
	body := widget.NewLabel(msg)
	dialog.ShowCustomConfirm("Update available", "Update & Restart", "Later", body, func(ok bool) {
		if ok {
			go sh.doUpdate(rel)
		}
	}, sh.win)
}

func (sh *shell) doUpdate(rel client.ClientRelease) {
	fail := func(err error) {
		fyne.Do(func() { dialog.ShowError(fmt.Errorf("update failed: %w", err), sh.win) })
	}

	exe, err := os.Executable()
	if err != nil {
		fail(err)
		return
	}

	// Progress dialog (indeterminate) while downloading.
	var prog dialog.Dialog
	fyne.Do(func() {
		bar := widget.NewProgressBarInfinite()
		prog = dialog.NewCustomWithoutButtons("Updating to "+rel.Version, container.NewCenter(bar), sh.win)
		prog.Show()
	})
	hide := func() {
		fyne.Do(func() {
			if prog != nil {
				prog.Hide()
			}
		})
	}

	newPath := exe + ".new"
	f, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		hide()
		fail(err)
		return
	}
	sum, err := sh.app.client.DownloadTo(rel.URL, f)
	f.Close()
	if err != nil {
		os.Remove(newPath)
		hide()
		fail(err)
		return
	}
	if rel.SHA256 != "" && !strings.EqualFold(sum, rel.SHA256) {
		os.Remove(newPath)
		hide()
		fail(fmt.Errorf("checksum mismatch (download may be corrupt)"))
		return
	}

	// applyUpdate swaps the binary and relaunches; on success it does not return.
	if err := applyUpdate(exe, newPath); err != nil {
		os.Remove(newPath)
		hide()
		fail(err)
		return
	}
}

// cleanupOldBinary removes a leftover "<exe>.old" from a previous Windows update
// (best-effort; a no-op elsewhere).
func cleanupOldBinary() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}

// versionNewer reports whether version a is strictly newer than b. Versions look
// like "vX.Y.Z-YYYYMMDD" (leading v and date optional).
func versionNewer(a, b string) bool {
	return cmpVersion(parseVersion(a), parseVersion(b)) > 0
}

func parseVersion(v string) [4]int {
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
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	d, _ := strconv.Atoi(date)
	out[3] = d
	return out
}

func cmpVersion(a, b [4]int) int {
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
