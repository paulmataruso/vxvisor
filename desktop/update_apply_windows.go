//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// applyUpdate replaces the running binary on Windows. A running .exe (with its
// WebView2 child processes holding handles) can't be reliably overwritten
// in-process, so we hand off to a detached `cmd` that waits for this process to
// exit, swaps the new file over the old one, and relaunches it. Then we exit so
// the file lock is released.
func applyUpdate(newPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if r, e := filepath.EvalSymlinks(exe); e == nil {
		exe = r
	}
	// ping gives this process ~2s to fully exit (and drop the .exe lock) before
	// the move; then relaunch. Quote paths for spaces.
	script := fmt.Sprintf(`ping -n 3 127.0.0.1 >nul & move /Y "%s" "%s" >nul & start "" "%s"`, newPath, exe, exe)
	cmd := exec.Command("cmd", "/C", script)
	// DETACHED_PROCESS (0x8) | CREATE_NO_WINDOW (0x08000000) so no console flashes
	// and the helper outlives us.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000008}
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
