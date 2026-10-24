//go:build linux

package ui

import (
	"os"
	"syscall"
)

// applyUpdate replaces the running binary with newPath and relaunches in place.
// On Linux a running executable can be renamed over, so this is a simple
// rename + exec (the exec replaces the current process image, so it never
// returns on success).
func applyUpdate(exe, newPath string) error {
	if err := os.Chmod(newPath, 0o755); err != nil {
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
