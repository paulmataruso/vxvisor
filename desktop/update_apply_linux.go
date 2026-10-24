//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
)

// applyUpdate replaces the running binary with newPath and relaunches in place.
func applyUpdate(newPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, e := filepath.EvalSymlinks(exe); e == nil {
		exe = resolved
	}
	if err := os.Chmod(newPath, 0o755); err != nil {
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
