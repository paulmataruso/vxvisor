//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// applyUpdate renames the running .exe aside (a running Windows binary can't be
// overwritten), moves the new one into place, relaunches, and exits. The stale
// "<exe>.old" is removed on the next launch (App.cleanupOld).
func applyUpdate(newPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, e := filepath.EvalSymlinks(exe); e == nil {
		exe = resolved
	}
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		os.Rename(old, exe) // roll back
		return err
	}
	_ = exec.Command(exe, os.Args[1:]...).Start()
	os.Exit(0)
	return nil
}
