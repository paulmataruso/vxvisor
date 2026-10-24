//go:build windows

package ui

import (
	"os"
	"os/exec"
)

// applyUpdate replaces the running binary on Windows, where a running .exe cannot
// be overwritten but CAN be renamed. Move the current exe aside, move the new one
// into place, launch it, and exit. The next launch cleans up the ".old" file.
func applyUpdate(exe, newPath string) error {
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(newPath, exe); err != nil {
		_ = os.Rename(old, exe) // roll back
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
