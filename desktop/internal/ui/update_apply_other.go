//go:build !linux && !windows

package ui

import "fmt"

// applyUpdate is unsupported outside Linux/Windows (e.g. macOS app bundles need a
// different mechanism). The caller reports the error and keeps running.
func applyUpdate(exe, newPath string) error {
	return fmt.Errorf("in-app update is not supported on this platform; download the latest client manually")
}
