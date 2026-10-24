//go:build !linux && !windows

package main

import "fmt"

func applyUpdate(string) error {
	return fmt.Errorf("self-update is not supported on this platform")
}
