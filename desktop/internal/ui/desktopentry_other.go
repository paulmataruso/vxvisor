//go:build !linux

package ui

// integrateDesktop is a no-op off Linux. Windows shows the taskbar icon from the
// icon resource embedded in the .exe; macOS from the app bundle.
func integrateDesktop() {}
