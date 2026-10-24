//go:build !linux

package main

// integrateDesktop is a no-op off Linux (Windows embeds the .exe icon; macOS
// uses the app bundle).
func (a *App) integrateDesktop() {}
