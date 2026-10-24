//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// integrateDesktop makes GNOME (and other DEs) show the app icon in the taskbar/
// dock. GNOME ignores the window's own icon and instead matches the window's
// WM_CLASS (= g_set_prgname = "vxconsole", set in main) to an installed .desktop
// via its filename / StartupWMClass. So we self-install a hicolor icon named
// "vxconsole" and a vxconsole.desktop pointing at it. (Same fix the Fyne client
// needed; GNOME may only pick it up on the NEXT launch, once the files exist.)
func (a *App) integrateDesktop() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if r, e := filepath.EvalSymlinks(exe); e == nil {
		exe = r
	}

	// Install the icon under hicolor by the name the .desktop references.
	for _, sz := range []string{"512x512", "256x256", "128x128"} {
		dir := filepath.Join(home, ".local", "share", "icons", "hicolor", sz, "apps")
		if os.MkdirAll(dir, 0o755) == nil {
			_ = os.WriteFile(filepath.Join(dir, "vxconsole.png"), appIcon, 0o644)
		}
	}

	appsDir := filepath.Join(home, ".local", "share", "applications")
	if os.MkdirAll(appsDir, 0o755) != nil {
		return
	}
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=VXVisor Console
Comment=VXVisor management console
Exec=%s %%U
Icon=vxconsole
Terminal=false
Categories=System;RemoteAccess;
StartupWMClass=vxconsole
`, exe)
	_ = os.WriteFile(filepath.Join(appsDir, "vxconsole.desktop"), []byte(entry), 0o644)

	// Refresh the desktop/icon caches (best-effort; ignore if the tools are absent).
	_ = exec.Command("update-desktop-database", appsDir).Run()
	_ = exec.Command("gtk-update-icon-cache", "-f", "-t", filepath.Join(home, ".local", "share", "icons", "hicolor")).Run()
}
