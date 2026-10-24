//go:build linux

package ui

import (
	"os"
	"path/filepath"
)

// wmClass is the stable X11 WM_CLASS instance name we pin via RESOURCE_NAME, and
// the StartupWMClass the .desktop advertises, so GNOME-style docks can match the
// running window to our launcher entry and show our icon.
const wmClass = "vxconsole"

// integrateDesktop makes the Linux taskbar/dock show our icon.
//
// X11 window managers that honor _NET_WM_ICON (KDE, XFCE, Cinnamon, MATE, …) get
// the icon straight from Window.SetIcon. GNOME Shell ignores _NET_WM_ICON and
// instead matches the window's WM_CLASS to an installed .desktop entry — so for
// GNOME we best-effort install a hicolor icon + a .desktop whose StartupWMClass
// equals our pinned WM_CLASS. All of this is best-effort: any failure is ignored
// (the app still runs; some environments just won't show the custom icon).
func integrateDesktop() {
	// Pin a stable WM_CLASS res_name (GLFW reads RESOURCE_NAME when no class hint
	// is set, otherwise it falls back to the window title, which changes between
	// the connect and shell windows). Must be set before any window is created.
	_ = os.Setenv("RESOURCE_NAME", wmClass)

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		dataHome = filepath.Join(home, ".local", "share")
	}

	// Install the icon into the hicolor theme (512x512 matches our PNG).
	iconDir := filepath.Join(dataHome, "icons", "hicolor", "512x512", "apps")
	if err := os.MkdirAll(iconDir, 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(iconDir, wmClass+".png"), appIconBytes, 0o644)
	}

	// Install the .desktop entry pointing at this very binary.
	exe, err := os.Executable()
	if err != nil {
		return
	}
	appsDir := filepath.Join(dataHome, "applications")
	if err := os.MkdirAll(appsDir, 0o755); err != nil {
		return
	}
	entry := "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=VXVisor Console\n" +
		"Comment=Connect to a VXVisor host\n" +
		"Exec=" + exe + "\n" +
		"Icon=" + wmClass + "\n" +
		"Terminal=false\n" +
		"Categories=Utility;System;\n" +
		"StartupWMClass=" + wmClass + "\n"
	_ = os.WriteFile(filepath.Join(appsDir, wmClass+".desktop"), []byte(entry), 0o644)
}
