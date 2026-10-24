package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
)

// version is the client build version, injected via -ldflags "-X main.version=...".
var version = "dev"

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

func main() {
	app := NewApp()
	err := wails.Run(&options.App{
		Title:     "VXVisor Console",
		Width:     1280,
		Height:    860,
		MinWidth:  940,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 0x0f, G: 0x14, B: 0x20, A: 1},
		// No application menu — the native GTK menubar renders as a white strip
		// over the dark UI. The shell is chromeless; the connect screen is "home".
		OnStartup: app.startup,
		Bind:      []interface{}{app},
		// Window/taskbar icon + a stable WM class so the desktop environment shows it.
		Linux: &linux.Options{
			Icon: appIcon,
			// g_set_prgname → X11 res_name / Wayland app_id. Keep it a clean, no-space
			// token so GNOME matches the installed vxconsole.desktop (StartupWMClass).
			ProgramName: "vxconsole",
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
