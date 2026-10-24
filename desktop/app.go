package main

import (
	"context"

	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	wrt "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails backend for the VXVisor desktop console. The client is a
// thin branded shell: the connect screen (frontend/dist) navigates the webview
// to the chosen VXVisor server, which then serves its own full web UI (including
// noVNC consoles). This gives 100% parity with the web admin UI by construction.
type App struct {
	ctx context.Context
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// Version returns the client build version (shown on the connect screen).
func (a *App) Version() string { return version }

// appMenu is the native window menu. "Connect to another server" uses
// WindowReloadApp to return to the embedded connect screen even while the
// webview is showing a remote server page.
func (a *App) appMenu() *menu.Menu {
	m := menu.NewMenu()
	srv := m.AddSubmenu("Server")
	srv.AddText("Connect to another server", keys.CmdOrCtrl("h"), func(*menu.CallbackData) {
		wrt.WindowReloadApp(a.ctx)
	})
	srv.AddText("Reload page", keys.CmdOrCtrl("r"), func(*menu.CallbackData) {
		wrt.WindowReload(a.ctx)
	})
	srv.AddText("Toggle full screen", keys.Key("F11"), func(*menu.CallbackData) {
		if wrt.WindowIsFullscreen(a.ctx) {
			wrt.WindowUnfullscreen(a.ctx)
		} else {
			wrt.WindowFullscreen(a.ctx)
		}
	})
	srv.AddSeparator()
	srv.AddText("Quit", keys.CmdOrCtrl("q"), func(*menu.CallbackData) {
		wrt.Quit(a.ctx)
	})
	// Standard edit menu so clipboard shortcuts work in the webview / console.
	m.Append(menu.EditMenu())
	return m
}
