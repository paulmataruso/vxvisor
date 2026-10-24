package main

import "context"

// App is the Wails backend for the VXVisor desktop console. The client is a
// thin branded shell: the connect screen (frontend/dist) logs in to the chosen
// VXVisor server and loads its web UI (including noVNC consoles). This gives
// 100% parity with the web admin UI by construction.
type App struct {
	ctx context.Context
}

func NewApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.cleanupOld() // remove a leftover "<exe>.old" from a prior Windows self-update
}

// Version returns the client build version (shown on the connect screen).
func (a *App) Version() string { return version }
