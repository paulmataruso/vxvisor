// Package ui is the Fyne desktop UI for the VXVisor console client.
package ui

import (
	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Version is the client build version, set from main at startup.
var Version = "dev"

// App is the running desktop application.
type App struct {
	fyne   fyne.App
	client *client.Client
}

// New builds the application.
func New() *App {
	// Make the OS taskbar/dock show our icon (sets RESOURCE_NAME for a stable
	// X11 WM_CLASS and, on GNOME-style Linux, installs a .desktop + hicolor icon).
	// Must run before the first window is created.
	integrateDesktop()
	cleanupOldBinary() // remove a leftover "<exe>.old" from a prior Windows update

	a := fyneapp.NewWithID("com.vxvisor.console")
	a.Settings().SetTheme(vxTheme{})
	a.SetIcon(appIcon)
	return &App{fyne: a}
}

// Run shows the connect window and blocks until the app exits.
func (a *App) Run() {
	a.showConnect()
	a.fyne.Run()
}

func (a *App) showConnect() {
	win := a.fyne.NewWindow("Connect to VXVisor")
	win.SetIcon(appIcon)
	win.Resize(fyne.NewSize(460, 560))
	win.CenterOnScreen()

	host := widget.NewEntry()
	host.SetPlaceHolder("host or ip (e.g. 10.0.0.5 or 10.0.0.5:8766)")
	user := widget.NewEntry()
	user.SetPlaceHolder("username")
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("password")

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord

	var connectBtn *widget.Button
	doConnect := func() {
		if host.Text == "" || user.Text == "" {
			status.SetText("Enter a host and username.")
			return
		}
		connectBtn.Disable()
		status.SetText("Connecting…")
		go func() {
			c, err := client.New(host.Text)
			if err == nil {
				err = c.Login(user.Text, pass.Text)
			}
			fyne.Do(func() {
				connectBtn.Enable()
				if err != nil {
					status.SetText(err.Error())
					return
				}
				a.client = c
				a.showShell()
				win.Close()
			})
		}()
	}
	pass.OnSubmitted = func(string) { doConnect() }
	connectBtn = widget.NewButtonWithIcon("Connect", theme.LoginIcon(), doConnect)
	connectBtn.Importance = widget.HighImportance

	// Centered brand hero: large logo over the wordmark over a subtitle, each
	// horizontally centered in the login column.
	brand := container.NewVBox(
		container.NewCenter(glyphBadge(84)),
		spacer(10),
		container.NewCenter(brandWordmark(34)),
		spacer(2),
		container.NewCenter(mutedText("Management Console", 13)),
		container.NewCenter(mutedText(Version, 11)),
	)

	field := func(label string, e fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(mutedText(label, 11.5), e)
	}

	form := container.NewVBox(
		field("Host", host),
		field("Username", user),
		field("Password", pass),
		spacer(4),
		connectBtn,
		status,
	)

	body := container.NewVBox(
		container.NewPadded(brand),
		spacer(6),
		card(container.NewPadded(form)),
	)
	// Width-only layout: GridWrap would pin the height too and clip the card's
	// bottom when the content is taller than the guess. This takes the body's
	// natural height so nothing is cut off.
	win.SetContent(container.NewCenter(container.New(&fixedWidthLayout{400}, container.NewPadded(body))))
	win.Canvas().Focus(host)
	win.Show()
}
