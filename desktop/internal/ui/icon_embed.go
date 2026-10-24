package ui

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

// appIconBytes is the VxV application icon (512x512 PNG), shown on the window
// titlebar / taskbar on both Linux (X11 window hint) and Windows.
//
//go:embed Icon.png
var appIconBytes []byte

// appIcon is the icon resource handed to fyne.App.SetIcon / Window.SetIcon.
var appIcon fyne.Resource = fyne.NewStaticResource("icon.png", appIconBytes)
