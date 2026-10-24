package ui

import (
	"embed"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// The desktop client wears the same "Data-Dense Dashboard" skin as the VXVisor
// web UI: identical palette, the Fira type family (self-hosted, not a system
// fallback), and a tight, Operate-mode sizing scale. Everything is dark; the
// web UI's light theme is intentionally not offered here — a console app is used
// in a dim room against a black framebuffer.

//go:embed assets/fonts/*.ttf
var fontFS embed.FS

// Palette — the exact tokens from internal/web/templates/head.html (:root dark).
var (
	colBg      = hex(0x0b0e14) // --bg
	colPanel   = hex(0x121722) // --panel
	colPanel2  = hex(0x1a2130) // --panel2
	colPanel3  = hex(0x212a3a) // --panel3
	colLine    = hex(0x27303f) // --line
	colFg      = hex(0xe6e9ef) // --fg
	colMuted   = hex(0x8a93a6) // --muted
	colFaint   = hex(0x5b6475) // --faint
	colPrimary = hex(0x3b82f6) // --primary
	colBrand   = hex(0x18a3f0) // wordmark "Vx" blue (from the logo gradient)
	colPrimSft = hex(0x14213d) // --primary-soft
	colAccent  = hex(0xf59e0b) // --accent
	colOK      = hex(0x34d399) // --ok
	colDanger  = hex(0xf87171) // --danger
	colWarn    = hex(0xfbbf24) // --warn
)

func hex(v uint32) color.Color {
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}
}

func alpha(c color.Color, a uint8) color.NRGBA {
	n := c.(color.NRGBA)
	n.A = a
	return n
}

var (
	fontSans     = mustFont("assets/fonts/FiraSans-Regular.ttf")
	fontSansBold = mustFont("assets/fonts/FiraSans-SemiBold.ttf")
	fontMono     = mustFont("assets/fonts/FiraMono-Regular.ttf")
	fontMonoBold = mustFont("assets/fonts/FiraMono-Medium.ttf")
)

func mustFont(path string) fyne.Resource {
	b, err := fontFS.ReadFile(path)
	if err != nil {
		panic("vxconsole: missing embedded font " + path + ": " + err.Error())
	}
	return fyne.NewStaticResource(path, b)
}

// vxTheme implements fyne.Theme. It overrides color, font and size; icons fall
// through to the default theme (Fyne's icons are already single-stroke SVGs that
// take currentColor, so they read fine against this palette).
type vxTheme struct{}

var _ fyne.Theme = vxTheme{}

func (vxTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground:
		return colBg
	case theme.ColorNameForeground:
		return colFg
	case theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnSuccess,
		theme.ColorNameForegroundOnError, theme.ColorNameForegroundOnWarning:
		return color.White
	case theme.ColorNameButton:
		return colPanel2
	case theme.ColorNameDisabledButton:
		return colPanel
	case theme.ColorNameDisabled:
		return colFaint
	case theme.ColorNameInputBackground:
		return colPanel2
	case theme.ColorNameInputBorder:
		return colLine
	case theme.ColorNamePlaceHolder:
		return colMuted
	case theme.ColorNamePrimary:
		return colPrimary
	case theme.ColorNameHover:
		return colPanel3
	case theme.ColorNamePressed:
		return alpha(colPrimary, 0x33)
	case theme.ColorNameFocus:
		return alpha(colPrimary, 0x80)
	case theme.ColorNameSelection:
		return alpha(colPrimary, 0x3a)
	case theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground:
		return colPanel
	case theme.ColorNameSeparator:
		return colLine
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x73}
	case theme.ColorNameScrollBar:
		return colLine
	case theme.ColorNameSuccess:
		return colOK
	case theme.ColorNameError:
		return colDanger
	case theme.ColorNameWarning:
		return colWarn
	case theme.ColorNameHyperlink:
		return colPrimary
	}
	return theme.DefaultTheme().Color(n, theme.VariantDark)
}

func (vxTheme) Font(s fyne.TextStyle) fyne.Resource {
	switch {
	case s.Symbol:
		return theme.DefaultTheme().Font(s)
	case s.Monospace && s.Bold:
		return fontMonoBold
	case s.Monospace:
		return fontMono
	case s.Bold:
		return fontSansBold
	default:
		return fontSans
	}
}

func (vxTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(n)
}

// compactTheme is vxTheme with tighter metrics (smaller inline icons, text and
// padding), applied to dense control clusters such as the overview power bar via
// container.NewThemeOverride so the buttons read as slim pills, not chunky blocks.
type compactTheme struct{ vxTheme }

// compactTheme mirrors the web product's small button (`.btn.sm`: 12.5px text,
// 5/10 padding, 7px radius) with a slightly smaller icon, so the desktop controls
// read as the same component the web UI ships.
func (compactTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNameInlineIcon:
		return 14
	case theme.SizeNameText:
		return 12.5
	case theme.SizeNamePadding:
		return 3
	case theme.SizeNameInnerPadding:
		return 6
	case theme.SizeNameInputRadius:
		return 7
	}
	return vxTheme{}.Size(n)
}

// slimTheme tightens the vertical padding of list rows (the VM sidebar) so they
// are compact, without shrinking the label text the way compactTheme does.
type slimTheme struct{ vxTheme }

func (slimTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNameInnerPadding:
		return 4
	case theme.SizeNamePadding:
		return 3
	}
	return vxTheme{}.Size(n)
}

func (vxTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNameText:
		return 13.5
	case theme.SizeNameHeadingText:
		return 20
	case theme.SizeNameSubHeadingText:
		return 15.5
	case theme.SizeNameCaptionText:
		return 11.5
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 9
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameSelectionRadius:
		return 8
	case theme.SizeNameScrollBar:
		return 10
	case theme.SizeNameScrollBarSmall:
		return 4
	case theme.SizeNameSeparatorThickness:
		return 1
	}
	return theme.DefaultTheme().Size(n)
}
