package ui

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// mutedPara is a wrapped, muted paragraph for hints and empty states (canvas.Text
// is single-line only, so multi-line muted copy goes through RichText).
func mutedPara(s string) fyne.CanvasObject {
	rt := widget.NewRichText(&widget.TextSegment{
		Text:  s,
		Style: widget.RichTextStyle{ColorName: theme.ColorNamePlaceHolder, SizeName: theme.SizeNameCaptionText},
	})
	rt.Wrapping = fyne.TextWrapWord
	return rt
}

// stateColor maps a VM/connection state word to its palette accent.
func stateColor(state string) color.Color {
	switch strings.ToLower(state) {
	case "running", "ok", "connected", "done", "completed", "ready", "active", "mounted", "enabled", "up", "online":
		return colOK
	case "error", "failed", "bad", "disconnected", "down":
		return colDanger
	case "stopped", "shutoff", "off", "revoked", "disabled", "offline":
		return colMuted
	default: // starting, stopping, connecting, paused…
		return colWarn
	}
}

// dot is a small filled circle sized to d px, used as a live state indicator.
func dot(state string, d float32) fyne.CanvasObject {
	c := canvas.NewCircle(stateColor(state))
	return container.NewGridWrap(fyne.NewSize(d, d), c)
}

// pill is a rounded state badge: tinted text on a soft tinted fill, matching the
// web UI's .pill.running / .stopped / .error.
func pill(text, state string) fyne.CanvasObject {
	fg := stateColor(state)
	bg := alpha(fg, 0x22)
	if strings.EqualFold(state, "stopped") || strings.EqualFold(state, "off") {
		bg = colPanel2.(color.NRGBA)
	}
	r := canvas.NewRectangle(bg)
	r.CornerRadius = 999
	r.StrokeColor = alpha(fg, 0x66)
	r.StrokeWidth = 1

	d := canvas.NewCircle(fg)
	t := canvas.NewText(strings.ToUpper(text), fg)
	t.TextSize = 11
	t.TextStyle = fyne.TextStyle{Bold: true}

	// Border keeps the dot inline with and vertically centered against the text
	// (an HBox top-aligns them, which made the label sit below-right of the dot).
	dotBox := container.NewGridWrap(fyne.NewSize(8, 8), d)
	row := container.NewBorder(nil, nil, container.NewCenter(dotBox), nil, t)
	return container.NewStack(r, container.New(&insetLayout{7, 3}, row))
}

// card wraps content in a panel surface: rounded, 1px line border, soft depth.
func card(content fyne.CanvasObject) fyne.CanvasObject {
	bg := canvas.NewRectangle(colPanel)
	bg.CornerRadius = 12
	bg.StrokeColor = colLine
	bg.StrokeWidth = 1
	return container.NewStack(bg, container.NewPadded(content))
}

// titledCard is a card with a section heading above its body.
func titledCard(title string, body fyne.CanvasObject) fyne.CanvasObject {
	return card(container.NewBorder(
		container.NewVBox(sectionLabel(title), spacer(4)),
		nil, nil, nil, body,
	))
}

// sectionLabel is the uppercase, letter-spaced, muted caption used for group
// headings throughout the web UI (.grp / .hero-cap).
func sectionLabel(text string) fyne.CanvasObject {
	t := canvas.NewText(spaceCaps(text), colMuted)
	t.TextSize = 11
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

// kv renders a label/value row: muted caption key on the left, foreground value
// on the right.
func kv(key, value string, mono bool) fyne.CanvasObject {
	k := canvas.NewText(key, colMuted)
	k.TextSize = 12
	v := canvas.NewText(value, colFg)
	v.TextSize = 13
	v.TextStyle = fyne.TextStyle{Monospace: mono}
	v.Alignment = fyne.TextAlignTrailing
	return container.NewBorder(nil, nil, k, v)
}

// statTile is one cell of the compact metric strip: a big value over a caption.
func statTile(value, label string, tint color.Color) fyne.CanvasObject {
	v := canvas.NewText(value, colFg)
	v.TextSize = 22
	v.TextStyle = fyne.TextStyle{Bold: true}
	if tint != nil {
		v.Color = tint
	}
	l := canvas.NewText(spaceCaps(label), colMuted)
	l.TextSize = 10.5
	l.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewVBox(v, l)
}

// segBar is a horizontal proportion bar (running vs stopped), like the web
// overview's .segbar — real counts, not a decorative sparkline.
func segBar(running, stopped int) fyne.CanvasObject {
	total := running + stopped
	if total == 0 {
		track := canvas.NewRectangle(colPanel2)
		track.CornerRadius = 999
		return container.NewGridWrap(fyne.NewSize(0, 10), track)
	}
	run := canvas.NewRectangle(colOK)
	run.CornerRadius = 999
	stop := canvas.NewRectangle(alpha(colMuted, 0x66))
	stop.CornerRadius = 999
	grid := container.New(&ratioLayout{ratios: []float32{float32(running), float32(stopped)}, gap: 3, h: 10}, run, stop)
	return grid
}

// tightRow lays children left-to-right with zero spacing (unlike HBox, which
// inserts theme padding between items) — used to butt wordmark glyphs together.
type tightRow struct{}

func (tightRow) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var w, h float32
	for _, o := range objs {
		s := o.MinSize()
		w += s.Width
		if s.Height > h {
			h = s.Height
		}
	}
	return fyne.NewSize(w, h)
}

func (tightRow) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	var x float32
	for _, o := range objs {
		s := o.MinSize()
		o.Resize(fyne.NewSize(s.Width, size.Height))
		o.Move(fyne.NewPos(x, 0))
		x += s.Width
	}
}

// glyphBadge is the app's brand mark: the VxV logo (the same icon used for the
// window/taskbar). The PNG already carries its own rounded slate background, so
// it's shown as-is at the requested size.
func glyphBadge(size float32) fyne.CanvasObject {
	img := canvas.NewImageFromResource(appIcon)
	img.FillMode = canvas.ImageFillContain
	img.ScaleMode = canvas.ImageScaleSmooth
	return container.NewGridWrap(fyne.NewSize(size, size), img)
}

func spacer(h float32) fyne.CanvasObject {
	return container.NewGridWrap(fyne.NewSize(1, h), canvas.NewRectangle(color.Transparent))
}

// hSpace is a fixed-width transparent gap, used to separate controls in an HBox.
func hSpace(w float32) fyne.CanvasObject {
	return container.NewGridWrap(fyne.NewSize(w, 1), canvas.NewRectangle(color.Transparent))
}

// spaceCaps upper-cases for the small caption headings (Fyne has no tracking
// control, so the weight + size carry the caption treatment).
func spaceCaps(s string) string { return strings.ToUpper(s) }

// --- tiny layouts -----------------------------------------------------------

// fixedWidthLayout pins its child to an exact width and lets the height fill
// (GridWrap would pin both axes). Used for the sidebar rail.
type fixedWidthLayout struct{ w float32 }

func (l *fixedWidthLayout) MinSize(o []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(l.w, o[0].MinSize().Height)
}
func (l *fixedWidthLayout) Layout(o []fyne.CanvasObject, s fyne.Size) {
	o[0].Move(fyne.NewPos(0, 0))
	o[0].Resize(fyne.NewSize(l.w, s.Height))
}

// fixedHeightLayout pins its child to an exact height and lets the width fill.
// Used for the console toolbar strip.
type fixedHeightLayout struct{ h float32 }

func (l *fixedHeightLayout) MinSize(o []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(o[0].MinSize().Width, l.h)
}
func (l *fixedHeightLayout) Layout(o []fyne.CanvasObject, s fyne.Size) {
	o[0].Move(fyne.NewPos(0, 0))
	o[0].Resize(fyne.NewSize(s.Width, l.h))
}

// insetLayout pads its (single) child by x,y on every side.
type insetLayout struct{ x, y float32 }

func (l *insetLayout) MinSize(objs []fyne.CanvasObject) fyne.Size {
	m := objs[0].MinSize()
	return fyne.NewSize(m.Width+l.x*2, m.Height+l.y*2)
}
func (l *insetLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	objs[0].Move(fyne.NewPos(l.x, l.y))
	objs[0].Resize(fyne.NewSize(size.Width-l.x*2, size.Height-l.y*2))
}

// padRightLayout reserves w px of empty space on the right of its single child,
// keeping sidebar rows clear of the VScroll scrollbar (which is drawn ~16px
// inward from the viewport's right edge and would otherwise overlay a row).
//
// Crucially its MinSize does NOT add w: a vertical Scroll resizes its content to
// content.MinSize().Max(viewport) and then clips horizontally, so any content
// wider than the viewport has its right edge cut off. Inflating the min width
// here would push every row past the viewport and clip the row bubble — the bug
// this layout was meant to prevent. We only shrink the child at layout time.
type padRightLayout struct{ w float32 }

func (l *padRightLayout) MinSize(o []fyne.CanvasObject) fyne.Size {
	return o[0].MinSize()
}
func (l *padRightLayout) Layout(o []fyne.CanvasObject, s fyne.Size) {
	o[0].Move(fyne.NewPos(0, 0))
	o[0].Resize(fyne.NewSize(s.Width-l.w, s.Height))
}

// ratioLayout lays children left-to-right, each width proportional to its ratio.
type ratioLayout struct {
	ratios []float32
	gap    float32
	h      float32
}

func (l *ratioLayout) MinSize([]fyne.CanvasObject) fyne.Size { return fyne.NewSize(40, l.h) }
func (l *ratioLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	var sum float32
	for _, r := range l.ratios {
		sum += r
	}
	if sum == 0 {
		sum = 1
	}
	gaps := l.gap * float32(len(objs)-1)
	avail := size.Width - gaps
	x := float32(0)
	for i, o := range objs {
		w := avail * (l.ratios[i] / sum)
		o.Move(fyne.NewPos(x, 0))
		o.Resize(fyne.NewSize(w, size.Height))
		x += w + l.gap
	}
}
