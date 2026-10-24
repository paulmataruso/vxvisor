package ui

import (
	"image"
	"image/color"
	"math"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
	"github.com/paulmataruso/vxvisor/desktop/internal/rfb"
)

// consoleTab is one open VM console, living inside a DocTab. Its toolbar mirrors
// the web console (gradient bar, pill controls, a live status dot); the screen
// below is the native RFB viewer.
type consoleTab struct {
	sh   *shell
	s    client.Session
	item *container.TabItem

	view      *vncView
	conn      interface{ Close() error }
	rc        *rfb.Client
	closed    bool
	closeCh   chan struct{} // closed on tab close; interrupts the reconnect backoff
	closeOnce sync.Once

	center    *fyne.Container
	statusDot *canvas.Circle
	statusTxt *canvas.Text
}

func newConsoleTab(sh *shell, s client.Session) *consoleTab {
	c := &consoleTab{sh: sh, s: s, closeCh: make(chan struct{})}
	c.view = newVNCView()

	// Screen area: the viewer on black, matching the web console's #wrap.
	black := canvas.NewRectangle(color.Black)
	c.center = container.NewStack(black, c.view)

	bar := c.toolbar()
	content := container.NewBorder(bar, nil, nil, nil, c.center)
	c.item = container.NewTabItemWithIcon(s.Name, monitorIcon(), content)

	c.connect()
	return c
}

func (c *consoleTab) connect() {
	c.setStatus("wait", "connecting…")
	go c.connLoop()
}

// connLoop keeps the console connected: it (re)dials + handshakes, runs the RFB
// read loop until the connection drops, then retries with capped backoff — so a
// server restart or a brief network blip recovers on its own, without the user
// closing the tab or logging back in. The session cookie survives a vdxd restart
// (sessions are DB-backed), so no re-auth is needed. Ends when the tab is closed.
func (c *consoleTab) connLoop() {
	backoff := time.Second
	first := true
	for {
		if c.closed {
			return
		}
		if !first {
			fyne.Do(func() {
				if !c.closed {
					c.setStatus("wait", "reconnecting…")
				}
			})
			select {
			case <-time.After(backoff):
			case <-c.closeCh:
				return
			}
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}
		first = false
		if c.dialAndRun() {
			backoff = time.Second // a good session resets the backoff
		}
	}
}

// dialAndRun connects once and blocks in the RFB read loop until it ends. Returns
// true if it actually got a live session (so the caller can reset backoff).
func (c *consoleTab) dialAndRun() (connected bool) {
	fyne.Do(func() {
		if !c.closed {
			c.setStatus("wait", "connecting…")
		}
	})
	conn, err := c.sh.app.client.DialWS(c.sh.app.client.ConsoleWSURL(c.s.ID))
	if err != nil {
		fyne.Do(func() {
			if !c.closed {
				c.setStatus("wait", "reconnecting… ("+err.Error()+")")
			}
		})
		return false
	}
	rw := client.WSReadWriter(conn)
	rc, err := rfb.Handshake(rw, c.s.VNCPassword)
	if err != nil {
		conn.Close()
		fyne.Do(func() {
			if !c.closed {
				c.setStatus("wait", "reconnecting… ("+err.Error()+")")
			}
		})
		return false
	}
	if c.closed { // tab closed while we were dialing
		conn.Close()
		return false
	}
	c.conn = conn
	c.rc = rc
	c.view.stopLoop() // end any prior repaint loop before re-attaching (reconnect)
	c.view.attach(rc, c.sh.win)
	rc.OnCutText = func(txt string) {
		fyne.Do(func() { c.sh.win.Clipboard().SetContent(txt) })
	}
	rc.OnResize = func(w, h int) {
		fyne.Do(func() { c.setStatus("ok", "connected  ·  "+itoa(w)+"×"+itoa(h)) })
	}
	fyne.Do(func() {
		if !c.closed {
			c.setStatus("ok", "connected")
			c.focus()
		}
	})
	rc.Run() // blocks until the connection ends; connLoop then retries
	return true
}

func (c *consoleTab) focus() {
	if c.sh.win != nil && c.view != nil {
		c.sh.win.Canvas().Focus(c.view)
	}
}

func (c *consoleTab) close() {
	c.closed = true
	c.closeOnce.Do(func() { close(c.closeCh) }) // stop the reconnect loop / backoff
	if c.view != nil {
		c.view.stopLoop()
	}
	if c.rc != nil {
		c.rc.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *consoleTab) setStatus(state, txt string) {
	if c.statusDot == nil {
		return
	}
	c.statusDot.FillColor = stateColor(state)
	canvas.Refresh(c.statusDot)
	c.statusTxt.Text = txt
	canvas.Refresh(c.statusTxt)
}

// toolbar reproduces the web console's control bar: a top-lit gradient strip
// with pill controls on the left (scrolling if they overflow) and a live status
// chip pinned to the right.
func (c *consoleTab) toolbar() fyne.CanvasObject {
	cad := pillBtn("Ctrl+Alt+Del", nil, func() { c.view.sendCtrlAltDel() })

	sendKey := widget.NewSelect([]string{
		"Send key…",
		"Ctrl+Alt+Backspace", "Esc", "Tab", "Alt+Tab",
		"Ctrl+C", "Ctrl+V", "Ctrl+Z", "Super (Win)",
		"Ctrl+Alt+F1", "Ctrl+Alt+F2", "Ctrl+Alt+F3", "Ctrl+Alt+F7",
	}, nil)
	sendKey.SetSelectedIndex(0)
	sendKey.OnChanged = func(v string) {
		c.sendCombo(v)
		sendKey.SetSelectedIndex(0)
	}

	ctrl := stickyBtn("Ctrl")
	alt := stickyBtn("Alt")
	shift := stickyBtn("Shift")
	bindSticky(ctrl, c.view, ksControlL)
	bindSticky(alt, c.view, ksAltL)
	bindSticky(shift, c.view, ksShiftL)

	pastePC := pillBtn("Paste from PC", theme.ContentPasteIcon(), func() {
		if txt := c.sh.win.Clipboard().Content(); txt != "" {
			go c.view.typeText(txt)
			c.setStatus("ok", "pasted clipboard into guest")
		}
	})
	sendClip := pillBtn("Send clipboard", nil, func() {
		if c.rc != nil {
			c.rc.SendCutText(c.sh.win.Clipboard().Content())
			c.setStatus("ok", "sent clipboard to guest")
		}
	})
	getClip := pillBtn("Get clipboard", nil, func() {
		c.setStatus("wait", "guest clipboard copies here on change")
	})

	display := widget.NewSelect([]string{"Fit to window", "Actual size (1:1)"}, func(v string) {
		c.setDisplayMode(v)
	})
	display.SetSelected("Fit to window")

	full := pillBtn("⛶ Full", nil, func() {
		if c.sh.win != nil {
			c.sh.win.SetFullScreen(!c.sh.win.FullScreen())
		}
	})

	left := container.NewHBox(
		cad, sep(), sendKey, ctrl, alt, shift, sep(),
		pastePC, sendClip, getClip, sep(),
		display, full,
	)
	leftScroll := container.NewHScroll(left)

	// Title mark + name, shown at the far left, non-scrolling.
	title := container.NewHBox(
		container.NewPadded(glyphBadge(26)),
		boldText(c.s.Name, 14),
	)

	// Status chip (dot + text), pinned right.
	c.statusDot = canvas.NewCircle(colWarn)
	c.statusTxt = mutedText("connecting…", 12)
	chipBG := canvas.NewRectangle(alpha(colFg, 0x12))
	chipBG.CornerRadius = 999
	chip := container.NewStack(chipBG, container.New(&insetLayout{12, 6},
		container.NewHBox(container.NewGridWrap(fyne.NewSize(8, 8), c.statusDot), c.statusTxt)))

	row := container.NewBorder(nil, nil, title, chip, leftScroll)

	grad := canvas.NewVerticalGradient(hex(0x1b2130), hex(0x12151e))
	bar := container.NewStack(grad, container.New(&insetLayout{10, 0}, row))
	// Fixed-height strip (54px, like the web #bar) with a 1px bottom divider.
	return container.NewVBox(
		container.New(&fixedHeightLayout{54}, bar),
		widget.NewSeparator(),
	)
}

func (c *consoleTab) setDisplayMode(v string) {
	if c.view == nil {
		return
	}
	actual := v == "Actual size (1:1)"
	c.view.setActual(actual)
	black := canvas.NewRectangle(color.Black)
	if actual {
		// 1:1 in a scroll so the full guest resolution can be panned.
		c.center.Objects = []fyne.CanvasObject{black, container.NewScroll(c.view)}
	} else {
		c.center.Objects = []fyne.CanvasObject{black, c.view}
	}
	c.center.Refresh()
	c.focus()
}

// sendCombo maps a web "Send key" label to a chord and sends it.
func (c *consoleTab) sendCombo(label string) {
	var syms []uint32
	switch label {
	case "Ctrl+Alt+Backspace":
		syms = []uint32{ksControlL, ksAltL, ksBackSpace}
	case "Esc":
		syms = []uint32{ksEscape}
	case "Tab":
		syms = []uint32{ksTab}
	case "Alt+Tab":
		syms = []uint32{ksAltL, ksTab}
	case "Ctrl+C":
		syms = []uint32{ksControlL, 'c'}
	case "Ctrl+V":
		syms = []uint32{ksControlL, 'v'}
	case "Ctrl+Z":
		syms = []uint32{ksControlL, 'z'}
	case "Super (Win)":
		syms = []uint32{ksSuperL}
	case "Ctrl+Alt+F1":
		syms = []uint32{ksControlL, ksAltL, ksF1}
	case "Ctrl+Alt+F2":
		syms = []uint32{ksControlL, ksAltL, ksF1 + 1}
	case "Ctrl+Alt+F3":
		syms = []uint32{ksControlL, ksAltL, ksF1 + 2}
	case "Ctrl+Alt+F7":
		syms = []uint32{ksControlL, ksAltL, ksF1 + 6}
	default:
		return
	}
	c.view.sendCombo(syms...)
}

// --- toolbar control helpers ----------------------------------------------

func pillBtn(label string, icon fyne.Resource, tap func()) *widget.Button {
	var b *widget.Button
	if icon != nil {
		b = widget.NewButtonWithIcon(label, icon, tap)
	} else {
		b = widget.NewButton(label, tap)
	}
	b.Importance = widget.LowImportance
	return b
}

func stickyBtn(label string) *widget.Button {
	b := widget.NewButton(label, nil)
	b.Importance = widget.LowImportance
	return b
}

func bindSticky(b *widget.Button, v *vncView, ks uint32) {
	b.OnTapped = func() {
		if v.toggleSticky(ks) {
			b.Importance = widget.HighImportance
		} else {
			b.Importance = widget.LowImportance
		}
		b.Refresh()
	}
}

func sep() fyne.CanvasObject {
	return widget.NewSeparator()
}

// --- the VNC viewer widget -------------------------------------------------

// tileSize is the edge of each framebuffer tile. The console is drawn as a grid
// of these so that a small change (a blinking cursor, a few typed characters)
// re-uploads only the one or two tiles it touched instead of the whole
// framebuffer — the thing that made a large desktop feel sluggish. 256 keeps the
// tile count modest (a 1080p screen is 8×5) while keeping each dirty upload tiny
// (256KB vs ~8MB for the full frame).
const tileSize = 256

type vncView struct {
	widget.BaseWidget
	rfb    *rfb.Client
	canvas fyne.Canvas

	// Tiled presentation. Each tile is a packed RGBA buffer (NOT a framebuffer
	// SubImage: the GL painter's *image.RGBA fast path ignores Stride, so a
	// SubImage would upload garbled rows); the damaged region is copied into it
	// on refresh.
	grid       *fyne.Container
	layout     *tileLayout
	tiles      []*canvas.Image
	bufs       []*image.RGBA
	fbw, fbh   int
	cols, rows int
	actual     bool

	mask   byte
	sticky map[uint32]bool

	// Local hardware cursor. curCursor is cached and only replaced when the shape
	// actually changes, so Fyne (which rebuilds the native cursor whenever the
	// returned value differs by identity) doesn't churn a new GLFW cursor on every
	// mouse move. Guarded by curMu: OnCursor runs on the read loop, Cursor() on UI.
	curMu     sync.Mutex
	curCursor desktop.Cursor

	wake chan struct{} // OnUpdate signals a pending repaint (coalesced)
	stop chan struct{} // closed on tab close to end the repaint loop
}

// vncCursor is a server-provided pointer shape rendered as a native cursor.
type vncCursor struct {
	img        image.Image
	hotX, hotY int
}

func (c *vncCursor) Image() (image.Image, int, int) { return c.img, c.hotX, c.hotY }

func newVNCView() *vncView {
	v := &vncView{
		sticky:    map[uint32]bool{},
		layout:    &tileLayout{},
		curCursor: desktop.DefaultCursor, // until the server sends a shape
	}
	v.grid = container.New(v.layout)
	v.ExtendBaseWidget(v)
	return v
}

func (v *vncView) attach(rc *rfb.Client, win fyne.Window) {
	v.rfb = rc
	v.canvas = win.Canvas()
	v.wake = make(chan struct{}, 1)
	v.stop = make(chan struct{})
	// Event-driven repaint: the read loop signals a pending frame; the loop
	// coalesces bursts and repaints as soon as the GPU is free, capped at ~60fps,
	// with zero idle wakeups.
	rc.OnUpdate = func() {
		select {
		case v.wake <- struct{}{}:
		default: // a repaint is already pending; coalesce into it
		}
	}
	// Local cursor: translate each server cursor shape into a native cursor. Fyne
	// re-queries Cursor() and applies it on the next pointer move (which is
	// happening continuously whenever the cursor matters), so no explicit refresh
	// is needed — and because the native cursor is drawn by the OS at the hardware
	// pointer, it tracks the real mouse with zero latency.
	rc.OnCursor = func() {
		img, hx, hy, have := rc.Cursor()
		var cur desktop.Cursor
		switch {
		case !have:
			cur = desktop.DefaultCursor
		case img == nil:
			cur = desktop.HiddenCursor // server asked for an invisible pointer
		default:
			cur = &vncCursor{img: img, hotX: hx, hotY: hy}
		}
		v.curMu.Lock()
		v.curCursor = cur
		v.curMu.Unlock()
	}
	go v.repaintLoop()
}

// Cursor implements desktop.Cursorable: it hands Fyne the latest server pointer
// shape as a native (hardware) cursor so it tracks the physical mouse instantly.
func (v *vncView) Cursor() desktop.Cursor {
	v.curMu.Lock()
	defer v.curMu.Unlock()
	return v.curCursor
}

// repaintLoop consumes coalesced updates and refreshes only the damaged tiles.
func (v *vncView) repaintLoop() {
	const minGap = 16 * time.Millisecond // ~60fps ceiling
	var last time.Time
	for {
		select {
		case <-v.stop:
			return
		case <-v.wake:
		}
		// Rate-limit: if we painted very recently, wait out the remainder so the
		// rectangles that land in the meantime batch into one pass.
		if gap := minGap - time.Since(last); gap > 0 {
			t := time.NewTimer(gap)
			select {
			case <-v.stop:
				t.Stop()
				return
			case <-t.C:
			}
		}
		rc := v.rfb
		if rc == nil {
			return
		}
		dmg := rc.TakeDamage()
		fyne.Do(func() { v.applyDamage(rc, dmg) })
		last = time.Now()
	}
}

// applyDamage (UI thread) rebuilds the tile grid on first frame / resize, else
// re-uploads only the tiles overlapping the damaged regions.
func (v *vncView) applyDamage(rc *rfb.Client, dmg []image.Rectangle) {
	fbw, fbh := rc.Dimensions()
	if fbw == 0 || fbh == 0 {
		return
	}
	if fbw != v.fbw || fbh != v.fbh || len(v.tiles) == 0 {
		v.buildGrid(rc, fbw, fbh)
		return
	}
	for _, r := range dmg {
		r = r.Intersect(image.Rect(0, 0, fbw, fbh))
		if r.Empty() {
			continue
		}
		c0, c1 := r.Min.X/tileSize, (r.Max.X-1)/tileSize
		r0, r1 := r.Min.Y/tileSize, (r.Max.Y-1)/tileSize
		for row := r0; row <= r1; row++ {
			for col := c0; col <= c1; col++ {
				v.refreshTile(rc, col, row)
			}
		}
	}
}

// buildGrid (re)creates the tile buffers + images for a framebuffer of fbw×fbh
// and uploads them all once.
func (v *vncView) buildGrid(rc *rfb.Client, fbw, fbh int) {
	cols := (fbw + tileSize - 1) / tileSize
	rows := (fbh + tileSize - 1) / tileSize
	tiles := make([]*canvas.Image, 0, cols*rows)
	bufs := make([]*image.RGBA, 0, cols*rows)
	for row := 0; row < rows; row++ {
		for col := 0; col < cols; col++ {
			w := min(tileSize, fbw-col*tileSize)
			h := min(tileSize, fbh-row*tileSize)
			buf := image.NewRGBA(image.Rect(0, 0, w, h))
			im := canvas.NewImageFromImage(buf)
			im.FillMode = canvas.ImageFillStretch
			im.ScaleMode = canvas.ImageScaleFastest
			bufs = append(bufs, buf)
			tiles = append(tiles, im)
		}
	}
	v.fbw, v.fbh, v.cols, v.rows = fbw, fbh, cols, rows
	v.tiles, v.bufs = tiles, bufs
	v.layout.set(fbw, fbh, cols, rows)

	objs := make([]fyne.CanvasObject, len(tiles))
	for i := range tiles {
		objs[i] = tiles[i]
	}
	v.grid.Objects = objs
	for col := 0; col < cols; col++ {
		for row := 0; row < rows; row++ {
			v.refreshTile(rc, col, row)
		}
	}
	v.grid.Refresh()
}

// refreshTile copies the tile's region out of the framebuffer and re-uploads it.
func (v *vncView) refreshTile(rc *rfb.Client, col, row int) {
	if col < 0 || row < 0 || col >= v.cols || row >= v.rows {
		return
	}
	idx := row*v.cols + col
	if idx >= len(v.tiles) {
		return
	}
	rc.CopyRegion(v.bufs[idx], col*tileSize, row*tileSize)
	v.tiles[idx].Refresh()
}

// setActual switches between fit-to-window and 1:1 presentation.
func (v *vncView) setActual(a bool) {
	v.actual = a
	v.layout.actual = a
	if v.grid != nil {
		v.grid.Refresh()
	}
	v.Refresh()
}

// stopLoop ends the repaint loop (called when the console tab closes).
func (v *vncView) stopLoop() {
	if v.stop != nil {
		close(v.stop)
		v.stop = nil
	}
}

func (v *vncView) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(v.grid)
}

func (v *vncView) toFB(pos fyne.Position) (int, int, bool) {
	fbw, fbh := v.fbw, v.fbh
	if fbw == 0 || fbh == 0 {
		if v.rfb != nil {
			fbw, fbh = v.rfb.Dimensions()
		}
		if fbw == 0 || fbh == 0 {
			return 0, 0, false
		}
	}
	// 1:1 mode: the view lives in a scroll and its coordinates already are
	// framebuffer pixels.
	if v.actual {
		return int(pos.X), int(pos.Y), true
	}
	size := v.Size()
	if size.Width <= 0 || size.Height <= 0 {
		return 0, 0, false
	}
	// Fit mode: same contain scale + centering the tile layout uses, inverted.
	s := size.Width / float32(fbw)
	if sh := size.Height / float32(fbh); sh < s {
		s = sh
	}
	offX := (size.Width - float32(fbw)*s) / 2
	offY := (size.Height - float32(fbh)*s) / 2
	x := int((pos.X - offX) / s)
	y := int((pos.Y - offY) / s)
	return x, y, true
}

// tileLayout positions the console tiles. In fit mode it fits the framebuffer's
// aspect inside the widget and centres it; in 1:1 mode it places tiles at native
// pixels. Tile boundaries are snapped to the same rounded pixel grid for every
// tile so neighbours abut exactly — no seams between tiles.
type tileLayout struct {
	fbw, fbh, cols, rows int
	actual               bool
}

func (l *tileLayout) set(fbw, fbh, cols, rows int) {
	l.fbw, l.fbh, l.cols, l.rows = fbw, fbh, cols, rows
}

func (l *tileLayout) MinSize([]fyne.CanvasObject) fyne.Size {
	if l.actual {
		return fyne.NewSize(float32(l.fbw), float32(l.fbh))
	}
	return fyne.NewSize(1, 1)
}

func (l *tileLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	if l.fbw == 0 || l.fbh == 0 || len(objs) == 0 {
		return
	}
	var s, offX, offY float32
	if l.actual {
		s = 1
	} else {
		s = size.Width / float32(l.fbw)
		if sh := size.Height / float32(l.fbh); sh < s {
			s = sh
		}
		offX = (size.Width - float32(l.fbw)*s) / 2
		offY = (size.Height - float32(l.fbh)*s) / 2
	}
	// Boundary of grid line i, snapped to a whole pixel. Using shared boundaries
	// (this tile's right edge == next tile's left edge) guarantees no gaps.
	bx := func(i int) float32 {
		px := min(i*tileSize, l.fbw)
		return float32(math.Round(float64(offX + float32(px)*s)))
	}
	by := func(j int) float32 {
		py := min(j*tileSize, l.fbh)
		return float32(math.Round(float64(offY + float32(py)*s)))
	}
	i := 0
	for row := 0; row < l.rows; row++ {
		y0, y1 := by(row), by(row+1)
		for col := 0; col < l.cols; col++ {
			if i >= len(objs) {
				return
			}
			x0, x1 := bx(col), bx(col+1)
			objs[i].Move(fyne.NewPos(x0, y0))
			objs[i].Resize(fyne.NewSize(x1-x0, y1-y0))
			i++
		}
	}
}

// rel converts an event's absolute (canvas) position into one relative to the
// viewer widget's top-left. Using the absolute pointer position minus the
// widget's absolute origin is robust to the surrounding chrome (the DocTabs tab
// bar + the 54px toolbar above the viewer); relying on the plain widget-relative
// Position was landing ~a tab-bar+toolbar off, which is what pushed the guest
// cursor out of alignment with the real pointer.
func (v *vncView) rel(e *fyne.PointEvent) fyne.Position {
	o := fyne.CurrentApp().Driver().AbsolutePositionForObject(v)
	return fyne.NewPos(e.AbsolutePosition.X-o.X, e.AbsolutePosition.Y-o.Y)
}

func (v *vncView) MouseDown(e *desktop.MouseEvent) {
	if v.canvas != nil {
		v.canvas.Focus(v)
	}
	v.mask |= buttonBit(e.Button)
	v.sendPointer(v.rel(&e.PointEvent))
}

func (v *vncView) MouseUp(e *desktop.MouseEvent) {
	v.mask &^= buttonBit(e.Button)
	v.sendPointer(v.rel(&e.PointEvent))
}

func (v *vncView) MouseIn(*desktop.MouseEvent)      {}
func (v *vncView) MouseOut()                        {}
func (v *vncView) MouseMoved(e *desktop.MouseEvent) { v.sendPointer(v.rel(&e.PointEvent)) }

func (v *vncView) Scrolled(e *fyne.ScrollEvent) {
	if v.rfb == nil {
		return
	}
	bit := byte(1 << 3)
	if e.Scrolled.DY < 0 {
		bit = 1 << 4
	}
	x, y, ok := v.toFB(v.rel(&e.PointEvent))
	if !ok {
		return
	}
	v.rfb.SendPointer(x, y, v.mask|bit)
	v.rfb.SendPointer(x, y, v.mask)
}

func (v *vncView) sendPointer(pos fyne.Position) {
	if v.rfb == nil {
		return
	}
	if x, y, ok := v.toFB(pos); ok {
		v.rfb.SendPointer(x, y, v.mask)
	}
}

func buttonBit(b desktop.MouseButton) byte {
	switch b {
	case desktop.MouseButtonPrimary:
		return 1 << 0
	case desktop.MouseButtonTertiary:
		return 1 << 1
	case desktop.MouseButtonSecondary:
		return 1 << 2
	}
	return 0
}

func (v *vncView) FocusGained() {}
func (v *vncView) FocusLost()   {}

func (v *vncView) TypedRune(r rune) { v.sendRune(runeKeysym(r), runeNeedsShift(r)) }

// sendRune taps a printable keysym, holding Shift around it when the character
// requires it (QEMU VNC needs the client to assert Shift for shifted keysyms).
// Any sticky modifiers from the toolbar are applied too; Shift isn't doubled if
// a sticky Shift is already active.
func (v *vncView) sendRune(ks uint32, shift bool) {
	if v.rfb == nil {
		return
	}
	mods := v.takeSticky()
	if shift {
		already := false
		for _, m := range mods {
			if m == ksShiftL {
				already = true
				break
			}
		}
		if !already {
			mods = append([]uint32{ksShiftL}, mods...)
		}
	}
	for _, m := range mods {
		v.rfb.SendKey(m, true)
	}
	v.rfb.TapKey(ks)
	for i := len(mods) - 1; i >= 0; i-- {
		v.rfb.SendKey(mods[i], false)
	}
}

func (v *vncView) TypedKey(e *fyne.KeyEvent) {
	if ks, ok := specialKeysym[e.Name]; ok {
		v.sendKey(ks)
	}
}

func (v *vncView) sendKey(ks uint32) {
	if v.rfb == nil {
		return
	}
	mods := v.takeSticky()
	for _, m := range mods {
		v.rfb.SendKey(m, true)
	}
	v.rfb.TapKey(ks)
	for i := len(mods) - 1; i >= 0; i-- {
		v.rfb.SendKey(mods[i], false)
	}
}

// sendCombo presses several keysyms together (press in order, release reverse).
func (v *vncView) sendCombo(syms ...uint32) {
	if v.rfb == nil || len(syms) == 0 {
		return
	}
	for _, s := range syms {
		v.rfb.SendKey(s, true)
	}
	for i := len(syms) - 1; i >= 0; i-- {
		v.rfb.SendKey(syms[i], false)
	}
}

func (v *vncView) toggleSticky(ks uint32) bool {
	if v.sticky[ks] {
		delete(v.sticky, ks)
		return false
	}
	v.sticky[ks] = true
	return true
}

func (v *vncView) takeSticky() []uint32 {
	if len(v.sticky) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(v.sticky))
	for _, m := range []uint32{ksShiftL, ksControlL, ksAltL, ksSuperL} {
		if v.sticky[m] {
			out = append(out, m)
		}
	}
	v.sticky = map[uint32]bool{}
	return out
}

func (v *vncView) sendCtrlAltDel() {
	v.sendCombo(ksControlL, ksAltL, ksDelete)
}

func (v *vncView) typeText(s string) {
	if v.rfb == nil {
		return
	}
	for _, r := range s {
		switch r {
		case '\n':
			v.rfb.TapKey(ksReturn)
		case '\t':
			v.rfb.TapKey(ksTab)
		default:
			v.rfb.TapKey(runeKeysym(r))
		}
		time.Sleep(4 * time.Millisecond)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
