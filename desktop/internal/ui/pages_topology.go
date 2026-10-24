package ui

import (
	"image/color"
	"math"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// This file is a faithful native port of the web topology diagram
// (internal/web/templates/topochart.html): a drawn 4-column vSphere-style map
// (Port Groups → vSwitch → Physical Adapters → Upstream Switch) plus the
// vRouter chain, rendered with absolutely-positioned Fyne canvas primitives and
// sampled bezier connectors — not nested cards.

// --- geometry constants (verbatim from topochart.html) ---------------------
const (
	tPad      = 18
	tPgW      = 330
	tUpW      = 210
	tColGap   = 84
	tPgColGap = 170
	tBlkGap   = 34
	tPgHdr    = 44
	tVMRow    = 42
	tPgFoot   = 14
	tPgGap    = 14
	tVMIpXtra = 22
	tNicH     = 48
	tBondHdr  = 34
	tBondRow  = 22
	tBondFoot = 12
	tUpGap    = 14
	tSwitchW  = 236
)

// fixedSizeLayout reports an exact content size and leaves children where the
// builder Move/Resize'd them (absolute positioning inside a scroll).
type fixedSizeLayout struct{ w, h float32 }

func (l *fixedSizeLayout) MinSize([]fyne.CanvasObject) fyne.Size { return fyne.NewSize(l.w, l.h) }
func (l *fixedSizeLayout) Layout([]fyne.CanvasObject, fyne.Size) {}

// topoBuilder accumulates positioned canvas objects.
type topoBuilder struct {
	objs []fyne.CanvasObject
}

func measure(s string, px float32, bold bool) float32 {
	return fyne.MeasureText(s, px, fyne.TextStyle{Bold: bold}).Width
}

func fit(s string, px float32, bold bool, maxw float32) string {
	if measure(s, px, bold) <= maxw {
		return s
	}
	r := []rune(s)
	for len(r) > 1 && measure(string(r)+"…", px, bold) > maxw {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

func (b *topoBuilder) rect(x, y, w, h float32, fill, stroke color.Color, radius, strokeW float32) {
	r := canvas.NewRectangle(fill)
	r.CornerRadius = radius
	if stroke != nil {
		r.StrokeColor = stroke
		r.StrokeWidth = strokeW
	}
	r.Move(fyne.NewPos(x, y))
	r.Resize(fyne.NewSize(w, h))
	b.objs = append(b.objs, r)
}

// text places s so (x,y) is the SVG baseline anchor point (l=start, m=middle,
// e=end), approximating the baseline→top offset.
func (b *topoBuilder) text(x, y float32, s string, col color.Color, anchor byte, bold bool, size float32) {
	if s == "" {
		return
	}
	t := canvas.NewText(s, col)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: bold}
	w := measure(s, size, bold)
	tx := x
	switch anchor {
	case 'm':
		tx = x - w/2
	case 'e':
		tx = x - w
	}
	t.Move(fyne.NewPos(tx, y-size*0.82))
	t.Resize(fyne.NewSize(w+2, size*1.35))
	b.objs = append(b.objs, t)
}

func (b *topoBuilder) line(x1, y1, x2, y2 float32, col color.Color, w float32) {
	l := canvas.NewLine(col)
	l.StrokeWidth = w
	l.Position1 = fyne.NewPos(x1, y1)
	l.Position2 = fyne.NewPos(x2, y2)
	b.objs = append(b.objs, l)
}

func (b *topoBuilder) circle(cx, cy, r float32, fill color.Color) {
	c := canvas.NewCircle(fill)
	c.Move(fyne.NewPos(cx-r, cy-r))
	c.Resize(fyne.NewSize(2*r, 2*r))
	b.objs = append(b.objs, c)
}

// conn draws the cubic-bezier connector from (x1,y1) to (x2,y2) as a sampled
// polyline (Fyne has no bezier primitive).
func (b *topoBuilder) conn(x1, y1, x2, y2 float32, col color.Color, on bool) {
	dx := (x2 - x1) / 2
	if dx < 30 {
		dx = 30
	}
	c := col
	if !on {
		c = alpha(col, 0x66)
	} else {
		c = alpha(col, 0xd8)
	}
	px, py := x1, y1
	const n = 20
	for i := 1; i <= n; i++ {
		t := float32(i) / n
		mt := 1 - t
		// cubic bezier with control points (x1+dx,y1) and (x2-dx,y2)
		bx := mt*mt*mt*x1 + 3*mt*mt*t*(x1+dx) + 3*mt*t*t*(x2-dx) + t*t*t*x2
		by := mt*mt*mt*y1 + 3*mt*mt*t*y1 + 3*mt*t*t*y2 + t*t*t*y2
		b.line(px, py, bx, by, c, 2)
		px, py = bx, by
	}
}

func (b *topoBuilder) monitor(x, y float32, col color.Color) {
	b.rect(x, y, 14, 10, color.Transparent, col, 1.5, 1.4)
	b.rect(x+5, y+10, 4, 2.5, col, nil, 0, 0)
}
func (b *topoBuilder) nicGlyph(x, y float32, col color.Color) {
	b.rect(x, y, 14, 12, color.Transparent, col, 1.5, 1.4)
	b.rect(x+4, y+9, 6, 3, col, nil, 0, 0)
}
func (b *topoBuilder) ctGlyph(x, y float32, col color.Color) {
	b.rect(x, y, 14, 12, color.Transparent, col, 1.5, 1.4)
	b.line(x, y+4, x+14, y+4, col, 1.1)
	b.line(x+7, y, x+7, y+12, col, 1.1)
}
func (b *topoBuilder) iconSwitch(cx, cy float32, col color.Color) {
	bw, bh := float32(22), float32(14)
	b.rect(cx-bw/2, cy-bh/2, bw, bh, color.Transparent, col, 3, 1.5)
	b.line(cx-bw/2+5, cy-3, cx+bw/2-5, cy-3, col, 1.2)
	b.line(cx-bw/2+5, cy+3, cx+bw/2-5, cy+3, col, 1.2)
}
func (b *topoBuilder) iconRouter(cx, cy float32, col color.Color) {
	b.circle(cx, cy, 9, color.Transparent)
	// ring
	ring := canvas.NewCircle(color.Transparent)
	ring.StrokeColor = col
	ring.StrokeWidth = 1.6
	ring.Move(fyne.NewPos(cx-9, cy-9))
	ring.Resize(fyne.NewSize(18, 18))
	b.objs = append(b.objs, ring)
	b.line(cx-4.5, cy-3, cx+4.5, cy-3, col, 1.3)
	b.line(cx-4.5, cy+3, cx+4.5, cy+3, col, 1.3)
}

// --- box renderers ---------------------------------------------------------

func pgHeight(pg client.TopoPortGroup) float32 {
	if len(pg.VMs) == 0 {
		return tPgHdr + tVMRow + tPgFoot
	}
	h := float32(tPgHdr + tPgFoot)
	for _, vm := range pg.VMs {
		h += tVMRow
		if vm.IP != "" {
			h += tVMIpXtra
		}
	}
	return h
}

func upHeight(up client.TopoUplink) float32 {
	if up.Kind == "bond" {
		m := len(up.Members)
		if m < 1 {
			m = 1
		}
		return float32(tBondHdr + m*tBondRow + tBondFoot)
	}
	return tNicH
}

// pgBox draws a port group; returns its exit-Y (where the connector leaves).
func (b *topoBuilder) pgBox(x, y float32, pg client.TopoPortGroup, col color.Color) float32 {
	h := pgHeight(pg)
	b.rect(x, y, tPgW, h, colPanel, col, 9, 1.4)
	b.rect(x, y, 4, h, col, nil, 0, 0) // left accent spine
	badge := "untagged"
	if pg.VLAN != 0 {
		badge = "VLAN " + itoa(pg.VLAN)
	}
	bw := measure(badge, 11, true) + 16
	b.rect(x+tPgW-bw-10, y+9, bw, 18, color.Transparent, col, 9, 1)
	b.text(x+tPgW-10-bw/2, y+22, badge, col, 'm', true, 11)
	b.text(x+14, y+22, fit(pg.Name, 13, true, tPgW-bw-36), colFg, 'l', true, 13)
	if pg.CIDR != "" {
		b.text(x+14, y+36, fit(pg.CIDR, 11, false, tPgW-28), colMuted, 'l', false, 11)
	}
	exitY := y + h/2
	if len(pg.VMs) == 0 {
		b.text(x+40, y+tPgHdr+14, "(no VMs attached)", colMuted, 'l', false, 12)
		return exitY
	}
	// mini bus enclosing the VM dots
	rowY := make([]float32, len(pg.VMs))
	cur := y + tPgHdr
	for i, vm := range pg.VMs {
		rowY[i] = cur
		cur += tVMRow
		if vm.IP != "" {
			cur += tVMIpXtra
		}
	}
	mids := make([]float32, len(rowY))
	for i, ry := range rowY {
		mids[i] = ry + 9
	}
	busHalf := float32(9)
	dotX := x + tPgW - 20
	busX := dotX - busHalf
	busR := dotX + busHalf
	bTop := mids[0] - busHalf
	bBot := mids[len(mids)-1] + busHalf
	bMid := (bTop + bBot) / 2
	exitY = bMid
	b.rect(busX, bTop, busHalf*2, bBot-bTop, colPanel2, col, 6, 1.3)
	b.line(busR, bMid, x+tPgW, bMid, alpha(col, 0x99), 1.6)
	for i, vm := range pg.VMs {
		ry, mid := rowY[i], mids[i]
		vcol := colMuted
		if vm.State == "running" {
			vcol = colOK
		}
		if vm.Kind == "container" {
			b.ctGlyph(x+16, ry+2, vcol)
		} else {
			b.monitor(x+16, ry+3, vcol)
		}
		label := vm.Name
		if label == "" {
			label = vm.Tap
		}
		if vm.Kind == "container" {
			label += " (lxc)"
		}
		lbl := fit(label, 12, false, busX-16-(x+40))
		b.text(x+40, ry+14, lbl, colFg, 'l', false, 12)
		nmR := x + 40 + measure(lbl, 12, false)
		b.line(nmR+8, mid, busX, mid, alpha(vcol, 0x80), 1.3)
		bBotY := ry + 24
		if vm.IP != "" {
			lx, lt, lb := x+46, ry+18, ry+30
			b.line(lx, lt, lx, lb, colMuted, 1.3)
			b.line(lx, lb, lx+8, lb, colMuted, 1.3)
			ipFit := fit(vm.IP, 11, true, busX-(lx+13)-10)
			b.text(lx+13, lb+4, ipFit, colFg, 'l', true, 11)
			if w := (lx + 13) + measure(ipFit, 11, true); w > nmR {
				nmR = w
			}
			bBotY = lb + 11
		}
		b.rect(x+32, ry-3, (nmR+12)-(x+32), bBotY-(ry-3), color.Transparent, colLine, 6, 1)
		b.circle(dotX, mid, 4, vcol)
	}
	return exitY
}

// spineBox draws the center vSwitch / vRouter box.
func (b *topoBuilder) spineBox(x, top, w, h float32, title string, accent bool, glyph string, lines []topoLine, footer string) {
	col := colMuted
	if accent {
		col = colAccent
	}
	sw := float32(1.5)
	if accent {
		sw = 2
	}
	b.rect(x, top, w, h, colPanel2, col, 10, sw)
	if glyph == "router" {
		b.iconRouter(x+w/2, top+16, col)
		b.text(x+w/2, top+38, title, col, 'm', true, 11)
	} else {
		rows := append([]topoLine{{t: title, sz: 11, wt: true, fill: colMuted}}, lines...)
		gap := float32(7)
		iconH, iconGap := float32(0), float32(0)
		if glyph == "switch" {
			iconH, iconGap = 18, 9
		}
		blockH := iconH + iconGap
		for _, r := range rows {
			blockH += r.sz
		}
		blockH += gap * float32(len(rows)-1)
		topY := top + (h-blockH)/2
		if iconH > 0 {
			b.iconSwitch(x+w/2, topY+iconH/2, col)
		}
		by := topY + iconH + iconGap + rows[0].sz
		for _, r := range rows {
			fill := r.fill
			if fill == nil {
				fill = colFg
			}
			b.text(x+w/2, by, fit(r.t, r.sz, r.wt, w-16), fill, 'm', r.wt, r.sz)
			by += r.sz + gap
		}
	}
	if footer != "" {
		b.text(x+w/2, top+h-12, footer, colMuted, 'm', false, 10)
	}
}

type topoLine struct {
	t    string
	sz   float32
	wt   bool
	fill color.Color
}

// upBox draws an upstream-switch (LLDP) box; returns its height.
func (b *topoBuilder) upBox(x, y, w float32, s client.TopoNeighbor, conns []string) float32 {
	via := s.Via
	if via == "" {
		via = "LLDP"
	}
	vw := measure(via, 9, true) + 14
	boxH := float32(36 + len(conns)*15 + 14)
	if s.MgmtIP != "" {
		boxH += 15
	}
	b.rect(x, y, w, boxH, colPanel, colMuted, 9, 1.4)
	b.rect(x+w-4, y, 4, boxH, colMuted, nil, 0, 0)
	b.rect(x+12, y+12, 16, 5, color.Transparent, colFg, 1, 1.2)
	b.rect(x+12, y+19, 16, 5, color.Transparent, colFg, 1, 1.2)
	b.rect(x+w-vw-10, y+10, vw, 16, color.Transparent, colMuted, 8, 1)
	b.text(x+w-10-vw/2, y+21, via, colMuted, 'm', true, 9)
	name := s.SwitchName
	if name == "" {
		name = "(unknown switch)"
	}
	b.text(x+36, y+24, fit(name, 13, true, w-vw-54), colFg, 'l', true, 13)
	ly := y + 40
	if s.MgmtIP != "" {
		b.text(x+14, ly, "mgmt "+fit(s.MgmtIP, 11, false, w-70), colMuted, 'l', false, 11)
		ly += 15
	}
	for _, c := range conns {
		b.text(x+14, ly, fit(c, 11, false, w-28), colFg, 'l', false, 11)
		ly += 15
	}
	return boxH
}

// networkMapSection renders the full topology map (web-faithful), inside a
// horizontal scroll so wide diagrams pan. Admin-only server-side.
func (sh *shell) networkMapSection() fyne.CanvasObject {
	topo, err := sh.app.client.Topology()
	if err != nil {
		return subSection("Network map", nil, card(container.NewPadded(mutedPara("Topology unavailable: "+err.Error()))))
	}
	if len(topo.Switches) == 0 && len(topo.VRouters) == 0 {
		return subSection("Network map", nil, card(container.NewPadded(mutedPara("No vSwitches or networks yet. Create a port group to see the diagram."))))
	}

	b := &topoBuilder{}
	kindOf := func(sw client.TopoSwitch) string {
		switch sw.Kind {
		case "standard":
			return "Standard Switch"
		case "overlay":
			return "Overlay (VXLAN)"
		case "management":
			return "Management"
		default:
			return "User-mode (NAT)"
		}
	}

	// center column width = widest vSwitch label, clamped [140,420]
	swW := float32(140)
	for _, sw := range topo.Switches {
		if w := measure(sw.Name, 14, true) + 28; w > swW {
			swW = w
		}
		if w := measure(kindOf(sw), 11, false) + 24; w > swW {
			swW = w
		}
		counts := itoa(len(sw.PortGroups)) + " PG · " + itoa(len(sw.Uplinks)) + " uplink"
		if w := measure(counts, 10, false) + 24; w > swW {
			swW = w
		}
	}
	if swW > 420 {
		swW = 420
	}
	swW = float32(math.Round(float64(swW)))

	hasNbr := false
	for _, sw := range topo.Switches {
		for _, u := range sw.Uplinks {
			if len(u.Neighbors) > 0 {
				hasNbr = true
			}
		}
	}
	pgX := float32(tPad)
	swX := pgX + tPgW + tPgColGap
	upX := swX + swW + tColGap
	switchX := upX + tUpW + tColGap
	W := upX + tUpW + tPad
	if hasNbr {
		W = switchX + tSwitchW + tPad
	}

	y := float32(tPad)
	H := float32(tPad)
	first := true
	for _, sw := range topo.Switches {
		pgs, ups, vmks := sw.PortGroups, sw.Uplinks, sw.VMKs
		leftH := float32(0)
		for _, k := range vmks {
			leftH += vmkHeight(k)
		}
		for _, pg := range pgs {
			leftH += pgHeight(pg)
		}
		if n := len(vmks) + len(pgs) - 1; n > 0 {
			leftH += tPgGap * float32(n)
		}
		rightH := float32(0)
		for _, u := range ups {
			rightH += upHeight(u)
		}
		if n := len(ups) - 1; n > 0 {
			rightH += tUpGap * float32(n)
		}
		blkH := leftH
		if rightH > blkH {
			blkH = rightH
		}
		if blkH < 130 {
			blkH = 130
		}
		top := y
		cy := top + blkH/2

		b.spineBox(swX, top, swW, blkH, "vSwitch", false, "switch",
			[]topoLine{{t: sw.Name, fill: colFg, sz: 14, wt: true}, {t: kindOf(sw), fill: colMuted, sz: 11}},
			itoa(len(pgs))+" PG · "+itoa(len(ups))+" uplink")

		py := top + (blkH-leftH)/2
		for _, k := range vmks {
			vh := vmkHeight(k)
			b.rect(pgX, py, tPgW, vh, colPanel, colOK, 9, 1.4)
			b.rect(pgX, py, 4, vh, colOK, nil, 0, 0)
			b.nicGlyph(pgX+16, py+16, colOK)
			vb := measure("host adapter", 11, true) + 16
			b.rect(pgX+tPgW-vb-10, py+9, vb, 18, color.Transparent, colOK, 9, 1)
			b.text(pgX+tPgW-10-vb/2, py+22, "host adapter", colOK, 'm', true, 11)
			b.text(pgX+40, py+20, fit(k.Label, 13, true, tPgW-vb-60), colFg, 'l', true, 13)
			for i, ip := range k.IPs {
				b.text(pgX+40, py+36+float32(i)*15, fit(ip, 11, false, tPgW-60), colMuted, 'l', false, 11)
			}
			b.conn(pgX+tPgW, py+vh/2, swX, cy, colOK, true)
			py += vh + tPgGap
		}
		for _, pg := range pgs {
			exitY := b.pgBox(pgX, py, pg, colPrimary)
			b.conn(pgX+tPgW, exitY, swX, cy, colPrimary, true)
			py += pgHeight(pg) + tPgGap
		}

		uy := top + (blkH-rightH)/2
		for _, up := range ups {
			h := upHeight(up)
			on := up.State != "down"
			b.conn(swX+swW, cy, upX, uy+h/2, colAccent, on)
			if up.Kind == "bond" {
				b.rect(upX, uy, tUpW, h, colPanel, colAccent, 9, 1.6)
				b.rect(upX+tUpW-4, uy, 4, h, colAccent, nil, 0, 0)
				mode := up.Mode
				switch up.Mode {
				case "lacp":
					mode = "LACP (802.3ad)"
				case "etherchannel":
					mode = "Etherchannel"
				case "":
					mode = "bond"
				}
				mw := measure(mode, 10, true)
				b.text(upX+tUpW-12, uy+21, mode, colAccent, 'e', true, 10)
				b.text(upX+12, uy+21, fit("LAG · "+up.Name, 13, true, tUpW-mw-30), colFg, 'l', true, 13)
				if len(up.Members) == 0 {
					b.text(upX+36, uy+tBondHdr+10, "(no members)", colMuted, 'l', false, 12)
				}
				for i, m := range up.Members {
					ry := uy + tBondHdr + float32(i)*tBondRow
					b.nicGlyph(upX+14, ry-1, colMuted)
					b.text(upX+36, ry+10, fit(m, 12, false, tUpW-48), colFg, 'l', false, 12)
				}
			} else {
				b.rect(upX, uy, tUpW, h, colPanel, colAccent, 9, 1.4)
				b.rect(upX+tUpW-4, uy, 4, h, colAccent, nil, 0, 0)
				b.nicGlyph(upX+14, uy+12, colAccent)
				b.text(upX+38, uy+22, fit(up.Name, 13, true, tUpW-64), colFg, 'l', true, 13)
				meta := ""
				if up.Speed > 0 {
					if up.Speed >= 1000 {
						meta = itoa(up.Speed/1000) + " GbE"
					} else {
						meta = itoa(up.Speed) + " Mb/s"
					}
				}
				if up.Speed > 0 && up.State != "" {
					meta += " · "
				}
				meta += up.State
				if meta == "" {
					meta = "physical adapter"
				}
				b.text(upX+38, uy+38, meta, colMuted, 'l', false, 11)
				dcol := colMuted
				if on {
					dcol = colOK
				}
				b.circle(upX+tUpW-16, uy+h/2, 4, dcol)
			}
			// upstream switch box (per first neighbor), to the right
			if hasNbr && len(up.Neighbors) > 0 {
				nb := up.Neighbors[0]
				var conns []string
				local := nb.Local
				if local == "" {
					local = up.Name
				}
				conns = append(conns, local+" → "+nb.PortID)
				bh := b.upBox(switchX, uy+h/2-24, tSwitchW, nb, conns)
				b.line(upX+tUpW, uy+h/2, switchX, uy+h/2-24+bh/2, alpha(colMuted, 0x99), 2)
			}
			uy += h + tUpGap
		}
		if len(ups) == 0 {
			b.rect(upX, cy-20, tUpW, 40, colPanel, colLine, 9, 1.2)
			b.text(upX+tUpW/2, cy+4, "no uplink (internal only)", colMuted, 'm', false, 12)
			b.conn(swX+swW, cy, upX, cy, colMuted, false)
		}

		if first {
			b.text(pgX+tPgW/2, top-8, "PORT GROUPS", colMuted, 'm', true, 10)
			b.text(swX+swW/2, top-8, "VSWITCH", colMuted, 'm', true, 10)
			b.text(upX+tUpW/2, top-8, "PHYSICAL ADAPTERS", colMuted, 'm', true, 10)
			if hasNbr {
				b.text(switchX+tSwitchW/2, top-8, "UPSTREAM SWITCH", colMuted, 'm', true, 10)
			}
			first = false
		}
		y = top + blkH + tBlkGap
		H = y
	}

	// vRouters: port-group stack → vRouter box → transit → external chain.
	if len(topo.VRouters) > 0 {
		hdrY := H + 30
		if len(topo.Switches) > 0 {
			b.text(pgX, hdrY, "VIRTUAL ROUTERS", colMuted, 'l', true, 10)
		}
		cy0 := hdrY + 16
		vrW := swW
		trW := float32(150)
		exW := float32(tSwitchW)
		vrX := swX
		exX := switchX
		trX := (vrX+vrW+exX)/2 - trW/2
		if exX+exW+tPad > W {
			W = exX + exW + tPad
		}
		for _, vr := range topo.VRouters {
			intl := vr.Internal
			stackH := float32(0)
			for _, pg := range intl {
				stackH += pgHeight(toPG(pg))
			}
			if n := len(intl) - 1; n > 0 {
				stackH += tPgGap * float32(n)
			}
			vrH := float32(96)
			if h := 54 + float32(1+len(intl))*16 + 14; h > vrH {
				vrH = h
			}
			vrH += 26
			rowH := stackH
			for _, v := range []float32{vrH, tPgHdr + tVMRow + tPgFoot} {
				if v > rowH {
					rowH = v
				}
			}
			rowH += 10
			top := cy0
			py := top + rowH/2 - stackH/2
			type exit struct {
				y  float32
				gw string
			}
			var exits []exit
			for _, pg := range intl {
				e := b.pgBox(pgX, py, toPG(pg), colPrimary)
				exits = append(exits, exit{y: e, gw: pg.GW})
				py += pgHeight(toPG(pg)) + tPgGap
			}
			n := len(exits)
			midIdx := 0
			if n > 0 {
				midIdx = (n - 1) / 2
			}
			spineY := top + rowH/2
			if n > 0 {
				spineY = exits[midIdx].y
			}
			vrY := spineY - vrH/2
			b.spineBox(vrX, vrY, vrW, vrH, "vRouter", true, "router", nil, "")
			// routing tag
			rtxt := "no routing"
			if len(vr.Routing) > 0 {
				rtxt = joinDot(vr.Routing)
			}
			hc := colMuted
			if vr.Health == "up" {
				hc = colOK
			} else if vr.Health == "down" {
				hc = colDanger
			}
			tw := measure(rtxt, 11, true) + 40
			tgx := vrX + vrW/2 - tw/2
			tgy := vrY + vrH - 26
			b.rect(tgx, tgy, tw, 20, colPanel, hc, 10, 1.3)
			b.circle(tgx+14, tgy+10, 4.5, hc)
			b.text(tgx+26, tgy+14, rtxt, colFg, 'l', true, 11)
			// links from each PG into the vRouter
			sp := float32(17)
			gy0 := spineY - float32(midIdx)*sp
			for i, e := range exits {
				pr := pgX + tPgW
				gy := gy0 + float32(i)*sp
				if i == midIdx {
					b.line(pr, e.y, vrX, e.y, alpha(colPrimary, 0xe6), 2)
				} else {
					b.conn(pr, e.y, vrX, gy, colPrimary, true)
				}
				b.text(vrX+10, gy+4, fit(e.gw, 12, true, vrW-20), colPrimary, 'l', true, 12)
			}
			if n == 0 {
				b.rect(pgX, spineY-30, tPgW, 60, colPanel, colLine, 9, 1.4)
				b.text(pgX+14, spineY+4, "(no port groups)", colMuted, 'l', false, 12)
			}
			if vr.Transit != nil {
				t := vr.Transit
				b.line(vrX+vrW, spineY, trX, spineY, alpha(colMuted, 0xd8), 2)
				b.rect(trX, spineY-28, trW, 56, colPanel, colMuted, 9, 1.4)
				b.text(trX+trW/2, spineY-4, "transit", colMuted, 'm', true, 10)
				b.text(trX+trW/2, spineY+15, fit(t.CIDR, 13, true, trW-20), colFg, 'm', true, 13)
				var conns []string
				if t.Phys != "" || t.Port != "" {
					conns = append(conns, t.Phys+" → "+t.Port)
				}
				nb := client.TopoNeighbor{SwitchName: t.Switch, Via: "LLDP"}
				if nb.SwitchName == "" {
					nb.SwitchName = "(external)"
				}
				exH := b.upBox(exX, spineY-((36+float32(len(conns)*15)+14)/2), exW, nb, conns)
				b.line(trX+trW, spineY, exX, spineY, alpha(colMuted, 0xd8), 2)
				_ = exH
			} else {
				b.text(vrX+vrW+20, spineY+4, "no transit link", colMuted, 'l', false, 11)
			}
			if bottom := top + rowH; bottom > py {
				cy0 = bottom + tBlkGap
			} else {
				cy0 = py + tBlkGap
			}
			H = cy0
		}
	}

	H += tPad
	chart := container.New(&fixedSizeLayout{w: W, h: H}, b.objs...)
	return subSection("Network map", nil, container.NewHScroll(chart))
}

// vmkHeight: one host-adapter box grows to hold all its IPs.
func vmkHeight(k client.TopoVMK) float32 {
	n := len(k.IPs)
	if n < 1 {
		n = 1
	}
	return float32(24 + n*15 + 9)
}

// toPG adapts a vRouter internal segment to the port-group box shape.
func toPG(in client.TopoVRInternal) client.TopoPortGroup {
	return client.TopoPortGroup{Name: in.Name, CIDR: in.Subnet, VMs: in.VMs}
}

func joinDot(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " · "
		}
		out += s
	}
	return out
}
