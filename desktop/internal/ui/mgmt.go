package ui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// This file holds the shared building blocks for the management pages (the ones
// that mirror the web UI's list+table+modal pages): a page scaffold, a
// weighted-column data table, cell/button helpers, and an async action helper.

// mgmtPage is the standard scaffold for a management section: a title row with
// optional right-aligned action controls, over a scrollable body. Matches the
// web UI's page header + content pattern.
func mgmtPage(title string, actions fyne.CanvasObject, body fyne.CanvasObject) fyne.CanvasObject {
	t := boldText(title, 22)
	var head fyne.CanvasObject = t
	if actions != nil {
		head = container.NewBorder(nil, nil, t, container.NewHBox(actions))
	}
	content := container.NewVBox(
		container.New(&insetLayout{2, 2}, head),
		spacer(10),
		body,
	)
	return container.NewVScroll(container.New(&insetLayout{20, 16}, content))
}

// columnsLayout positions each child into a weighted column (left-aligned, width
// = weight share of the available space) with a gap between columns. Used for
// table header + data rows so columns line up.
type columnsLayout struct {
	weights []float32
	gap     float32
}

func (l *columnsLayout) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var h float32
	for _, o := range objs {
		if m := o.MinSize().Height; m > h {
			h = m
		}
	}
	return fyne.NewSize(120, h)
}

func (l *columnsLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	var sum float32
	for _, w := range l.weights {
		sum += w
	}
	if sum == 0 {
		sum = 1
	}
	gaps := l.gap * float32(len(objs)-1)
	avail := size.Width - gaps
	if avail < 0 {
		avail = 0
	}
	x := float32(0)
	for i, o := range objs {
		var w float32
		if i < len(l.weights) {
			w = avail * (l.weights[i] / sum)
		}
		o.Move(fyne.NewPos(x, 0))
		o.Resize(fyne.NewSize(w, size.Height))
		x += w + l.gap
	}
}

// dataTable renders a web-style table: a muted header row over data rows with 1px
// separators, inside a card. headers and weights (relative column widths) must be
// the same length as each row's cell slice. An empty rows slice shows emptyMsg.
func dataTable(headers []string, weights []float32, rows [][]fyne.CanvasObject, emptyMsg string) fyne.CanvasObject {
	gap := float32(12)
	head := make([]fyne.CanvasObject, len(headers))
	for i, h := range headers {
		head[i] = sectionLabel(h)
	}
	body := container.NewVBox(
		container.New(&insetLayout{14, 8}, container.New(&columnsLayout{weights, gap}, head...)),
		thinLine(),
	)
	if len(rows) == 0 {
		body.Add(container.New(&insetLayout{14, 12}, mutedPara(emptyMsg)))
	}
	for i, r := range rows {
		body.Add(container.New(&insetLayout{14, 9}, container.New(&columnsLayout{weights, gap}, r...)))
		if i < len(rows)-1 {
			body.Add(thinLine())
		}
	}
	return card(body)
}

// subSection is a titled block within a page: a bold heading with an optional
// right-aligned action, over a body (used for Bonds/vSwitches under Networks,
// etc.).
func subSection(title string, action fyne.CanvasObject, body fyne.CanvasObject) fyne.CanvasObject {
	var head fyne.CanvasObject = boldText(title, 15)
	if action != nil {
		head = container.NewBorder(nil, nil, boldText(title, 15), container.NewThemeOverride(container.NewHBox(action), compactTheme{}))
	}
	return container.NewVBox(head, spacer(6), body)
}

// thinLine is a full-width 1px divider (like the web table row separators). It
// must stretch horizontally, so it uses a height-pinned layout (a GridWrap would
// make a 1x1 dot).
func thinLine() fyne.CanvasObject {
	return container.New(&fixedHeightLayout{1}, canvas.NewRectangle(colLine))
}

// cell is a left-aligned, single-line (truncating) table cell for plain text.
func cell(s string) fyne.CanvasObject {
	l := widget.NewLabel(s)
	l.Truncation = fyne.TextTruncateEllipsis
	return l
}

// cellBold is a cell with bold emphasis (used for the name column).
func cellBold(s string) fyne.CanvasObject {
	l := widget.NewLabel(s)
	l.TextStyle = fyne.TextStyle{Bold: true}
	l.Truncation = fyne.TextTruncateEllipsis
	return l
}

// cellMono is a cell for identifiers / addresses.
func cellMono(s string) fyne.CanvasObject {
	l := widget.NewLabel(s)
	l.TextStyle = fyne.TextStyle{Monospace: true}
	l.Truncation = fyne.TextTruncateEllipsis
	return l
}

// cellState is a cell holding a status pill.
func cellState(state string) fyne.CanvasObject {
	return container.NewHBox(pill(state, state))
}

// rowActions right-aligns a cluster of small buttons in an action cell. A
// leading layout.Spacer() pushes the buttons to the cell's right edge.
func rowActions(btns ...fyne.CanvasObject) fyne.CanvasObject {
	objs := append([]fyne.CanvasObject{layout.NewSpacer()}, btns...)
	return container.NewThemeOverride(container.NewHBox(objs...), compactTheme{})
}

// layoutExpand is a box-expanding spacer (pushes following HBox items right).
func layoutExpand() fyne.CanvasObject { return layout.NewSpacer() }

// --- buttons ---------------------------------------------------------------

// mkBtn builds a button with a bordered "bubble" (a real importance, never flat
// Low) and an icon inferred from the label so every button reads like the web UI.
func mkBtn(label string, imp widget.Importance, tap func()) *widget.Button {
	var b *widget.Button
	if ic := iconFor(label); ic != nil {
		b = widget.NewButtonWithIcon(label, ic, tap)
	} else {
		b = widget.NewButton(label, tap)
	}
	b.Importance = imp
	return b
}

func primaryBtn(label string, tap func()) *widget.Button {
	return mkBtn(label, widget.HighImportance, tap)
}

func dangerBtn(label string, tap func()) *widget.Button {
	return mkBtn(label, widget.DangerImportance, tap)
}

// plainBtn is a secondary button WITH a bubble (Medium importance fills with the
// theme button color), matching the web's outlined buttons.
func plainBtn(label string, tap func()) *widget.Button {
	return mkBtn(label, widget.MediumImportance, tap)
}

func iconBtn(label string, icon fyne.Resource, tap func()) *widget.Button {
	b := widget.NewButtonWithIcon(label, icon, tap)
	b.Importance = widget.MediumImportance
	return b
}

// iconFor maps a button label to a web-sprite-style icon so buttons are
// consistently glyphed. Returns nil when no icon fits (plain text button).
func iconFor(label string) fyne.Resource {
	l := strings.ToLower(strings.TrimSpace(label))
	switch {
	case l == "":
		return nil
	case hasAny(l, "delete", "remove", "purge", "unmount", "revoke", "eject"):
		return trashIcon()
	case hasAny(l, "start", "launch", "console"):
		return playIcon()
	case l == "stop" || strings.HasPrefix(l, "stop "):
		return stopIcon()
	case hasAny(l, "restart", "refresh", "apply", "probe", "reconnect"):
		return refreshIcon()
	case hasAny(l, "restore", "revert"):
		return refreshIcon()
	case hasAny(l, "new ", "add", "create", "register", "pull", "mount", "attach", "advertise", "connect", "back up", "set uplink", "set transit"):
		return plusIcon()
	case hasAny(l, "browse"):
		return folderOpenIcon()
	case hasAny(l, "test", "save", "set ", "apply"):
		return checkIcon()
	case hasAny(l, "configure", "edit"):
		return gearIcon()
	case hasAny(l, "rename"):
		return pencilIcon()
	case hasAny(l, "snapshot"):
		return cameraIcon()
	case hasAny(l, "zone"):
		return tagIcon()
	case hasAny(l, "update", "download"):
		return downloadIcon()
	case hasAny(l, "network"):
		return networkIcon()
	}
	return nil
}

func hasAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// --- async actions ----------------------------------------------------------

// do runs a mutating API call off the UI thread. On error it shows a dialog;
// on success it runs after (typically a page reload). Both run back on the UI
// thread.
func (sh *shell) do(fn func() error, after func()) {
	go func() {
		err := fn()
		fyne.Do(func() {
			if err != nil {
				sh.fail(err)
				return
			}
			if after != nil {
				after()
			}
		})
	}()
}

// fail surfaces an error both as a modal (so it isn't missed) and on the toast
// line.
func (sh *shell) fail(err error) {
	if err == nil {
		return
	}
	sh.toast(err.Error())
	if sh.win != nil {
		dialog.ShowError(err, sh.win)
	}
}

// confirm asks a yes/no question before running a (usually destructive) action.
func (sh *shell) confirm(title, message string, onYes func()) {
	dialog.ShowConfirm(title, message, func(ok bool) {
		if ok {
			onYes()
		}
	}, sh.win)
}

// showForm presents a modal form; on confirm it runs submit off-thread and, on
// success, refreshes the active page.
func (sh *shell) showForm(title, confirm string, items []*widget.FormItem, submit func() error) {
	sh.showFormThen(title, confirm, items, submit, sh.reloadActive)
}

// showFormThen is showForm with a custom success callback (e.g. refresh a
// different page than the active one).
func (sh *shell) showFormThen(title, confirm string, items []*widget.FormItem, submit func() error, after func()) {
	d := dialog.NewForm(title, confirm, "Cancel", items, func(ok bool) {
		if !ok {
			return
		}
		sh.do(submit, after)
	}, sh.win)
	d.Resize(fyne.NewSize(480, 0))
	d.Show()
}

// errReq is a small helper for required-field validation errors.
func errReq(msg string) error { return fmt.Errorf("%s", msg) }

// uniqueLabels disambiguates repeated option labels (appending " (2)", " (3)")
// so widget.Select.SelectedIndex() — which returns the FIRST option equal to the
// selected text — maps back to the correct parallel slice index even when the
// underlying names (folders, VMs, groups) collide.
func uniqueLabels(names []string) []string {
	seen := map[string]int{}
	out := make([]string, len(names))
	for i, n := range names {
		seen[n]++
		if seen[n] > 1 {
			out[i] = fmt.Sprintf("%s (%d)", n, seen[n])
		} else {
			out[i] = n
		}
	}
	return out
}

// itoaf / itoaf2 format floats for stat tiles (0 and 2 decimal places).
func itoaf(f float64) string  { return fmt.Sprintf("%.0f", f) }
func itoaf2(f float64) string { return fmt.Sprintf("%.2f", f) }

// reloadActive refreshes whichever management page is currently shown. Pages
// register a reload func in sh.pageReload keyed by their nav id; the Instances
// page falls back to the VM-list reload.
func (sh *shell) reloadActive() {
	if fn := sh.pageReload[sh.activeItem]; fn != nil {
		fn()
		return
	}
	sh.reload(true)
}

// listPage builds a standard data page: a title + action bar over a body that is
// (re)rendered by render(), which fetches off the UI thread and returns the
// content to show. The page registers a reload hook under id so mutations and
// the Refresh button can repaint it.
func (sh *shell) listPage(id, title string, actions fyne.CanvasObject, render func() (fyne.CanvasObject, error)) fyne.CanvasObject {
	host := container.NewStack()
	reload := func() {
		host.Objects = []fyne.CanvasObject{container.New(&insetLayout{2, 8}, mutedText("Loading…", 12))}
		host.Refresh()
		go func() {
			obj, err := render()
			fyne.Do(func() {
				if err != nil {
					obj = card(container.NewPadded(mutedPara("Could not load: " + err.Error())))
				}
				host.Objects = []fyne.CanvasObject{obj}
				host.Refresh()
			})
		}()
	}
	sh.pageReload[id] = reload
	reload()
	return mgmtPage(title, actions, host)
}

// humanBytes formats a byte count like the web UI's humanBytes template func.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
