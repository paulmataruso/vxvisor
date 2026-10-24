package ui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// shell is the main application window: a fixed VM sidebar on the left and a
// tabbed work area on the right whose first tab is the monitoring dashboard and
// whose other tabs are open VM consoles.
type shell struct {
	app *App
	win fyne.Window

	tabs     *container.DocTabs
	overview *container.TabItem
	dash     *dashboard

	// sidebar
	listBox  *fyne.Container
	search   *widget.Entry
	countTxt *canvas.Text
	toastTxt *canvas.Text

	// view switching: "list" (flat) or "folders" (tree)
	viewMode   string
	viewStack  *fyne.Container
	listWrap   fyne.CanvasObject
	folderWrap fyne.CanvasObject
	listBtn    *widget.Button
	folderBtn  *widget.Button

	// folder tree
	tree      *widget.Tree
	folders   []client.Folder
	vmFolder  map[string]int64 // vm id -> folder id
	selFolder int64            // currently selected folder in the tree (0 = none)
	selTreeVM string           // currently selected VM in the tree
	renameBtn *widget.Button
	deleteBtn *widget.Button
	moveBtn   *widget.Button

	vms      []client.Session
	selID    string
	consoles map[string]*consoleTab
}

func (a *App) showShell() {
	sh := &shell{
		app:      a,
		consoles: map[string]*consoleTab{},
	}
	win := a.fyne.NewWindow("VXVisor Console — " + a.client.BaseURL())
	win.SetIcon(appIcon)
	win.Resize(fyne.NewSize(1180, 760))
	win.CenterOnScreen()
	sh.win = win

	sh.dash = newDashboard(sh)
	sh.overview = container.NewTabItemWithIcon("Overview", gridIcon(), sh.dash.root)
	sh.tabs = container.NewDocTabs(sh.overview)
	sh.tabs.SetTabLocation(container.TabLocationTop)
	sh.tabs.CloseIntercept = func(ti *container.TabItem) {
		if ti == sh.overview {
			return // the dashboard tab is permanent
		}
		sh.closeConsoleTab(ti)
	}
	sh.tabs.OnSelected = func(ti *container.TabItem) {
		// Re-focus a console when its tab is shown so keys flow immediately.
		for _, c := range sh.consoles {
			if c.item == ti {
				c.focus()
			}
		}
	}

	win.SetContent(container.NewBorder(nil, nil, sh.sidebar(), nil, sh.tabs))
	win.Show()

	// Offer an in-app update if the server has a newer client build.
	go sh.checkForUpdate()

	sh.reload(false)
	sh.startAutoRefresh()
}

// --- sidebar ---------------------------------------------------------------

func (sh *shell) sidebar() fyne.CanvasObject {
	// Brand header.
	brand := container.NewHBox(
		glyphBadge(34),
		container.NewVBox(
			brandWordmark(19),
			mutedText("Console", 11.5),
		),
	)

	sh.search = widget.NewEntry()
	sh.search.SetPlaceHolder("Filter VMs…")
	sh.search.OnChanged = func(string) { sh.renderList() }

	sh.countTxt = mutedText("", 11)

	header := container.NewVBox(
		container.NewPadded(brand),
		container.NewPadded(sh.search),
		container.New(&insetLayout{14, 2}, sh.countTxt),
		spacer(4),
	)

	sh.listBox = container.NewVBox()
	// Reserve a right gutter so the overlay scrollbar doesn't cover a row, and run
	// the rows under a slimmer theme (tighter padding) so they read as a compact
	// list.
	sh.listWrap = container.NewVScroll(container.NewThemeOverride(
		container.New(&padRightLayout{16}, sh.listBox), slimTheme{}))

	// Folders view: a collapsible tree + a context-sensitive action bar.
	sh.folderWrap = sh.buildFolderView()

	// View toggle (All / Folders), remembered for the session.
	sh.listBtn = widget.NewButton("All", func() { sh.setView("list") })
	sh.folderBtn = widget.NewButton("Folders", func() { sh.setView("folders") })
	sh.listBtn.Importance = widget.LowImportance
	sh.folderBtn.Importance = widget.LowImportance
	toggle := container.NewThemeOverride(
		container.New(&insetLayout{14, 0}, container.NewGridWithColumns(2, sh.listBtn, sh.folderBtn)),
		compactTheme{})

	sh.viewStack = container.NewStack(sh.listWrap, sh.folderWrap)

	// Footer: who/where + disconnect.
	sh.toastTxt = mutedText("", 11)
	disconnect := widget.NewButtonWithIcon("Disconnect", theme.LogoutIcon(), func() {
		sh.stop()
		sh.win.Close()
		sh.app.showConnect()
	})
	disconnect.Importance = widget.LowImportance
	foot := container.NewVBox(
		widget.NewSeparator(),
		container.New(&insetLayout{14, 2}, mutedText(sh.app.client.User+" @ "+hostOnly(sh.app.client.BaseURL()), 12)),
		container.New(&insetLayout{14, 0}, sh.toastTxt),
		container.NewPadded(disconnect),
	)

	inner := container.NewBorder(container.NewVBox(header, toggle, spacer(4)), foot, nil, nil, sh.viewStack)
	sh.setView(sh.viewMode)

	// Sidebar surface: a panel at a fixed width with a 1px right divider, like the
	// web rail.
	bg := canvas.NewRectangle(colPanel)
	rail := container.New(&fixedWidthLayout{272}, container.NewStack(bg, inner))
	return container.NewBorder(nil, nil, nil, widget.NewSeparator(), rail)
}

// renderList rebuilds the sidebar VM rows from sh.vms applying the filter.
func (sh *shell) renderList() {
	if sh.listBox == nil {
		return
	}
	q := strings.ToLower(strings.TrimSpace(sh.search.Text))
	sh.listBox.Objects = sh.listBox.Objects[:0]

	shown := 0
	for _, s := range sh.vms {
		if q != "" && !strings.Contains(strings.ToLower(s.Name), q) {
			continue
		}
		shown++
		sh.listBox.Objects = append(sh.listBox.Objects, sh.vmRow(s))
	}
	if shown == 0 {
		msg := "No VMs match."
		if len(sh.vms) == 0 {
			msg = "No virtual machines yet. Create one in the web UI."
		}
		sh.listBox.Objects = append(sh.listBox.Objects, container.NewPadded(mutedPara(msg)))
	}
	sh.listBox.Refresh()

	run := 0
	for _, s := range sh.vms {
		if isRunning(s.State) {
			run++
		}
	}
	sh.countTxt.Text = spaceCaps(itoa(len(sh.vms)) + " VMs · " + itoa(run) + " running")
	canvas.Refresh(sh.countTxt)

	if sh.tree != nil {
		sh.tree.Refresh()
	}
}

// --- folder tree view ------------------------------------------------------

// buildFolderView wires the collapsible inventory tree plus a context-sensitive
// action bar (new/rename/delete folder, move VM). Rename/Delete light up when a
// folder is selected; Move lights up when a VM is selected.
func (sh *shell) buildFolderView() fyne.CanvasObject {
	sh.vmFolder = map[string]int64{}
	sh.tree = widget.NewTree(sh.treeChildUIDs, sh.treeIsBranch, sh.treeCreateNode, sh.treeUpdateNode)
	sh.tree.OnSelected = sh.treeSelected

	newB := widget.NewButton("+ Folder", func() { sh.newFolderDialog(sh.selFolder) })
	sh.moveBtn = widget.NewButton("Move…", func() {
		if sh.selTreeVM != "" {
			sh.moveVMDialog(sh.selTreeVM)
		}
	})
	sh.renameBtn = widget.NewButton("Rename", func() {
		if sh.selFolder != 0 {
			sh.renameFolderDialog(sh.selFolder)
		}
	})
	sh.deleteBtn = widget.NewButton("Delete", func() {
		if sh.selFolder != 0 {
			sh.deleteFolderConfirm(sh.selFolder)
		}
	})
	sh.deleteBtn.Importance = widget.DangerImportance
	sh.renameBtn.Disable()
	sh.deleteBtn.Disable()
	sh.moveBtn.Disable()

	bar := container.NewThemeOverride(
		container.New(&insetLayout{10, 4}, container.NewGridWithColumns(2,
			newB, sh.moveBtn, sh.renameBtn, sh.deleteBtn)),
		compactTheme{})
	return container.NewBorder(nil, bar, nil, nil, sh.tree)
}

// setView swaps the sidebar between the flat list and the folder tree.
func (sh *shell) setView(mode string) {
	if mode != "folders" {
		mode = "list"
	}
	sh.viewMode = mode
	if sh.listWrap == nil || sh.folderWrap == nil {
		return
	}
	folders := mode == "folders"
	if folders {
		sh.listWrap.Hide()
		sh.folderWrap.Show()
		if sh.tree != nil {
			sh.tree.Refresh()
			sh.tree.OpenAllBranches()
		}
	} else {
		sh.folderWrap.Hide()
		sh.listWrap.Show()
	}
	hi, lo := widget.HighImportance, widget.LowImportance
	sh.folderBtn.Importance, sh.listBtn.Importance = lo, hi
	if folders {
		sh.folderBtn.Importance, sh.listBtn.Importance = hi, lo
	}
	sh.listBtn.Refresh()
	sh.folderBtn.Refresh()
}

func (sh *shell) treeChildUIDs(uid widget.TreeNodeID) []widget.TreeNodeID {
	var out []widget.TreeNodeID
	var parent int64 // which folder's children we list; 0 = root
	switch {
	case uid == "":
		parent = 0
	case strings.HasPrefix(uid, "f:"):
		parent = parseFID(uid[2:])
	default:
		return nil // VM leaf
	}
	for _, f := range sh.folders {
		if f.ParentID == parent {
			out = append(out, "f:"+strconv.FormatInt(f.ID, 10))
		}
	}
	for _, v := range sh.filteredVMs() {
		if sh.vmFolder[v.ID] == parent {
			out = append(out, "vm:"+v.ID)
		}
	}
	return out
}

func (sh *shell) treeIsBranch(uid widget.TreeNodeID) bool {
	return uid == "" || strings.HasPrefix(uid, "f:")
}

func (sh *shell) treeCreateNode(branch bool) fyne.CanvasObject {
	// No ellipsis truncation here: inside an HBox a truncating label reports a
	// min width of just the ellipsis, so it collapses to "..." and the VM name
	// vanishes. Let the tree size to the name (it scrolls horizontally if needed).
	if branch {
		lbl := widget.NewLabel("")
		return container.NewHBox(widget.NewIcon(theme.FolderIcon()), lbl)
	}
	c := canvas.NewCircle(colMuted)
	lbl := widget.NewLabel("")
	return container.NewHBox(container.NewGridWrap(fyne.NewSize(9, 9), c), lbl)
}

func (sh *shell) treeUpdateNode(uid widget.TreeNodeID, branch bool, o fyne.CanvasObject) {
	row, ok := o.(*fyne.Container)
	if !ok || len(row.Objects) < 2 {
		return
	}
	lbl, _ := row.Objects[1].(*widget.Label)
	if lbl == nil {
		return
	}
	if branch {
		fid := parseFID(strings.TrimPrefix(uid, "f:"))
		f := sh.folderByID(fid)
		lbl.SetText(fmt.Sprintf("%s  (%d)", f.Name, sh.folderVMCount(fid)))
		return
	}
	v := sh.vmByID(strings.TrimPrefix(uid, "vm:"))
	if wrap, ok := row.Objects[0].(*fyne.Container); ok && len(wrap.Objects) > 0 {
		if circle, ok := wrap.Objects[0].(*canvas.Circle); ok {
			circle.FillColor = stateColor(v.State)
			circle.Refresh()
		}
	}
	lbl.SetText(v.Name)
}

func (sh *shell) treeSelected(uid widget.TreeNodeID) {
	switch {
	case strings.HasPrefix(uid, "f:"):
		sh.selFolder = parseFID(uid[2:])
		sh.selTreeVM = ""
		sh.renameBtn.Enable()
		sh.deleteBtn.Enable()
		sh.moveBtn.Disable()
	case strings.HasPrefix(uid, "vm:"):
		sh.selTreeVM = uid[3:]
		sh.selFolder = 0
		sh.renameBtn.Disable()
		sh.deleteBtn.Disable()
		sh.moveBtn.Enable()
		sh.selectVM(sh.selTreeVM) // mirror the flat list: drive the dashboard
	}
}

// --- folder helpers + dialogs ----------------------------------------------

func parseFID(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

func (sh *shell) filteredVMs() []client.Session {
	q := strings.ToLower(strings.TrimSpace(sh.search.Text))
	if q == "" {
		return sh.vms
	}
	var out []client.Session
	for _, s := range sh.vms {
		if strings.Contains(strings.ToLower(s.Name), q) {
			out = append(out, s)
		}
	}
	return out
}

func (sh *shell) folderByID(id int64) client.Folder {
	for _, f := range sh.folders {
		if f.ID == id {
			return f
		}
	}
	return client.Folder{ID: id, Name: "folder"}
}

func (sh *shell) vmByID(id string) client.Session {
	for _, v := range sh.vms {
		if v.ID == id {
			return v
		}
	}
	return client.Session{ID: id, Name: id}
}

func (sh *shell) folderVMCount(id int64) int {
	n := 0
	for _, fid := range sh.vmFolder {
		if fid == id {
			n++
		}
	}
	return n
}

func (sh *shell) newFolderDialog(parent int64) {
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Folder name")
	dialog.ShowForm("New folder", "Create", "Cancel",
		[]*widget.FormItem{widget.NewFormItem("Name", entry)},
		func(ok bool) {
			if !ok || strings.TrimSpace(entry.Text) == "" {
				return
			}
			sh.folderMutate(func() error { return sh.app.client.CreateFolder(parent, entry.Text) })
		}, sh.win)
}

func (sh *shell) renameFolderDialog(id int64) {
	entry := widget.NewEntry()
	entry.SetText(sh.folderByID(id).Name)
	dialog.ShowForm("Rename folder", "Save", "Cancel",
		[]*widget.FormItem{widget.NewFormItem("Name", entry)},
		func(ok bool) {
			if !ok || strings.TrimSpace(entry.Text) == "" {
				return
			}
			sh.folderMutate(func() error { return sh.app.client.RenameFolder(id, entry.Text) })
		}, sh.win)
}

func (sh *shell) deleteFolderConfirm(id int64) {
	name := sh.folderByID(id).Name
	dialog.ShowConfirm("Delete folder",
		"Delete \""+name+"\"? Its instances and subfolders move up a level — nothing is deleted.",
		func(ok bool) {
			if !ok {
				return
			}
			sh.folderMutate(func() error { return sh.app.client.DeleteFolder(id) })
		}, sh.win)
}

func (sh *shell) moveVMDialog(vmID string) {
	names := []string{"— Ungrouped (root) —"}
	ids := []int64{0}
	for _, f := range sh.folders {
		names = append(names, f.Name)
		ids = append(ids, f.ID)
	}
	sel := widget.NewSelect(names, nil)
	sel.SetSelectedIndex(0)
	dialog.ShowForm("Move "+sh.vmByID(vmID).Name, "Move", "Cancel",
		[]*widget.FormItem{widget.NewFormItem("Folder", sel)},
		func(ok bool) {
			if !ok {
				return
			}
			i := sel.SelectedIndex()
			if i < 0 || i >= len(ids) {
				return
			}
			sh.folderMutate(func() error { return sh.app.client.MoveVM(vmID, ids[i]) })
		}, sh.win)
}

// folderMutate runs a folder API call off the UI thread and reloads on success.
func (sh *shell) folderMutate(fn func() error) {
	go func() {
		err := fn()
		fyne.Do(func() {
			if err != nil {
				sh.toast(err.Error())
				return
			}
			sh.reload(false)
		})
	}()
}

func (sh *shell) vmRow(s client.Session) fyne.CanvasObject {
	// One slim line: a state dot + the VM name. No per-row Console button (open a
	// console from the overview) and no "running" text — the dot colour carries the
	// state. A truncating Label (not canvas.Text) keeps the name from inflating the
	// row past the scroll viewport, whose right edge is clipped.
	name := widget.NewLabel(s.Name)
	name.TextStyle = fyne.TextStyle{Bold: true}
	name.Truncation = fyne.TextTruncateEllipsis

	body := container.NewBorder(nil, nil,
		container.New(&insetLayout{4, 0}, dot(s.State, 8)),
		nil,
		name,
	)

	tc := newTapCard(body, func() { sh.selectVM(s.ID) })
	tc.selected = s.ID == sh.selID
	tc.refreshBG()
	// Horizontal inset keeps the bubble off the rail edges; the vertical inset is
	// the visible gap between rows.
	return container.New(&insetLayout{8, 3}, tc)
}

func (sh *shell) selectVM(id string) {
	sh.selID = id
	sh.renderList() // repaint selection highlight
	sh.tabs.Select(sh.overview)
	sh.refreshDash()
}

// --- data ------------------------------------------------------------------

func (sh *shell) startAutoRefresh() {
	go func() {
		t := time.NewTicker(6 * time.Second)
		defer t.Stop()
		for range t.C {
			if sh.win == nil {
				return
			}
			sh.reload(false)
		}
	}()
}

func (sh *shell) reload(flash bool) {
	go func() {
		vms, err := sh.app.client.Sessions()
		usage, _ := sh.app.client.Usage()
		fd, _ := sh.app.client.Folders()
		fyne.Do(func() {
			if err != nil {
				sh.toast("Refresh failed: " + err.Error())
				return
			}
			sh.folders = fd.Folders
			sh.vmFolder = fd.Members
			if sh.vmFolder == nil {
				sh.vmFolder = map[string]int64{}
			}
			sort.SliceStable(vms, func(i, j int) bool {
				ri, rj := isRunning(vms[i].State), isRunning(vms[j].State)
				if ri != rj {
					return ri // running first
				}
				return strings.ToLower(vms[i].Name) < strings.ToLower(vms[j].Name)
			})
			sh.vms = vms
			if sh.selID == "" && len(vms) > 0 {
				sh.selID = vms[0].ID
			}
			sh.renderList()
			sh.dash.usage = usage
			sh.refreshDash()
			if flash {
				sh.toast("Refreshed.")
			}
		})
	}()
}

func (sh *shell) current() (client.Session, bool) {
	for _, s := range sh.vms {
		if s.ID == sh.selID {
			return s, true
		}
	}
	return client.Session{}, false
}

func (sh *shell) refreshDash() {
	s, ok := sh.current()
	if !ok {
		sh.dash.update(nil, sh.vms)
		return
	}
	sh.dash.update(&s, sh.vms)
}

func (sh *shell) toast(msg string) {
	if sh.toastTxt == nil {
		return
	}
	sh.toastTxt.Text = msg
	sh.toastTxt.Color = colMuted
	canvas.Refresh(sh.toastTxt)
}

func (sh *shell) stop() {
	sh.win = nil
	for _, c := range sh.consoles {
		c.close()
	}
	sh.consoles = map[string]*consoleTab{}
}

// --- console tabs ----------------------------------------------------------

func (sh *shell) openConsoleTab(s client.Session) {
	if c, ok := sh.consoles[s.ID]; ok {
		sh.tabs.Select(c.item)
		return
	}
	c := newConsoleTab(sh, s)
	sh.consoles[s.ID] = c
	sh.tabs.Append(c.item)
	sh.tabs.Select(c.item)
}

func (sh *shell) closeConsoleTab(ti *container.TabItem) {
	for id, c := range sh.consoles {
		if c.item == ti {
			c.close()
			delete(sh.consoles, id)
			break
		}
	}
	sh.tabs.Remove(ti)
}

// --- small helpers ---------------------------------------------------------

func isRunning(state string) bool { return strings.EqualFold(state, "running") }

func hostOnly(base string) string {
	b := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	return b
}

func boldText(s string, size float32) *canvas.Text {
	t := canvas.NewText(s, colFg)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: true}
	return t
}

// brandWordmark renders the two-tone "Vxvisor" wordmark ("Vx" in brand blue,
// "visor" in foreground) as adjacent bold glyphs with no inter-letter gap.
func brandWordmark(size float32) fyne.CanvasObject {
	vx := canvas.NewText("Vx", colBrand)
	vx.TextSize = size
	vx.TextStyle = fyne.TextStyle{Bold: true}
	visor := canvas.NewText("visor", colFg)
	visor.TextSize = size
	visor.TextStyle = fyne.TextStyle{Bold: true}
	return container.New(tightRow{}, vx, visor)
}

func mutedText(s string, size float32) *canvas.Text {
	t := canvas.NewText(s, colMuted)
	t.TextSize = size
	return t
}

// tapCard is a clickable, hoverable surface used for sidebar rows.
type tapCard struct {
	widget.BaseWidget
	content  fyne.CanvasObject
	bg       *canvas.Rectangle
	onTap    func()
	hovered  bool
	selected bool
}

func newTapCard(content fyne.CanvasObject, onTap func()) *tapCard {
	bg := canvas.NewRectangle(colPanel)
	bg.CornerRadius = 9
	t := &tapCard{content: content, bg: bg, onTap: onTap}
	t.ExtendBaseWidget(t)
	return t
}

func (t *tapCard) refreshBG() {
	switch {
	case t.selected:
		t.bg.FillColor = colPrimSft
		t.bg.StrokeColor = alpha(colPrimary, 0xcc)
		t.bg.StrokeWidth = 1
	case t.hovered:
		t.bg.FillColor = colPanel2
		t.bg.StrokeColor = colLine
		t.bg.StrokeWidth = 1
	default:
		t.bg.FillColor = colPanel
		t.bg.StrokeColor = colPanel
		t.bg.StrokeWidth = 0
	}
	canvas.Refresh(t.bg)
}

func (t *tapCard) Tapped(*fyne.PointEvent) {
	if t.onTap != nil {
		t.onTap()
	}
}
func (t *tapCard) MouseIn(*desktop.MouseEvent)    { t.hovered = true; t.refreshBG() }
func (t *tapCard) MouseOut()                      { t.hovered = false; t.refreshBG() }
func (t *tapCard) MouseMoved(*desktop.MouseEvent) {}

func (t *tapCard) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(container.NewStack(t.bg, t.content))
}
