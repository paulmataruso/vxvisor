package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// navItem defines one entry in the management nav rail, mirroring the web UI's
// grouped sidebar. Pages are built lazily the first time they are shown and then
// kept alive in the content stack, so e.g. open console tabs survive switching
// between sections.
type navItem struct {
	id        string
	title     string
	group     string
	icon      func() fyne.Resource
	adminOnly bool
	// pageID is the content page this item selects; several items may share one
	// page (Overview reuses the Instances page and just focuses its dashboard tab).
	pageID string
	build  func() fyne.CanvasObject
}

// navItems is the full management surface, grouped and ordered like the web nav.
// Admin-only entries are hidden until the client learns the user is an instance
// admin (via /api/v1/me). Non-foundation pages are placeholders for now and get
// replaced with real pages phase by phase.
func (sh *shell) navItems() []navItem {
	return []navItem{
		{id: "overview", title: "Overview", icon: gridIcon, pageID: "instances"},

		{id: "instances", title: "Instances", group: "Compute", icon: serverIcon, pageID: "instances", build: sh.buildInstancesPage},
		{id: "containers", title: "Containers", group: "Compute", icon: boxIcon, build: sh.containersPage},
		{id: "templates", title: "Templates", group: "Compute", icon: layersIcon, build: sh.templatesPage},
		{id: "monitoring", title: "Monitoring", group: "Compute", icon: activityIcon, build: sh.monitoringPage},
		{id: "trash", title: "Trash", group: "Compute", icon: trashIcon, build: sh.trashPage},

		{id: "isos", title: "ISO Library", group: "Storage", icon: discIcon, build: sh.isosPage},
		{id: "backups", title: "Backups", group: "Storage", icon: archiveIcon, build: sh.backupsPage},
		{id: "pools", title: "Pools", group: "Storage", icon: databaseIcon, build: sh.poolsPage},
		{id: "shared", title: "Shared Storage", group: "Storage", icon: shareIcon, adminOnly: true, build: sh.sharedPage},
		{id: "ceph", title: "Ceph / HCI", group: "Storage", icon: databaseIcon, adminOnly: true, build: sh.cephPage},

		{id: "networks", title: "Networks", group: "Network", icon: networkIcon, build: sh.networksPage},
		{id: "routing", title: "L3 Routing", group: "Network", icon: routeIcon, adminOnly: true, build: sh.routingPage},
		{id: "vrouters", title: "vRouters", group: "Network", icon: routerIcon, adminOnly: true, build: sh.vroutersPage},
		{id: "vfirewall", title: "vFirewall", group: "Network", icon: shieldIcon, adminOnly: true, build: sh.vfirewallPage},

		{id: "members", title: "Members", group: "Tenancy", icon: usersIcon, build: sh.membersPage},
		{id: "apikeys", title: "API Keys", group: "Tenancy", icon: keyIcon, build: sh.apikeysPage},
		{id: "audit", title: "Audit Log", group: "Tenancy", icon: listIcon, build: sh.auditPage},
		{id: "billing", title: "Usage & Quota", group: "Tenancy", icon: creditIcon, build: sh.billingPage},

		{id: "import", title: "Import / Export", group: "Admin", icon: downloadIcon, adminOnly: true, build: sh.importPage},
		{id: "orgs", title: "Organizations", group: "Admin", icon: buildingIcon, adminOnly: true, build: sh.orgsPage},
		{id: "cluster", title: "Cluster", group: "Admin", icon: clusterIcon, adminOnly: true, build: sh.clusterPage},
		{id: "auth", title: "Authentication", group: "Admin", icon: lockIcon, adminOnly: true, build: sh.authPage},
		{id: "updates", title: "Updates", group: "Admin", icon: downloadIcon, adminOnly: true, build: sh.updatesPage},
	}
}

func (sh *shell) isAdmin() bool { return sh.me != nil && sh.me.IsAdmin }

func (sh *shell) itemByID(id string) *navItem {
	for i := range sh.items {
		if sh.items[i].id == id {
			return &sh.items[i]
		}
	}
	return nil
}

// buildByPage returns the build func for the item whose id is the page id.
func (sh *shell) buildByPage(pageID string) func() fyne.CanvasObject {
	for i := range sh.items {
		if sh.items[i].id == pageID && sh.items[i].build != nil {
			return sh.items[i].build
		}
	}
	return nil
}

// navRail builds the far-left management rail: brand, grouped section links, and
// a footer with identity + disconnect. It is the primary navigation surface.
func (sh *shell) navRail() fyne.CanvasObject {
	sh.navBox = container.NewVBox()
	sh.rebuildNav()
	scroll := container.NewVScroll(container.NewThemeOverride(
		container.New(&padRightLayout{10}, sh.navBox), slimTheme{}))

	sh.toastTxt = mutedText("", 11)
	sh.navVer = mutedText("client "+Version, 10.5)
	disconnect := widget.NewButtonWithIcon("Disconnect", theme.LogoutIcon(), func() {
		sh.stop()
		sh.win.Close()
		sh.app.showConnect()
	})
	disconnect.Importance = widget.LowImportance
	foot := container.NewVBox(
		widget.NewSeparator(),
		container.New(&insetLayout{12, 3}, mutedText(sh.app.client.User+" @ "+hostOnly(sh.app.client.BaseURL()), 11.5)),
		container.New(&insetLayout{12, 0}, sh.navVer),
		container.New(&insetLayout{12, 0}, sh.toastTxt),
		container.NewPadded(container.NewThemeOverride(disconnect, compactTheme{})),
	)

	inner := container.NewBorder(nil, foot, nil, nil, scroll)
	bg := canvas.NewRectangle(colPanel)
	rail := container.New(&fixedWidthLayout{212}, container.NewStack(bg, inner))
	return container.NewBorder(nil, nil, nil, widget.NewSeparator(), rail)
}

// rebuildNav repopulates the rail rows, honoring the current admin status. Called
// once at build time and again once identity (admin flag) is known.
func (sh *shell) rebuildNav() {
	if sh.navBox == nil {
		return
	}
	sh.navRows = map[string]*tapCard{}
	sh.navBox.Objects = sh.navBox.Objects[:0]

	brand := container.NewHBox(
		glyphBadge(30),
		container.NewVBox(brandWordmark(18), mutedText("Management Console", 10.5)),
	)
	sh.navBox.Add(container.NewPadded(brand))
	sh.navBox.Add(spacer(6))

	lastGroup := "\x00"
	for _, it := range sh.items {
		if it.adminOnly && !sh.isAdmin() {
			continue
		}
		if it.group != lastGroup {
			lastGroup = it.group
			if it.group != "" {
				sh.navBox.Add(spacer(4))
				sh.navBox.Add(container.New(&insetLayout{16, 4}, sectionLabel(it.group)))
			}
		}
		sh.navBox.Add(sh.navRow(it))
	}
	sh.navBox.Refresh()
	sh.highlightNav(sh.activeItem)
}

func (sh *shell) navRow(it navItem) fyne.CanvasObject {
	ic := widget.NewIcon(it.icon())
	lbl := widget.NewLabel(it.title)
	lbl.Truncation = fyne.TextTruncateEllipsis
	body := container.NewBorder(nil, nil,
		container.New(&insetLayout{6, 0}, container.NewGridWrap(fyne.NewSize(16, 16), ic)),
		nil, lbl)
	id := it.id
	tc := newTapCard(body, func() { sh.setPage(id) })
	sh.navRows[id] = tc
	return container.New(&insetLayout{8, 1}, tc)
}

func (sh *shell) highlightNav(id string) {
	for rid, tc := range sh.navRows {
		tc.selected = rid == id
		tc.refreshBG()
	}
}

// setPage shows the content page for a nav item, building it on first visit and
// keeping previously built pages alive (hidden) in the stack.
func (sh *shell) setPage(id string) {
	it := sh.itemByID(id)
	if it == nil {
		return
	}
	pageID := it.pageID
	if pageID == "" {
		pageID = it.id
	}
	if _, ok := sh.realized[pageID]; !ok {
		var obj fyne.CanvasObject
		if b := sh.buildByPage(pageID); b != nil {
			obj = b()
		} else {
			obj = sh.placeholderPage(it.title)
		}
		sh.realized[pageID] = obj
		sh.content.Add(obj)
	}
	for pid, obj := range sh.realized {
		if pid == pageID {
			obj.Show()
		} else {
			obj.Hide()
		}
	}
	sh.content.Refresh()
	if it.id == "overview" && sh.overview != nil {
		sh.tabs.Select(sh.overview)
	}
	sh.activeItem = id
	sh.highlightNav(id)
}

// placeholderPage is shown for management sections not yet ported to the desktop
// client. It is replaced with a real page as each phase lands.
func (sh *shell) placeholderPage(title string) fyne.CanvasObject {
	body := container.NewVBox(
		boldText(title, 20),
		spacer(8),
		mutedPara("This section is coming to the desktop management client. Until then, manage "+title+" from the web UI."),
	)
	return container.NewCenter(container.New(&fixedWidthLayout{480}, card(container.NewPadded(body))))
}
