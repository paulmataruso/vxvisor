package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-2 storage pages: Pools (with datastore browser), Shared Storage, Ceph.

func (sh *shell) poolsPage() fyne.CanvasObject {
	reg := primaryBtn("Register pool", func() { sh.registerPoolDialog() })
	return sh.listPage("pools", "Storage Pools", reg, func() (fyne.CanvasObject, error) {
		pools, err := sh.app.client.Pools()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, p := range pools {
			p := p
			browse := plainBtn("Browse", func() { sh.browsePool(p) })
			del := dangerBtn("Remove", func() {
				sh.confirm("Remove pool", "Unregister pool \""+p.Name+"\"? (Data is not erased.)", func() {
					sh.do(func() error { return sh.app.client.DeletePool(p.ID) }, sh.reloadActive)
				})
			})
			used := "—"
			if p.TotalBytes > 0 {
				used = humanBytes(p.UsedBytes) + " / " + humanBytes(p.TotalBytes)
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(p.Name), cell(p.Kind), cell(used), cellMono(p.Path), rowActions(browse, del),
			})
		}
		return dataTable([]string{"Name", "Kind", "Used / total", "Path", ""},
			[]float32{2.2, 1.2, 2.2, 3, 2}, rows, "No storage pools."), nil
	})
}

func (sh *shell) browsePool(p client.Pool) {
	content := container.NewStack(container.New(&insetLayout{2, 8}, mutedText("Loading…", 12)))
	go func() {
		b, err := sh.app.client.BrowsePool(p.ID)
		fyne.Do(func() {
			if err != nil {
				content.Objects = []fyne.CanvasObject{mutedPara("Could not browse: " + err.Error())}
				content.Refresh()
				return
			}
			var rows [][]fyne.CanvasObject
			for _, e := range b.Entries {
				size := "—"
				if e.Bytes > 0 {
					size = humanBytes(e.Bytes)
				}
				rows = append(rows, []fyne.CanvasObject{cellBold(e.Name), cell(e.Kind), cell(size), cell(e.Modified)})
			}
			content.Objects = []fyne.CanvasObject{dataTable(
				[]string{"Name", "Kind", "Size", "Modified"},
				[]float32{3.4, 1.4, 1.6, 2}, rows, "Empty.")}
			content.Refresh()
		})
	}()
	d := dialog.NewCustom("Browse — "+p.Name, "Close", content, sh.win)
	d.Resize(fyne.NewSize(640, 480))
	d.Show()
}

func (sh *shell) registerPoolDialog() {
	name := widget.NewEntry()
	kind := selectWith([]string{"dir", "zfs", "lvm", "rbd"}, "dir")
	path := widget.NewEntry()
	path.SetPlaceHolder("/var/lib/vdxclone/data/pools/… or pool name")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Kind", kind),
		widget.NewFormItem("Path", path),
	}
	sh.showForm("Register pool", "Register", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.UpsertPool(strings.TrimSpace(name.Text), kind.Selected, strings.TrimSpace(path.Text))
	})
}

func (sh *shell) sharedPage() fyne.CanvasObject {
	actions := container.NewHBox(
		plainBtn("NFS", func() { sh.nfsDialog() }),
		plainBtn("CIFS", func() { sh.cifsDialog() }),
		plainBtn("Ceph", func() { sh.cephMountDialog() }),
	)
	return sh.listPage("shared", "Shared Storage", actions, func() (fyne.CanvasObject, error) {
		ms, err := sh.app.client.SharedMounts()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, m := range ms {
			m := m
			unmount := dangerBtn("Unmount", func() {
				sh.confirm("Unmount", "Unmount \""+m.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.UnmountShared(m.ID) }, sh.reloadActive)
				})
			})
			rows = append(rows, []fyne.CanvasObject{
				cellBold(m.Name), cell(m.Kind), cellMono(m.Spec), cellState(m.Status), rowActions(unmount),
			})
		}
		return dataTable([]string{"Name", "Kind", "Spec", "Status", ""},
			[]float32{2, 1, 3, 1.4, 1.6}, rows, "No shared mounts."), nil
	})
}

func (sh *shell) nfsDialog() {
	name := widget.NewEntry()
	server := widget.NewEntry()
	export := widget.NewEntry()
	export.SetPlaceHolder("/export/path")
	vers := widget.NewEntry()
	vers.SetPlaceHolder("4.2 (optional)")
	opts := widget.NewEntry()
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Server", server),
		widget.NewFormItem("Export", export),
		widget.NewFormItem("Version", vers),
		widget.NewFormItem("Options", opts),
	}
	sh.showForm("Mount NFS", "Mount", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.AddNFS(name.Text, server.Text, export.Text, vers.Text, opts.Text)
	})
}

func (sh *shell) cifsDialog() {
	name := widget.NewEntry()
	unc := widget.NewEntry()
	unc.SetPlaceHolder(`\\server\share`)
	user := widget.NewEntry()
	pass := widget.NewPasswordEntry()
	domain := widget.NewEntry()
	vers := widget.NewEntry()
	opts := widget.NewEntry()
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("UNC path", unc),
		widget.NewFormItem("Username", user),
		widget.NewFormItem("Password", pass),
		widget.NewFormItem("Domain", domain),
		widget.NewFormItem("Version", vers),
		widget.NewFormItem("Options", opts),
	}
	sh.showForm("Mount CIFS", "Mount", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.AddCIFS(name.Text, unc.Text, user.Text, pass.Text, domain.Text, vers.Text, opts.Text)
	})
}

func (sh *shell) cephMountDialog() {
	name := widget.NewEntry()
	mons := widget.NewEntry()
	mons.SetPlaceHolder("mon1,mon2,mon3")
	path := widget.NewEntry()
	path.SetPlaceHolder("/")
	cephName := widget.NewEntry()
	cephName.SetPlaceHolder("admin")
	secret := widget.NewPasswordEntry()
	opts := widget.NewEntry()
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Monitors", mons),
		widget.NewFormItem("Path", path),
		widget.NewFormItem("Ceph user", cephName),
		widget.NewFormItem("Secret", secret),
		widget.NewFormItem("Options", opts),
	}
	sh.showForm("Mount CephFS", "Mount", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.AddCeph(name.Text, mons.Text, path.Text, cephName.Text, secret.Text, opts.Text)
	})
}

func (sh *shell) cephPage() fyne.CanvasObject {
	refresh := plainBtn("Refresh", func() { sh.reloadActive() })
	return sh.listPage("ceph", "Ceph / HCI", refresh, func() (fyne.CanvasObject, error) {
		h, err := sh.app.client.CephStatus()
		if err != nil {
			return nil, err
		}
		if !h.Configured {
			return card(container.NewPadded(container.NewVBox(
				boldText("Ceph not configured", 16),
				spacer(4),
				mutedPara("No on-node Ceph cluster is configured. Bootstrap Ceph from the web UI."),
			))), nil
		}
		strip := container.NewGridWithColumns(4,
			statTile(itoa(h.NumMons), "Monitors", nil),
			statTile(itoa(h.OSDsUp)+"/"+itoa(h.NumOSDs), "OSDs up", nil),
			statTile(humanBytes(h.UsedBytes), "Used", colAccent),
			statTile(humanBytes(h.TotalBytes), "Total", nil),
		)
		head := container.NewHBox(boldText("Cluster health", 16), container.NewPadded(pill(cephState(h.Status), cephState(h.Status))))
		body := container.NewVBox(head, spacer(6), strip)
		if h.Summary != "" {
			body.Add(spacer(6))
			body.Add(mutedPara(h.Summary))
		}
		return card(container.NewPadded(body)), nil
	})
}

func cephState(s string) string {
	switch s {
	case "HEALTH_OK":
		return "ok"
	case "HEALTH_WARN":
		return "warn"
	case "HEALTH_ERR":
		return "error"
	default:
		return strings.ToLower(s)
	}
}
