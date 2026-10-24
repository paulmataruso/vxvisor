package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-1 library pages: Trash, Templates, and ISO Library. Each mirrors the web
// list page (table of items + row actions + a header action).

func (sh *shell) trashPage() fyne.CanvasObject {
	refresh := plainBtn("Refresh", func() { sh.reloadActive() })
	return sh.listPage("trash", "Trash", refresh, func() (fyne.CanvasObject, error) {
		vms, err := sh.app.client.Trash()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, v := range vms {
			v := v
			restore := plainBtn("Restore", func() {
				sh.do(func() error { return sh.app.client.RestoreSession(v.ID) }, sh.reloadActive)
			})
			purge := dangerBtn("Purge", func() {
				sh.confirm("Purge instance", "Permanently delete \""+v.Name+"\"? This cannot be undone.", func() {
					sh.do(func() error { return sh.app.client.PurgeSession(v.ID) }, sh.reloadActive)
				})
			})
			rows = append(rows, []fyne.CanvasObject{
				cellBold(v.Name),
				cell(itoa(v.CPUs) + " vCPU · " + itoa(v.MemoryMB) + " MB"),
				cell(shortTime(v.CreatedAt)),
				rowActions(restore, purge),
			})
		}
		return dataTable(
			[]string{"Name", "Spec", "Deleted", ""},
			[]float32{3, 2.6, 2, 3},
			rows, "Trash is empty."), nil
	})
}

func (sh *shell) templatesPage() fyne.CanvasObject {
	refresh := plainBtn("Refresh", func() { sh.reloadActive() })
	return sh.listPage("templates", "Templates", refresh, func() (fyne.CanvasObject, error) {
		tpls, err := sh.app.client.Templates()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, t := range tpls {
			t := t
			launch := primaryBtn("Launch", func() { sh.launchTemplateDialog(t) })
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete template", "Delete template \""+t.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteTemplate(t.ID) }, sh.reloadActive)
				})
			})
			rows = append(rows, []fyne.CanvasObject{
				cellBold(t.Name),
				cell(t.ImageName),
				cell(itoa(t.CPUs) + " vCPU · " + itoa(t.MemoryMB) + " MB · " + itoa(t.DiskGB) + " GB"),
				rowActions(launch, del),
			})
		}
		return dataTable(
			[]string{"Name", "Image", "Spec", ""},
			[]float32{2.6, 2.4, 3, 2.6},
			rows, "No templates yet."), nil
	})
}

func (sh *shell) launchTemplateDialog(t client.Template) {
	name := widget.NewEntry()
	name.SetText(t.Name + "-1")
	items := []*widget.FormItem{widget.NewFormItem("New VM name", name)}
	// Launch creates a VM (shows on the Instances page), so refresh the fleet.
	d := func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.LaunchTemplate(t.ID, strings.TrimSpace(name.Text))
	}
	sh.showFormThen("Launch "+t.Name, "Launch", items, d, func() {
		sh.toast("Launching from template…")
		sh.reload(true)
	})
}

func (sh *shell) isosPage() fyne.CanvasObject {
	actions := primaryBtn("Pull ISO", func() { sh.pullISODialog() })
	return sh.listPage("isos", "ISO Library", actions, func() (fyne.CanvasObject, error) {
		isos, err := sh.app.client.ISOs()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, is := range isos {
			is := is
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete ISO", "Delete ISO \""+is.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteISO(is.ID) }, sh.reloadActive)
				})
			})
			size := "—"
			if is.SizeBytes > 0 {
				size = humanBytes(is.SizeBytes)
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(is.Name),
				cell(size),
				cellState(is.Status),
				rowActions(del),
			})
		}
		return dataTable(
			[]string{"Name", "Size", "Status", ""},
			[]float32{3.4, 1.6, 1.8, 2},
			rows, "No ISOs yet — pull one from a URL."), nil
	})
}

func (sh *shell) pullISODialog() {
	name := widget.NewEntry()
	name.SetPlaceHolder("ubuntu-24.04.iso")
	src := widget.NewEntry()
	src.SetPlaceHolder("https://… .iso")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("URL", src),
	}
	sh.showForm("Pull ISO from URL", "Pull", items, func() error {
		if strings.TrimSpace(name.Text) == "" || strings.TrimSpace(src.Text) == "" {
			return errReq("name and URL are required")
		}
		return sh.app.client.PullISO(strings.TrimSpace(name.Text), strings.TrimSpace(src.Text))
	})
}
