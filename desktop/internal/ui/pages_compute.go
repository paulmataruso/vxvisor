package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-2 Containers (LXC) page.

func (sh *shell) containersPage() fyne.CanvasObject {
	create := primaryBtn("New container", func() { sh.newContainerDialog() })
	return sh.listPage("containers", "Containers", create, func() (fyne.CanvasObject, error) {
		cs, err := sh.app.client.Containers()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, c := range cs {
			c := c
			state := c.State
			if state == "" {
				state = c.Status
			}
			running := strings.EqualFold(state, "running")

			start := plainBtn("Start", func() {
				sh.do(func() error { return sh.app.client.StartContainer(c.ID) }, sh.reloadActive)
			})
			stop := plainBtn("Stop", func() {
				sh.do(func() error { return sh.app.client.StopContainer(c.ID) }, sh.reloadActive)
			})
			snap := plainBtn("Snapshot", func() {
				sh.do(func() error { return sh.app.client.SnapshotContainer(c.ID) }, sh.reloadActive)
			})
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete container", "Delete \""+c.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteContainer(c.ID) }, sh.reloadActive)
				})
			})
			if running {
				start.Disable()
			} else {
				stop.Disable()
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(c.Name),
				cell(strings.TrimSpace(c.Dist + " " + c.Release)),
				cellState(strings.ToLower(state)),
				cell(itoa(c.CPUs) + " vCPU · " + itoa(c.MemoryMB) + " MB"),
				rowActions(start, stop, snap, del),
			})
		}
		return dataTable([]string{"Name", "Image", "State", "Spec", ""},
			[]float32{2.2, 2, 1.4, 2.2, 3}, rows, "No containers."), nil
	})
}

func (sh *shell) newContainerDialog() {
	name := widget.NewEntry()
	dist := selectWith([]string{"ubuntu", "debian", "alpine", "rockylinux", "centos"}, "ubuntu")
	release := widget.NewEntry()
	release.SetPlaceHolder("noble / bookworm / 3.20 …")
	bridge := widget.NewEntry()
	bridge.SetPlaceHolder("auto (leave blank)")
	cpus := widget.NewEntry()
	cpus.SetText("1")
	mem := widget.NewEntry()
	mem.SetText("512")
	disk := widget.NewEntry()
	disk.SetPlaceHolder("0 = default")
	copies := widget.NewEntry()
	copies.SetText("1")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Distro", dist),
		widget.NewFormItem("Release", release),
		widget.NewFormItem("Bridge", bridge),
		widget.NewFormItem("vCPUs", cpus),
		widget.NewFormItem("Memory (MB)", mem),
		widget.NewFormItem("Disk (GB)", disk),
		widget.NewFormItem("Copies", copies),
	}
	sh.showForm("New container", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.CreateContainer(client.CreateContainerInput{
			Name:     strings.TrimSpace(name.Text),
			Dist:     dist.Selected,
			Release:  strings.TrimSpace(release.Text),
			Bridge:   strings.TrimSpace(bridge.Text),
			CPUs:     atoiDefault(cpus.Text, 1),
			MemoryMB: atoiDefault(mem.Text, 512),
			DiskGB:   atoiDefault(disk.Text, 0),
			Copies:   atoiDefault(copies.Text, 1),
		})
	})
}
