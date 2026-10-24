package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
)

// Phase-4 Cluster page: list nodes + add/probe/remove.

func (sh *shell) clusterPage() fyne.CanvasObject {
	add := primaryBtn("Add node", func() { sh.addNodeDialog() })
	return sh.listPage("cluster", "Cluster", add, func() (fyne.CanvasObject, error) {
		ns, err := sh.app.client.Nodes()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, n := range ns {
			n := n
			probe := plainBtn("Probe", func() {
				sh.do(func() error { return sh.app.client.ProbeNode(n.ID) }, sh.reloadActive)
			})
			del := dangerBtn("Remove", func() {
				sh.confirm("Remove node", "Remove node \""+n.Name+"\" from the cluster?", func() {
					sh.do(func() error { return sh.app.client.DeleteNode(n.ID) }, sh.reloadActive)
				})
			})
			acts := rowActions(probe, del)
			if strings.EqualFold(n.Role, "local") {
				acts = rowActions(probe)
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(n.Name), cellMono(n.Address), cell(n.Role), cellState(n.Status), acts,
			})
		}
		return dataTable([]string{"Name", "Address", "Role", "Status", ""},
			[]float32{2, 2, 1.2, 1.4, 1.8}, rows, "No cluster nodes."), nil
	})
}

func (sh *shell) addNodeDialog() {
	name := widget.NewEntry()
	addr := widget.NewEntry()
	addr.SetPlaceHolder("ip or host")
	sshUser := widget.NewEntry()
	sshUser.SetPlaceHolder("ssh user (sudo)")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Address", addr),
		widget.NewFormItem("SSH user", sshUser),
	}
	sh.showForm("Add node", "Add", items, func() error {
		if strings.TrimSpace(name.Text) == "" || strings.TrimSpace(addr.Text) == "" {
			return errReq("name and address are required")
		}
		return sh.app.client.AddNode(strings.TrimSpace(name.Text), strings.TrimSpace(addr.Text), strings.TrimSpace(sshUser.Text))
	})
}
