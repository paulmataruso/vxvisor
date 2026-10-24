package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-2 Networks page: port groups + (admin) bonds and vSwitches.

func (sh *shell) networksPage() fyne.CanvasObject {
	create := primaryBtn("New network", func() { sh.newNetworkDialog() })
	return sh.listPage("networks", "Networks", create, func() (fyne.CanvasObject, error) {
		nets, err := sh.app.client.Networks()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, n := range nets {
			n := n
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete network", "Delete \""+n.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteNetwork(n.ID) }, sh.reloadActive)
				})
			})
			det := n.Mode
			if n.CIDR != "" {
				det += " · " + n.CIDR
			}
			if n.VLANID != 0 {
				det += " · VLAN " + itoa(n.VLANID)
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(n.Name), cell(det), cell(n.Bridge), rowActions(del),
			})
		}
		netTable := dataTable([]string{"Name", "Mode / subnet", "Bridge", ""},
			[]float32{2.6, 3, 2, 1.6}, rows, "No networks.")

		var sections []fyne.CanvasObject
		if sh.isAdmin() {
			sections = append(sections, sh.networkMapSection(), spacer(16))
		}
		sections = append(sections, subSection("Port groups", nil, netTable))
		if sh.isAdmin() {
			sections = append(sections, spacer(16), sh.bondsSection(), spacer(16), sh.vswitchesSection())
		}
		return container.NewVBox(sections...), nil
	})
}

func (sh *shell) bondsSection() fyne.CanvasObject {
	add := plainBtn("Add bond", func() { sh.newBondDialog() })
	bonds, err := sh.app.client.Bonds()
	if err != nil {
		return subSection("Bonds", add, card(container.NewPadded(mutedPara(err.Error()))))
	}
	var rows [][]fyne.CanvasObject
	for _, b := range bonds {
		b := b
		del := dangerBtn("Delete", func() {
			sh.confirm("Delete bond", "Delete bond \""+b.Name+"\"?", func() {
				sh.do(func() error { return sh.app.client.DeleteBond(b.Name) }, sh.reloadActive)
			})
		})
		rows = append(rows, []fyne.CanvasObject{
			cellBold(b.Name), cell(b.Mode), cell(strings.Join(b.Members, ", ")), rowActions(del),
		})
	}
	return subSection("Bonds", add, dataTable([]string{"Name", "Mode", "Members", ""},
		[]float32{2, 2, 3, 1.6}, rows, "No bonds."))
}

func (sh *shell) vswitchesSection() fyne.CanvasObject {
	add := plainBtn("Add vSwitch", func() { sh.newVSwitchDialog() })
	vs, err := sh.app.client.VSwitches()
	if err != nil {
		return subSection("vSwitches", add, card(container.NewPadded(mutedPara(err.Error()))))
	}
	var rows [][]fyne.CanvasObject
	for _, v := range vs {
		v := v
		del := dangerBtn("Delete", func() {
			sh.confirm("Delete vSwitch", "Delete vSwitch \""+v.Name+"\"?", func() {
				sh.do(func() error { return sh.app.client.DeleteVSwitch(v.Name) }, sh.reloadActive)
			})
		})
		rows = append(rows, []fyne.CanvasObject{
			cellBold(v.Name), cell(v.Bridge), cell(v.Uplink), rowActions(del),
		})
	}
	return subSection("vSwitches", add, dataTable([]string{"Name", "Bridge", "Uplink", ""},
		[]float32{2.4, 2, 2, 1.6}, rows, "No vSwitches."))
}

func (sh *shell) newNetworkDialog() {
	name := widget.NewEntry()
	mode := selectWith([]string{"bridge", "user", "vxlan"}, "bridge")
	bridge := widget.NewEntry()
	bridge.SetPlaceHolder("auto (leave blank)")
	vlan := widget.NewEntry()
	cidr := widget.NewEntry()
	cidr.SetPlaceHolder("10.0.0.0/24")
	gw := widget.NewEntry()
	poolStart := widget.NewEntry()
	poolEnd := widget.NewEntry()
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Mode", mode),
		widget.NewFormItem("Bridge", bridge),
		widget.NewFormItem("VLAN ID", vlan),
		widget.NewFormItem("CIDR", cidr),
		widget.NewFormItem("Gateway", gw),
		widget.NewFormItem("DHCP start", poolStart),
		widget.NewFormItem("DHCP end", poolEnd),
	}
	sh.showForm("New network", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.CreateNetwork(client.CreateNetworkInput{
			Name:      strings.TrimSpace(name.Text),
			Mode:      mode.Selected,
			Bridge:    strings.TrimSpace(bridge.Text),
			VLANID:    atoiDefault(vlan.Text, 0),
			CIDR:      strings.TrimSpace(cidr.Text),
			Gateway:   strings.TrimSpace(gw.Text),
			PoolStart: strings.TrimSpace(poolStart.Text),
			PoolEnd:   strings.TrimSpace(poolEnd.Text),
		})
	})
}

func (sh *shell) newBondDialog() {
	name := widget.NewEntry()
	mode := selectWith([]string{"lacp", "balance-alb", "active-backup", "balance-rr"}, "lacp")
	hash := selectWith([]string{"layer3+4", "layer2", "layer2+3"}, "layer3+4")
	members := widget.NewEntry()
	members.SetPlaceHolder("eth1, eth2")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Mode", mode),
		widget.NewFormItem("Hash policy", hash),
		widget.NewFormItem("Members", members),
	}
	sh.showForm("Add bond", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.CreateBond(strings.TrimSpace(name.Text), mode.Selected, hash.Selected, splitList(members.Text))
	})
}

func (sh *shell) newVSwitchDialog() {
	name := widget.NewEntry()
	uplink := widget.NewEntry()
	uplink.SetPlaceHolder("eth1 or bond0")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Uplink", uplink),
	}
	sh.showForm("Add vSwitch", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.CreateVSwitch(strings.TrimSpace(name.Text), strings.TrimSpace(uplink.Text))
	})
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
