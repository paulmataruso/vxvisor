package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-4 vFirewall page: enable toggle, VM/zone groups, and ordered N-S / E-W
// rules. Group membership (VM/network assignment) stays on the web UI for now.

func (sh *shell) vfirewallPage() fyne.CanvasObject {
	return sh.listPage("vfirewall", "vFirewall", nil, func() (fyne.CanvasObject, error) {
		v, err := sh.app.client.Firewall()
		if err != nil {
			return nil, err
		}

		// Set the initial state BEFORE wiring OnChanged — SetChecked fires the
		// handler whenever the value differs from the default (false), which would
		// POST a spurious FWSetEnabled (and mutate UI off the render goroutine) on
		// every load of an already-enabled firewall.
		en := widget.NewCheck("Distributed firewall enabled", nil)
		en.SetChecked(v.Enabled)
		en.OnChanged = func(b bool) {
			sh.do(func() error { return sh.app.client.FWSetEnabled(b) }, func() { sh.toast("Firewall " + onoff(b)) })
		}
		enRow := card(container.NewPadded(en))

		addGrp := plainBtn("Add group", func() { sh.fwAddGroupDialog() })
		var grows [][]fyne.CanvasObject
		for _, g := range v.Groups {
			g := g
			rename := plainBtn("Rename", func() {
				e := entryVal(g.Name, "")
				sh.showForm("Rename group", "Save", []*widget.FormItem{widget.NewFormItem("Name", e)},
					func() error { return sh.app.client.FWRenameGroup(g.ID, strings.TrimSpace(e.Text)) })
			})
			zone := plainBtn("Zone", func() {
				z := selectWith([]string{"Internal", "External"}, g.Zone)
				sh.showForm("Set zone — "+g.Name, "Save", []*widget.FormItem{widget.NewFormItem("Zone", z)},
					func() error { return sh.app.client.FWSetGroupZone(g.ID, z.Selected) })
			})
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete group", "Delete group \""+g.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.FWDelGroup(g.ID) }, sh.reloadActive)
				})
			})
			grows = append(grows, []fyne.CanvasObject{
				cellBold(g.Name), cell(g.Zone), cell(itoa(g.Count) + " VMs"), rowActions(rename, zone, del),
			})
		}
		groupsTable := dataTable([]string{"Group", "Zone", "Members", ""}, []float32{2.4, 1.4, 1.6, 2.6}, grows, "No groups.")

		nsAdd := plainBtn("Add N-S rule", func() { sh.fwAddRuleDialog("ns", v) })
		ewAdd := plainBtn("Add E-W rule", func() { sh.fwAddRuleDialog("ew", v) })

		return container.NewVBox(
			enRow,
			spacer(16), subSection("Groups", addGrp, groupsTable),
			spacer(16), subSection("North-South rules (routed)", nsAdd, sh.fwRulesTable(v.RulesNS, "ns")),
			spacer(16), subSection("East-West rules (same L2)", ewAdd, sh.fwRulesTable(v.RulesEW, "ew")),
			spacer(10), mutedPara("Assign VMs/networks to groups from the web UI (drag-and-drop palette)."),
		), nil
	})
}

func (sh *shell) fwRulesTable(groups []client.FWRuleGroupView, dir string) fyne.CanvasObject {
	var rows [][]fyne.CanvasObject
	for _, g := range groups {
		for _, it := range g.Items {
			it := it
			fromName := g.FromName
			if it.FromName != "" {
				fromName = it.FromName
			}
			toName := g.ToName
			if it.ToName != "" {
				toName = it.ToName
			}
			port := it.Rule.Proto
			if it.Rule.DPort != "" {
				port += "/" + it.Rule.DPort
			}
			up := plainBtn("↑", func() { sh.do(func() error { return sh.app.client.FWMoveRule(dir, it.Idx, "up") }, sh.reloadActive) })
			dn := plainBtn("↓", func() { sh.do(func() error { return sh.app.client.FWMoveRule(dir, it.Idx, "down") }, sh.reloadActive) })
			del := dangerBtn("Delete", func() { sh.do(func() error { return sh.app.client.FWDelRule(dir, it.Idx) }, sh.reloadActive) })
			rows = append(rows, []fyne.CanvasObject{
				cell(fromName), cell(toName), cell(it.Rule.Action), cell(port), rowActions(up, dn, del),
			})
		}
	}
	return dataTable([]string{"From", "To", "Action", "Proto/Port", ""}, []float32{2, 2, 1.2, 1.6, 2.2}, rows, "No rules.")
}

func (sh *shell) fwAddGroupDialog() {
	name := widget.NewEntry()
	name.SetPlaceHolder("group name")
	sh.showForm("Add firewall group", "Create", []*widget.FormItem{widget.NewFormItem("Name", name)}, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		_, err := sh.app.client.FWAddGroup(strings.TrimSpace(name.Text))
		return err
	})
}

func (sh *shell) fwAddRuleDialog(dir string, v client.OrgFirewallView) {
	eps := v.Endpoints
	if dir == "ew" {
		eps = v.EWEndpoints
	}
	var names, keys []string
	for _, e := range eps {
		names = append(names, e.Name)
		keys = append(keys, e.Key)
	}
	un := uniqueLabels(names)
	from := widget.NewSelect(un, nil)
	to := widget.NewSelect(un, nil)
	if len(names) > 0 {
		from.SetSelectedIndex(0)
		to.SetSelectedIndex(0)
	}
	action := selectWith([]string{"allow", "deny"}, "allow")
	proto := selectWith([]string{"any", "tcp", "udp", "icmp"}, "any")
	dport := entryVal("", "port(s), blank = any")
	desc := entryVal("", "description")
	reverse := widget.NewCheck("Also add the reverse rule", nil)

	items := []*widget.FormItem{
		widget.NewFormItem("From", from),
		widget.NewFormItem("To", to),
		widget.NewFormItem("Action", action),
		widget.NewFormItem("Proto", proto),
		widget.NewFormItem("Dest port", dport),
		widget.NewFormItem("Description", desc),
		widget.NewFormItem("", reverse),
	}
	sh.showForm("Add "+strings.ToUpper(dir)+" rule", "Add", items, func() error {
		fi, ti := from.SelectedIndex(), to.SelectedIndex()
		if fi < 0 || ti < 0 || fi >= len(keys) || ti >= len(keys) {
			return errReq("choose From and To endpoints")
		}
		return sh.app.client.FWAddRule(dir, client.FWRule{
			From: keys[fi], To: keys[ti], Action: action.Selected, Proto: proto.Selected,
			DPort: strings.TrimSpace(dport.Text), Desc: strings.TrimSpace(desc.Text),
		}, reverse.Checked)
	})
}

func onoff(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}
