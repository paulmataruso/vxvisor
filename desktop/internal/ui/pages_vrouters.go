package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-4 vRouters page: per-tenant FRR routers. List + lifecycle + a configure
// dialog (transit, internal nets, static routes, OSPF/BGP/EIGRP).

func (sh *shell) vroutersPage() fyne.CanvasObject {
	create := primaryBtn("New vRouter", func() { sh.newVRouterDialog() })
	return sh.listPage("vrouters", "vRouters", create, func() (fyne.CanvasObject, error) {
		vrs, err := sh.app.client.VRouters()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, vr := range vrs {
			vr := vr
			running := strings.EqualFold(vr.Status, "running") || strings.EqualFold(vr.LiveState, "running")
			start := plainBtn("Start", func() { sh.do(func() error { return sh.app.client.StartVRouter(vr.ID) }, sh.reloadActive) })
			stop := plainBtn("Stop", func() { sh.do(func() error { return sh.app.client.StopVRouter(vr.ID) }, sh.reloadActive) })
			cfg := plainBtn("Configure", func() { sh.vrouterDetailDialog(vr.ID) })
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete vRouter", "Delete \""+vr.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteVRouter(vr.ID) }, sh.reloadActive)
				})
			})
			if running {
				start.Disable()
			} else {
				stop.Disable()
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(vr.Name), cell(vr.Runtime), cellState(strings.ToLower(vr.Status)), rowActions(start, stop, cfg, del),
			})
		}
		return dataTable([]string{"Name", "Runtime", "Status", ""}, []float32{2.4, 1.4, 1.4, 3}, rows, "No vRouters."), nil
	})
}

func (sh *shell) newVRouterDialog() {
	name := widget.NewEntry()
	runtime := selectWith([]string{"lxc", "netns"}, "lxc")
	cpus := entryVal("1", "")
	mem := entryVal("256", "")
	dist := entryVal("", "ubuntu (lxc only)")
	release := entryVal("", "noble (lxc only)")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Runtime", runtime),
		widget.NewFormItem("vCPUs", cpus),
		widget.NewFormItem("Memory (MB)", mem),
		widget.NewFormItem("Distro", dist),
		widget.NewFormItem("Release", release),
	}
	sh.showForm("New vRouter", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		_, err := sh.app.client.CreateVRouter(client.VRouterInput{
			Name: strings.TrimSpace(name.Text), Runtime: runtime.Selected,
			CPUs: atoiDefault(cpus.Text, 1), MemMB: atoiDefault(mem.Text, 256),
			Dist: strings.TrimSpace(dist.Text), Release: strings.TrimSpace(release.Text),
		})
		return err
	})
}

func (sh *shell) vrouterDetailDialog(id int64) {
	host := container.NewVBox(mutedText("Loading…", 12))
	var reload func()
	reload = func() {
		go func() {
			vr, err := sh.app.client.VRouter(id)
			fyne.Do(func() {
				if err != nil {
					host.Objects = []fyne.CanvasObject{mutedPara("Could not load: " + err.Error())}
				} else {
					host.Objects = []fyne.CanvasObject{sh.vrouterDetailBody(vr, reload)}
				}
				host.Refresh()
			})
		}()
	}
	reload()
	d := dialog.NewCustom("vRouter", "Close", container.NewVScroll(host), sh.win)
	d.Resize(fyne.NewSize(720, 600))
	d.Show()
}

func (sh *shell) vrouterDetailBody(vr *client.VRouterView, reload func()) fyne.CanvasObject {
	id := vr.ID
	do := func(fn func() error) { sh.do(fn, func() { reload(); sh.reloadActive() }) }

	// Transit + internal legs.
	setTransit := plainBtn("Set transit", func() {
		iface := entryVal("", "eth0 / transit NIC")
		cidr := entryVal("", "203.0.113.2/30")
		sh.showFormThen("Set transit link", "Save", []*widget.FormItem{
			widget.NewFormItem("Interface", iface), widget.NewFormItem("CIDR", cidr),
		}, func() error {
			return sh.app.client.VRouterAddTransit(id, strings.TrimSpace(iface.Text), strings.TrimSpace(cidr.Text))
		}, reload)
	})
	attach := plainBtn("Attach internal", func() {
		nm := entryVal("", "lan name")
		cidr := entryVal("", "10.10.0.1/24")
		gw := entryVal("", "gateway (optional)")
		dhcp := widget.NewCheck("DHCP", nil)
		rng := entryVal("", "dhcp range (optional)")
		dns := entryVal("", "dns (optional)")
		sh.showFormThen("Attach internal network", "Attach", []*widget.FormItem{
			widget.NewFormItem("Name", nm), widget.NewFormItem("CIDR", cidr), widget.NewFormItem("Gateway", gw),
			widget.NewFormItem("", dhcp), widget.NewFormItem("DHCP range", rng), widget.NewFormItem("DNS", dns),
		}, func() error {
			return sh.app.client.VRouterAddInternal(id, strings.TrimSpace(nm.Text), strings.TrimSpace(cidr.Text),
				strings.TrimSpace(gw.Text), dhcp.Checked, strings.TrimSpace(rng.Text), strings.TrimSpace(dns.Text))
		}, reload)
	})
	var legRows [][]fyne.CanvasObject
	for _, l := range vr.Legs {
		legRows = append(legRows, []fyne.CanvasObject{cell(l.Kind), cellMono(l.IfaceName), cellMono(l.CIDR), cell(yesno(l.DHCP))})
	}
	legsTable := dataTable([]string{"Kind", "Interface", "CIDR", "DHCP"}, []float32{1.4, 2, 2.4, 1}, legRows, "No legs attached.")

	// Static routes.
	addStatic := plainBtn("Add route", func() {
		dest := entryVal("", "10.0.0.0/24")
		nh := entryVal("", "next hop")
		sh.showFormThen("Add static route", "Add", []*widget.FormItem{
			widget.NewFormItem("Destination", dest), widget.NewFormItem("Next hop", nh),
		}, func() error {
			return sh.app.client.VRouterAddStatic(id, strings.TrimSpace(dest.Text), strings.TrimSpace(nh.Text))
		}, reload)
	})
	var sRows [][]fyne.CanvasObject
	for i, r := range vr.Cfg.Static {
		i := i
		sRows = append(sRows, []fyne.CanvasObject{cellMono(r.Dest), cellMono(r.NextHop),
			rowActions(dangerBtn("Delete", func() { do(func() error { return sh.app.client.VRouterDeleteStatic(id, i) }) }))})
	}
	staticTable := dataTable([]string{"Destination", "Next hop", ""}, []float32{3, 3, 1.6}, sRows, "No static routes.")

	return container.NewVBox(
		container.NewHBox(boldText(vr.Name, 18), hSpace(8), pill(strings.ToLower(vr.Status), strings.ToLower(vr.Status))),
		mutedText(vr.Runtime+" · "+vr.Dist+" "+vr.Release, 12),
		spacer(12),
		subSection("Interfaces", container.NewThemeOverride(container.NewHBox(setTransit, attach), compactTheme{}), legsTable),
		spacer(14), subSection("Static routes", addStatic, staticTable),
		spacer(14), sh.vrOSPFSection(vr, reload),
		spacer(14), sh.vrBGPSection(vr, reload),
		spacer(14), sh.vrEIGRPSection(vr, reload),
	)
}

func (sh *shell) vrOSPFSection(vr *client.VRouterView, reload func()) fyne.CanvasObject {
	id := vr.ID
	edit := plainBtn("Configure", func() {
		en := widget.NewCheck("Enabled", nil)
		en.SetChecked(vr.Cfg.OSPF.Enabled)
		rid := entryVal(vr.Cfg.OSPF.RouterID, "router-id (optional)")
		sh.showFormThen("OSPF", "Save", []*widget.FormItem{widget.NewFormItem("", en), widget.NewFormItem("Router ID", rid)},
			func() error { return sh.app.client.VRouterSetOSPF(id, en.Checked, strings.TrimSpace(rid.Text)) }, reload)
	})
	add := plainBtn("Add network", func() {
		cidr := entryVal("", "10.0.0.0/24")
		area := entryVal("0", "area")
		sh.showFormThen("Add OSPF network", "Add", []*widget.FormItem{widget.NewFormItem("CIDR", cidr), widget.NewFormItem("Area", area)},
			func() error {
				return sh.app.client.VRouterAddOSPFNet(id, strings.TrimSpace(cidr.Text), strings.TrimSpace(area.Text))
			}, reload)
	})
	var rows [][]fyne.CanvasObject
	for i, n := range vr.Cfg.OSPF.Networks {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellMono(n.CIDR), cell(n.Area),
			rowActions(dangerBtn("Delete", func() { sh.do(func() error { return sh.app.client.VRouterDeleteOSPFNet(id, i) }, reload) }))})
	}
	head := container.NewThemeOverride(container.NewHBox(protoState("OSPF", vr.Cfg.OSPF.Enabled), layoutExpand(), edit, add), compactTheme{})
	return subSection("OSPF", nil, container.NewVBox(head, spacer(6), dataTable([]string{"Network", "Area", ""}, []float32{3, 2, 1.6}, rows, "No networks.")))
}

func (sh *shell) vrBGPSection(vr *client.VRouterView, reload func()) fyne.CanvasObject {
	id := vr.ID
	edit := plainBtn("Configure", func() {
		en := widget.NewCheck("Enabled", nil)
		en.SetChecked(vr.Cfg.BGP.Enabled)
		asn := entryVal(itoa(vr.Cfg.BGP.ASN), "local ASN")
		rid := entryVal(vr.Cfg.BGP.RouterID, "router-id")
		sh.showFormThen("BGP", "Save", []*widget.FormItem{widget.NewFormItem("", en), widget.NewFormItem("ASN", asn), widget.NewFormItem("Router ID", rid)},
			func() error {
				return sh.app.client.VRouterSetBGP(id, en.Checked, atoiDefault(asn.Text, 0), strings.TrimSpace(rid.Text))
			}, reload)
	})
	addN := plainBtn("Add neighbor", func() {
		addr := entryVal("", "peer IP")
		ras := entryVal("", "remote ASN")
		sh.showFormThen("Add BGP neighbor", "Add", []*widget.FormItem{widget.NewFormItem("Address", addr), widget.NewFormItem("Remote AS", ras)},
			func() error {
				return sh.app.client.VRouterAddBGPNeighbor(id, strings.TrimSpace(addr.Text), atoiDefault(ras.Text, 0))
			}, reload)
	})
	addNet := plainBtn("Advertise", func() {
		cidr := entryVal("", "10.0.0.0/24")
		sh.showFormThen("Advertise BGP network", "Add", []*widget.FormItem{widget.NewFormItem("CIDR", cidr)},
			func() error { return sh.app.client.VRouterAddBGPNetwork(id, strings.TrimSpace(cidr.Text)) }, reload)
	})
	var nrows [][]fyne.CanvasObject
	for i, n := range vr.Cfg.BGP.Neighbors {
		i := i
		nrows = append(nrows, []fyne.CanvasObject{cellMono(n.Addr), cell(itoa(n.RemoteAS)),
			rowActions(dangerBtn("Delete", func() { sh.do(func() error { return sh.app.client.VRouterDeleteBGPNeighbor(id, i) }, reload) }))})
	}
	var wrows [][]fyne.CanvasObject
	for i, c := range vr.Cfg.BGP.Networks {
		i := i
		wrows = append(wrows, []fyne.CanvasObject{cellMono(c),
			rowActions(dangerBtn("Delete", func() { sh.do(func() error { return sh.app.client.VRouterDeleteBGPNetwork(id, i) }, reload) }))})
	}
	head := container.NewThemeOverride(container.NewHBox(protoState("BGP AS"+itoa(vr.Cfg.BGP.ASN), vr.Cfg.BGP.Enabled), layoutExpand(), edit, addN, addNet), compactTheme{})
	return subSection("BGP", nil, container.NewVBox(head, spacer(6),
		dataTable([]string{"Neighbor", "Remote AS", ""}, []float32{3, 2, 1.6}, nrows, "No neighbors."),
		spacer(8),
		dataTable([]string{"Advertised", ""}, []float32{5, 1.6}, wrows, "No advertised networks.")))
}

func (sh *shell) vrEIGRPSection(vr *client.VRouterView, reload func()) fyne.CanvasObject {
	id := vr.ID
	edit := plainBtn("Configure", func() {
		en := widget.NewCheck("Enabled", nil)
		en.SetChecked(vr.Cfg.EIGRP.Enabled)
		asn := entryVal(itoa(vr.Cfg.EIGRP.ASN), "ASN")
		rid := entryVal(vr.Cfg.EIGRP.RouterID, "router-id")
		sh.showFormThen("EIGRP", "Save", []*widget.FormItem{widget.NewFormItem("", en), widget.NewFormItem("ASN", asn), widget.NewFormItem("Router ID", rid)},
			func() error {
				return sh.app.client.VRouterSetEIGRP(id, en.Checked, atoiDefault(asn.Text, 0), strings.TrimSpace(rid.Text))
			}, reload)
	})
	add := plainBtn("Add network", func() {
		cidr := entryVal("", "10.0.0.0/24")
		sh.showFormThen("Add EIGRP network", "Add", []*widget.FormItem{widget.NewFormItem("CIDR", cidr)},
			func() error { return sh.app.client.VRouterAddEIGRPNet(id, strings.TrimSpace(cidr.Text)) }, reload)
	})
	var rows [][]fyne.CanvasObject
	for i, c := range vr.Cfg.EIGRP.Networks {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellMono(c),
			rowActions(dangerBtn("Delete", func() { sh.do(func() error { return sh.app.client.VRouterDeleteEIGRPNet(id, i) }, reload) }))})
	}
	head := container.NewThemeOverride(container.NewHBox(protoState("EIGRP AS"+itoa(vr.Cfg.EIGRP.ASN), vr.Cfg.EIGRP.Enabled), layoutExpand(), edit, add), compactTheme{})
	return subSection("EIGRP", nil, container.NewVBox(head, spacer(6), dataTable([]string{"Network", ""}, []float32{5, 1.6}, rows, "No networks.")))
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
