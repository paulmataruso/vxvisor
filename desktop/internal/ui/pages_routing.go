package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-4 L3 Routing page (FRR): uplink, static routes, interface prefixes, edge
// firewall, OSPF/BGP/EIGRP, prefix-lists and route-maps. Granular add/delete
// matches the web /routing page; Apply re-applies the config to FRR+nft.

func (sh *shell) routingPage() fyne.CanvasObject {
	apply := primaryBtn("Apply config", func() {
		sh.do(func() error { return sh.app.client.ApplyRouting() }, func() { sh.toast("Routing configuration applied.") })
	})
	return sh.listPage("routing", "L3 Routing", apply, func() (fyne.CanvasObject, error) {
		cfg, err := sh.app.client.Routing()
		if err != nil {
			return nil, err
		}
		return container.NewVBox(
			sh.routingUplinkSection(cfg),
			spacer(16), sh.routingStaticSection(cfg),
			spacer(16), sh.routingPrefixSection(cfg),
			spacer(16), sh.routingFirewallSection(cfg),
			spacer(16), sh.routingOSPFSection(cfg),
			spacer(16), sh.routingBGPSection(cfg),
			spacer(16), sh.routingEIGRPSection(cfg),
			spacer(16), sh.routingPrefixListSection(cfg),
			spacer(16), sh.routingRouteMapSection(cfg),
		), nil
	})
}

func idxDelete(onDel func()) fyne.CanvasObject { return rowActions(dangerBtn("Delete", onDel)) }

func (sh *shell) routingUplinkSection(cfg client.RoutingConfig) fyne.CanvasObject {
	cur := cfg.Uplink
	if cur == "" {
		cur = "(none)"
	}
	set := plainBtn("Set uplink", func() {
		e := entryVal(cfg.Uplink, "eth0 / bond0")
		sh.showForm("Set uplink NIC", "Save", []*widget.FormItem{widget.NewFormItem("Uplink", e)}, func() error {
			return sh.app.client.SetRoutingUplink(strings.TrimSpace(e.Text))
		})
	})
	body := container.NewBorder(nil, nil, kv("Edge uplink (SNAT)", cur, true), set)
	return subSection("Uplink", nil, card(container.NewPadded(body)))
}

func (sh *shell) routingStaticSection(cfg client.RoutingConfig) fyne.CanvasObject {
	add := plainBtn("Add route", func() {
		dest := entryVal("", "10.0.0.0/24 or default")
		nh := entryVal("", "gateway IP")
		sh.showForm("Add static route", "Add", []*widget.FormItem{
			widget.NewFormItem("Destination", dest), widget.NewFormItem("Next hop", nh),
		}, func() error {
			return sh.app.client.AddStaticRoute(strings.TrimSpace(dest.Text), strings.TrimSpace(nh.Text))
		})
	})
	var rows [][]fyne.CanvasObject
	for i, r := range cfg.Static {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellMono(r.Dest), cellMono(r.NextHop),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteStaticRoute(i) }, sh.reloadActive) })})
	}
	return subSection("Static routes", add, dataTable([]string{"Destination", "Next hop", ""}, []float32{3, 3, 1.6}, rows, "No static routes."))
}

func (sh *shell) routingPrefixSection(cfg client.RoutingConfig) fyne.CanvasObject {
	add := plainBtn("Add prefix", func() {
		iface := entryVal("", "eth1")
		cidr := entryVal("", "192.168.10.1/24")
		sh.showForm("Add interface prefix", "Add", []*widget.FormItem{
			widget.NewFormItem("Interface", iface), widget.NewFormItem("CIDR", cidr),
		}, func() error {
			return sh.app.client.AddIfPrefix(strings.TrimSpace(iface.Text), strings.TrimSpace(cidr.Text))
		})
	})
	var rows [][]fyne.CanvasObject
	for i, p := range cfg.Prefixes {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellMono(p.Iface), cellMono(p.CIDR),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteIfPrefix(i) }, sh.reloadActive) })})
	}
	return subSection("Interface prefixes (transit IPs)", add, dataTable([]string{"Interface", "CIDR", ""}, []float32{3, 3, 1.6}, rows, "No interface prefixes."))
}

func (sh *shell) routingFirewallSection(cfg client.RoutingConfig) fyne.CanvasObject {
	add := plainBtn("Add rule", func() {
		action := selectWith([]string{"accept", "drop"}, "accept")
		proto := selectWith([]string{"any", "tcp", "udp"}, "any")
		dport := entryVal("", "e.g. 22 (blank = any)")
		source := entryVal("", "CIDR (blank = any)")
		sh.showForm("Add edge firewall rule", "Add", []*widget.FormItem{
			widget.NewFormItem("Action", action), widget.NewFormItem("Proto", proto),
			widget.NewFormItem("Dest port", dport), widget.NewFormItem("Source", source),
		}, func() error {
			pr := proto.Selected
			if pr == "any" {
				pr = ""
			}
			return sh.app.client.AddRoutingFirewallRule(action.Selected, pr, strings.TrimSpace(dport.Text), strings.TrimSpace(source.Text))
		})
	})
	var rows [][]fyne.CanvasObject
	for i, r := range cfg.Firewall {
		i := i
		proto := r.Proto
		if proto == "" {
			proto = "any"
		}
		rows = append(rows, []fyne.CanvasObject{cell(r.Action), cell(proto), cell(orDash(r.DPort)), cellMono(orDash(r.Source)),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteRoutingFirewallRule(i) }, sh.reloadActive) })})
	}
	return subSection("Edge firewall", add, dataTable([]string{"Action", "Proto", "Port", "Source", ""}, []float32{1.4, 1.2, 1.2, 2.4, 1.6}, rows, "No edge firewall rules."))
}

func (sh *shell) routingOSPFSection(cfg client.RoutingConfig) fyne.CanvasObject {
	edit := plainBtn("Configure", func() {
		en := widget.NewCheck("Enabled", nil)
		en.SetChecked(cfg.OSPF.Enabled)
		rid := entryVal(cfg.OSPF.RouterID, "router-id (optional)")
		sh.showForm("OSPF", "Save", []*widget.FormItem{
			widget.NewFormItem("", en), widget.NewFormItem("Router ID", rid),
		}, func() error { return sh.app.client.SetOSPF(en.Checked, strings.TrimSpace(rid.Text)) })
	})
	addNet := plainBtn("Add network", func() {
		cidr := entryVal("", "10.0.0.0/24")
		area := entryVal("0", "area")
		sh.showForm("Add OSPF network", "Add", []*widget.FormItem{
			widget.NewFormItem("CIDR", cidr), widget.NewFormItem("Area", area),
		}, func() error {
			return sh.app.client.AddOSPFNetwork(strings.TrimSpace(cidr.Text), strings.TrimSpace(area.Text))
		})
	})
	var rows [][]fyne.CanvasObject
	for i, n := range cfg.OSPF.Networks {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellMono(n.CIDR), cell(n.Area),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteOSPFNetwork(i) }, sh.reloadActive) })})
	}
	head := container.NewThemeOverride(container.NewHBox(protoState("OSPF", cfg.OSPF.Enabled), layoutExpand(), edit, addNet), compactTheme{})
	return subSection("OSPF", nil, container.NewVBox(head, spacer(6), dataTable([]string{"Network", "Area", ""}, []float32{3, 2, 1.6}, rows, "No OSPF networks.")))
}

func (sh *shell) routingBGPSection(cfg client.RoutingConfig) fyne.CanvasObject {
	edit := plainBtn("Configure", func() {
		en := widget.NewCheck("Enabled", nil)
		en.SetChecked(cfg.BGP.Enabled)
		asn := entryVal(itoa(cfg.BGP.ASN), "local ASN")
		rid := entryVal(cfg.BGP.RouterID, "router-id (optional)")
		sh.showForm("BGP", "Save", []*widget.FormItem{
			widget.NewFormItem("", en), widget.NewFormItem("ASN", asn), widget.NewFormItem("Router ID", rid),
		}, func() error {
			return sh.app.client.SetBGP(en.Checked, atoiDefault(asn.Text, 0), strings.TrimSpace(rid.Text))
		})
	})
	addN := plainBtn("Add neighbor", func() {
		addr := entryVal("", "peer IP")
		ras := entryVal("", "remote ASN")
		sh.showForm("Add BGP neighbor", "Add", []*widget.FormItem{
			widget.NewFormItem("Address", addr), widget.NewFormItem("Remote AS", ras),
		}, func() error {
			return sh.app.client.AddBGPNeighbor(client.BGPNeighbor{Addr: strings.TrimSpace(addr.Text), RemoteAS: atoiDefault(ras.Text, 0)})
		})
	})
	addNet := plainBtn("Advertise network", func() {
		cidr := entryVal("", "10.0.0.0/24")
		sh.showForm("Advertise BGP network", "Add", []*widget.FormItem{widget.NewFormItem("CIDR", cidr)},
			func() error { return sh.app.client.AddBGPNetwork(strings.TrimSpace(cidr.Text)) })
	})
	var nrows [][]fyne.CanvasObject
	for i, n := range cfg.BGP.Neighbors {
		i := i
		nrows = append(nrows, []fyne.CanvasObject{cellMono(n.Addr), cell(itoa(n.RemoteAS)),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteBGPNeighbor(i) }, sh.reloadActive) })})
	}
	var wrows [][]fyne.CanvasObject
	for i, c := range cfg.BGP.Networks {
		i := i
		wrows = append(wrows, []fyne.CanvasObject{cellMono(c),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteBGPNetwork(i) }, sh.reloadActive) })})
	}
	head := container.NewThemeOverride(container.NewHBox(protoState("BGP AS"+itoa(cfg.BGP.ASN), cfg.BGP.Enabled), layoutExpand(), edit, addN, addNet), compactTheme{})
	return subSection("BGP", nil, container.NewVBox(
		head, spacer(6),
		dataTable([]string{"Neighbor", "Remote AS", ""}, []float32{3, 2, 1.6}, nrows, "No neighbors."),
		spacer(8),
		dataTable([]string{"Advertised network", ""}, []float32{5, 1.6}, wrows, "No advertised networks."),
	))
}

func (sh *shell) routingEIGRPSection(cfg client.RoutingConfig) fyne.CanvasObject {
	edit := plainBtn("Configure", func() {
		en := widget.NewCheck("Enabled", nil)
		en.SetChecked(cfg.EIGRP.Enabled)
		asn := entryVal(itoa(cfg.EIGRP.ASN), "ASN 1-65535")
		rid := entryVal(cfg.EIGRP.RouterID, "router-id (optional)")
		sh.showForm("EIGRP", "Save", []*widget.FormItem{
			widget.NewFormItem("", en), widget.NewFormItem("ASN", asn), widget.NewFormItem("Router ID", rid),
		}, func() error {
			return sh.app.client.SetEIGRP(en.Checked, atoiDefault(asn.Text, 0), strings.TrimSpace(rid.Text))
		})
	})
	addNet := plainBtn("Add network", func() {
		cidr := entryVal("", "10.0.0.0/24")
		sh.showForm("Add EIGRP network", "Add", []*widget.FormItem{widget.NewFormItem("CIDR", cidr)},
			func() error { return sh.app.client.AddEIGRPNetwork(strings.TrimSpace(cidr.Text)) })
	})
	var rows [][]fyne.CanvasObject
	for i, c := range cfg.EIGRP.Networks {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellMono(c),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteEIGRPNetwork(i) }, sh.reloadActive) })})
	}
	head := container.NewThemeOverride(container.NewHBox(protoState("EIGRP AS"+itoa(cfg.EIGRP.ASN), cfg.EIGRP.Enabled), layoutExpand(), edit, addNet), compactTheme{})
	return subSection("EIGRP", nil, container.NewVBox(head, spacer(6), dataTable([]string{"Network", ""}, []float32{5, 1.6}, rows, "No EIGRP networks.")))
}

func (sh *shell) routingPrefixListSection(cfg client.RoutingConfig) fyne.CanvasObject {
	add := plainBtn("Add entry", func() {
		name := entryVal("", "list name")
		seq := entryVal("", "seq")
		action := selectWith([]string{"permit", "deny"}, "permit")
		prefix := entryVal("", "CIDR or any")
		ge := entryVal("", "ge (0=unset)")
		le := entryVal("", "le (0=unset)")
		sh.showForm("Add prefix-list entry", "Add", []*widget.FormItem{
			widget.NewFormItem("Name", name), widget.NewFormItem("Seq", seq), widget.NewFormItem("Action", action),
			widget.NewFormItem("Prefix", prefix), widget.NewFormItem("ge", ge), widget.NewFormItem("le", le),
		}, func() error {
			return sh.app.client.AddPrefixList(client.PrefixList{
				Name: strings.TrimSpace(name.Text), Seq: atoiDefault(seq.Text, 0), Action: action.Selected,
				Prefix: strings.TrimSpace(prefix.Text), Ge: atoiDefault(ge.Text, 0), Le: atoiDefault(le.Text, 0),
			})
		})
	})
	var rows [][]fyne.CanvasObject
	for i, p := range cfg.PrefixLists {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellBold(p.Name), cell(itoa(p.Seq)), cell(p.Action), cellMono(p.Prefix),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeletePrefixList(i) }, sh.reloadActive) })})
	}
	return subSection("Prefix lists", add, dataTable([]string{"Name", "Seq", "Action", "Prefix", ""}, []float32{2, 1, 1.4, 2.4, 1.6}, rows, "No prefix lists."))
}

func (sh *shell) routingRouteMapSection(cfg client.RoutingConfig) fyne.CanvasObject {
	add := plainBtn("Add clause", func() {
		name := entryVal("", "map name")
		seq := entryVal("", "seq")
		action := selectWith([]string{"permit", "deny"}, "permit")
		match := entryVal("", "match prefix-list")
		metric := entryVal("", "set metric (0=unset)")
		lp := entryVal("", "set local-pref (0=unset)")
		sh.showForm("Add route-map clause", "Add", []*widget.FormItem{
			widget.NewFormItem("Name", name), widget.NewFormItem("Seq", seq), widget.NewFormItem("Action", action),
			widget.NewFormItem("Match prefix-list", match), widget.NewFormItem("Set metric", metric), widget.NewFormItem("Set local-pref", lp),
		}, func() error {
			return sh.app.client.AddRouteMap(client.RouteMapClause{
				Name: strings.TrimSpace(name.Text), Seq: atoiDefault(seq.Text, 0), Action: action.Selected,
				MatchPrefixList: strings.TrimSpace(match.Text), SetMetric: atoiDefault(metric.Text, 0), SetLocalPref: atoiDefault(lp.Text, 0),
			})
		})
	})
	var rows [][]fyne.CanvasObject
	for i, m := range cfg.RouteMaps {
		i := i
		rows = append(rows, []fyne.CanvasObject{cellBold(m.Name), cell(itoa(m.Seq)), cell(m.Action), cellMono(m.MatchPrefixList),
			idxDelete(func() { sh.do(func() error { return sh.app.client.DeleteRouteMap(i) }, sh.reloadActive) })})
	}
	return subSection("Route maps", add, dataTable([]string{"Name", "Seq", "Action", "Match", ""}, []float32{2, 1, 1.4, 2.4, 1.6}, rows, "No route maps."))
}

func protoState(label string, enabled bool) fyne.CanvasObject {
	st := "stopped"
	if enabled {
		st = "running"
	}
	return container.NewHBox(boldText(label, 14), hSpace(8), pill(stateWord(enabled), st))
}

func stateWord(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "any"
	}
	return s
}
