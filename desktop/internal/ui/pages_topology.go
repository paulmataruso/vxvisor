package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// networkMapSection renders the VMware-style network map (vSwitch → port groups
// → VMs, uplinks, host adapters, and vRouters) as nested cards — the native
// equivalent of the web topology diagram. Admin-only (server returns 403 to
// non-admins), so callers guard on sh.isAdmin().
func (sh *shell) networkMapSection() fyne.CanvasObject {
	topo, err := sh.app.client.Topology()
	if err != nil {
		return subSection("Network map", nil, card(container.NewPadded(mutedPara("Topology unavailable: "+err.Error()))))
	}
	var blocks []fyne.CanvasObject
	for _, sw := range topo.Switches {
		blocks = append(blocks, sh.topoSwitchCard(sw), spacer(10))
	}
	if len(topo.Switches) == 0 {
		blocks = append(blocks, card(container.NewPadded(mutedPara("No switches to display."))))
	}
	for _, vr := range topo.VRouters {
		blocks = append(blocks, sh.topoVRouterCard(vr), spacer(10))
	}
	if len(topo.FreeNICs) > 0 {
		var chips []fyne.CanvasObject
		for _, n := range topo.FreeNICs {
			chips = append(chips, topoNicChip(n))
		}
		blocks = append(blocks, subSection("Free uplinks (unused NICs)", nil, chipFlow(chips, 190)))
	}
	return subSection("Network map", nil, container.NewVBox(blocks...))
}

func (sh *shell) topoSwitchCard(sw client.TopoSwitch) fyne.CanvasObject {
	title := "vSwitch " + sw.Name
	if sw.VRouter != "" {
		title = "vRouter " + sw.VRouter + " · " + sw.VRouterRole
	}
	head := container.NewHBox(boldText(title, 15), hSpace(8), pill(sw.Kind, "ok"))
	if sw.VXLAN {
		head.Add(hSpace(6))
		head.Add(pill("vxlan", "connecting"))
	}
	body := container.NewVBox(head)

	// Uplinks (physical NICs / bonds, with link state + LLDP neighbor).
	for _, u := range sw.Uplinks {
		body.Add(topoUplinkRow(u))
	}
	// Host adapters (management vmk boxes).
	for _, k := range sw.VMKs {
		body.Add(container.NewHBox(dotInline("running"), mutedText(k.Label+": "+strings.Join(k.IPs, ", "), 11.5)))
	}

	// Port groups, each an indented box with its VM chips.
	for _, pg := range sw.PortGroups {
		meta := ""
		if pg.VLAN != 0 {
			meta += "VLAN " + itoa(pg.VLAN)
		}
		if pg.CIDR != "" {
			if meta != "" {
				meta += " · "
			}
			meta += pg.CIDR
		}
		pgHead := container.NewHBox(boldText(pg.Name, 13))
		if meta != "" {
			pgHead.Add(hSpace(8))
			pgHead.Add(mutedText(meta, 11))
		}
		var chips []fyne.CanvasObject
		for _, v := range pg.VMs {
			chips = append(chips, topoVMChip(v))
		}
		inner := container.NewVBox(pgHead)
		if len(chips) > 0 {
			inner.Add(chipFlow(chips, 180))
		} else {
			inner.Add(mutedText("(no VMs)", 11))
		}
		pgBG := canvas.NewRectangle(colPanel2)
		pgBG.CornerRadius = 8
		pgBG.StrokeColor = colLine
		pgBG.StrokeWidth = 1
		body.Add(container.NewStack(pgBG, container.New(&insetLayout{10, 8}, inner)))
	}
	return card(body)
}

func (sh *shell) topoVRouterCard(vr client.TopoVRouter) fyne.CanvasObject {
	head := container.NewHBox(boldText("vRouter "+vr.Name, 15))
	if len(vr.Routing) > 0 {
		head.Add(hSpace(8))
		h := "connecting"
		if vr.Health == "up" {
			h = "running"
		} else if vr.Health == "down" {
			h = "error"
		}
		head.Add(pill(strings.Join(vr.Routing, "+"), h))
	}
	if vr.Firewall {
		head.Add(hSpace(6))
		head.Add(pill("firewall", "ok"))
	}
	body := container.NewVBox(head)
	if vr.Transit != nil {
		body.Add(container.NewHBox(dotInline("running"), mutedText("transit "+vr.Transit.Iface+" "+vr.Transit.CIDR, 11.5)))
	}
	for _, in := range vr.Internal {
		line := in.Iface + " " + in.GW
		if in.Subnet != "" {
			line += " (" + in.Subnet + ")"
		}
		lan := container.NewVBox(container.NewHBox(boldText(in.Name, 13), hSpace(8), mutedText(line, 11)))
		var chips []fyne.CanvasObject
		for _, v := range in.VMs {
			chips = append(chips, topoVMChip(v))
		}
		if len(chips) > 0 {
			lan.Add(chipFlow(chips, 180))
		}
		bg := canvas.NewRectangle(colPanel2)
		bg.CornerRadius = 8
		bg.StrokeColor = colLine
		bg.StrokeWidth = 1
		body.Add(container.NewStack(bg, container.New(&insetLayout{10, 8}, lan)))
	}
	return card(body)
}

func topoUplinkRow(u client.TopoUplink) fyne.CanvasObject {
	label := u.Name
	if u.Kind == "bond" {
		label += " (" + u.Mode + ")"
	}
	row := container.NewHBox(dotInline(u.State), mutedText(label, 12))
	if u.Speed > 0 {
		row.Add(mutedText(itoa(u.Speed)+" Mbps", 11))
	}
	if len(u.Neighbors) > 0 && u.Neighbors[0].SwitchName != "" {
		n := u.Neighbors[0]
		row.Add(mutedText("→ "+n.SwitchName+" "+n.PortID, 11))
	}
	return row
}

func topoVMChip(v client.TopoVM) fyne.CanvasObject {
	st := v.State
	if st == "" {
		st = "stopped"
	}
	name := v.Name
	if v.Kind == "container" {
		name = "▣ " + name
	}
	txt := canvas.NewText(name, colFg)
	txt.TextSize = 11.5
	bg := canvas.NewRectangle(colPanel)
	bg.CornerRadius = 8
	bg.StrokeColor = colLine
	bg.StrokeWidth = 1
	row := container.NewBorder(nil, nil, dotInline(st), nil, txt)
	return container.NewStack(bg, container.New(&insetLayout{8, 4}, row))
}

func topoNicChip(n client.TopoNIC) fyne.CanvasObject {
	txt := canvas.NewText(n.Name, colFg)
	txt.TextSize = 11.5
	bg := canvas.NewRectangle(colPanel)
	bg.CornerRadius = 8
	bg.StrokeColor = colLine
	bg.StrokeWidth = 1
	row := container.NewBorder(nil, nil, dotInline(n.State), nil, txt)
	return container.NewStack(bg, container.New(&insetLayout{8, 4}, row))
}

// dotInline is a state dot vertically centered for use beside a text baseline.
func dotInline(state string) fyne.CanvasObject {
	return container.NewCenter(container.NewGridWrap(fyne.NewSize(8, 8), canvas.NewCircle(stateColor(state))))
}

// chipFlow lays chips into a wrapping grid of fixed-width cells.
func chipFlow(chips []fyne.CanvasObject, cellW float32) fyne.CanvasObject {
	return container.NewGridWrap(fyne.NewSize(cellW, 30), chips...)
}
