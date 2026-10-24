package ui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// dashboard is the Overview tab: fleet summary, the selected VM's live detail
// and power controls, and the org's usage. It only renders data the server
// actually exposes — no invented charts.
type dashboard struct {
	sh    *shell
	root  *container.Scroll
	body  *fyne.Container
	usage *client.Usage

	guestCache map[string]*client.GuestInfo
	guestWait  map[string]bool
}

func newDashboard(sh *shell) *dashboard {
	d := &dashboard{
		sh:         sh,
		body:       container.NewVBox(),
		guestCache: map[string]*client.GuestInfo{},
		guestWait:  map[string]bool{},
	}
	d.root = container.NewVScroll(container.NewPadded(d.body))
	return d
}

func (d *dashboard) update(sel *client.Session, vms []client.Session) {
	objs := []fyne.CanvasObject{
		d.heroSection(sel),
		spacer(8),
		d.fleetSection(vms),
		spacer(8),
	}
	if sel != nil {
		objs = append(objs, d.detailSection(*sel), spacer(8))
	}
	objs = append(objs, d.usageSection())

	d.body.Objects = objs
	d.body.Refresh()
}

// hero: the selected VM's name + state + guest host, and the power controls.
func (d *dashboard) heroSection(sel *client.Session) fyne.CanvasObject {
	if sel == nil {
		title := boldText("No VM selected", 20)
		hint := mutedPara("Pick a virtual machine from the sidebar to see its status, or press Console on any running VM.")
		return card(container.NewVBox(title, spacer(4), hint))
	}

	title := boldText(sel.Name, 22)
	statePill := pill(sel.State, sel.State)

	sub := mutedText(vmTagline(*sel), 12.5)
	head := container.NewVBox(
		container.NewHBox(title, container.NewPadded(statePill)),
		sub,
	)

	// The power controls use a tighter theme (slim pills, small icons) and are
	// centered so they keep their natural size instead of stretching to fill the
	// hero card's height.
	controls := container.NewThemeOverride(container.NewCenter(d.powerBar(*sel)), compactTheme{})
	return card(container.NewBorder(nil, nil, head, controls))
}

func (d *dashboard) powerBar(s client.Session) fyne.CanvasObject {
	running := isRunning(s.State)

	// Text-only primary (like the web "New instance" button) so the label sits
	// centered in the pill — an icon would push "Console" off to the right.
	console := widget.NewButton("Console", func() { d.sh.openConsoleTab(s) })
	console.Importance = widget.HighImportance
	if !running {
		console.Disable()
	}

	start := widget.NewButtonWithIcon("Start", theme.MediaPlayIcon(), func() { d.power(s, "start") })
	stop := widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), func() { d.power(s, "stop") })
	restart := widget.NewButtonWithIcon("Restart", theme.ViewRefreshIcon(), func() { d.power(s, "restart") })
	del := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() { d.confirmDelete(s) })
	del.Importance = widget.DangerImportance

	if running {
		start.Disable()
	} else {
		stop.Disable()
		restart.Disable()
	}

	// All controls on one horizontal plane, with real gaps between them. (The
	// caller vertically centers this row so the buttons keep their natural height
	// instead of being stretched to the full hero-card height.)
	gap := func() fyne.CanvasObject { return hSpace(10) }
	return container.NewHBox(console, gap(), start, gap(), stop, gap(), restart, gap(), del)
}

// fleet: counts + allocation across all VMs, with a running/stopped proportion
// bar (real counts, not a decorative widget).
func (d *dashboard) fleetSection(vms []client.Session) fyne.CanvasObject {
	var running, stopped, vcpu, memMB, diskGB int
	for _, s := range vms {
		if isRunning(s.State) {
			running++
		} else {
			stopped++
		}
		vcpu += s.CPUs
		memMB += s.MemoryMB
		diskGB += s.DiskGB
	}

	strip := container.NewGridWithColumns(5,
		statTile(itoa(len(vms)), "Machines", nil),
		statTile(itoa(running), "Running", colOK),
		statTile(itoa(stopped), "Stopped", colMuted),
		statTile(itoa(vcpu), "vCPU allocated", nil),
		statTile(fmtGB(float64(memMB)/1024)+"B", "RAM allocated", nil),
	)

	legend := container.NewHBox(
		dot("running", 8), mutedText(itoa(running)+" running", 11.5),
		spacer(1),
		dot("stopped", 8), mutedText(itoa(stopped)+" stopped", 11.5),
		spacer(1),
		mutedText(fmtGB(float64(diskGB))+"B disk allocated", 11.5),
	)

	body := container.NewVBox(
		strip,
		spacer(6),
		segBar(running, stopped),
		spacer(4),
		legend,
	)
	return titledCard("Fleet", body)
}

// detail: everything the server knows about the selected VM.
func (d *dashboard) detailSection(s client.Session) fyne.CanvasObject {
	rows := []fyne.CanvasObject{
		kv("State", s.State, false),
		kv("vCPUs", itoa(s.CPUs), false),
		kv("Memory", fmtGB(float64(s.MemoryMB)/1024)+"B  ("+itoa(s.MemoryMB)+" MB)", false),
		kv("Disk", itoa(s.DiskGB)+" GB", false),
	}
	if s.GuestOS != "" {
		rows = append(rows, kv("Guest OS", s.GuestOS, false))
	} else if s.OSType != "" {
		rows = append(rows, kv("OS type", s.OSType, false))
	}
	if s.Kind != "" {
		rows = append(rows, kv("Role", s.Kind, false))
	}
	if s.Display != "" {
		rows = append(rows, kv("Display", s.Display, false))
	}
	if s.MAC != "" {
		rows = append(rows, kv("MAC", s.MAC, true))
	}
	rows = append(rows, kv("Created", shortTime(s.CreatedAt), false))

	// Guest IPs (async, cached).
	ipVal := d.guestLine(s)
	rows = append(rows, kv("IP address", ipVal, true))

	return titledCard("Machine detail", container.NewVBox(rows...))
}

func (d *dashboard) guestLine(s client.Session) string {
	if !isRunning(s.State) {
		return "—"
	}
	if gi, ok := d.guestCache[s.ID]; ok {
		if gi != nil && len(gi.Addresses) > 0 {
			return strings.Join(gi.Addresses, ", ")
		}
		return "(no guest agent)"
	}
	if !d.guestWait[s.ID] {
		d.guestWait[s.ID] = true
		go func(id string) {
			gi, err := d.sh.app.client.GuestInfo(id)
			fyne.Do(func() {
				if err != nil {
					d.guestCache[id] = nil
				} else {
					d.guestCache[id] = gi
				}
				d.guestWait[id] = false
				if cur, ok := d.sh.current(); ok && cur.ID == id {
					d.sh.refreshDash()
				}
			})
		}(s.ID)
	}
	return "resolving…"
}

func (d *dashboard) usageSection() fyne.CanvasObject {
	if d.usage == nil {
		return titledCard("Usage", mutedText("Usage data unavailable.", 12))
	}
	u := d.usage
	window := itoa(u.Days) + "-day window"
	strip := container.NewGridWithColumns(4,
		statTile(fmt.Sprintf("%.0f", u.InstanceHours), "Instance-hours", nil),
		statTile(fmt.Sprintf("%.0f", float64(u.VCPUSeconds)/3600), "vCPU-hours", nil),
		statTile(fmt.Sprintf("%.0f", float64(u.MemMBSeconds)/3600/1024), "GB-hours RAM", nil),
		statTile(fmt.Sprintf("%.2f", u.CostCredits), "Credits", colAccent),
	)
	return titledCard("Usage · "+window, strip)
}

// --- actions ---------------------------------------------------------------

func (d *dashboard) power(s client.Session, action string) {
	d.sh.toast(title(action) + "ing " + s.Name + "…")
	go func() {
		var err error
		switch action {
		case "start":
			err = d.sh.app.client.Start(s.ID)
		case "stop":
			err = d.sh.app.client.Stop(s.ID)
		case "restart":
			err = d.sh.app.client.Restart(s.ID)
		}
		fyne.Do(func() {
			if err != nil {
				d.sh.toast(err.Error())
			} else {
				d.sh.toast(s.Name + ": " + action + " requested.")
			}
			d.sh.reload(false)
		})
	}()
}

func (d *dashboard) confirmDelete(s client.Session) {
	dialog.ShowConfirm("Delete VM",
		"Move \""+s.Name+"\" to trash? A running VM is stopped first.",
		func(yes bool) {
			if !yes {
				return
			}
			go func() {
				err := d.sh.app.client.Delete(s.ID)
				fyne.Do(func() {
					if err != nil {
						d.sh.toast(err.Error())
					} else {
						d.sh.toast(s.Name + " deleted.")
						d.sh.selID = ""
					}
					d.sh.reload(false)
				})
			}()
		}, d.sh.win)
}

// --- formatting ------------------------------------------------------------

func vmTagline(s client.Session) string {
	parts := []string{itoa(s.CPUs) + " vCPU", fmtGB(float64(s.MemoryMB)/1024) + "B RAM", itoa(s.DiskGB) + " GB disk"}
	if s.GuestOS != "" {
		parts = append(parts, s.GuestOS)
	}
	return strings.Join(parts, "  ·  ")
}

func fmtGB(gb float64) string {
	if gb == 0 {
		return "0 G"
	}
	if gb < 10 {
		return fmt.Sprintf("%.1f G", gb)
	}
	return fmt.Sprintf("%.0f G", gb)
}

func shortTime(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	if s == "" {
		return "—"
	}
	return s
}
