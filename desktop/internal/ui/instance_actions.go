package ui

import (
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// This file holds the per-VM management dialogs reached from the Overview tab's
// "Manage" card: hardware profile, NIC rebind, snapshots, installer media, and
// the autostart toggle. They mirror the web instance page's controls.

func selectWith(options []string, current string) *widget.Select {
	s := widget.NewSelect(options, nil)
	if current != "" {
		for _, o := range options {
			if strings.EqualFold(o, current) {
				s.SetSelected(o)
				break
			}
		}
	}
	if s.Selected == "" && len(options) > 0 {
		s.SetSelected(options[0])
	}
	return s
}

// specDialog edits a stopped VM's hardware profile. The form is pre-filled from
// the VM's current values so saving never silently resets an unshown field.
func (sh *shell) specDialog(s client.Session) {
	firmware := selectWith([]string{"uefi", "bios"}, s.Firmware)
	osType := selectWith([]string{"linux", "windows"}, s.OSType)
	machine := selectWith([]string{"q35", "pc"}, s.MachineType)
	diskBus := selectWith([]string{"virtio-blk", "virtio-scsi", "sata"}, s.DiskBus)
	nic := selectWith([]string{"virtio", "e1000e", "rtl8139"}, s.NICModel)
	vga := selectWith([]string{"qxl", "virtio", "std"}, s.VGA)

	guestAgent := widget.NewCheck("", nil)
	guestAgent.SetChecked(s.GuestAgent)
	tpm := widget.NewCheck("", nil)
	tpm.SetChecked(s.TPM)
	secure := widget.NewCheck("", nil)
	secure.SetChecked(s.SecureBoot)
	pin := widget.NewCheck("", nil)
	pin.SetChecked(s.PinCPUs)
	huge := widget.NewCheck("", nil)
	huge.SetChecked(s.HugePages)

	items := []*widget.FormItem{
		widget.NewFormItem("Firmware", firmware),
		widget.NewFormItem("OS type", osType),
		widget.NewFormItem("Machine", machine),
		widget.NewFormItem("Disk bus", diskBus),
		widget.NewFormItem("NIC model", nic),
		widget.NewFormItem("VGA", vga),
		widget.NewFormItem("Guest agent", guestAgent),
		widget.NewFormItem("TPM 2.0", tpm),
		widget.NewFormItem("Secure Boot", secure),
		widget.NewFormItem("Pin vCPUs", pin),
		widget.NewFormItem("Hugepages", huge),
	}
	sh.showForm("Edit hardware — "+s.Name, "Save", items, func() error {
		return sh.app.client.UpdateSpec(s.ID, client.HardwareSpec{
			Firmware:    firmware.Selected,
			OSType:      osType.Selected,
			MachineType: machine.Selected,
			DiskBus:     diskBus.Selected,
			NICModel:    nic.Selected,
			VGA:         vga.Selected,
			GuestAgent:  guestAgent.Checked,
			TPM:         tpm.Checked,
			SecureBoot:  secure.Checked,
			PinCPUs:     pin.Checked,
			HugePages:   huge.Checked,
		})
	})
}

// networkDialog rebinds a VM's NIC to a port group id (0 = default/NAT). A full
// network picker arrives with the Networks page.
func (sh *shell) networkDialog(s client.Session) {
	netID := widget.NewEntry()
	netID.SetText(strconv.FormatInt(s.NetworkID, 10))
	items := []*widget.FormItem{
		widget.NewFormItem("Network ID", netID),
	}
	sh.showForm("Change network — "+s.Name, "Apply", items, func() error {
		n, err := strconv.ParseInt(strings.TrimSpace(netID.Text), 10, 64)
		if err != nil {
			return fmt.Errorf("network id must be a number (0 = default/NAT)")
		}
		return sh.app.client.SetNetwork(s.ID, n)
	})
}

// toggleAutostart flips the start-at-boot flag.
func (sh *shell) toggleAutostart(s client.Session) {
	sh.do(func() error { return sh.app.client.SetAutostart(s.ID, !s.Autostart) }, sh.reloadActive)
}

// mediaDialog manages the installer ISO and the virtio-win driver CD.
func (sh *shell) mediaDialog(s client.Session) {
	var d dialog.Dialog
	act := func(fn func() error) func() {
		return func() {
			if d != nil {
				d.Hide()
			}
			sh.do(fn, sh.reloadActive)
		}
	}
	body := container.NewVBox(
		mutedPara("Media changes apply on the VM's next start."),
		spacer(6),
		plainBtn("Eject boot/installer ISO", act(func() error { return sh.app.client.EjectISO(s.ID) })),
		plainBtn("Attach virtio-win driver CD", act(func() error { return sh.app.client.MountVirtio(s.ID) })),
		plainBtn("Eject virtio-win driver CD", act(func() error { return sh.app.client.EjectVirtio(s.ID) })),
	)
	d = dialog.NewCustom("Media — "+s.Name, "Close", body, sh.win)
	d.Resize(fyne.NewSize(420, 0))
	d.Show()
}

// snapshotsDialog lists snapshots with create/revert/delete, re-fetching after
// each change.
func (sh *shell) snapshotsDialog(s client.Session) {
	content := container.NewVBox()
	var reload func()
	reload = func() {
		content.Objects = []fyne.CanvasObject{mutedText("Loading…", 12)}
		content.Refresh()
		go func() {
			snaps, err := sh.app.client.Snapshots(s.ID)
			fyne.Do(func() {
				content.Objects = []fyne.CanvasObject{sh.snapshotBody(s, snaps, err, reload)}
				content.Refresh()
			})
		}()
	}
	reload()
	d := dialog.NewCustom("Snapshots — "+s.Name, "Close", content, sh.win)
	d.Resize(fyne.NewSize(560, 440))
	d.Show()
}

func (sh *shell) snapshotBody(s client.Session, snaps []client.Snapshot, err error, reload func()) fyne.CanvasObject {
	name := widget.NewEntry()
	name.SetPlaceHolder("snapshot name")
	create := primaryBtn("Take snapshot", func() {
		if strings.TrimSpace(name.Text) == "" {
			return
		}
		sh.do(func() error { return sh.app.client.CreateSnapshot(s.ID, strings.TrimSpace(name.Text)) }, reload)
	})
	top := container.NewBorder(nil, nil, nil, create, name)

	if err != nil {
		return container.NewVBox(top, spacer(8), mutedPara("Could not load snapshots: "+err.Error()))
	}

	var rows [][]fyne.CanvasObject
	for _, sn := range snaps {
		sn := sn
		state := "offline"
		if sn.Online {
			state = "online"
		}
		revert := plainBtn("Revert", func() {
			sh.confirm("Revert snapshot", "Roll \""+s.Name+"\" back to \""+sn.Name+"\"? Current state is lost.", func() {
				sh.do(func() error { return sh.app.client.RevertSnapshot(s.ID, sn.ID) }, reload)
			})
		})
		del := dangerBtn("Delete", func() {
			sh.confirm("Delete snapshot", "Delete snapshot \""+sn.Name+"\"?", func() {
				sh.do(func() error { return sh.app.client.DeleteSnapshot(s.ID, sn.ID) }, reload)
			})
		})
		rows = append(rows, []fyne.CanvasObject{
			cellBold(sn.Name),
			cell(shortTime(sn.CreatedAt)),
			cellState(state),
			rowActions(revert, del),
		})
	}
	table := dataTable(
		[]string{"Name", "Created", "State", ""},
		[]float32{3, 2.4, 1.4, 3},
		rows, "No snapshots yet.")
	return container.NewVBox(top, spacer(10), table)
}
