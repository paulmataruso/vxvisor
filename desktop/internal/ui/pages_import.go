package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-4 Import / Export page: connect to vCenter/ESXi, import a VM, and watch
// import/export job progress. (The batch "Plan Migration" wizard stays on web.)

func (sh *shell) importPage() fyne.CanvasObject {
	connect := primaryBtn("Connect to vCenter/ESXi", func() { sh.vmwareConnectDialog() })
	return sh.listPage("import", "Import / Export", connect, func() (fyne.CanvasObject, error) {
		imp, _ := sh.app.client.ImportStatus()
		exp, _ := sh.app.client.ExportStatus()

		var irows [][]fyne.CanvasObject
		for _, j := range imp {
			irows = append(irows, []fyne.CanvasObject{
				cellBold(j.VMName), cellState(j.Status), cell(j.Step), cell(itoa(j.Pct) + "%"), cell(j.Err),
			})
		}
		importTable := dataTable([]string{"VM", "Status", "Step", "Progress", "Error"},
			[]float32{2, 1.4, 2, 1, 2.4}, irows, "No imports in progress.")

		var erows [][]fyne.CanvasObject
		for _, j := range exp {
			erows = append(erows, []fyne.CanvasObject{
				cellBold(j.VMName), cell(j.Target), cellState(j.Status), cell(j.Step), cell(j.Err),
			})
		}
		exportTable := dataTable([]string{"VM", "Target", "Status", "Step", "Error"},
			[]float32{2, 1.4, 1.4, 2, 2.4}, erows, "No exports in progress.")

		return container.NewVBox(
			subSection("Imports", plainBtn("Refresh", func() { sh.reloadActive() }), importTable),
			spacer(16),
			subSection("Exports", nil, exportTable),
		), nil
	})
}

func (sh *shell) vmwareConnectDialog() {
	host := widget.NewEntry()
	host.SetPlaceHolder("vcenter.example.com or esxi ip")
	user := widget.NewEntry()
	pass := widget.NewPasswordEntry()
	insecure := widget.NewCheck("Skip TLS verify", nil)
	insecure.SetChecked(true)
	items := []*widget.FormItem{
		widget.NewFormItem("Host", host),
		widget.NewFormItem("Username", user),
		widget.NewFormItem("Password", pass),
		widget.NewFormItem("TLS", insecure),
	}
	d := dialog.NewForm("Connect to vCenter/ESXi", "Connect", "Cancel", items, func(ok bool) {
		if !ok {
			return
		}
		sh.toast("Connecting to " + host.Text + "…")
		go func() {
			vms, err := sh.app.client.VMwareConnect(host.Text, user.Text, pass.Text, insecure.Checked)
			fyne.Do(func() {
				if err != nil {
					sh.fail(err)
					return
				}
				sh.showDiscoveredVMs(host.Text, user.Text, pass.Text, insecure.Checked, vms)
			})
		}()
	}, sh.win)
	d.Resize(fyne.NewSize(480, 0))
	d.Show()
}

func (sh *shell) showDiscoveredVMs(host, user, pass string, insecure bool, vms []client.DiscoveredVM) {
	var rows [][]fyne.CanvasObject
	for _, v := range vms {
		v := v
		var action fyne.CanvasObject
		if v.Importable {
			action = rowActions(primaryBtn("Import", func() {
				sh.importOptionsDialog(host, user, pass, insecure, v)
			}))
		} else {
			action = cell(v.ImportNote)
		}
		rows = append(rows, []fyne.CanvasObject{
			cellBold(v.Name),
			cell(v.GuestFullName),
			cell(itoa(int(v.NumCPU)) + " vCPU · " + itoa(int(v.MemMB)) + " MB"),
			cell(v.PowerState),
			action,
		})
	}
	table := dataTable([]string{"Name", "Guest OS", "Spec", "Power", ""},
		[]float32{2.4, 2.6, 2.2, 1.4, 1.6}, rows, "No VMs found.")
	d := dialog.NewCustom("Discovered VMs — "+host, "Close", container.NewVScroll(table), sh.win)
	d.Resize(fyne.NewSize(760, 520))
	d.Show()
}

func (sh *shell) importOptionsDialog(host, user, pass string, insecure bool, vm client.DiscoveredVM) {
	go func() {
		pools, _ := sh.app.client.Pools()
		fyne.Do(func() {
			osDefault := "linux"
			if strings.Contains(strings.ToLower(vm.GuestFullName), "windows") {
				osDefault = "windows"
			}
			osType := selectWith([]string{"linux", "windows"}, osDefault)
			transport := selectWith([]string{"auto", "nbd", "nfc"}, "auto")
			poolNames := []string{"Default disk dir"}
			poolIDs := []int64{0}
			for _, p := range pools {
				poolNames = append(poolNames, p.Name)
				poolIDs = append(poolIDs, p.ID)
			}
			pool := widget.NewSelect(uniqueLabels(poolNames), nil)
			pool.SetSelectedIndex(0)
			items := []*widget.FormItem{
				widget.NewFormItem("OS type", osType),
				widget.NewFormItem("Transport", transport),
				widget.NewFormItem("Target pool", pool),
			}
			sh.showFormThen("Import "+vm.Name, "Import", items, func() error {
				tr := transport.Selected
				if tr == "auto" {
					tr = ""
				}
				_, err := sh.app.client.StartVMwareImport(host, user, pass, insecure, vm.MOID, osType.Selected, tr, pickID(poolIDs, pool.SelectedIndex()))
				return err
			}, func() {
				sh.toast("Import started for " + vm.Name)
				if sh.activeItem == "import" {
					sh.reloadActive()
				}
			})
		})
	}()
}
