package ui

import (
	"fmt"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// newVMDialog fetches the available base images, then presents a create-VM form
// that posts to /api/v1/sessions — the desktop mirror of the web "New instance"
// modal (core fields; advanced hardware knobs stay on the web form for now).
func (sh *shell) newVMDialog() {
	go func() {
		imgs, err := sh.app.client.Images()
		fyne.Do(func() {
			if err != nil {
				sh.fail(err)
				return
			}
			sh.showCreateForm(imgs)
		})
	}()
}

func (sh *shell) showCreateForm(imgs []client.Image) {
	name := widget.NewEntry()
	name.SetPlaceHolder("my-vm")

	var imgNames []string
	for _, im := range imgs {
		label := im.Name
		if im.Status != "" && !strings.EqualFold(im.Status, "ready") {
			label = im.Name + "  (" + im.Status + ")"
		}
		imgNames = append(imgNames, label)
	}
	image := widget.NewSelect(uniqueLabels(imgNames), nil)
	if len(imgNames) > 0 {
		image.SetSelectedIndex(0)
	}

	cpus := widget.NewEntry()
	cpus.SetText("2")
	mem := widget.NewEntry()
	mem.SetText("2048")
	disk := widget.NewEntry()
	disk.SetPlaceHolder("0 = image default")

	firmware := widget.NewSelect([]string{"uefi", "bios"}, nil)
	firmware.SetSelected("uefi")

	cloud := widget.NewCheck("Enable cloud-init (set login below)", nil)
	cloud.SetChecked(true)
	ciUser := widget.NewEntry()
	ciUser.SetPlaceHolder("username (optional)")
	ciPass := widget.NewPasswordEntry()
	ciPass.SetPlaceHolder("password (optional)")

	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Image", image),
		widget.NewFormItem("vCPUs", cpus),
		widget.NewFormItem("Memory (MB)", mem),
		widget.NewFormItem("Disk (GB)", disk),
		widget.NewFormItem("Firmware", firmware),
		widget.NewFormItem("Cloud-init", cloud),
		widget.NewFormItem("CI user", ciUser),
		widget.NewFormItem("CI password", ciPass),
	}

	sh.showForm("New instance", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return fmt.Errorf("name is required")
		}
		idx := image.SelectedIndex()
		if idx < 0 || idx >= len(imgs) {
			return fmt.Errorf("select an image")
		}
		ci := cloud.Checked
		in := client.CreateVMInput{
			Name:       strings.TrimSpace(name.Text),
			Image:      imgs[idx].Name,
			Firmware:   firmware.Selected,
			CPUs:       atoiDefault(cpus.Text, 2),
			MemoryMB:   atoiDefault(mem.Text, 2048),
			DiskGB:     atoiDefault(disk.Text, 0),
			CloudInit:  &ci,
			CIUsername: strings.TrimSpace(ciUser.Text),
			CIPassword: ciPass.Text,
		}
		return sh.app.client.CreateVM(in)
	})
}

func atoiDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
