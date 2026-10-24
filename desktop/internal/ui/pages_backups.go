package ui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-2 Backups page: backups, schedules, and backup targets (mirrors web
// /backups).

func (sh *shell) backupsPage() fyne.CanvasObject {
	backupNow := primaryBtn("Back up now", func() { sh.backupNowDialog() })
	return sh.listPage("backups", "Backups", backupNow, func() (fyne.CanvasObject, error) {
		backups, err := sh.app.client.Backups()
		if err != nil {
			return nil, err
		}
		scheds, _ := sh.app.client.BackupSchedules()
		targets, _ := sh.app.client.BackupTargets()

		var brows [][]fyne.CanvasObject
		for _, b := range backups {
			b := b
			restore := plainBtn("Restore", func() {
				sh.confirm("Restore backup", "Restore \""+b.Name+"\" as a new base image?", func() {
					sh.do(func() error { _, e := sh.app.client.RestoreBackup(b.ID); return e }, sh.reloadActive)
				})
			})
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete backup", "Delete backup \""+b.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteBackup(b.ID) }, sh.reloadActive)
				})
			})
			size := "—"
			if b.SizeBytes > 0 {
				size = humanBytes(b.SizeBytes)
			}
			brows = append(brows, []fyne.CanvasObject{
				cellBold(b.Name), cell(sh.vmByID(b.SessionID).Name), cell(size), cellState(b.Status), rowActions(restore, del),
			})
		}
		backupsTable := dataTable([]string{"Name", "Instance", "Size", "Status", ""},
			[]float32{2.4, 2, 1.4, 1.4, 2}, brows, "No backups yet.")

		var srows [][]fyne.CanvasObject
		for _, s := range scheds {
			s := s
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete schedule", "Delete this schedule?", func() {
					sh.do(func() error { return sh.app.client.DeleteSchedule(s.ID) }, sh.reloadActive)
				})
			})
			srows = append(srows, []fyne.CanvasObject{
				cellBold(sh.vmByID(s.SessionID).Name),
				cell("every " + itoa(s.IntervalHours) + "h, keep " + itoa(s.Keep)),
				cell(shortTime(s.NextRunAt)),
				rowActions(del),
			})
		}
		schedTable := dataTable([]string{"Instance", "Policy", "Next run", ""},
			[]float32{2.4, 2.6, 2, 1.6}, srows, "No schedules.")

		var trows [][]fyne.CanvasObject
		for _, t := range targets {
			t := t
			test := plainBtn("Test", func() {
				var msg string
				sh.do(func() error {
					m, e := sh.app.client.TestBackupTarget(t.ID)
					msg = m
					return e
				}, func() { sh.toast(msg) }) // toast runs in fyne.Do
			})
			del := dangerBtn("Delete", func() {
				sh.confirm("Delete target", "Delete target \""+t.Name+"\"?", func() {
					sh.do(func() error { return sh.app.client.DeleteBackupTarget(t.ID) }, sh.reloadActive)
				})
			})
			mounted := "no"
			if t.Mounted {
				mounted = "yes"
			}
			acts := rowActions(test, del)
			if t.ID == 0 { // built-in local default: no delete
				acts = rowActions(test)
			}
			trows = append(trows, []fyne.CanvasObject{
				cellBold(t.Name), cell(t.Kind), cellMono(t.Path), cell(mounted), acts,
			})
		}
		targetTable := dataTable([]string{"Name", "Kind", "Path", "Mounted", ""},
			[]float32{2, 1.2, 3, 1.2, 2}, trows, "Only the local default target.")

		return container.NewVBox(
			backupsTable,
			spacer(16), subSection("Schedules", plainBtn("Add schedule", func() { sh.scheduleDialog() }), schedTable),
			spacer(16), subSection("Targets", plainBtn("Add target", func() { sh.targetDialog() }), targetTable),
		), nil
	})
}

// sessionSelect builds a VM picker returning the parallel id slice.
func (sh *shell) sessionSelect() (*widget.Select, []string) {
	var names, ids []string
	for _, v := range sh.vms {
		names = append(names, v.Name)
		ids = append(ids, v.ID)
	}
	sel := widget.NewSelect(uniqueLabels(names), nil)
	if len(names) > 0 {
		sel.SetSelectedIndex(0)
	}
	return sel, ids
}

func targetSelect(ts []client.BackupTarget) (*widget.Select, []int64) {
	names := []string{"Local default"}
	ids := []int64{0}
	for _, t := range ts {
		if t.ID == 0 {
			continue
		}
		names = append(names, t.Name)
		ids = append(ids, t.ID)
	}
	sel := widget.NewSelect(names, nil)
	sel.SetSelectedIndex(0)
	return sel, ids
}

func (sh *shell) backupNowDialog() {
	go func() {
		ts, _ := sh.app.client.BackupTargets()
		fyne.Do(func() {
			sess, ids := sh.sessionSelect()
			if len(ids) == 0 {
				sh.fail(errReq("no instances to back up"))
				return
			}
			name := widget.NewEntry()
			name.SetPlaceHolder("manual")
			tgt, tids := targetSelect(ts)
			items := []*widget.FormItem{
				widget.NewFormItem("Instance", sess),
				widget.NewFormItem("Name", name),
				widget.NewFormItem("Target", tgt),
			}
			sh.showForm("Back up now", "Back up", items, func() error {
				si := sess.SelectedIndex()
				if si < 0 || si >= len(ids) {
					return errReq("select an instance")
				}
				return sh.app.client.CreateBackup(ids[si], strings.TrimSpace(name.Text), pickID(tids, tgt.SelectedIndex()))
			})
		})
	}()
}

func (sh *shell) scheduleDialog() {
	go func() {
		ts, _ := sh.app.client.BackupTargets()
		fyne.Do(func() {
			sess, ids := sh.sessionSelect()
			if len(ids) == 0 {
				sh.fail(errReq("no instances to schedule"))
				return
			}
			interval := widget.NewEntry()
			interval.SetText("24")
			keep := widget.NewEntry()
			keep.SetText("7")
			tgt, tids := targetSelect(ts)
			items := []*widget.FormItem{
				widget.NewFormItem("Instance", sess),
				widget.NewFormItem("Interval (hours)", interval),
				widget.NewFormItem("Keep", keep),
				widget.NewFormItem("Target", tgt),
			}
			sh.showForm("New backup schedule", "Create", items, func() error {
				si := sess.SelectedIndex()
				if si < 0 || si >= len(ids) {
					return errReq("select an instance")
				}
				return sh.app.client.CreateSchedule(ids[si], atoiDefault(interval.Text, 24), atoiDefault(keep.Text, 7), pickID(tids, tgt.SelectedIndex()))
			})
		})
	}()
}

func (sh *shell) targetDialog() {
	name := widget.NewEntry()
	kind := selectWith([]string{"nfs", "cifs", "dir"}, "nfs")
	path := widget.NewEntry()
	path.SetPlaceHolder("mountpoint or local dir")
	server := widget.NewEntry()
	share := widget.NewEntry()
	user := widget.NewEntry()
	pass := widget.NewPasswordEntry()
	domain := widget.NewEntry()
	vers := widget.NewEntry()
	opts := widget.NewEntry()
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Kind", kind),
		widget.NewFormItem("Path", path),
		widget.NewFormItem("Server", server),
		widget.NewFormItem("Share", share),
		widget.NewFormItem("Username", user),
		widget.NewFormItem("Password", pass),
		widget.NewFormItem("Domain", domain),
		widget.NewFormItem("Version", vers),
		widget.NewFormItem("Options", opts),
	}
	sh.showForm("Add backup target", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" {
			return errReq("name is required")
		}
		return sh.app.client.CreateBackupTarget(name.Text, kind.Selected, path.Text,
			server.Text, share.Text, user.Text, pass.Text, domain.Text, vers.Text, opts.Text)
	})
}

func pickID(ids []int64, idx int) int64 {
	if idx < 0 || idx >= len(ids) {
		return 0
	}
	return ids[idx]
}
