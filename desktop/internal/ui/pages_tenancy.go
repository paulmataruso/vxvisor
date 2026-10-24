package ui

import (
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-3 tenancy pages: Members, API Keys, Organizations, Audit Log, and
// Usage & Quota. Mirrors the web tenancy pages.

func (sh *shell) membersPage() fyne.CanvasObject {
	add := primaryBtn("Add member", func() { sh.addMemberDialog() })
	return sh.listPage("members", "Members", add, func() (fyne.CanvasObject, error) {
		ms, err := sh.app.client.Members()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, m := range ms {
			m := m
			reset := plainBtn("Reset password", func() { sh.resetPwDialog(m) })
			remove := dangerBtn("Remove", func() {
				sh.confirm("Remove member", "Remove "+m.Username+" from this org?", func() {
					sh.do(func() error { return sh.app.client.RemoveMember(m.UserID) }, sh.reloadActive)
				})
			})
			rows = append(rows, []fyne.CanvasObject{
				cellBold(m.Username),
				cell(m.Role),
				rowActions(reset, remove),
			})
		}
		return dataTable([]string{"User", "Role", ""}, []float32{3, 2, 3}, rows, "No members."), nil
	})
}

func (sh *shell) addMemberDialog() {
	user := widget.NewEntry()
	user.SetPlaceHolder("existing username")
	role := selectWith([]string{"member", "admin", "viewer", "owner"}, "member")
	items := []*widget.FormItem{
		widget.NewFormItem("Username", user),
		widget.NewFormItem("Role", role),
	}
	sh.showForm("Add member", "Add", items, func() error {
		if strings.TrimSpace(user.Text) == "" {
			return errReq("username is required")
		}
		return sh.app.client.AddMember(strings.TrimSpace(user.Text), role.Selected)
	})
}

func (sh *shell) resetPwDialog(m client.Member) {
	pw := widget.NewPasswordEntry()
	pw.SetPlaceHolder("new password (min 4 chars)")
	items := []*widget.FormItem{widget.NewFormItem("Password", pw)}
	sh.showForm("Reset password — "+m.Username, "Set", items, func() error {
		if len(pw.Text) < 4 {
			return errReq("password must be at least 4 characters")
		}
		return sh.app.client.ResetMemberPassword(m.UserID, pw.Text)
	})
}

func (sh *shell) apikeysPage() fyne.CanvasObject {
	create := primaryBtn("Create key", func() { sh.createKeyDialog() })
	return sh.listPage("apikeys", "API Keys", create, func() (fyne.CanvasObject, error) {
		keys, err := sh.app.client.APIKeys()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, k := range keys {
			k := k
			status := "active"
			if k.Revoked {
				status = "revoked"
			}
			revoke := dangerBtn("Revoke", func() {
				sh.confirm("Revoke key", "Revoke API key \""+k.Label+"\"?", func() {
					sh.do(func() error { return sh.app.client.RevokeAPIKey(k.ID) }, sh.reloadActive)
				})
			})
			if k.Revoked {
				revoke.Disable()
			}
			rows = append(rows, []fyne.CanvasObject{
				cellBold(k.Label),
				cellMono(k.Prefix),
				cell(lastUsed(k.LastUsed)),
				cell(status),
				rowActions(revoke),
			})
		}
		return dataTable([]string{"Label", "Prefix", "Last used", "Status", ""},
			[]float32{2.6, 2, 2, 1.3, 1.6}, rows, "No API keys."), nil
	})
}

func lastUsed(s string) string {
	if strings.TrimSpace(s) == "" {
		return "never"
	}
	return shortTime(s)
}

func (sh *shell) createKeyDialog() {
	label := widget.NewEntry()
	label.SetPlaceHolder("my integration")
	ro := widget.NewCheck("Read-only", nil)
	items := []*widget.FormItem{
		widget.NewFormItem("Label", label),
		widget.NewFormItem("Scope", ro),
	}
	d := dialog.NewForm("Create API key", "Create", "Cancel", items, func(ok bool) {
		if !ok {
			return
		}
		go func() {
			ck, err := sh.app.client.CreateAPIKey(strings.TrimSpace(label.Text), ro.Checked)
			fyne.Do(func() {
				if err != nil {
					sh.fail(err)
					return
				}
				sh.reloadActive()
				sh.showSecret("API key created", "Copy this key now — it is shown only once:", ck.Key)
			})
		}()
	}, sh.win)
	d.Resize(fyne.NewSize(480, 0))
	d.Show()
}

// showSecret presents a one-time secret in a read-only, selectable field.
func (sh *shell) showSecret(title, note, secret string) {
	entry := widget.NewMultiLineEntry()
	entry.SetText(secret)
	entry.Wrapping = fyne.TextWrapBreak
	body := container.NewVBox(mutedPara(note), spacer(6), entry)
	d := dialog.NewCustom(title, "Done", body, sh.win)
	d.Resize(fyne.NewSize(520, 220))
	d.Show()
}

func (sh *shell) orgsPage() fyne.CanvasObject {
	create := primaryBtn("New org", func() { sh.newOrgDialog() })
	return sh.listPage("orgs", "Organizations", create, func() (fyne.CanvasObject, error) {
		orgs, err := sh.app.client.Orgs()
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, o := range orgs {
			rows = append(rows, []fyne.CanvasObject{
				cellBold(o.Name),
				cellMono(o.Slug),
				cell(shortTime(o.CreatedAt)),
			})
		}
		return dataTable([]string{"Name", "Slug", "Created"}, []float32{3, 2, 2}, rows, "No organizations."), nil
	})
}

func (sh *shell) newOrgDialog() {
	name := widget.NewEntry()
	name.SetPlaceHolder("Acme Inc")
	slug := widget.NewEntry()
	slug.SetPlaceHolder("acme")
	items := []*widget.FormItem{
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Slug", slug),
	}
	sh.showForm("New organization", "Create", items, func() error {
		if strings.TrimSpace(name.Text) == "" || strings.TrimSpace(slug.Text) == "" {
			return errReq("name and slug are required")
		}
		_, err := sh.app.client.CreateOrg(strings.TrimSpace(name.Text), strings.TrimSpace(slug.Text))
		return err
	})
}

func (sh *shell) auditPage() fyne.CanvasObject {
	refresh := plainBtn("Refresh", func() { sh.reloadActive() })
	return sh.listPage("audit", "Audit Log", refresh, func() (fyne.CanvasObject, error) {
		es, err := sh.app.client.Audit(200)
		if err != nil {
			return nil, err
		}
		var rows [][]fyne.CanvasObject
		for _, e := range es {
			target := e.TargetType
			if e.TargetID != "" {
				target = strings.TrimSpace(e.TargetType + " " + e.TargetID)
			}
			rows = append(rows, []fyne.CanvasObject{
				cell(shortTime(e.CreatedAt)),
				cell(auditActor(e)),
				cellMono(e.Action),
				cell(target),
			})
		}
		return dataTable([]string{"Time", "Actor", "Action", "Target"},
			[]float32{1.6, 2, 2.4, 2.4}, rows, "No audit entries."), nil
	})
}

func auditActor(e client.AuditEntry) string {
	switch e.ActorKind {
	case "system":
		return "system"
	case "apikey":
		return "API key: " + e.ActorName
	default:
		if e.ActorName == "" {
			return "—"
		}
		return e.ActorName
	}
}

func (sh *shell) billingPage() fyne.CanvasObject {
	edit := primaryBtn("Edit quota", func() { sh.quotaDialog() })
	return sh.listPage("billing", "Usage & Quota", edit, func() (fyne.CanvasObject, error) {
		u, err := sh.app.client.Usage()
		if err != nil {
			return nil, err
		}
		q, qerr := sh.app.client.Quota()

		usageStrip := container.NewGridWithColumns(4,
			statTile(itoaf(u.InstanceHours), "Instance-hours", nil),
			statTile(itoaf(float64(u.VCPUSeconds)/3600), "vCPU-hours", nil),
			statTile(itoaf(float64(u.MemMBSeconds)/3600/1024), "GB-hours RAM", nil),
			statTile(itoaf2(u.CostCredits), "Credits", colAccent),
		)
		cards := []fyne.CanvasObject{
			titledCard("Usage · "+itoa(u.Days)+"-day window", usageStrip),
			spacer(8),
		}
		if qerr == nil {
			quotaRows := container.NewVBox(
				kv("Max servers", qval(q.MaxServers), false),
				kv("Max running", qval(q.MaxRunning), false),
				kv("Max vCPUs", qval(q.MaxVCPUs), false),
				kv("Max memory", qvalMB(q.MaxMemoryMB), false),
				kv("Max disk", qvalGB(q.MaxDiskGB), false),
			)
			cards = append(cards, titledCard("Quota (0 = unlimited)", quotaRows))
		} else {
			cards = append(cards, titledCard("Quota", mutedPara("Quota unavailable: "+qerr.Error())))
		}
		return container.NewVBox(cards...), nil
	})
}

func (sh *shell) quotaDialog() {
	go func() {
		q, err := sh.app.client.Quota()
		fyne.Do(func() {
			if err != nil {
				sh.fail(err)
				return
			}
			sh.showQuotaForm(q)
		})
	}()
}

func (sh *shell) showQuotaForm(q client.Quota) {
	srv := qentry(q.MaxServers)
	run := qentry(q.MaxRunning)
	vcpu := qentry(q.MaxVCPUs)
	mem := qentry(q.MaxMemoryMB)
	disk := qentry(q.MaxDiskGB)
	items := []*widget.FormItem{
		widget.NewFormItem("Max servers", srv),
		widget.NewFormItem("Max running", run),
		widget.NewFormItem("Max vCPUs", vcpu),
		widget.NewFormItem("Max memory (MB)", mem),
		widget.NewFormItem("Max disk (GB)", disk),
	}
	sh.showForm("Edit quota (0 = unlimited)", "Save", items, func() error {
		return sh.app.client.SetQuota(client.Quota{
			MaxServers:  atoiDefault(srv.Text, 0),
			MaxRunning:  atoiDefault(run.Text, 0),
			MaxVCPUs:    atoiDefault(vcpu.Text, 0),
			MaxMemoryMB: atoiDefault(mem.Text, 0),
			MaxDiskGB:   atoiDefault(disk.Text, 0),
		})
	})
}

func qentry(n int) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(strconv.Itoa(n))
	return e
}

func qval(n int) string {
	if n == 0 {
		return "unlimited"
	}
	return strconv.Itoa(n)
}

func qvalMB(n int) string {
	if n == 0 {
		return "unlimited"
	}
	return strconv.Itoa(n) + " MB"
}

func qvalGB(n int) string {
	if n == 0 {
		return "unlimited"
	}
	return strconv.Itoa(n) + " GB"
}
