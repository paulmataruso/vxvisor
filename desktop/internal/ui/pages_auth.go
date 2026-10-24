package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"github.com/paulmataruso/vxvisor/desktop/internal/client"
)

// Phase-4 Authentication page: AD/LDAP directory settings (inline form with
// Save + Test). OIDC stays on the web UI (TOML-only config, no API).

func (sh *shell) authPage() fyne.CanvasObject {
	return sh.listPage("auth", "Authentication", nil, func() (fyne.CanvasObject, error) {
		s, err := sh.app.client.AuthSettings()
		if err != nil {
			return nil, err
		}
		return sh.authForm(s), nil
	})
}

func (sh *shell) authForm(s client.AuthSettings) fyne.CanvasObject {
	enabled := widget.NewCheck("Enable AD/LDAP authentication", nil)
	enabled.SetChecked(s.Enabled)
	url := entryVal(s.URL, "ldaps://dc.example.com:636")
	domain := entryVal(s.Domain, "EXAMPLE")
	startTLS := widget.NewCheck("StartTLS", nil)
	startTLS.SetChecked(s.StartTLS)
	insecure := widget.NewCheck("Skip TLS verify (insecure)", nil)
	insecure.SetChecked(s.Insecure)
	bindDN := entryVal(s.BindDN, "cn=svc,ou=users,dc=example,dc=com")
	bindPw := widget.NewPasswordEntry()
	if s.HasBindPassword {
		bindPw.SetPlaceHolder("•••••• (unchanged)")
	} else {
		bindPw.SetPlaceHolder("bind password")
	}
	baseDN := entryVal(s.BaseDN, "dc=example,dc=com")
	userFilter := entryVal(s.UserFilter, "(sAMAccountName=%s)")
	adminGroup := entryVal(s.AdminGroup, "CN=vxvisor-admins,…")

	collect := func() client.AuthSettings {
		return client.AuthSettings{
			Enabled:    enabled.Checked,
			URL:        url.Text,
			Domain:     domain.Text,
			StartTLS:   startTLS.Checked,
			Insecure:   insecure.Checked,
			BindDN:     bindDN.Text,
			BaseDN:     baseDN.Text,
			UserFilter: userFilter.Text,
			AdminGroup: adminGroup.Text,
		}
	}

	save := primaryBtn("Save", func() {
		sh.do(func() error { return sh.app.client.SaveAuthSettings(collect(), bindPw.Text) }, func() { sh.toast("Authentication settings saved.") })
	})
	test := plainBtn("Test bind", func() {
		sh.toast("Testing directory bind…")
		go func() {
			res, err := sh.app.client.TestAuthSettings(collect(), bindPw.Text)
			fyne.Do(func() {
				if err != nil {
					sh.fail(err)
					return
				}
				if res.Ok {
					sh.toast("Bind OK: " + res.Message)
				} else {
					sh.toast("Bind failed: " + res.Message)
				}
			})
		}()
	})

	form := container.NewVBox(
		enabled,
		formRow("Server URL", url),
		formRow("Domain", domain),
		container.NewHBox(startTLS, hSpace(16), insecure),
		formRow("Bind DN", bindDN),
		formRow("Bind password", bindPw),
		formRow("Base DN", baseDN),
		formRow("User filter", userFilter),
		formRow("Admin group", adminGroup),
		spacer(6),
		container.NewThemeOverride(container.NewHBox(save, hSpace(10), test), compactTheme{}),
	)
	return titledCard("Directory (AD / LDAP)", form)
}

func entryVal(val, placeholder string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(val)
	if placeholder != "" {
		e.SetPlaceHolder(placeholder)
	}
	return e
}

// formRow is a labeled field for inline (non-dialog) forms.
func formRow(label string, field fyne.CanvasObject) fyne.CanvasObject {
	return container.NewVBox(mutedText(label, 11.5), field)
}
