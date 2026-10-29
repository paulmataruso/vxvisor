package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
)

// TestBondsCardRender: the management bond is labelled and, like every in-use
// bond, shows why it can't be deleted instead of a Delete button; a free bond
// keeps its Delete.
func TestBondsCardRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	var b bytes.Buffer
	if err := tm.ExecuteTemplate(&b, "networks.html", map[string]any{"P": p, "CSRF": "tok", "Active": "networks",
		"Networks":   []netdrv.Network{},
		"Bonds":      []netdrv.Bond{{Name: "bond0", Mode: "balance-alb", Members: []string{"eno1", "eno2"}}, {Name: "bond1", Mode: "lacp"}},
		"BondInUse":  map[string]string{"bond0": `refusing to delete bond "bond0": it carries host management`},
		"VSwitches":  []netdrv.VSwitch{{Name: "vSwitch0", Bridge: "vSwitch0", Uplink: "bond0"}},
		"MgmtBridge": "vSwitch0",
	}); err != nil {
		t.Fatalf("networks.html: %v", err)
	}
	out := b.String()
	if strings.Contains(out, `action="/networks/bonds/bond0/delete"`) || !strings.Contains(out, `title="refusing to delete bond &#34;bond0&#34;: it carries host management">in use`) {
		t.Fatalf("the management bond must show why it's in use, not Delete")
	}
	if !strings.Contains(out, `action="/networks/bonds/bond1/delete"`) {
		t.Fatalf("a free bond keeps its Delete")
	}
	sel := out[strings.Index(out, `id="uplinksel"`):]
	sel = sel[:strings.Index(sel, `</select>`)]
	if strings.Contains(sel, `value="bond0"`) || !strings.Contains(sel, `value="bond1"`) {
		t.Fatalf("the vSwitch uplink picker must offer free bonds only: %s", sel)
	}
	if strings.Contains(out, `data-vsbond="vSwitch0"`) {
		t.Fatalf("a vSwitch whose uplink is already a team must not offer Add teaming")
	}
	i := strings.Index(out, `<strong>bond0</strong>`)
	if i < 0 || !strings.Contains(out[i:i+120], `management</span>`) {
		t.Fatalf("bond0 must be labelled management")
	}
}
