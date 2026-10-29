package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

// TestVMPortGroupPickersRender: the launch modal and the instance page offer
// "default (NAT)" to the Default org only. A tenant org (here viewed by an
// instance admin in TenantView) picks among its own port groups, with its
// default tenant network preselected at launch.
func TestVMPortGroupPickersRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pgs := []netdrv.Network{{ID: 7, Name: "default", Bridge: "vdxt7"}, {ID: 9, Name: "default/db", Bridge: "vdxt7", VLANID: 20}}
	tenant := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 2, OrgRole: "owner", ProviderAdmin: true, TenantView: true}
	provider := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}

	render := func(name string, data map[string]any) string {
		t.Helper()
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, name, data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return b.String()
	}

	out := render("dashboard.html", map[string]any{"P": tenant, "CSRF": "tok", "Active": "compute",
		"Networks": pgs, "DefNetID": int64(7), "TenantOrg": true})
	if strings.Contains(out, "default (NAT)") {
		t.Errorf("launch modal offers default (NAT) to a tenant org")
	}
	if !strings.Contains(out, `<option value="7" selected>default</option>`) || !strings.Contains(out, `<option value="9">default/db · VLAN 20</option>`) {
		t.Errorf("launch modal: tenant port groups / default preselection missing")
	}
	out = render("dashboard.html", map[string]any{"P": provider, "CSRF": "tok", "Active": "compute", "TenantOrg": false})
	if !strings.Contains(out, `<option value="0">— default (NAT) —</option>`) {
		t.Errorf("launch modal lost default (NAT) for the Default org")
	}

	unbound := &session.Session{ID: "s1", Name: "web", State: "stopped", OrgID: 2}
	out = render("instance.html", map[string]any{"P": tenant, "CSRF": "tok", "Active": "compute",
		"Session": unbound, "Networks": pgs, "TenantOrg": true})
	if strings.Contains(out, "default (NAT)") {
		t.Errorf("instance page offers default (NAT) to a tenant org")
	}
	if !strings.Contains(out, `<option value="" selected disabled>— choose a port group —</option>`) {
		t.Errorf("instance page: unbound tenant VM has no placeholder")
	}
	out = render("instance.html", map[string]any{"P": provider, "CSRF": "tok", "Active": "compute",
		"Session": &session.Session{ID: "s2", Name: "db", State: "stopped", OrgID: 1}, "TenantOrg": false})
	if !strings.Contains(out, "default (NAT)") {
		t.Errorf("instance page lost default (NAT) for the Default org")
	}
}
