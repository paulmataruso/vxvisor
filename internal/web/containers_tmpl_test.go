package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
)

// TestContainersTemplatePortGroups renders containers.html (page chrome stubbed
// out) and checks the port-group pickers: a tenant org gets only its own port
// groups (never lxcbr0), the Default org keeps lxcbr0, and a container's edit
// modal preselects its bound port group.
func TestContainersTemplatePortGroups(t *testing.T) {
	root, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	tm := template.Must(root.Clone())
	template.Must(tm.New("head").Parse(""))
	template.Must(tm.New("foot").Parse(""))

	render := func(data map[string]any) string {
		t.Helper()
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, "containers.html", data); err != nil {
			t.Fatalf("execute containers.html: %v", err)
		}
		return b.String()
	}
	pg := []netdrv.Network{{ID: 7, Name: "web", Bridge: "vdxt7"}, {ID: 9, Name: "db", Bridge: "vdxt7", VLANID: 20}}

	// Tenant org 2: one container bound to port group 9.
	out := render(map[string]any{
		"CSRF":         "tok",
		"LXCReady":     true,
		"Containers":   []service.ContainerRow{{ID: 1, Name: "c1", OrgID: 2, Bridge: "vdxt7", NetworkID: 9, Status: "stopped", State: "STOPPED"}},
		"PortGroups":   map[int64][]netdrv.Network{2: pg},
		"TenantOrgs":   map[int64]bool{2: true},
		"MyPortGroups": pg,
		"MyTenant":     true,
	})
	if strings.Contains(out, "lxcbr0 (default LXC NAT)") {
		t.Errorf("tenant org offered lxcbr0")
	}
	if strings.Contains(out, `name="bridge"`) {
		t.Errorf("a free-text bridge field is still posted")
	}
	if !strings.Contains(out, `<option value="9" selected>db — vdxt7 · VLAN 20</option>`) {
		t.Errorf("edit modal doesn't preselect the bound port group:\n%s", out)
	}

	// Default org 1: lxcbr0 offered; a legacy container on a raw bridge must
	// be moved consciously (placeholder, nothing preselected).
	out = render(map[string]any{
		"CSRF":         "tok",
		"LXCReady":     true,
		"Containers":   []service.ContainerRow{{ID: 3, Name: "old", OrgID: 1, Bridge: "vdxbr0", Status: "stopped", State: "STOPPED"}},
		"PortGroups":   map[int64][]netdrv.Network{1: nil},
		"TenantOrgs":   map[int64]bool{1: false},
		"MyPortGroups": nil,
		"MyTenant":     false,
	})
	if !strings.Contains(out, `<option value="0">lxcbr0 (default LXC NAT)</option>`) {
		t.Errorf("Default org lost lxcbr0:\n%s", out)
	}
	if !strings.Contains(out, "now on vdxbr0") {
		t.Errorf("legacy container's current bridge not shown:\n%s", out)
	}
}
