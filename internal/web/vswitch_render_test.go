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

// TestVSwitchPortGroupDeleteRender: the management vSwitch is protected, an
// in-use vSwitch or port group shows why instead of a Delete button, and free
// ones keep Delete. Without the in-use maps (older callers) the page still
// renders and offers Delete.
func TestVSwitchPortGroupDeleteRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	data := func(inUse bool) map[string]any {
		m := map[string]any{"P": p, "CSRF": "tok", "Active": "networks",
			"Networks": []netdrv.Network{{ID: 7, Name: "VM Network", Mode: "bridge", Bridge: "vSwitch0"},
				{ID: 8, Name: "lab", Mode: "bridge", Bridge: "vdsprod", VLANID: 20}},
			"VSwitches": []netdrv.VSwitch{{Name: "vSwitch0", Bridge: "vSwitch0", Uplink: "bond0"},
				{Name: "prod", Bridge: "vdsprod", Uplink: "eno3"}, {Name: "lab", Bridge: "vdslab"}},
			"MgmtBridge": "vSwitch0",
		}
		if inUse {
			m["VSwitchInUse"] = map[string]string{"vSwitch0": "carries host management", "prod": `vSwitch "prod" still has port groups (lab) — delete them first`}
			m["PortGroupInUse"] = map[int64]string{7: `1 instance(s) use port group "VM Network" (web1)`}
		}
		return m
	}
	var b bytes.Buffer
	if err := tm.ExecuteTemplate(&b, "networks.html", data(true)); err != nil {
		t.Fatalf("networks.html: %v", err)
	}
	out := b.String()
	if strings.Contains(out, `action="/networks/vswitches/vSwitch0/delete"`) || !strings.Contains(out, `>protected</span>`) {
		t.Fatalf("the management vSwitch must be protected, not deletable")
	}
	if strings.Contains(out, `action="/networks/vswitches/prod/delete"`) ||
		!strings.Contains(out, `title="vSwitch &#34;prod&#34; still has port groups (lab) — delete them first">in use`) {
		t.Fatalf("an in-use vSwitch must show why, not Delete")
	}
	if !strings.Contains(out, `action="/networks/vswitches/lab/delete"`) {
		t.Fatalf("a free vSwitch keeps its Delete")
	}
	if strings.Contains(out, `action="/networks/7/delete"`) || !strings.Contains(out, `(web1)">in use`) {
		t.Fatalf("an in-use port group must show why, not Delete")
	}
	if !strings.Contains(out, `action="/networks/8/delete"`) {
		t.Fatalf("a free port group keeps its Delete")
	}

	b.Reset()
	if err := tm.ExecuteTemplate(&b, "networks.html", data(false)); err != nil {
		t.Fatalf("networks.html without in-use maps: %v", err)
	}
	if out := b.String(); !strings.Contains(out, `action="/networks/vswitches/prod/delete"`) || !strings.Contains(out, `action="/networks/7/delete"`) {
		t.Fatalf("without in-use data, Delete is offered")
	}
}
