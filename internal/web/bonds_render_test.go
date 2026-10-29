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

// TestTeamEditRender: an editable team gets Edit / Edit team (with its live
// mode, hash and members for the modal), a netplan-owned one says so instead,
// and a non-management vSwitch offers its MTU.
func TestTeamEditRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	var b bytes.Buffer
	if err := tm.ExecuteTemplate(&b, "networks.html", map[string]any{"P": p, "CSRF": "tok", "Active": "networks",
		"Networks":  []netdrv.Network{},
		"Bonds":     []netdrv.Bond{{Name: "bond0", Mode: "balance-alb"}, {Name: "bond1", Mode: "lacp/layer2+3"}},
		"BondInUse": map[string]string{"bond0": "in use", "bond1": "in use"},
		"VSwitches": []netdrv.VSwitch{{Name: "vSwitch0", Bridge: "vSwitch0", Uplink: "bond0"}, {Name: "vsA", Bridge: "vdsvsA", Uplink: "bond1"},
			{Name: "vsB", Bridge: "vdsvsB", Uplink: "eno3"}},
		"MgmtBridge": "vSwitch0",
		"Teams": map[string]service.TeamDetail{
			"bond0": {Mode: "balance-alb", Members: []string{"eno1", "eno2"}, Locked: "defined by netplan"},
			"bond1": {Mode: "lacp", Hash: "layer2+3", Members: []string{"eno5", "eno6"}},
		},
		"VSwitchMTU": map[string]int{"vsA": 9000},
	}); err != nil {
		t.Fatalf("networks.html: %v", err)
	}
	out := b.String()
	for _, want := range []string{
		`<h2>NIC teams</h2>`, `+ Add NIC team`, `<th>Physical adapter</th>`,
		`title="defined by netplan">netplan-managed</span>`,
		`data-teamedit="bond1" data-mode="lacp" data-hash="layer2&#43;3" data-members="eno5,eno6"`,
		`>Edit team</button>`,
		`data-vsbond="vsB"`,                // a single adapter can still be teamed
		`data-vsmtu="vsA" data-mtu="9000"`, // recorded MTU
		`data-vsmtu="vsB" data-mtu="1500"`, // kernel default
		`id="m-teamedit"`, `id="m-vsmtu"`,
		`vSphere`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("networks.html missing %q", want)
		}
	}
	for _, bad := range []string{`data-teamedit="bond0"`, `data-vsbond="vSwitch0"`, `data-vsbond="vsA"`, `data-vsmtu="vSwitch0"`} {
		if strings.Contains(out, bad) {
			t.Errorf("networks.html must not contain %q", bad)
		}
	}
	for _, m := range []string{"m-bond", "m-vswitch", "m-vsbond", "m-teamedit", "m-vsmtu", "m-pg", "m-vxlan"} {
		if strings.Contains(out, `data-modal="`+m+`"`) && !strings.Contains(out, `id="`+m+`"`) {
			t.Errorf("data-modal=%q has no matching modal", m)
		}
	}
}
