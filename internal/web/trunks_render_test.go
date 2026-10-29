package web

import (
	"bytes"
	"database/sql"
	"html/template"
	"os"
	"regexp"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/service"
)

// TestTrunksPageRender executes the Tenant Egress page with a trunk of each kind,
// a pool and a connected + an unconnected uplink: every Edit button needs its
// modal, the uplink modals offer only their own tenant's free vSwitches, and the
// wizard is there. VX_TRUNKS_HTML=<file> dumps the page (for driving it in a
// headless browser).
func TestTrunksPageRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	data := map[string]any{"P": p, "CSRF": "tok", "Active": "trunks",
		"Trunks": []service.ExtTrunkView{
			{ID: 1, Iface: "bond1", Kind: "bond", MTU: 1600, QinQCapable: true, Slaves: []string{"eno1", "eno2"}, UplinkCount: 2},
			{ID: 2, Iface: "bond0", Kind: "bond", MTU: 1500, Shared: true},
		},
		"Pools": []service.VlanPoolView{{ID: 3, OrgID: 2, OrgName: "acme", TrunkID: 1, TrunkName: "bond1", VidMin: 100, VidMax: 109, Used: 1, Available: 9}},
		"Uplinks": []service.UplinkView{
			{ID: 4, OrgID: 2, OrgName: "acme", Name: "wan", TrunkID: sql.NullInt64{Int64: 1, Valid: true}, TrunkName: "bond1", Mode: "qinq", OuterVID: 100, Status: "bound", InUseBy: "default", InUseByID: 7},
			{ID: 5, OrgID: 2, OrgName: "acme", Name: "spare", TrunkID: sql.NullInt64{Int64: 1, Valid: true}, TrunkName: "bond1", Mode: "access", OuterVID: 101, Status: "unbound"},
		},
		"Orgs":        []service.OrgLite{{ID: 1, Name: "default", Slug: "default"}, {ID: 2, Name: "acme", Slug: "acme"}, {ID: 3, Name: "globex", Slug: "globex"}},
		"Candidates":  []service.TransitIface{{Name: "enp9s0"}},
		"SharedCands": []service.TransitIface{{Name: "bond0"}},
		"TenantNets": []service.TenantNetLite{
			{ID: 7, OrgID: 2, Name: "default", IsDefault: true, UplinkID: 4},
			{ID: 8, OrgID: 2, Name: "lab"},
			{ID: 9, OrgID: 3, Name: "globex-net"},
		},
	}
	var b bytes.Buffer
	if err := tm.ExecuteTemplate(&b, "trunks.html", data); err != nil {
		t.Fatalf("trunks.html: %v", err)
	}
	out := b.String()
	for _, want := range []string{`id="m-wiz"`, `action="/trunks/wizard"`, `id="m-trunk-1"`, `action="/trunks/1/edit"`,
		`id="m-pool-3"`, `id="m-upl-4"`, `id="m-upl-5"`, `action="/trunks/uplink/4/edit"`, `data-connected="default"`, "</html>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("trunks.html missing %q", want)
		}
	}
	// Every Edit/+ button opens a modal that exists.
	for _, m := range regexp.MustCompile(`data-modal="([^"]+)"`).FindAllStringSubmatch(out, -1) {
		if !strings.Contains(out, `id="`+m[1]+`"`) {
			t.Fatalf("data-modal=%q has no modal", m[1])
		}
	}
	if strings.Contains(out, `id="m-trunk-2"`) {
		t.Fatalf("a shared (mgmt) trunk must not be editable")
	}
	modal := func(id string) string {
		i := strings.Index(out, `id="`+id+`"`)
		j := strings.Index(out[i:], `</form>`)
		return out[i : i+j]
	}
	// wan: its own vSwitch (selected) + acme's free "lab"; never globex's.
	wan := modal("m-upl-4")
	if !strings.Contains(wan, `<option value="7" selected>default (default)</option>`) || !strings.Contains(wan, `<option value="8">lab</option>`) ||
		strings.Contains(wan, "globex-net") {
		t.Fatalf("wan's vSwitch picker is wrong:\n%s", wan)
	}
	// spare: "default" belongs to wan, so only lab.
	if spare := modal("m-upl-5"); strings.Contains(spare, `value="7"`) || !strings.Contains(spare, `value="8"`) {
		t.Fatalf("spare's vSwitch picker is wrong:\n%s", spare)
	}
	if f := os.Getenv("VX_TRUNKS_HTML"); f != "" {
		_ = os.WriteFile(f, []byte(out), 0o644)
	}
}
