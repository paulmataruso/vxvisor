package web

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/service"
)

// TestCBTImportRender: the "Use CBT (warm migration)" consent checkbox, its
// sync interval and the cut-over / cancel modals render only when VDDK is
// ready; without VDDK the dialog explains why instead. The read-only cold
// import form (transport select, powered-off picker) renders either way, and
// every data-modal has its modal.
func TestCBTImportRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	for _, ready := range []bool{true, false} {
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, "migrate.html", map[string]any{"P": p, "CSRF": "tok", "Active": "migrate",
			"VDDKReady": ready, "VDDKInstalled": true, "VDDKLibDir": "/opt/vddk", "DefaultTransport": "datastore"}); err != nil {
			t.Fatalf("migrate.html (vddk=%v): %v", ready, err)
		}
		out := b.String()
		hasBox := strings.Contains(out, `name="cbt" value="1"`)
		if hasBox != ready {
			t.Fatalf("vddk=%v: CBT checkbox rendered=%v", ready, hasBox)
		}
		if ready {
			for _, want := range []string{`name="cbt_interval"`, `id="m-cbtcut"`, `id="m-cbtcancel"`, `name="shutdown_guest"`, `vxvisor-cbt-`, `id="cbtprog"`} {
				if !strings.Contains(out, want) {
					t.Fatalf("vddk ready: missing %s", want)
				}
			}
		} else if !strings.Contains(out, "needs VMware VDDK") {
			t.Fatalf("without VDDK the dialog must say why warm migration is unavailable")
		}
		if !strings.Contains(out, `<select name="transport">`) || !strings.Contains(out, `action="/import/vmware/start"`) {
			t.Fatalf("vddk=%v: the cold import form changed", ready)
		}
		if n := strings.Count(out, `name="csrf" value="tok"`); n < 4 {
			t.Fatalf("vddk=%v: only %d CSRF fields", ready, n)
		}
		ids := map[string]bool{}
		for _, m := range regexp.MustCompile(`class="modal" id="([^"]+)"`).FindAllStringSubmatch(out, -1) {
			ids[m[1]] = true
		}
		for _, m := range regexp.MustCompile(`data-modal="([^"]+)"`).FindAllStringSubmatch(out, -1) {
			if !ids[m[1]] {
				t.Fatalf("vddk=%v: data-modal=%q has no modal", ready, m[1])
			}
		}
	}
}
