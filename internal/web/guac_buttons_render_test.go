package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

// TestGuacButtonsRender: with the RustGuac add-on enabled, the instances list
// (list + folder views) and the instance page offer "⚡ RustGuac" beside the
// console for running VMs only; with it disabled there's no button anywhere.
func TestGuacButtonsRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	run := &session.Session{ID: "run-1", Name: "web", State: "running"}
	stop := &session.Session{ID: "stop-1", Name: "db", State: "stopped"}
	nested := &session.Session{ID: "run-2", Name: "app", State: "running"}
	for _, on := range []bool{true, false} {
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, "dashboard.html", map[string]any{"P": p, "CSRF": "tok", "Active": "compute",
			"Sessions": []*session.Session{run, stop, nested}, "RootVMs": []*session.Session{run},
			"FolderRoots": []*folderNode{{ID: 1, Name: "prod", Children: []*folderNode{{ID: 2, Name: "apps", VMs: []*session.Session{nested}}}}},
			"LocalNode":   "vxvisor", "GuacEnabled": on,
		}); err != nil {
			t.Fatalf("dashboard.html (guac=%v): %v", on, err)
		}
		out := b.String()
		// list row + root folder row for run-1; list row + nested folder row for run-2.
		if n := strings.Count(out, `href="/console/run-1/advanced"`); (on && n != 2) || (!on && n != 0) {
			t.Fatalf("instances (guac=%v): run-1 has %d RustGuac buttons", on, n)
		}
		if n := strings.Count(out, `href="/console/run-2/advanced"`); (on && n != 2) || (!on && n != 0) {
			t.Fatalf("instances (guac=%v): nested run-2 has %d RustGuac buttons", on, n)
		}
		if strings.Contains(out, `/console/stop-1/advanced`) {
			t.Fatalf("a stopped VM gets no RustGuac button")
		}
		b.Reset()
		if err := tm.ExecuteTemplate(&b, "instance.html", map[string]any{"P": p, "CSRF": "tok", "Active": "compute",
			"Session": run, "Running": true, "GuacEnabled": on}); err != nil {
			t.Fatalf("instance.html (guac=%v): %v", on, err)
		}
		out = b.String()
		i, j := strings.Index(out, `>VNC console</a>`), strings.Index(out, `href="/console/run-1/advanced"`)
		if on && (j < 0 || j < i || j > strings.Index(out, `/console/run-1/serial`)) {
			t.Fatalf("instance page: RustGuac must sit right after VNC console")
		}
		if !on && j >= 0 {
			t.Fatalf("instance page shows RustGuac while disabled")
		}
	}
}
