package web

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/service"
	"vdxclone/internal/session"
)

func snapTemplates(t *testing.T) *template.Template {
	t.Helper()
	root, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	tm := template.Must(root.Clone())
	template.Must(tm.New("head").Parse(""))
	template.Must(tm.New("foot").Parse(""))
	return tm
}

// checkModalsAndCSRF: every data-modal has its modal, and every POST form
// carries the CSRF token.
func checkModalsAndCSRF(t *testing.T, out string) {
	t.Helper()
	for _, m := range regexp.MustCompile(`data-modal="([^"]+)"`).FindAllStringSubmatch(out, -1) {
		if !strings.Contains(out, `id="`+m[1]+`"`) {
			t.Errorf("data-modal=%q has no matching modal", m[1])
		}
	}
	forms := regexp.MustCompile(`(?s)<form[^>]*method="post"[^>]*>.*?</form>`).FindAllString(out, -1)
	if len(forms) == 0 {
		t.Fatal("no POST forms rendered")
	}
	for _, f := range forms {
		if !strings.Contains(f, `name="csrf" value="tok"`) && !strings.Contains(f, `action="/logout"`) { // page chrome, not ours
			t.Errorf("POST form without CSRF: %.120s", f)
		}
	}
}

func TestSnapshotPoliciesTemplate(t *testing.T) {
	tm := snapTemplates(t)
	pols := []service.SnapshotPolicy{
		{ID: 3, OrgID: 2, OrgName: "Acme", Name: "nightly", TargetKind: "org", TargetLabel: "All instances",
			Schedule: "daily", AtHour: 1, KeepLast: 7, KeepDays: 30, Immutable: true, Enabled: true,
			LastRunLocal: "2026-10-29 01:00 UTC", LastStatus: "2 snapshot(s)", NextRunLocal: "2026-10-30 01:00 UTC", Snapshots: 2},
		{ID: 4, OrgID: 2, OrgName: "Acme", Name: "hourly-db", TargetKind: "vm", TargetLabel: "Instance db",
			Schedule: "hourly", AtMinute: 5, KeepLast: 24},
	}
	form := service.SnapshotPolicyFormData{
		Orgs:    []service.PolicyOrg{{ID: 1, Name: "Default"}, {ID: 2, Name: "Acme"}},
		VMs:     []service.PolicyTarget{{ID: "vm-1", OrgID: 2, OrgName: "Acme", Name: "db"}},
		Folders: []service.PolicyTarget{{ID: "5", OrgID: 2, OrgName: "Acme", Name: "prod"}},
	}
	snaps := []service.PolicySnap{{ID: 1, SessionID: "vm-1", SessionName: "db", Name: "nightly 2026-10-29 01:00",
		Consistency: "app", Locked: true, LockedUntil: "2026-11-28 01:00 UTC", ExpiresAt: "2026-11-28 01:00 UTC", CreatedAt: "2026-10-29 01:00:02"}}
	u := &auth.User{ID: 1, Username: "u"}

	render := func(p *service.Principal) string {
		var b bytes.Buffer
		err := tm.ExecuteTemplate(&b, "snapshot_policies.html", map[string]any{
			"CSRF": "tok", "P": p, "Policies": pols, "Form": form,
			"SelectedID": int64(3), "SelectedName": "nightly", "PolicySnaps": snaps,
		})
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		return b.String()
	}
	admin := render(&service.Principal{User: u, OrgID: 1, IsAdmin: true, OrgRole: "owner"})
	checkModalsAndCSRF(t, admin)
	for _, want := range []string{"<th>Organization</th>", `name="org_id"`, "Daily at 01:00", "Hourly at :05",
		"keep last 7 &#43; 30 days", "immutable", "paused", "Snapshots taken by nightly", "app-consistent", "locked"} {
		if !strings.Contains(admin, want) {
			t.Errorf("admin view missing %q", want)
		}
	}
	// A tenant org admin: same page, no org column / org picker.
	tenant := render(&service.Principal{User: u, OrgID: 2, OrgRole: "admin"})
	checkModalsAndCSRF(t, tenant)
	if strings.Contains(tenant, "<th>Organization</th>") || strings.Contains(tenant, `name="org_id"`) {
		t.Error("tenant view shows the org column / picker")
	}
}

func TestInstanceSnapshotCard(t *testing.T) {
	tm := snapTemplates(t)
	s := &session.Session{ID: "11111111-aaaa", Name: "web", State: "stopped", DiskBackend: "zvol", Firmware: "uefi",
		CloudInit: true, TPM: true, GuestAgent: true}
	snaps := []session.SnapRecord{
		{ID: 9, Name: "nightly", Tag: "snap-3", Backend: "zvol", Consistency: "app", PolicyID: 3, PolicyName: "nightly",
			Immutable: true, LockedUntil: "2026-11-28T01:00:00Z", CreatedAt: "2026-10-29 01:00:02"},
		{ID: 8, Name: "base", Tag: "snap-2", Backend: "zvol", Consistency: "crash", Transient: true,
			Clones: []session.CloneRef{{ID: "c1", Name: "web-clone"}}, Newer: 1, CreatedAt: "2026-10-28 01:00:02"},
		{ID: 7, Name: "first", Tag: "snap-1", Backend: "zvol", Consistency: "offline", Newer: 2, CreatedAt: "2026-10-27"},
	}
	var b bytes.Buffer
	err := tm.ExecuteTemplate(&b, "instance.html", map[string]any{
		"CSRF": "tok", "P": &service.Principal{User: &auth.User{ID: 1}, OrgID: 1, IsAdmin: true},
		"Session": s, "Snapshots": snaps, "IsClone": true,
		"CloneLink": session.CloneLink{OriginID: "0000", OriginName: "golden", SnapshotID: 4, SnapshotName: "v1",
			Backend: "zvol", Method: "zfs-clone", OriginExists: true},
	})
	if err != nil {
		t.Fatalf("execute instance.html: %v", err)
	}
	out := b.String()
	checkModalsAndCSRF(t, out)
	for _, want := range []string{
		`id="m-clone"`, `data-snap="9"`, `<option value="8">base`, "immutable until", "app-consistent",
		"crash-consistent", "clone base", `policy <a href="/snapshot-policies?policy=3">nightly</a>`,
		"Clones depending on it", `name="discard_newer" value="1"`, "Instant clone of", "golden",
		"still shares storage", "ZFS clone", "new, empty TPM", "machine-id",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("instance page missing %q", want)
		}
	}
	// Delete is disabled for the immutable and the clone-pinned snapshot.
	if n := strings.Count(out, `class="btn sm danger" disabled`); n < 2 {
		t.Errorf("want 2+ disabled delete buttons, got %d", n)
	}
}
