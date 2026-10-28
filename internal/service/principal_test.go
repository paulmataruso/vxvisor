package service

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/db"
	"vdxclone/internal/store"
)

// loginRequest starts a web session for username and returns a request that
// carries its cookie.
func loginRequest(t *testing.T, d *db.DB, username string) *http.Request {
	t.Helper()
	u, err := auth.UserByName(d, username)
	if err != nil {
		t.Fatalf("user %s: %v", username, err)
	}
	rec := httptest.NewRecorder()
	if err := auth.StartSession(d, rec, u.ID); err != nil {
		t.Fatalf("session: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	return r
}

// TestPrincipalTenantView: an instance admin is a full admin in the provider
// (Default) org, but switched into a tenant org sees exactly what that org's
// owner sees — while keeping the provider-only actions and the org switcher.
func TestPrincipalTenantView(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer d.Close()
	st := store.New(d)
	s := &Service{db: d, store: st}

	provider, err := st.DefaultOrgID()
	if err != nil {
		t.Fatalf("default org: %v", err)
	}
	// "Acme" sorts before "Default": an admin with no current org must still
	// land in the provider org, not the alphabetically-first tenant.
	acme, err := st.CreateOrg("Acme", "acme")
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	if err := auth.CreateUser(d, "root", "pw-root-123", "admin"); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if err := auth.CreateUser(d, "alice", "pw-alice-123", "user"); err != nil {
		t.Fatalf("user: %v", err)
	}
	alice, _ := auth.UserByName(d, "alice")
	if err := st.AddMember(acme, alice.ID, "admin"); err != nil {
		t.Fatalf("member: %v", err)
	}

	r := loginRequest(t, d, "root")
	p := s.Principal(r)
	if p.OrgID != provider || !p.IsAdmin || !p.ProviderAdmin || p.TenantView {
		t.Fatalf("admin default context: org=%d admin=%v provider=%v tenantView=%v",
			p.OrgID, p.IsAdmin, p.ProviderAdmin, p.TenantView)
	}

	if err := s.SwitchOrg(p, acme); err != nil {
		t.Fatalf("switch: %v", err)
	}
	p = s.Principal(r)
	if p.OrgID != acme || p.IsAdmin || !p.TenantView || !p.ProviderAdmin || p.OrgRole != "owner" {
		t.Fatalf("admin in tenant: org=%d admin=%v tenantView=%v provider=%v role=%q",
			p.OrgID, p.IsAdmin, p.TenantView, p.ProviderAdmin, p.OrgRole)
	}
	if !p.OrgAdmin() {
		t.Fatalf("tenant view must keep org-admin rights over the tenant")
	}
	if len(p.Orgs) != 2 {
		t.Fatalf("org switcher must still list every org, got %d", len(p.Orgs))
	}
	// And back to the provider view.
	if err := s.SwitchOrg(p, provider); err != nil {
		t.Fatalf("switch back: %v", err)
	}
	if p = s.Principal(r); !p.IsAdmin || p.TenantView {
		t.Fatalf("back in Default: admin=%v tenantView=%v", p.IsAdmin, p.TenantView)
	}

	// A real tenant org admin is never an instance admin and never "tenant view".
	pa := s.Principal(loginRequest(t, d, "alice"))
	if pa.OrgID != acme || pa.IsAdmin || pa.ProviderAdmin || pa.TenantView || !pa.OrgAdmin() {
		t.Fatalf("tenant admin: org=%d admin=%v provider=%v tenantView=%v orgAdmin=%v",
			pa.OrgID, pa.IsAdmin, pa.ProviderAdmin, pa.TenantView, pa.OrgAdmin())
	}
}
