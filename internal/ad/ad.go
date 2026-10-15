// Package ad provides Active Directory / LDAP bind authentication. It mirrors the
// shape of internal/oidc (a provider built from config, enabled-gated), but the
// bind is synchronous during POST /login rather than a browser redirect.
//
// Design goal: EASY. With just url + domain set, a user signs in with their AD
// username + password (UPN bind) and is JIT-provisioned locally. The optional
// service-account + group fields enable admin-group → role mapping.
//
// The live config is held behind a mutex so the Settings → Authentication page
// can swap it at runtime (SetConfig) without a daemon restart.
package ad

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"vdxclone/internal/config"
)

type Provider struct {
	mu  sync.RWMutex
	cfg config.ADConfig
}

func New(cfg config.ADConfig) *Provider { return &Provider{cfg: cfg} }

// SetConfig swaps the live configuration. Called at startup (to apply the
// DB-persisted config over the TOML default) and whenever an admin saves the
// Settings → Authentication form, so changes take effect without a restart.
func (p *Provider) SetConfig(cfg config.ADConfig) {
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
}

// Config returns a snapshot of the live configuration.
func (p *Provider) Config() config.ADConfig {
	if p == nil {
		return config.ADConfig{}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// Enabled reports whether AD auth is configured.
func (p *Provider) Enabled() bool {
	if p == nil {
		return false
	}
	c := p.Config()
	return c.Enabled && c.URL != ""
}

// Identity is the result of a successful AD authentication.
type Identity struct {
	Username string // the login name (sAMAccountName / left of @)
	DN       string // the user's distinguished name (if resolved)
	Admin    bool   // member of the configured admin group
}

func dial(c config.ADConfig) (*ldap.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: c.Insecure}
	conn, err := ldap.DialURL(c.URL, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("connect AD: %w", err)
	}
	conn.SetTimeout(10 * time.Second)
	if c.StartTLS && strings.HasPrefix(strings.ToLower(c.URL), "ldap://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("AD StartTLS: %w", err)
		}
	}
	return conn, nil
}

// upn builds the bind principal for a login name. A bare name becomes
// user@domain (AD UPN bind); names already containing @ or \ are used as-is.
func upn(c config.ADConfig, username string) string {
	if strings.ContainsAny(username, "@\\") || c.Domain == "" {
		return username
	}
	return username + "@" + c.Domain
}

// loginName normalizes a login name to the bare sAMAccountName for local
// provisioning (strips @domain / DOMAIN\ prefixes).
func loginName(username string) string {
	if i := strings.IndexByte(username, '@'); i >= 0 {
		return username[:i]
	}
	if i := strings.LastIndexByte(username, '\\'); i >= 0 {
		return username[i+1:]
	}
	return username
}

// Authenticate verifies username+password against AD and returns the identity.
// A wrong password yields ErrInvalidCredentials. When a service account + base
// DN are configured it also resolves the user's DN and admin-group membership.
func (p *Provider) Authenticate(username, password string) (*Identity, error) {
	return authenticate(p.Config(), username, password)
}

func authenticate(c config.ADConfig, username, password string) (*Identity, error) {
	if password == "" { // AD treats an empty password as an anonymous bind — reject.
		return nil, ErrInvalidCredentials
	}
	conn, err := dial(c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(upn(c, username), password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("AD bind: %w", err)
	}
	id := &Identity{Username: loginName(username)}

	// Optional directory lookup for DN + group membership (role mapping).
	if c.BindDN != "" && c.BaseDN != "" {
		if dn, groups, err := lookup(c, id.Username); err == nil {
			id.DN = dn
			id.Admin = inAdminGroup(c, groups)
		}
	}
	return id, nil
}

// lookup binds as the service account and reads the user's DN + memberOf groups.
func lookup(c config.ADConfig, sam string) (dn string, groups []string, err error) {
	conn, err := dial(c)
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()
	if err := conn.Bind(upn(c, c.BindDN), c.BindPassword); err != nil {
		return "", nil, fmt.Errorf("AD service bind: %w", err)
	}
	filter := c.UserFilter
	if filter == "" {
		filter = "(&(objectClass=user)(sAMAccountName=%s))"
	}
	req := ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 10, false, fmt.Sprintf(filter, ldap.EscapeFilter(sam)), []string{"dn", "memberOf"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return "", nil, fmt.Errorf("AD user search: not found")
	}
	e := res.Entries[0]
	return e.DN, e.GetAttributeValues("memberOf"), nil
}

// inAdminGroup reports whether any of the user's groups matches AdminGroup (by
// full DN or by bare CN, case-insensitive).
func inAdminGroup(c config.ADConfig, groups []string) bool {
	want := strings.ToLower(strings.TrimSpace(c.AdminGroup))
	if want == "" {
		return false
	}
	for _, g := range groups {
		gl := strings.ToLower(g)
		if gl == want {
			return true
		}
		// match bare CN, e.g. admin_group="VDX-Admins" vs "CN=VDX-Admins,OU=...".
		if strings.HasPrefix(gl, "cn="+want+",") {
			return true
		}
	}
	return false
}

// TestConfig validates a candidate config WITHOUT making it live: it dials the
// directory and, when a service account is configured, binds as it and (if a
// base DN is set) runs a trivial search. It returns a human-readable summary of
// the checks that passed, or the first error encountered. This backs the
// Settings → Authentication "Test connection" button.
func TestConfig(c config.ADConfig) (string, error) {
	if c.URL == "" {
		return "", fmt.Errorf("directory URL is required")
	}
	conn, err := dial(c)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	steps := []string{"connected to " + c.URL}

	if c.BindDN == "" {
		steps = append(steps, "no service account set — users will bind directly (UPN)")
		return strings.Join(steps, "; "), nil
	}
	if err := conn.Bind(upn(c, c.BindDN), c.BindPassword); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return "", fmt.Errorf("service account bind failed: invalid credentials")
		}
		return "", fmt.Errorf("service account bind failed: %w", err)
	}
	steps = append(steps, "service account bind OK")

	if c.BaseDN != "" {
		req := ldap.NewSearchRequest(c.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			0, 5, false, "(objectClass=*)", []string{"dn"}, nil)
		if _, err := conn.Search(req); err != nil {
			return "", fmt.Errorf("base DN %q not searchable: %w", c.BaseDN, err)
		}
		steps = append(steps, "base DN reachable")
	}
	return strings.Join(steps, "; "), nil
}

// ErrInvalidCredentials is returned for a bad username/password (so callers can
// fall through without leaking whether the account exists).
var ErrInvalidCredentials = fmt.Errorf("invalid credentials")
