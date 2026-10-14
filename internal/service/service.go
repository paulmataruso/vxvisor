// Package service is the business-logic layer. It is the ONLY place authorization
// is enforced and audit events are written; web and api handlers call it and
// never touch the store or raw SQL directly. This keeps multi-tenant isolation
// in one auditable location.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"vdxclone/internal/auth"
	"vdxclone/internal/broker"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/policy"
	"vdxclone/internal/cluster"
	"vdxclone/internal/metrics"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/platform"
	"vdxclone/internal/session"
	"vdxclone/internal/storage"
	"vdxclone/internal/store"
)

type Service struct {
	cfg   *config.Config
	db    *db.DB
	store *store.Store
	stg   *storage.Store
	net   *netdrv.Store
	mgr   *session.Manager
	enf   policy.Enforcer
	mc     *metrics.Collector
	cl     *cluster.Store
	pools  *broker.PoolStore
	signer *broker.Signer
}

func New(cfg *config.Config, d *db.DB, st *store.Store, stg *storage.Store, net *netdrv.Store, mgr *session.Manager, enf policy.Enforcer) *Service {
	return &Service{cfg: cfg, db: d, store: st, stg: stg, net: net, mgr: mgr, enf: enf}
}

// SetMetrics attaches the metrics collector so the web layer can read it.
func (s *Service) SetMetrics(mc *metrics.Collector) { s.mc = mc }
func (s *Service) Metrics() *metrics.Collector      { return s.mc }

// SetCluster attaches the cluster store.
func (s *Service) SetCluster(cl *cluster.Store) { s.cl = cl }
func (s *Service) Cluster() *cluster.Store      { return s.cl }

func (s *Service) Store() *store.Store       { return s.store }
func (s *Service) Storage() *storage.Store   { return s.stg }
func (s *Service) Net() *netdrv.Store        { return s.net }
func (s *Service) Manager() *session.Manager { return s.mgr }
func (s *Service) DB() *db.DB                 { return s.db }
func (s *Service) Config() *config.Config    { return s.cfg }

var (
	ErrUnauthorized = errors.New("not authorized")
	ErrNotFound     = errors.New("not found")
)

// ---- principal -----------------------------------------------------------

// Principal is the authenticated caller plus their current org context.
type Principal struct {
	User      *auth.User
	OrgID     int64
	OrgRole   string // role within the current org
	IsAdmin   bool   // instance admin
	Orgs      []store.Org
	ActorKind string   // "user" | "apikey"
	Scopes    []string // for apikey principals; users are unrestricted
	token     string
}

// HasScope reports whether the principal may perform an action of the given
// scope. Interactive users are unrestricted; API keys are limited to their
// granted scopes ("*" grants all).
func (p *Principal) HasScope(scope string) bool {
	if p.ActorKind != "apikey" {
		return true
	}
	for _, s := range p.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// Principal resolves the caller from the request, selecting (and persisting) a
// valid current org. Returns nil when not authenticated.
func (s *Service) Principal(r *http.Request) *Principal {
	u := auth.FromRequest(s.db, r)
	if u == nil {
		return nil
	}
	token := auth.TokenFromRequest(r)
	isAdmin := u.Role == "admin"
	orgs, _ := s.store.UserOrgs(u.ID, isAdmin)

	accessible := func(id int64) bool {
		for _, o := range orgs {
			if o.ID == id {
				return true
			}
		}
		return false
	}

	cur, ok := s.store.CurrentOrg(token)
	if !ok || !accessible(cur) {
		cur = 0
		if len(orgs) > 0 {
			cur = orgs[0].ID
			_ = s.store.SetCurrentOrg(token, cur)
		}
	}
	role, _ := s.store.OrgRole(cur, u.ID)
	return &Principal{User: u, OrgID: cur, OrgRole: role, IsAdmin: isAdmin, Orgs: orgs, ActorKind: "user", token: token}
}

// APIPrincipal resolves a caller for the REST API: a cookie session if present,
// otherwise an "Authorization: Bearer vdx_..." API key scoped to its org.
func (s *Service) APIPrincipal(r *http.Request) *Principal {
	if p := s.Principal(r); p != nil {
		return p
	}
	h := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if len(h) <= len(pfx) || h[:len(pfx)] != pfx {
		return nil
	}
	orgID, keyID, scopesJSON, ok := s.store.APIKeyByHash(auth.HashAPIKey(h[len(pfx):]))
	if !ok {
		return nil
	}
	org, _ := s.store.GetOrg(orgID)
	scopes := []string{"read", "write"}
	if scopesJSON != "" {
		var parsed []string
		if json.Unmarshal([]byte(scopesJSON), &parsed) == nil && len(parsed) > 0 {
			scopes = parsed
		}
	}
	return &Principal{
		User:      &auth.User{ID: keyID, Username: fmt.Sprintf("apikey:%d", keyID), Role: "user"},
		OrgID:     orgID,
		OrgRole:   "admin", // keys act as org admins within their org, limited by scopes
		Orgs:      []store.Org{org},
		ActorKind: "apikey",
		Scopes:    scopes,
	}
}

// Token returns the caller's web-session token (used to derive the CSRF token).
func (p *Principal) Token() string { return p.token }

// roleRank orders org roles; instance admins outrank everything.
var roleRank = map[string]int{"viewer": 1, "member": 2, "admin": 3, "owner": 4}

func (p *Principal) effectiveRank() int {
	if p.IsAdmin {
		return roleRank["owner"]
	}
	return roleRank[p.OrgRole]
}

func (p *Principal) atLeast(role string) bool { return p.effectiveRank() >= roleRank[role] }

// SwitchOrg changes the caller's current org after verifying access.
func (s *Service) SwitchOrg(p *Principal, orgID int64) error {
	for _, o := range p.Orgs {
		if o.ID == orgID {
			return s.store.SetCurrentOrg(p.token, orgID)
		}
	}
	return ErrUnauthorized
}

func (s *Service) audit(p *Principal, orgID int64, action, targetType, targetID, ip string, detail any) {
	d := "{}"
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	kind := p.ActorKind
	if kind == "" {
		kind = "user"
	}
	s.store.Audit(store.AuditEntry{
		OrgID: orgID, ActorID: p.User.ID, ActorKind: kind,
		Action: action, TargetType: targetType, TargetID: targetID, Detail: d, IP: ip,
	})
}

// ---- sessions ------------------------------------------------------------

func (s *Service) ListSessions(p *Principal) ([]*session.Session, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.mgr.List(p.OrgID)
}

func (s *Service) counts(orgID int64) policy.Counts {
	var running, servers int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE org_id=? AND state='running' AND deleted_at IS NULL`, orgID).Scan(&running)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE org_id=? AND kind='server' AND deleted_at IS NULL`, orgID).Scan(&servers)
	return policy.Counts{RunningSessions: running, ServerVMs: servers}
}

// CreateInput carries the fields a web/api caller supplies for a new instance.
type CreateInput struct {
	Name       string
	Image      string
	Kind       string
	Firmware   string
	BootISOID  int64
	CPUs       int
	MemoryMB   int
	DiskGB     int
	CloudInit   bool
	CIUsername  string
	CIPassword  string
	CISSHKey    string
	Passthrough   string // csv of host PCI addresses
	NetworkID     int64  // port group to attach the NIC to; 0 = default/NAT
	StoragePoolID int64  // storage pool for the disk; 0 = default disk dir
	Display       string // vnc | spice
	DiskBackend   string // qcow2 | zvol
	ZvolPool      string // ZFS pool name for the zvol (zvol backend)
	Desktop       string // "" | xfce
}

func (s *Service) CreateSession(p *Principal, in CreateInput, ip string) (*session.Session, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	if err := s.checkQuotaCreate(p.OrgID, in); err != nil {
		return nil, err
	}
	if in.Passthrough != "" {
		if pt := platform.DetectPassthrough(); !pt.IOMMU {
			return nil, fmt.Errorf("host not passthrough-capable: %s", pt.Note)
		}
	}
	if in.Kind == "server" {
		if d := s.enf.CanCreateServer(context.Background(), p.OrgID, s.counts(p.OrgID)); !d.Allow {
			return nil, errors.New(d.Reason)
		}
	}
	// A bound port group must belong to this org (prevents attaching a NIC to
	// another tenant's network).
	if in.NetworkID > 0 {
		if _, err := s.net.GetNetwork(p.OrgID, in.NetworkID); err != nil {
			return nil, fmt.Errorf("unknown port group")
		}
	}
	sess, err := s.mgr.Create(session.CreateOpts{
		OrgID: p.OrgID, OwnerID: p.User.ID,
		Name: in.Name, ImageName: in.Image, Kind: in.Kind, Firmware: in.Firmware, BootISOID: in.BootISOID,
		CPUs: in.CPUs, MemoryMB: in.MemoryMB, DiskGB: in.DiskGB,
		CloudInit: in.CloudInit, CIUsername: in.CIUsername, CIPassword: in.CIPassword, CISSHKey: in.CISSHKey,
		Passthrough: in.Passthrough, NetworkID: in.NetworkID, StoragePoolID: in.StoragePoolID, Display: in.Display,
		DiskBackend: in.DiskBackend, ZvolPool: in.ZvolPool, Desktop: in.Desktop,
	})
	if err != nil {
		return nil, err
	}
	// Audit records the shape of the instance, never the first-boot secret.
	s.audit(p, p.OrgID, "session.create", "session", sess.ID, ip, map[string]any{
		"name": in.Name, "image": in.Image, "kind": in.Kind,
		"firmware": sess.Firmware, "cpus": in.CPUs, "memory_mb": in.MemoryMB, "disk_gb": in.DiskGB,
	})
	return sess, nil
}

// EjectISO detaches the boot ISO from an instance so it boots its disk (e.g.
// after installing an OS from the ISO). Takes effect on the next start.
func (s *Service) EjectISO(p *Principal, id, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.SetBootISO(id, 0); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "session.eject_iso", "session", id, ip, nil)
	return nil
}

// GetSession returns one org-scoped instance (for the detail screen).
func (s *Service) GetSession(p *Principal, id string) (*session.Session, error) {
	return s.sessionInOrg(p, id)
}

// SessionEvents returns the audit trail for one instance.
func (s *Service) SessionEvents(p *Principal, id string) ([]store.AuditEntry, error) {
	if _, err := s.sessionInOrg(p, id); err != nil {
		return nil, err
	}
	return s.store.ListAuditForTarget(p.OrgID, "session", id, 50)
}

// ResizeSession changes an offline instance's specs (CPU/mem/disk).
func (s *Service) ResizeSession(p *Principal, id string, cpus, mem, diskGB int, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.Resize(id, cpus, mem, diskGB); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "session.resize", "session", id, ip, map[string]any{"cpus": cpus, "memory_mb": mem, "disk_gb": diskGB})
	return nil
}

// sessionInOrg loads a session and verifies the principal may act on it.
func (s *Service) sessionInOrg(p *Principal, id string) (*session.Session, error) {
	sess, err := s.mgr.Get(id)
	if err != nil {
		return nil, ErrNotFound
	}
	if !p.IsAdmin && sess.OrgID != p.OrgID {
		return nil, ErrUnauthorized
	}
	return sess, nil
}

func (s *Service) StartSession(p *Principal, id, ip string) (*session.Session, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, id)
	if err != nil {
		return nil, err
	}
	if err := s.checkQuotaStart(sess.OrgID); err != nil {
		return nil, err
	}
	kind := policy.SessionKind(sess.Kind)
	if d := s.enf.CanStartSession(context.Background(), sess.OrgID, kind, s.counts(sess.OrgID)); !d.Allow {
		return nil, errors.New(d.Reason)
	}
	// Auto-placement: pick the least-loaded node and record it on the session.
	// Single-host installs resolve to the local node; multi-node clusters place
	// by live gossiped capacity.
	if s.cl != nil {
		_, _ = s.cl.PlaceSession(id, sess.MemoryMB)
	}
	out, err := s.mgr.Start(id)
	if err != nil {
		return nil, err
	}
	s.audit(p, sess.OrgID, "session.start", "session", id, ip, nil)
	return out, nil
}

func (s *Service) StopSession(p *Principal, id, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.Stop(id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "session.stop", "session", id, ip, nil)
	return nil
}

func (s *Service) DeleteSession(p *Principal, id, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, id)
	if err != nil {
		return err
	}
	if err := s.mgr.Delete(id); err != nil {
		return err
	}
	s.audit(p, sess.OrgID, "session.delete", "session", id, ip, nil)
	return nil
}

// ConsoleTarget authorizes console access (B2: the single check both the HTML
// console page and the websocket proxy use) and returns the live session.
func (s *Service) ConsoleTarget(p *Principal, id string) (*session.Session, error) {
	sess, err := s.sessionInOrg(p, id)
	if err != nil {
		return nil, err
	}
	if !s.mgr.Running(sess) {
		return nil, fmt.Errorf("session not running")
	}
	return sess, nil
}

// DesktopInfo is the resolved target for the browser-desktop gateway.
type DesktopInfo struct {
	SessionID string
	Name      string
	Protocol  string // rdp | vnc
	Hostname  string
	Port      string
	Username  string
	Password  string
}

// DesktopTarget authorizes browser-desktop access (same check as ConsoleTarget)
// and resolves how guacd should reach the guest. When the VM has a routable
// overlay/bridge lease it uses the configured protocol (RDP by default, which
// carries clipboard/audio/mic/webcam) against the guest's own IP and cloud-init
// credentials. Otherwise it falls back to VNC against the loopback QEMU display,
// which always works regardless of guest OS or networking mode.
func (s *Service) DesktopTarget(p *Principal, id string) (*DesktopInfo, error) {
	sess, err := s.ConsoleTarget(p, id)
	if err != nil {
		return nil, err
	}
	return s.desktopInfoFor(sess), nil
}

// DesktopTargetByToken authorizes desktop access via a signed connection token
// (the public portal path). The token itself is the grant — it names the exact
// session and user the broker leased — so it stands in for the org-membership
// check used by the cookie path.
func (s *Service) DesktopTargetByToken(token, id string) (*DesktopInfo, error) {
	if s.signer == nil {
		return nil, ErrUnauthorized
	}
	c, err := s.signer.Verify(token)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if c.SessionID != id {
		return nil, ErrUnauthorized
	}
	sess, err := s.mgr.Get(id)
	if err != nil {
		return nil, ErrNotFound
	}
	if !s.mgr.Running(sess) {
		return nil, errors.New("session not running")
	}
	if s.pools != nil {
		s.pools.Touch(id)
	}
	return s.desktopInfoFor(sess), nil
}

// desktopInfoFor resolves how guacd should reach a guest. With a routable
// overlay/bridge lease it uses the configured protocol (RDP by default, which
// carries clipboard/audio/mic/webcam) against the guest's own IP and cloud-init
// credentials; otherwise it falls back to VNC against the loopback QEMU display.
func (s *Service) desktopInfoFor(sess *session.Session) *DesktopInfo {
	di := &DesktopInfo{SessionID: sess.ID, Name: sess.Name}
	leaseIP := ""
	if s.net != nil {
		leaseIP = s.net.LeaseFor(sess.ID)
	}
	proto := s.cfg.Gateway.Protocol
	if proto == "" {
		proto = "rdp"
	}
	// SPICE VMs: the guac gateway speaks SPICE straight to the loopback port.
	if sess.Display == "spice" && sess.SPICEPort > 0 {
		di.Protocol = "spice"
		di.Hostname = "127.0.0.1"
		di.Port = strconv.Itoa(sess.SPICEPort)
		return di
	}
	if leaseIP != "" && proto == "rdp" {
		di.Protocol = "rdp"
		di.Hostname = leaseIP
		di.Port = "3389"
		di.Username = sess.CIUsername
		di.Password = sess.CIPassword
		return di
	}
	di.Protocol = "vnc"
	di.Hostname = "127.0.0.1"
	di.Port = strconv.Itoa(sess.VNCPort)
	di.Password = sess.VNCPassword
	return di
}

// ---- orgs & members ------------------------------------------------------

func (s *Service) CreateOrg(p *Principal, name, slug, ip string) (int64, error) {
	if !p.IsAdmin {
		return 0, ErrUnauthorized
	}
	id, err := s.store.CreateOrg(name, slug)
	if err != nil {
		return 0, err
	}
	_ = s.store.AddMember(id, p.User.ID, "owner")
	s.audit(p, id, "org.create", "org", slug, ip, map[string]any{"name": name})
	return id, nil
}

func (s *Service) ListMembers(p *Principal) ([]store.Member, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	return s.store.ListMembers(p.OrgID)
}

func (s *Service) AddMember(p *Principal, username, role, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if roleRank[role] == 0 {
		return errors.New("invalid role")
	}
	uid, err := s.store.UserIDByName(username)
	if err != nil {
		return fmt.Errorf("no such user %q", username)
	}
	if err := s.store.AddMember(p.OrgID, uid, role); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "member.add", "user", username, ip, map[string]any{"role": role})
	return nil
}

func (s *Service) RemoveMember(p *Principal, userID int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.store.RemoveMember(p.OrgID, userID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "member.remove", "user", fmt.Sprint(userID), ip, nil)
	return nil
}

func (s *Service) ListUsers(p *Principal) ([]store.User, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return s.store.ListUsers()
}

// ---- API keys ------------------------------------------------------------

func (s *Service) CreateAPIKey(p *Principal, label string, readonly bool, ip string) (string, error) {
	if !p.atLeast("admin") {
		return "", ErrUnauthorized
	}
	scopes := `["read","write"]`
	if readonly {
		scopes = `["read"]`
	}
	plaintext, prefix, hash := auth.NewAPIKey()
	if _, err := s.store.CreateAPIKey(p.OrgID, hash, prefix, label, scopes); err != nil {
		return "", err
	}
	s.audit(p, p.OrgID, "apikey.create", "apikey", prefix, ip, map[string]any{"label": label, "readonly": readonly})
	return plaintext, nil
}

func (s *Service) ListAPIKeys(p *Principal) ([]store.APIKey, error) {
	if !p.atLeast("admin") {
		return nil, ErrUnauthorized
	}
	return s.store.ListAPIKeys(p.OrgID)
}

func (s *Service) RevokeAPIKey(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.store.RevokeAPIKey(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "apikey.revoke", "apikey", fmt.Sprint(id), ip, nil)
	return nil
}

// ---- audit ---------------------------------------------------------------

func (s *Service) ListAudit(p *Principal) ([]store.AuditEntry, error) {
	return s.ListAuditFiltered(p, "")
}

func (s *Service) ListAuditFiltered(p *Principal, actionPrefix string) ([]store.AuditEntry, error) {
	if !p.atLeast("admin") {
		return nil, ErrUnauthorized
	}
	return s.store.ListAuditFiltered(p.OrgID, actionPrefix, 200)
}
