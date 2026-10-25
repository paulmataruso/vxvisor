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
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"vdxclone/internal/auth"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/policy"
	"vdxclone/internal/qemu"
	"vdxclone/internal/cluster"
	"vdxclone/internal/metrics"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/peer"
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
	role   *cluster.Role
	peerc  *peer.Client
	migtr  *migTracker
	joins  *joinTracker
	vmwimp *vmwImportTracker
	vmwexp *vmExportTracker
	// adReload, when registered by the web layer, pushes a freshly-saved or
	// freshly-replicated AD config to the live auth provider (no restart). Lets a
	// follower apply the leader's AD settings the moment a snapshot lands.
	adReload func(config.ADConfig)
}

func New(cfg *config.Config, d *db.DB, st *store.Store, stg *storage.Store, net *netdrv.Store, mgr *session.Manager, enf policy.Enforcer) *Service {
	s := &Service{cfg: cfg, db: d, store: st, stg: stg, net: net, mgr: mgr, enf: enf, migtr: newMigTracker(), joins: newJoinTracker(), vmwimp: newVmwImportTracker(), vmwexp: newVMExportTracker()}
	s.reloadExports() // re-register export files left on disk so they stay listable/deletable across restarts
	return s
}

// SetADReloadHook registers the callback that applies AD config to the live
// auth provider. The web layer passes its provider's SetConfig.
func (s *Service) SetADReloadHook(fn func(config.ADConfig)) { s.adReload = fn }

// SetMetrics attaches the metrics collector so the web layer can read it.
func (s *Service) SetMetrics(mc *metrics.Collector) { s.mc = mc }
func (s *Service) Metrics() *metrics.Collector      { return s.mc }

// SetCluster attaches the cluster store.
func (s *Service) SetCluster(cl *cluster.Store) { s.cl = cl }
func (s *Service) Cluster() *cluster.Store      { return s.cl }

// SetClusterRuntime attaches the live election role + a peer-API client (built
// from the shared cluster secret) so the service can aggregate across nodes and
// followers can pull account state from the leader.
func (s *Service) SetClusterRuntime(role *cluster.Role, secret []byte) {
	s.role = role
	s.peerc = peer.NewClient(secret)
}

// Role returns the cluster election role (nil on a single-host install).
func (s *Service) Role() *cluster.Role { return s.role }

// ClusterEnabled reports whether this node runs in cluster mode.
func (s *Service) ClusterEnabled() bool { return s.role != nil }

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
	// Unified is set by the web layer per-request: true when the request arrived
	// on the cluster management VIP (→ unified, cluster-wide "vCenter" view),
	// false when it arrived on a node's own mgmt IP (→ standalone "ESXi host" view).
	Unified bool
	// TrustedPeer marks a principal built from an authenticated cluster-admin
	// reverse-proxy request (another node acting for an admin on the VIP). CSRF is
	// enforced at the originating node, so it is bypassed for these.
	TrustedPeer bool
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

// TrustedAdminPrincipal builds a principal for an authenticated cluster-admin
// reverse-proxy request (the owning node acting on behalf of an admin who is
// logged in at the VIP). The HMAC cluster header is verified by the caller; here
// we just load the named user and require instance-admin. Admins bypass per-org
// scoping (see sessionInOrg), so the VM's org need not match.
func (s *Service) TrustedAdminPrincipal(username string) *Principal {
	u, err := auth.UserByName(s.db, username)
	if err != nil || u == nil || u.Role != "admin" {
		return nil
	}
	orgs, _ := s.store.UserOrgs(u.ID, true)
	var cur int64
	if len(orgs) > 0 {
		cur = orgs[0].ID
	}
	role, _ := s.store.OrgRole(cur, u.ID)
	return &Principal{User: u, OrgID: cur, OrgRole: role, IsAdmin: true, Orgs: orgs,
		ActorKind: "user", TrustedPeer: true}
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
	name := ""
	if p.User != nil && kind == "user" {
		name = p.User.Username
	}
	s.store.Audit(store.AuditEntry{
		OrgID: orgID, ActorID: p.User.ID, ActorKind: kind, ActorName: name,
		Action: action, TargetType: targetType, TargetID: targetID, Detail: d, IP: ip,
	})
}

// AuditAuth records an authentication event (login / logout / failed login /
// password change). It takes the actor identity explicitly because these happen
// at the edges of a session, where a Principal may not exist yet (failed login)
// or is being torn down (logout). Never pass a password in detail.
func (s *Service) AuditAuth(actorID int64, actorName, action, ip string, detail any) {
	kind := "user"
	if actorID == 0 {
		kind = "system" // unauthenticated attempt — no real identity
	}
	d := "{}"
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	s.store.Audit(store.AuditEntry{
		ActorID: actorID, ActorKind: kind, ActorName: actorName,
		Action: action, TargetType: "auth", Detail: d, IP: ip,
	})
}

// SysAudit records an action taken by the control plane itself (scheduled backup,
// retention deprovision, crash recovery) with no human actor — tied to "system"
// so the trail still answers who/what/when with zero ambiguity.
func (s *Service) SysAudit(orgID int64, action, targetType, targetID string, detail any) {
	d := "{}"
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	s.store.Audit(store.AuditEntry{
		OrgID: orgID, ActorID: 0, ActorKind: "system", ActorName: "system",
		Action: action, TargetType: targetType, TargetID: targetID, Detail: d, IP: "",
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
	MAC           string // pin the NIC MAC (preserved from a VMware import); "" = generate
	StoragePoolID int64  // storage pool for the disk; 0 = default disk dir
	Display       string // vnc | spice
	DiskBackend   string // qcow2 | zvol | lvm | rbd
	ZvolPool      string // ZFS pool name for the zvol (zvol backend)
	Desktop       string // "" | xfce
	// Hardware profile knobs (empty => safe defaults; see normalizeHardware).
	MachineType string // q35 | pc
	DiskBus     string // virtio-blk | virtio-scsi | sata
	NICModel    string // virtio | e1000e | rtl8139
	VGA         string // qxl | virtio | std
	GuestAgent  bool   // qemu-guest-agent channel
	TPM         bool   // swtpm TPM 2.0
	SecureBoot  bool   // UEFI Secure Boot
	OSType      string // linux | windows
	PinCPUs     bool   // pin vCPU threads 1:1 to host CPUs
	HugePages   bool   // back guest RAM with hugepages (host pool permitting)
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
		Passthrough: in.Passthrough, NetworkID: in.NetworkID, MAC: in.MAC, StoragePoolID: in.StoragePoolID, Display: in.Display,
		DiskBackend: in.DiskBackend, ZvolPool: in.ZvolPool, Desktop: in.Desktop,
		MachineType: in.MachineType, DiskBus: in.DiskBus, NICModel: in.NICModel, VGA: in.VGA,
		GuestAgent: in.GuestAgent, TPM: in.TPM, SecureBoot: in.SecureBoot, OSType: in.OSType,
		PinCPUs: in.PinCPUs, HugePages: in.HugePages,
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

// VirtioISOAvailable reports whether the virtio-win driver ISO is present on the
// host (so the UI can show an "eject virtio drivers" control only when relevant).
func (s *Service) VirtioISOAvailable() bool {
	return qemu.VirtioWinISO(s.cfg.Paths.ISODir) != ""
}

// EjectVirtioISO stops auto-attaching the virtio-win driver CD to a (Windows)
// instance — for after the drivers are installed. Takes effect on the next start.
func (s *Service) EjectVirtioISO(p *Principal, id, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.SetEjectVirtio(id, true); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "session.eject_virtio", "session", id, ip, nil)
	return nil
}

// MountVirtioISO (re)enables auto-attaching the virtio-win driver CD to a
// (Windows) instance — e.g. to install/repair drivers or the guest agent. Takes
// effect on the next start.
func (s *Service) MountVirtioISO(p *Principal, id, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.SetEjectVirtio(id, false); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "session.mount_virtio", "session", id, ip, nil)
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

// UpdateSessionSpec changes a stopped instance's hardware profile (firmware,
// machine type, disk bus, NIC model, graphics, OS type, and the agent/TPM/
// Secure Boot toggles). Applied on next start; never touches the data disk.
func (s *Service) UpdateSessionSpec(p *Principal, id string, hw session.HardwareSpec, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.UpdateHardware(id, hw); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "session.spec", "session", id, ip, map[string]any{
		"firmware": hw.Firmware, "os_type": hw.OSType, "machine_type": hw.MachineType,
		"disk_bus": hw.DiskBus, "nic_model": hw.NICModel, "vga": hw.VGA,
		"guest_agent": hw.GuestAgent, "tpm": hw.TPM, "secure_boot": hw.SecureBoot,
	})
	return nil
}

// SetSessionNetwork rebinds an instance's NIC to a different port group (network).
// 0 = default/NAT. The change is persisted now and applied when the tap attaches
// on the next start (same model as a resize), so it never disrupts a running NIC.
func (s *Service) SetSessionNetwork(p *Principal, id string, networkID int64, ip string) (live bool, err error) {
	if !p.atLeast("member") {
		return false, ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, id)
	if err != nil {
		return false, err
	}
	if networkID > 0 {
		if _, err := s.net.GetNetwork(sess.OrgID, networkID); err != nil {
			return false, fmt.Errorf("unknown port group")
		}
	}
	live, err = s.mgr.SetNetwork(id, networkID)
	if err != nil {
		return false, err
	}
	s.audit(p, p.OrgID, "session.network", "session", id, ip, map[string]any{"network_id": networkID, "live": live})
	return live, nil
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

// GuestAgentInfo returns qemu-guest-agent data for a VM this org owns (and that
// is hosted on this node). It degrades to an empty/non-responsive result rather
// than erroring, so the UI can always render.
func (s *Service) GuestAgentInfo(p *Principal, id string) (qemu.GuestInfo, error) {
	if _, err := s.sessionInOrg(p, id); err != nil {
		return qemu.GuestInfo{}, err
	}
	return s.mgr.GuestAgentInfo(id), nil
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

// RestartSession power-cycles a VM: a graceful stop (ACPI, then force if the
// guest ignores it) followed by a fresh start. It launches a new QEMU process,
// so any updated VM settings take effect. Quota/placement are not re-checked —
// a running VM already passed those and its resource use is unchanged.
func (s *Service) RestartSession(p *Principal, id, ip string) (*session.Session, error) {
	if !p.atLeast("member") {
		return nil, ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, id)
	if err != nil {
		return nil, err
	}
	if err := s.mgr.Stop(id); err != nil {
		return nil, err
	}
	if s.cl != nil {
		_, _ = s.cl.PlaceSession(id, sess.MemoryMB)
	}
	out, err := s.mgr.Start(id)
	if err != nil {
		return nil, err
	}
	s.audit(p, sess.OrgID, "session.restart", "session", id, ip, nil)
	return out, nil
}

// SetAutostart toggles a VM's "start at boot" flag (powered on automatically
// after a host reboot).
func (s *Service) SetAutostart(p *Principal, id string, on bool, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, id); err != nil {
		return err
	}
	if err := s.mgr.SetAutostart(id, on); err != nil {
		return err
	}
	action := "session.autostart.off"
	if on {
		action = "session.autostart.on"
	}
	s.audit(p, p.OrgID, action, "session", id, ip, nil)
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

// guestPrimaryIP finds a running guest's primary IPv4 — first from the guest
// agent's reported interfaces, else from the host's neighbor table by the VM's
// MAC. Empty when it can't be determined (e.g. no agent and no ARP entry yet).
func (s *Service) guestPrimaryIP(sess *session.Session) string {
	gi := s.mgr.GuestAgentInfo(sess.ID)
	if gi.Responsive {
		for _, nic := range gi.Interfaces {
			for _, ip := range nic.IPs {
				v := net.ParseIP(strings.SplitN(ip, "/", 2)[0])
				if v != nil && v.To4() != nil && !v.IsLoopback() && !v.IsLinkLocalUnicast() {
					return v.String()
				}
			}
		}
	}
	if sess.MAC != "" {
		if out, err := exec.Command("ip", "neigh").Output(); err == nil {
			mac := strings.ToLower(sess.MAC)
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.Contains(strings.ToLower(ln), mac) {
					if f := strings.Fields(ln); len(f) > 0 {
						if v := net.ParseIP(f[0]); v != nil && v.To4() != nil {
							return v.String()
						}
					}
				}
			}
		}
	}
	return ""
}

// rdpReachable reports whether an RDP server is listening on the guest's 3389,
// so we only route the browser desktop to RDP when it will actually paint.
func rdpReachable(ip string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "3389"), 600*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// ---- orgs & members ------------------------------------------------------

func (s *Service) CreateOrg(p *Principal, name, slug, ip string) (int64, error) {
	if !p.IsAdmin {
		return 0, ErrUnauthorized
	}
	if err := s.guardClusterWrite(); err != nil {
		return 0, err
	}
	id, err := s.store.CreateOrg(name, slug)
	if err != nil {
		return 0, err
	}
	_ = s.store.AddMember(id, p.User.ID, "owner")
	// Isolate the new org by default: give it a dedicated isolated tenant network
	// so its VMs don't share an L2 segment with other orgs. Best-effort — a
	// failure here must not fail org creation.
	s.provisionDefaultForOrg(id)
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
	if err := s.guardClusterWrite(); err != nil {
		return err
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
	if err := s.guardClusterWrite(); err != nil {
		return err
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

// minPasswordLen is intentionally small: this is an on-prem/self-hosted control
// plane where operators set their own policy (and bootstrap with short demo
// passwords). Keep it permissive, just reject empties/typos.
const minPasswordLen = 4

func validatePassword(pw string) error {
	if len(pw) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	return nil
}

// ChangeOwnPassword lets any authenticated interactive user change their own
// password after re-entering their current one. Not available to API-key
// principals (they have no password). In cluster mode it is guarded to the
// leader so the new hash replicates to followers.
func (s *Service) ChangeOwnPassword(p *Principal, current, next, ip string) error {
	if p.ActorKind == "apikey" || p.User == nil {
		return ErrUnauthorized
	}
	if err := s.guardClusterWrite(); err != nil {
		return err
	}
	if err := validatePassword(next); err != nil {
		return err
	}
	if !auth.CheckPassword(s.db, p.User.ID, current) {
		return errors.New("current password is incorrect")
	}
	if err := auth.SetPassword(s.db, p.User.ID, next); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "user.password.change", "user", p.User.Username, ip, nil)
	return nil
}

// AdminResetPassword lets an instance admin set another user's password without
// knowing the current one. Guarded to the cluster leader like other account
// writes so the change replicates.
func (s *Service) AdminResetPassword(p *Principal, userID int64, next, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.guardClusterWrite(); err != nil {
		return err
	}
	if err := validatePassword(next); err != nil {
		return err
	}
	if err := auth.SetPassword(s.db, userID, next); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "user.password.reset", "user", fmt.Sprint(userID), ip, nil)
	return nil
}

// ---- API keys ------------------------------------------------------------

func (s *Service) CreateAPIKey(p *Principal, label string, readonly bool, ip string) (string, error) {
	if !p.atLeast("admin") {
		return "", ErrUnauthorized
	}
	if err := s.guardClusterWrite(); err != nil {
		return "", err
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
