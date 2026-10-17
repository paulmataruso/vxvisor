package service

import (
	"errors"
	"fmt"
	"time"

	"vdxclone/internal/broker"
	"vdxclone/internal/session"
)

// Broker wiring. The VDI broker lets a user open a desktop from a pool they are
// granted, minting a short-lived connection token the public desktop endpoint
// verifies per-connection. Pool administration is instance-admin only.

// SetBroker attaches the pool store and connection-token signer.
func (s *Service) SetBroker(ps *broker.PoolStore, sg *broker.Signer) {
	s.pools = ps
	s.signer = sg
}

// BrokerReady reports whether the VDI broker is configured.
func (s *Service) BrokerReady() bool { return s.pools != nil && s.signer != nil }

// ---- pool administration -------------------------------------------------

func (s *Service) CreatePool(p *Principal, pool broker.Pool, ip string) (int64, error) {
	if !p.IsAdmin || s.pools == nil {
		return 0, ErrUnauthorized
	}
	pool.OrgID = p.OrgID
	if pool.AssignMode != "persistent" {
		pool.AssignMode = "pooled"
	}
	id, err := s.pools.Create(pool)
	if err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "pool.create", "pool", fmt.Sprint(id), ip, map[string]any{"name": pool.Name, "mode": pool.AssignMode})
	return id, nil
}

func (s *Service) ListDesktopPools(p *Principal) ([]broker.Pool, error) {
	if s.pools == nil || !p.atLeast("viewer") {
		return nil, nil
	}
	return s.pools.List(p.OrgID)
}

func (s *Service) DeletePool(p *Principal, id int64, ip string) error {
	if !p.IsAdmin || s.pools == nil {
		return ErrUnauthorized
	}
	if err := s.pools.Delete(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "pool.delete", "pool", fmt.Sprint(id), ip, nil)
	return nil
}

func (s *Service) GrantPool(p *Principal, poolID int64, username, ip string) error {
	if !p.IsAdmin || s.pools == nil {
		return ErrUnauthorized
	}
	uid, err := s.store.UserIDByName(username)
	if err != nil {
		return ErrNotFound
	}
	if err := s.pools.Grant(poolID, uid); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "pool.grant", "pool", fmt.Sprint(poolID), ip, map[string]any{"user": username})
	return nil
}

// ---- the broker (user-facing) --------------------------------------------

// Desktop is one row in a user's "My Desktops" view.
type Desktop struct {
	PoolID     int64
	PoolName   string
	AssignMode string
	SessionID  string // set when the user already holds a VM in this pool
	State      string
	Available  bool // a VM can be leased/created right now
}

// MyDesktops lists the pools a user may draw from and any desktop they hold.
func (s *Service) MyDesktops(p *Principal) ([]Desktop, error) {
	if s.pools == nil || p.User == nil {
		return nil, nil
	}
	pools, err := s.pools.PoolsForUser(p.User.ID)
	if err != nil {
		return nil, err
	}
	var out []Desktop
	for _, pool := range pools {
		d := Desktop{PoolID: pool.ID, PoolName: pool.Name, AssignMode: pool.AssignMode, Available: true}
		// Surface an already-held VM — PersistentVM returns the user's assigned VM
		// in the pool regardless of mode (dedicated for persistent, active lease for
		// pooled), so a connected pooled user sees "Open desktop" too.
		held, _ := s.pools.PersistentVM(pool.ID, p.User.ID)
		if held != "" {
			d.SessionID = held
			if sess, err := s.mgr.Get(held); err == nil {
				d.State = sess.State
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// ConnectDesktop leases (or creates) a desktop for the user from a pool they are
// granted, ensures it is running, and returns the session id plus a short-lived
// connection token for the desktop WebSocket.
func (s *Service) ConnectDesktop(p *Principal, poolID int64, ip string) (string, string, error) {
	if s.pools == nil || s.signer == nil || p.User == nil {
		return "", "", errors.New("broker not configured")
	}
	// Authorization: the user must be granted this pool.
	granted, err := s.pools.PoolsForUser(p.User.ID)
	if err != nil {
		return "", "", err
	}
	var pool *broker.Pool
	for i := range granted {
		if granted[i].ID == poolID {
			pool = &granted[i]
			break
		}
	}
	if pool == nil {
		return "", "", ErrUnauthorized
	}

	sid, err := s.acquireDesktop(p, pool)
	if err != nil {
		return "", "", err
	}
	// Ensure the VM is running.
	sess, err := s.mgr.Get(sid)
	if err != nil {
		return "", "", err
	}
	if !s.mgr.Running(sess) {
		if _, err := s.mgr.Start(sid); err != nil {
			return "", "", fmt.Errorf("start desktop: %w", err)
		}
	}
	s.pools.Touch(sid)
	s.audit(p, p.OrgID, "desktop.connect", "session", sid, ip, map[string]any{"pool": pool.Name})
	token := s.signer.Mint(sid, p.User.ID, 2*time.Minute)
	return sid, token, nil
}

// acquireDesktop resolves which VM the user should get, creating one within the
// pool's max_size when necessary.
func (s *Service) acquireDesktop(p *Principal, pool *broker.Pool) (string, error) {
	// Idempotent: if the user already holds a VM in this pool (dedicated or an
	// active lease), reuse it so re-connecting never spawns a duplicate.
	if sid, _ := s.pools.PersistentVM(pool.ID, p.User.ID); sid != "" {
		return sid, nil
	}
	if pool.AssignMode != "persistent" {
		if sid, _ := s.pools.FreeVM(pool.ID); sid != "" {
			if err := s.pools.Assign(sid, pool.ID, p.User.ID); err != nil {
				return "", err
			}
			return sid, nil
		}
	}
	// None available — create a new VM if the pool has headroom.
	n, _ := s.pools.CountVMs(pool.ID)
	if pool.MaxSize > 0 && n >= pool.MaxSize {
		return "", errors.New("desktop pool is at capacity — try again shortly")
	}
	// A Linux pool installs a lightweight XFCE+Firefox desktop on first boot so the
	// VDI VM shows a usable graphical desktop over VNC; a Windows pool brings its
	// own desktop. Guest agent on so the broker can read the VM's IP/health.
	desktop := ""
	if pool.OSType != "windows" {
		desktop = "xfce"
	}
	sess, err := s.mgr.Create(session.CreateOpts{
		OrgID:     pool.OrgID,
		OwnerID:   p.User.ID,
		Name:      fmt.Sprintf("%s-%s", pool.Name, shortID(p.User.Username)),
		ImageName: pool.ImageName,
		Kind:      "desktop",
		Firmware:  "uefi",
		OSType:    pool.OSType,
		Desktop:    desktop,
		GuestAgent: true,
		CPUs:      pool.CPUs,
		MemoryMB:  pool.MemoryMB,
		DiskGB:    pool.DiskGB,
		CloudInit:  true,
		CIUsername: p.User.Username,
	})
	if err != nil {
		return "", err
	}
	if err := s.pools.AddToPool(sess.ID, pool.ID); err != nil {
		return "", err
	}
	if err := s.pools.Assign(sess.ID, pool.ID, p.User.ID); err != nil {
		return "", err
	}
	return sess.ID, nil
}

// VerifyConnToken validates a connection token for the desktop WebSocket.
func (s *Service) VerifyConnToken(token string) (broker.Claims, error) {
	if s.signer == nil {
		return broker.Claims{}, errors.New("broker not configured")
	}
	return s.signer.Verify(token)
}

// ReleaseDesktop returns a pooled VM to the free set and stops it (persistent
// desktops are kept assigned). Called on disconnect and by the idle reaper.
func (s *Service) ReleaseDesktop(sessionID string) {
	if s.pools == nil {
		return
	}
	sess, err := s.mgr.Get(sessionID)
	if err != nil || sess.PoolID == 0 {
		return
	}
	// Persistent desktops stay with their user; only stop them.
	if s.poolMode(sess.PoolID) == "pooled" {
		_ = s.pools.Release(sessionID)
	}
	_ = s.mgr.Stop(sessionID)
}

func (s *Service) poolMode(poolID int64) string {
	if p, err := s.pools.Get(poolID); err == nil {
		return p.AssignMode
	}
	return "pooled"
}

// TouchDesktop records activity so the idle reaper leaves an active session be.
func (s *Service) TouchDesktop(sessionID string) {
	if s.pools != nil {
		s.pools.Touch(sessionID)
	}
}

// ReclaimIdle stops and frees pooled desktops idle past the configured timeout.
// It is driven by a background worker. Returns the number reclaimed.
func (s *Service) ReclaimIdle() int {
	if s.pools == nil {
		return 0
	}
	idle := time.Duration(s.cfg.Broker.IdleMinutes) * time.Minute
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	ids, err := s.pools.IdleLeased(idle)
	if err != nil {
		return 0
	}
	for _, id := range ids {
		s.ReleaseDesktop(id)
	}
	s.EnsureWarmPools() // top pools back up to their warm size after reclaiming
	return len(ids)
}

// EnsureWarmPools pre-provisions free desktops so a pool always has at least
// MinSize VMs ready to lease (removing the create-a-VM latency from Connect),
// never exceeding MaxSize. Pre-created VMs are left stopped+unassigned; Connect
// leases and starts one. Returns how many it created.
func (s *Service) EnsureWarmPools() int {
	if s.pools == nil {
		return 0
	}
	pools, err := s.pools.AllPools()
	if err != nil {
		return 0
	}
	created := 0
	for _, pool := range pools {
		if pool.MinSize <= 0 || pool.AssignMode == "persistent" {
			continue // warm pool only makes sense for pooled
		}
		free, _ := s.pools.FreeCount(pool.ID)
		total, _ := s.pools.CountVMs(pool.ID)
		for free < pool.MinSize && (pool.MaxSize <= 0 || total < pool.MaxSize) {
			sess, err := s.mgr.Create(session.CreateOpts{
				OrgID: pool.OrgID, OwnerID: 0,
				Name:      fmt.Sprintf("%s-warm-%d", pool.Name, time.Now().UnixNano()%1000000),
				ImageName: pool.ImageName, Kind: "desktop", Firmware: "uefi",
				CPUs: pool.CPUs, MemoryMB: pool.MemoryMB, DiskGB: pool.DiskGB,
				CloudInit: true, CIUsername: "vdx",
			})
			if err != nil {
				break // out of space / image missing — stop topping up this pool
			}
			if err := s.pools.AddToPool(sess.ID, pool.ID); err != nil {
				break
			}
			free++
			total++
			created++
		}
	}
	return created
}

func shortID(s string) string {
	if len(s) > 6 {
		return s[:6]
	}
	return s
}

// ---- published app library -----------------------------------------------

// ListApps returns all published apps in the admin's org.
func (s *Service) ListApps(p *Principal) ([]broker.App, error) {
	if !p.IsAdmin || s.pools == nil {
		return nil, ErrUnauthorized
	}
	return s.pools.ListApps(p.OrgID)
}

// CreateApp publishes an app (admin). Pool-backed kinds require a pool; web
// requires a target URL.
func (s *Service) CreateApp(p *Principal, a broker.App, ip string) (int64, error) {
	if !p.IsAdmin || s.pools == nil {
		return 0, ErrUnauthorized
	}
	a.OrgID = p.OrgID
	switch a.Kind {
	case "web":
		if a.Target == "" {
			return 0, errors.New("a web app needs a target URL")
		}
		a.PoolID = 0
	case "desktop", "remoteapp":
		if a.PoolID == 0 {
			return 0, errors.New("a desktop/remoteapp app needs a backing pool")
		}
		if a.Kind == "remoteapp" && a.Target == "" {
			return 0, errors.New("a RemoteApp needs a program (target)")
		}
	default:
		return 0, errors.New("unknown app kind")
	}
	id, err := s.pools.CreateApp(a)
	if err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "app.create", "app", fmt.Sprint(id), ip, map[string]any{"name": a.Name, "kind": a.Kind})
	return id, nil
}

// DeleteApp removes a published app (admin).
func (s *Service) DeleteApp(p *Principal, id int64, ip string) error {
	if !p.IsAdmin || s.pools == nil {
		return ErrUnauthorized
	}
	if err := s.pools.DeleteApp(p.OrgID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "app.delete", "app", fmt.Sprint(id), ip, nil)
	return nil
}

// MyApps returns the apps a portal user may launch.
func (s *Service) MyApps(p *Principal) ([]broker.App, error) {
	if s.pools == nil || p.User == nil {
		return nil, nil
	}
	return s.pools.AppsForUser(p.User.ID)
}

// ConnectApp launches a published app. For a web app it returns (webURL) and the
// caller redirects there. For desktop/remoteapp it leases the backing pool VM
// and returns a desktop redirect ("/desktop/{sid}?t={token}"); a RemoteApp pins
// its seamless program into the token.
func (s *Service) ConnectApp(p *Principal, appID int64, ip string) (redirect string, err error) {
	if s.pools == nil || p.User == nil {
		return "", errors.New("broker not configured")
	}
	// Authorization: the app must be in the user's launchable set.
	apps, err := s.pools.AppsForUser(p.User.ID)
	if err != nil {
		return "", err
	}
	var app *broker.App
	for i := range apps {
		if apps[i].ID == appID {
			app = &apps[i]
			break
		}
	}
	if app == nil {
		return "", ErrUnauthorized
	}
	if app.Kind == "web" {
		s.audit(p, p.OrgID, "app.launch", "app", fmt.Sprint(appID), ip, map[string]any{"kind": "web"})
		return app.Target, nil
	}
	if s.signer == nil {
		return "", errors.New("broker not configured")
	}
	pool, err := s.pools.Get(app.PoolID)
	if err != nil {
		return "", ErrNotFound
	}
	sid, err := s.acquireDesktop(p, &pool)
	if err != nil {
		return "", err
	}
	sess, err := s.mgr.Get(sid)
	if err != nil {
		return "", err
	}
	if !s.mgr.Running(sess) {
		if _, err := s.mgr.Start(sid); err != nil {
			return "", fmt.Errorf("start app: %w", err)
		}
	}
	s.pools.Touch(sid)
	remoteApp := ""
	if app.Kind == "remoteapp" {
		remoteApp = app.Target
	}
	s.audit(p, p.OrgID, "app.launch", "app", fmt.Sprint(appID), ip, map[string]any{"kind": app.Kind, "pool": pool.Name})
	token := s.signer.MintApp(sid, p.User.ID, 2*time.Minute, remoteApp, app.Args)
	return "/desktop/" + sid + "?t=" + token, nil
}
