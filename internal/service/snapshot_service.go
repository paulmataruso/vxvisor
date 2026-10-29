package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"vdxclone/internal/session"
)

// ---- snapshots + instant clones (docs/SNAPSHOTS.md) ----------------------
//
// Authz: any member of the VM's org (or an instance admin) may snapshot, revert,
// delete and clone; immutability and clone dependencies are enforced by the
// engine (session/snapshots.go) for every caller, admins included.

// Re-exported engine errors so web/api can map them.
var (
	ErrImmutable = session.ErrImmutable
	ErrHasClones = session.ErrHasClones
)

const maxSnapName = 80

func snapName(name string, now time.Time) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "snapshot " + now.Format("2006-01-02 15:04")
	}
	if len(name) > maxSnapName {
		return "", fmt.Errorf("snapshot name is too long (max %d characters)", maxSnapName)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("snapshot name contains control characters")
		}
	}
	return name, nil
}

// ListSnapshots returns an instance's snapshots, newest first.
func (s *Service) ListSnapshots(p *Principal, sessionID string) ([]session.SnapRecord, error) {
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return nil, err
	}
	return s.mgr.ListSnapshots(sessionID)
}

// CreateSnapshot snapshots an instance now (live: guest-frozen when its agent
// answers, else crash-consistent; stopped: offline).
func (s *Service) CreateSnapshot(p *Principal, sessionID, name, ip string) (session.SnapRecord, error) {
	if !p.atLeast("member") {
		return session.SnapRecord{}, ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return session.SnapRecord{}, err
	}
	name, err = snapName(name, time.Now())
	if err != nil {
		return session.SnapRecord{}, err
	}
	r, err := s.mgr.TakeSnapshot(sessionID)
	if err != nil {
		return session.SnapRecord{}, err
	}
	snapID, err := s.mgr.RecordSnapshot(sessionID, name, r, session.SnapMeta{})
	if err != nil {
		return session.SnapRecord{}, err
	}
	s.audit(p, sess.OrgID, "snapshot.create", "session", sessionID, ip, map[string]any{
		"name": name, "snapshot_id": snapID, "backend": r.Backend, "online": r.Online, "consistency": r.Consistency})
	return s.mgr.GetSnapshot(sessionID, snapID)
}

// RevertSnapshot restores a stopped instance to a snapshot. discardNewer
// confirms destroying newer snapshots where the backend needs it (ZFS).
func (s *Service) RevertSnapshot(p *Principal, sessionID string, snapID int64, discardNewer bool, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return err
	}
	sn, err := s.mgr.GetSnapshot(sessionID, snapID)
	if err != nil {
		return ErrNotFound
	}
	if err := s.mgr.RevertSnapshot(sessionID, snapID, discardNewer); err != nil {
		return err
	}
	s.audit(p, sess.OrgID, "snapshot.revert", "session", sessionID, ip, map[string]any{
		"snapshot": sn.Name, "snapshot_id": snapID, "backend": sn.Backend, "discard_newer": discardNewer})
	return nil
}

// DeleteSnapshot destroys a snapshot. Refused while it is immutable or instant
// clones depend on it.
func (s *Service) DeleteSnapshot(p *Principal, sessionID string, snapID int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	sess, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return err
	}
	sn, err := s.mgr.GetSnapshot(sessionID, snapID)
	if err != nil {
		return ErrNotFound
	}
	if err := s.mgr.DeleteSnapshot(sessionID, snapID); err != nil {
		return err
	}
	s.audit(p, sess.OrgID, "snapshot.delete", "session", sessionID, ip, map[string]any{
		"snapshot": sn.Name, "snapshot_id": snapID, "backend": sn.Backend})
	return nil
}

// CloneSession creates an instant clone of an instance from one of its
// snapshots, or (snapID 0) from its state right now via a transient snapshot.
// The clone lands in the origin's org (and folder), stopped, with a new identity.
func (s *Service) CloneSession(p *Principal, sessionID string, snapID int64, name, ip string) (*session.Session, error) {
	if !p.atLeast("member") || p.User == nil {
		return nil, ErrUnauthorized
	}
	origin, err := s.sessionInOrg(p, sessionID)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = origin.Name + "-clone"
	}
	if len(name) > 100 {
		return nil, errors.New("instance name is too long")
	}
	in := CreateInput{Kind: origin.Kind, CPUs: origin.CPUs, MemoryMB: origin.MemoryMB, DiskGB: origin.DiskGB}
	if err := s.checkQuotaCreate(origin.OrgID, in); err != nil {
		return nil, err
	}
	if origin.Kind == "server" {
		if d := s.enf.CanCreateServer(context.Background(), origin.OrgID, s.counts(origin.OrgID)); !d.Allow {
			return nil, errors.New(d.Reason)
		}
	}
	if err := s.vmPortGroupCheck(origin.OrgID, origin.NetworkID, true); err != nil {
		return nil, err
	}

	transient := int64(0)
	if snapID == 0 {
		r, err := s.mgr.TakeSnapshot(sessionID)
		if err != nil {
			return nil, err
		}
		snapID, err = s.mgr.RecordSnapshot(sessionID, "clone base "+time.Now().Format("2006-01-02 15:04"), r,
			session.SnapMeta{Transient: true})
		if err != nil {
			return nil, err
		}
		transient = snapID
	} else if _, err := s.mgr.GetSnapshot(sessionID, snapID); err != nil {
		return nil, ErrNotFound
	}
	sn, _ := s.mgr.GetSnapshot(sessionID, snapID)

	clone, cerr := s.mgr.CloneFromSnapshot(session.CloneOpts{OriginID: sessionID, SnapID: snapID, Name: name, OwnerID: p.User.ID})
	if transient > 0 {
		// A clone base nothing depends on (a failed clone, or a backend whose
		// clones are independent copies) is removed right away; a dependent
		// clone's base stays until that clone is purged or made independent.
		if l, ok := s.mgr.CloneLinkOf(cloneID(clone)); cerr != nil || !ok || l.SnapshotID == 0 {
			_ = s.mgr.DeleteSnapshot(sessionID, transient)
		}
	}
	if cerr != nil {
		return nil, cerr
	}
	// Same folder as the origin.
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO vm_folder_members(vm_id, org_id, folder_id)
		SELECT ?, org_id, folder_id FROM vm_folder_members WHERE vm_id=? AND org_id=?`, clone.ID, sessionID, origin.OrgID)
	l, _ := s.mgr.CloneLinkOf(clone.ID)
	s.audit(p, origin.OrgID, "session.clone", "session", clone.ID, ip, map[string]any{
		"name": clone.Name, "origin": sessionID, "origin_name": origin.Name, "snapshot": sn.Name,
		"from_now": transient > 0, "backend": l.Backend, "method": l.Method, "dependent": l.SnapshotID > 0})
	return clone, nil
}

func cloneID(s *session.Session) string {
	if s == nil {
		return ""
	}
	return s.ID
}

// CloneLink returns where an instance was cloned from (if it is a clone).
func (s *Service) CloneLink(p *Principal, sessionID string) (session.CloneLink, bool) {
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return session.CloneLink{}, false
	}
	return s.mgr.CloneLinkOf(sessionID)
}

// snapshotMoveGuard refuses a storage move / host migration of an instance with
// snapshots or a dependent-clone tie: the snapshots live on its current storage
// (and in this node's DB), and a dependent clone shares blocks with its origin.
func (s *Service) snapshotMoveGuard(sessionID string) error {
	n, dep := s.mgr.HasSnapshotDeps(sessionID)
	if n > 0 {
		return fmt.Errorf("this instance has %d snapshot(s) on its current storage; delete them before moving or migrating it", n)
	}
	if dep {
		return errors.New("this instance is an instant clone that still shares storage with its origin's snapshot, so it can't be moved yet (purging the origin makes it independent)")
	}
	return nil
}
