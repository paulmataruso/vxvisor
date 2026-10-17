package service

import (
	"database/sql"
	"errors"
	"time"
)

// VDI desktops: the simple model. A VDI desktop is just an existing VM tagged to
// a specific user. The user sees their tagged VM(s) on the portal and connects
// over VNC; an admin does the tagging. Tagged VMs are hidden from the regular
// instances list. One assignee per VM; a user may hold several.

// VDIDesktop is one tagged VM (admin view carries the assignee; portal view is
// the same shape for the current user).
type VDIDesktop struct {
	SessionID string
	Name      string
	OSType    string // linux | windows
	State     string
	UserID    int64
	Username  string
}

// vdiSessionIDs returns the set of VM ids tagged as VDI in an org, so the regular
// instances list can exclude them.
func (s *Service) vdiSessionIDs(orgID int64) map[string]bool {
	out := map[string]bool{}
	rows, err := s.db.Query(`SELECT session_id FROM vdi_desktops WHERE org_id=?`, orgID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// ListVDIDesktops returns every VDI-tagged VM in the caller's org (admin only).
func (s *Service) ListVDIDesktops(p *Principal) ([]VDIDesktop, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT v.session_id, s.name, COALESCE(s.os_type,'linux'), s.state, v.user_id, COALESCE(u.username,'(deleted user)')
		FROM vdi_desktops v
		JOIN sessions s ON s.id=v.session_id AND s.deleted_at IS NULL
		LEFT JOIN users u ON u.id=v.user_id
		WHERE v.org_id=? ORDER BY u.username, s.name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVDI(rows)
}

// MyVDIDesktops returns the VMs tagged to the calling user (portal view).
func (s *Service) MyVDIDesktops(p *Principal) ([]VDIDesktop, error) {
	if p.User == nil {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT v.session_id, s.name, COALESCE(s.os_type,'linux'), s.state, v.user_id, ?
		FROM vdi_desktops v
		JOIN sessions s ON s.id=v.session_id AND s.deleted_at IS NULL
		WHERE v.user_id=? ORDER BY s.name`, p.User.Username, p.User.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVDI(rows)
}

func scanVDI(rows *sql.Rows) ([]VDIDesktop, error) {
	var out []VDIDesktop
	for rows.Next() {
		var d VDIDesktop
		if err := rows.Scan(&d.SessionID, &d.Name, &d.OSType, &d.State, &d.UserID, &d.Username); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AssignVDI tags a VM to a user (admin only). Upsert: re-assigning moves it to the
// new user. The VM must be in the caller's org; the user must exist.
func (s *Service) AssignVDI(p *Principal, sessionID, username, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if sessionID == "" || username == "" {
		return errors.New("pick a VM and a user")
	}
	// VM must exist in this org.
	var exists int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=? AND org_id=? AND deleted_at IS NULL`, sessionID, p.OrgID).Scan(&exists)
	if exists == 0 {
		return ErrNotFound
	}
	uid, err := s.store.UserIDByName(username)
	if err != nil {
		return errors.New("no such user: " + username)
	}
	if _, err := s.db.Exec(`INSERT INTO vdi_desktops(session_id,user_id,org_id,created_at)
		VALUES(?,?,?,?)
		ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id`,
		sessionID, uid, p.OrgID, time.Now().UTC().Format("2006-01-02 15:04:05")); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vdi.assign", "session", sessionID, ip, map[string]any{"user": username})
	return nil
}

// UnassignVDI removes a VM's VDI tag (admin only); it returns to the regular
// instances list. The VM itself is untouched.
func (s *Service) UnassignVDI(p *Principal, sessionID, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if _, err := s.db.Exec(`DELETE FROM vdi_desktops WHERE session_id=? AND org_id=?`, sessionID, p.OrgID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vdi.unassign", "session", sessionID, ip, nil)
	return nil
}

// ConnectVDI authorizes the calling portal user for a VM tagged to them, ensures
// it is running, and mints a short-lived desktop connection token (VNC).
func (s *Service) ConnectVDI(p *Principal, sessionID, ip string) (string, error) {
	if p.User == nil || s.signer == nil {
		return "", errors.New("portal not configured")
	}
	var owner int64
	if err := s.db.QueryRow(`SELECT user_id FROM vdi_desktops WHERE session_id=?`, sessionID).Scan(&owner); err != nil {
		return "", ErrUnauthorized
	}
	if owner != p.User.ID {
		return "", ErrUnauthorized
	}
	sess, err := s.mgr.Get(sessionID)
	if err != nil {
		return "", ErrNotFound
	}
	if !s.mgr.Running(sess) {
		if _, err := s.mgr.Start(sessionID); err != nil {
			return "", err
		}
	}
	s.audit(p, p.OrgID, "vdi.connect", "session", sessionID, ip, nil)
	// A desktop session is long-lived and the noVNC client auto-reconnects on any
	// blip; the token is re-checked on every (re)connect of the loopback-VNC
	// bridge, so a 2-minute grant would break the desktop after the first drop.
	// The token names this exact user+VM and only unlocks a desktop they already
	// own, so a working-day grant is safe.
	return s.signer.Mint(sessionID, p.User.ID, 12*time.Hour), nil
}
