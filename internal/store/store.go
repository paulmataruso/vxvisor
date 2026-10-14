// Package store is the typed data-access layer. It owns SQL for tenancy
// entities (orgs, members, audit, API keys, users) so the service layer never
// writes raw queries. The session/image packages retain their own persistence.
package store

import (
	"database/sql"
	"errors"
	"time"

	"vdxclone/internal/db"
)

type Store struct{ db *db.DB }

func New(d *db.DB) *Store { return &Store{db: d} }

// ---- orgs ----------------------------------------------------------------

type Org struct {
	ID        int64
	Name      string
	Slug      string
	CreatedAt string
}

func (s *Store) CreateOrg(name, slug string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO orgs(name, slug) VALUES(?,?)`, name, slug)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetOrg(id int64) (Org, error) {
	var o Org
	err := s.db.QueryRow(`SELECT id,name,slug,created_at FROM orgs WHERE id=?`, id).
		Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	return o, err
}

func (s *Store) OrgBySlug(slug string) (Org, error) {
	var o Org
	err := s.db.QueryRow(`SELECT id,name,slug,created_at FROM orgs WHERE slug=?`, slug).
		Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	return o, err
}

func (s *Store) DefaultOrgID() (int64, error) {
	o, err := s.OrgBySlug("default")
	return o.ID, err
}

func (s *Store) ListOrgs() ([]Org, error) {
	rows, err := s.db.Query(`SELECT id,name,slug,created_at FROM orgs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---- members -------------------------------------------------------------

type Member struct {
	OrgID    int64
	UserID   int64
	Role     string
	Username string
}

func (s *Store) AddMember(orgID, userID int64, role string) error {
	_, err := s.db.Exec(`INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)
		ON CONFLICT(org_id,user_id) DO UPDATE SET role=excluded.role`, orgID, userID, role)
	return err
}

func (s *Store) RemoveMember(orgID, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM org_members WHERE org_id=? AND user_id=?`, orgID, userID)
	return err
}

// OrgRole returns a user's role in an org and whether they are a member.
func (s *Store) OrgRole(orgID, userID int64) (string, bool) {
	var role string
	err := s.db.QueryRow(`SELECT role FROM org_members WHERE org_id=? AND user_id=?`, orgID, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		return "", false
	}
	return role, true
}

func (s *Store) ListMembers(orgID int64) ([]Member, error) {
	rows, err := s.db.Query(`SELECT m.org_id,m.user_id,m.role,u.username
		FROM org_members m JOIN users u ON u.id=m.user_id
		WHERE m.org_id=? ORDER BY u.username`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Role, &m.Username); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UserOrgs lists the orgs a user belongs to (instance admins see all orgs).
func (s *Store) UserOrgs(userID int64, isAdmin bool) ([]Org, error) {
	if isAdmin {
		return s.ListOrgs()
	}
	rows, err := s.db.Query(`SELECT o.id,o.name,o.slug,o.created_at
		FROM orgs o JOIN org_members m ON m.org_id=o.id
		WHERE m.user_id=? ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---- users (listing for admin screens) -----------------------------------

type User struct {
	ID       int64
	Username string
	Role     string
	Disabled bool
}

func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT id,username,role,disabled FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var dis int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &dis); err != nil {
			return nil, err
		}
		u.Disabled = dis != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UserIDByName(name string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM users WHERE username=?`, name).Scan(&id)
	return id, err
}

// ---- web session current-org --------------------------------------------

func (s *Store) SetCurrentOrg(token string, orgID int64) error {
	_, err := s.db.Exec(`UPDATE web_sessions SET current_org_id=? WHERE token=?`, orgID, token)
	return err
}

func (s *Store) CurrentOrg(token string) (int64, bool) {
	var id sql.NullInt64
	err := s.db.QueryRow(`SELECT current_org_id FROM web_sessions WHERE token=?`, token).Scan(&id)
	if err != nil || !id.Valid {
		return 0, false
	}
	return id.Int64, true
}

// ---- audit ---------------------------------------------------------------

type AuditEntry struct {
	ID         int64
	OrgID      int64
	ActorID    int64
	ActorKind  string
	Action     string
	TargetType string
	TargetID   string
	Detail     string
	IP         string
	CreatedAt  string
}

func (s *Store) Audit(e AuditEntry) {
	if e.ActorKind == "" {
		e.ActorKind = "user"
	}
	if e.Detail == "" {
		e.Detail = "{}"
	}
	_, _ = s.db.Exec(`INSERT INTO audit_log(org_id,actor_id,actor_kind,action,target_type,target_id,detail_json,ip)
		VALUES(?,?,?,?,?,?,?,?)`, e.OrgID, e.ActorID, e.ActorKind, e.Action, e.TargetType, e.TargetID, e.Detail, e.IP)
}

func (s *Store) ListAudit(orgID int64, limit int) ([]AuditEntry, error) {
	return s.ListAuditFiltered(orgID, "", limit)
}

// ListAuditFiltered lists an org's audit entries, optionally filtered by an
// action prefix (e.g. "session." or "snapshot.create").
func (s *Store) ListAuditFiltered(orgID int64, actionPrefix string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id,COALESCE(org_id,0),COALESCE(actor_id,0),actor_kind,action,target_type,target_id,detail_json,ip,created_at
		FROM audit_log WHERE org_id=?`
	args := []any{orgID}
	if actionPrefix != "" {
		q += ` AND action LIKE ?`
		args = append(args, actionPrefix+"%")
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.ActorID, &e.ActorKind, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAuditForTarget returns an org's audit entries for one target object.
func (s *Store) ListAuditForTarget(orgID int64, targetType, targetID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id,COALESCE(org_id,0),COALESCE(actor_id,0),actor_kind,action,target_type,target_id,detail_json,ip,created_at
		FROM audit_log WHERE org_id=? AND target_type=? AND target_id=? ORDER BY id DESC LIMIT ?`,
		orgID, targetType, targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.ActorID, &e.ActorKind, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IP, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- API keys ------------------------------------------------------------

type APIKey struct {
	ID        int64
	OrgID     int64
	Prefix    string
	Label     string
	CreatedAt string
	LastUsed  string
	Revoked   bool
}

func (s *Store) CreateAPIKey(orgID int64, hash, prefix, label, scopesJSON string) (int64, error) {
	if scopesJSON == "" {
		scopesJSON = `["read","write"]`
	}
	res, err := s.db.Exec(`INSERT INTO api_keys(org_id,hash,prefix,label,scopes_json) VALUES(?,?,?,?,?)`,
		orgID, hash, prefix, label, scopesJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListAPIKeys(orgID int64) ([]APIKey, error) {
	rows, err := s.db.Query(`SELECT id,org_id,prefix,label,created_at,COALESCE(last_used,''),revoked
		FROM api_keys WHERE org_id=? ORDER BY id DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var rev int
		if err := rows.Scan(&k.ID, &k.OrgID, &k.Prefix, &k.Label, &k.CreatedAt, &k.LastUsed, &rev); err != nil {
			return nil, err
		}
		k.Revoked = rev != 0
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(orgID, id int64) error {
	_, err := s.db.Exec(`UPDATE api_keys SET revoked=1 WHERE id=? AND org_id=?`, id, orgID)
	return err
}

// APIKeyByHash resolves a presented key hash to (orgID, keyID, scopesJSON) if active.
func (s *Store) APIKeyByHash(hash string) (orgID, keyID int64, scopesJSON string, ok bool) {
	var exp sql.NullString
	err := s.db.QueryRow(`SELECT id,org_id,expires_at,scopes_json FROM api_keys WHERE hash=? AND revoked=0`, hash).
		Scan(&keyID, &orgID, &exp, &scopesJSON)
	if err != nil {
		return 0, 0, "", false
	}
	if exp.Valid && exp.String != "" {
		if t, err := time.Parse(time.RFC3339, exp.String); err == nil && time.Now().After(t) {
			return 0, 0, "", false
		}
	}
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), keyID)
	return orgID, keyID, scopesJSON, true
}
