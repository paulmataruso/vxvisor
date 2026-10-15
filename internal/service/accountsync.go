package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// Cluster-wide account replication. In cluster mode the leader is the authority
// for account state; followers pull a snapshot of the account tables and upsert
// it locally so a login (and API-key auth) works on any node and via the VIP.
//
// This is UPSERT-only by design: rows are inserted/updated by primary key but
// never deleted on followers. That deliberately avoids SQLite's ON DELETE CASCADE
// from users→sessions wiping a follower's running VMs during a sync. New users,
// password changes and role changes propagate; account DELETIONS do not yet
// propagate to followers (documented limitation — do destructive account ops at
// the VIP/leader, which holds the authority). Account writes on a follower are
// refused (see guardClusterWrite) so the leader's snapshot is never clobbered.

type acctUser struct {
	ID           int64  `json:"id"`
	Username     string `json:"u"`
	PasswordHash string `json:"p"`
	Role         string `json:"r"`
	CreatedAt    string `json:"c"`
}
type acctOrg struct {
	ID        int64  `json:"id"`
	Name      string `json:"n"`
	Slug      string `json:"s"`
	CreatedAt string `json:"c"`
	Settings  string `json:"j"`
}
type acctMember struct {
	OrgID  int64  `json:"o"`
	UserID int64  `json:"u"`
	Role   string `json:"r"`
}
type acctKey struct {
	ID        int64          `json:"id"`
	OrgID     int64          `json:"o"`
	Hash      string         `json:"h"`
	Prefix    string         `json:"p"`
	Label     string         `json:"l"`
	Scopes    string         `json:"s"`
	CreatedAt string         `json:"c"`
	LastUsed  sql.NullString `json:"lu"`
}

// AccountSnapshot is the replicated account state (leader → followers).
type AccountSnapshot struct {
	Users   []acctUser   `json:"users"`
	Orgs    []acctOrg    `json:"orgs"`
	Members []acctMember `json:"members"`
	Keys    []acctKey    `json:"keys"`
	// AD is the raw settings['ad_config'] blob (bind password already sealed with
	// the shared cluster.key, so it decrypts on every node). Replicated so AD
	// sign-in configured once at the VIP/leader applies cluster-wide. omitempty
	// keeps older followers forward-compatible.
	AD string `json:"ad,omitempty"`
}

// AccountSnapshotJSON dumps the account tables as JSON (served by the peer API on
// the leader).
func (s *Service) AccountSnapshotJSON() ([]byte, error) {
	var snap AccountSnapshot
	rows, err := s.db.Query(`SELECT id,username,password_hash,role,created_at FROM users`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u acctUser
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt); err == nil {
			snap.Users = append(snap.Users, u)
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT id,name,slug,created_at,settings_json FROM orgs`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var o acctOrg
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.Settings); err == nil {
			snap.Orgs = append(snap.Orgs, o)
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT org_id,user_id,role FROM org_members`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m acctMember
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Role); err == nil {
			snap.Members = append(snap.Members, m)
		}
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT id,org_id,hash,prefix,label,scopes_json,created_at,last_used FROM api_keys`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k acctKey
		if err := rows.Scan(&k.ID, &k.OrgID, &k.Hash, &k.Prefix, &k.Label, &k.Scopes, &k.CreatedAt, &k.LastUsed); err == nil {
			snap.Keys = append(snap.Keys, k)
		}
	}
	rows.Close()
	// AD config (if an admin has saved it) — replicate so it applies cluster-wide.
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, adSettingsKey).Scan(&snap.AD)
	return json.Marshal(snap)
}

// ApplyAccountSnapshot upserts a leader's account snapshot into the local DB.
// Parents (orgs, users) are applied before children (members, keys) so foreign
// keys hold. Upsert-only — see the package note on why we never delete here.
func (s *Service) ApplyAccountSnapshot(data []byte) error {
	var snap AccountSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("decode account snapshot: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, o := range snap.Orgs {
		if _, err := tx.Exec(`INSERT INTO orgs(id,name,slug,created_at,settings_json) VALUES(?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,slug=excluded.slug,settings_json=excluded.settings_json`,
			o.ID, o.Name, o.Slug, o.CreatedAt, o.Settings); err != nil {
			return fmt.Errorf("apply org %d: %w", o.ID, err)
		}
	}
	for _, u := range snap.Users {
		if _, err := tx.Exec(`INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET username=excluded.username,password_hash=excluded.password_hash,role=excluded.role`,
			u.ID, u.Username, u.PasswordHash, u.Role, u.CreatedAt); err != nil {
			return fmt.Errorf("apply user %d: %w", u.ID, err)
		}
	}
	for _, m := range snap.Members {
		if _, err := tx.Exec(`INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)
			ON CONFLICT(org_id,user_id) DO UPDATE SET role=excluded.role`,
			m.OrgID, m.UserID, m.Role); err != nil {
			return fmt.Errorf("apply member %d/%d: %w", m.OrgID, m.UserID, err)
		}
	}
	for _, k := range snap.Keys {
		if _, err := tx.Exec(`INSERT INTO api_keys(id,org_id,hash,prefix,label,scopes_json,created_at,last_used) VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET label=excluded.label,scopes_json=excluded.scopes_json`,
			k.ID, k.OrgID, k.Hash, k.Prefix, k.Label, k.Scopes, k.CreatedAt, k.LastUsed); err != nil {
			return fmt.Errorf("apply key %d: %w", k.ID, err)
		}
	}
	adChanged := false
	if snap.AD != "" {
		var cur string
		_ = tx.QueryRow(`SELECT value FROM settings WHERE key=?`, adSettingsKey).Scan(&cur)
		if cur != snap.AD {
			if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
				ON CONFLICT(key) DO UPDATE SET value=excluded.value`, adSettingsKey, snap.AD); err != nil {
				return fmt.Errorf("apply ad config: %w", err)
			}
			adChanged = true
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Push the leader's AD config to this follower's live provider (no restart).
	if adChanged && s.adReload != nil {
		s.adReload(s.ADConfig())
	}
	return nil
}
