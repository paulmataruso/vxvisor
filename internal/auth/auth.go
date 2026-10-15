// Package auth handles password hashing and cookie-based web sessions.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"vdxclone/internal/db"
)

const cookieName = "vdx_session"
const sessionTTL = 7 * 24 * time.Hour

type User struct {
	ID       int64
	Username string
	Role     string
}

var ErrInvalidCredentials = errors.New("invalid username or password")
var ErrRateLimited = errors.New("too many failed attempts; try again shortly")

// CreateUser inserts a user with a bcrypt-hashed password and enrolls them in
// the default org (owner if an instance admin, else member) so every user has
// at least one org context.
func CreateUser(d *db.DB, username, password, role string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := d.Exec(`INSERT INTO users(username, password_hash, role) VALUES(?,?,?)`,
		username, string(hash), role)
	if err != nil {
		return err
	}
	uid, _ := res.LastInsertId()
	orgRole := "member"
	if role == "admin" {
		orgRole = "owner"
	}
	_, _ = d.Exec(`INSERT OR IGNORE INTO org_members(org_id, user_id, role)
		SELECT id, ?, ? FROM orgs WHERE slug='default'`, uid, orgRole)
	return nil
}

// UpsertOIDCUser maps an identity-provider subject to a local user, creating the
// user (with an unusable random password) and enrolling it in the default org on
// first login — "just-in-time" provisioning. Returns the local user id.
func UpsertOIDCUser(d *db.DB, sub, username, email string) (*User, error) {
	var u User
	// Existing mapping by subject.
	err := d.QueryRow(`SELECT id,username,role FROM users WHERE oidc_sub=?`, sub).Scan(&u.ID, &u.Username, &u.Role)
	if err == nil {
		return &u, nil
	}
	// Link an existing local account that shares the username, else create one.
	var existingID int64
	if e := d.QueryRow(`SELECT id FROM users WHERE username=?`, username).Scan(&existingID); e == nil {
		_, _ = d.Exec(`UPDATE users SET oidc_sub=? WHERE id=?`, sub, existingID)
		return &User{ID: existingID, Username: username}, nil
	}
	randPw := make([]byte, 24)
	_, _ = rand.Read(randPw)
	hash, err := bcrypt.GenerateFromPassword(randPw, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	res, err := d.Exec(`INSERT INTO users(username, password_hash, role, oidc_sub) VALUES(?,?,'user',?)`,
		username, string(hash), sub)
	if err != nil {
		return nil, err
	}
	uid, _ := res.LastInsertId()
	_, _ = d.Exec(`INSERT OR IGNORE INTO org_members(org_id, user_id, role)
		SELECT id, ?, 'member' FROM orgs WHERE slug='default'`, uid)
	return &User{ID: uid, Username: username, Role: "user"}, nil
}

// UpsertADUser JIT-provisions (or re-syncs) a user authenticated via Active
// Directory. The admin flag — derived from AD group membership — is re-evaluated
// on EVERY login (unlike OIDC, which is sticky) so revoking an AD admin group
// takes effect on next sign-in. A new user gets an unusable random local
// password (they can only ever authenticate via AD) and default-org membership.
func UpsertADUser(d *db.DB, username, dn string, admin bool) (*User, error) {
	role := "user"
	orgRole := "member"
	if admin {
		role, orgRole = "admin", "owner"
	}
	var id int64
	err := d.QueryRow(`SELECT id FROM users WHERE ad_dn=? OR username=?`, dn, username).Scan(&id)
	if err == nil {
		// Existing user → re-sync role + DN from AD each login.
		_, _ = d.Exec(`UPDATE users SET role=?, ad_dn=? WHERE id=?`, role, dn, id)
		_, _ = d.Exec(`UPDATE org_members SET role=? WHERE user_id=? AND org_id=(SELECT id FROM orgs WHERE slug='default')`, orgRole, id)
		return &User{ID: id, Username: username, Role: role}, nil
	}
	randPw := make([]byte, 24)
	_, _ = rand.Read(randPw)
	hash, err := bcrypt.GenerateFromPassword(randPw, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	res, err := d.Exec(`INSERT INTO users(username, password_hash, role, ad_dn) VALUES(?,?,?,?)`,
		username, string(hash), role, dn)
	if err != nil {
		return nil, err
	}
	uid, _ := res.LastInsertId()
	_, _ = d.Exec(`INSERT OR IGNORE INTO org_members(org_id, user_id, role)
		SELECT id, ?, ? FROM orgs WHERE slug='default'`, uid, orgRole)
	return &User{ID: uid, Username: username, Role: role}, nil
}

// ---- login throttle (per-username) ---------------------------------------
//
// bcrypt verification is deliberately expensive, which makes unthrottled login
// a CPU-exhaustion lever. Track recent failures and refuse once a threshold is
// crossed, for a short cooldown.

const maxFailures = 8
const failWindow = 15 * time.Minute

type throttle struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

var loginThrottle = &throttle{fail: map[string][]time.Time{}}

func (t *throttle) blocked(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	cut := time.Now().Add(-failWindow)
	recent := t.fail[key][:0]
	for _, ts := range t.fail[key] {
		if ts.After(cut) {
			recent = append(recent, ts)
		}
	}
	t.fail[key] = recent
	return len(recent) >= maxFailures
}

func (t *throttle) record(key string) {
	t.mu.Lock()
	t.fail[key] = append(t.fail[key], time.Now())
	t.mu.Unlock()
}

func (t *throttle) clear(key string) {
	t.mu.Lock()
	delete(t.fail, key)
	t.mu.Unlock()
}

// Authenticate verifies credentials and returns the user on success. It is
// rate-limited per username to blunt brute-force and bcrypt-DoS attempts.
func Authenticate(d *db.DB, username, password string) (*User, error) {
	if loginThrottle.blocked(username) {
		return nil, ErrRateLimited
	}
	var u User
	var hash string
	var disabled int
	err := d.QueryRow(`SELECT id, username, role, password_hash, disabled FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &hash, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		loginThrottle.record(username)
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if disabled != 0 {
		return nil, ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		loginThrottle.record(username)
		return nil, ErrInvalidCredentials
	}
	loginThrottle.clear(username)
	return &u, nil
}

// SetPassword replaces a user's password with a fresh bcrypt hash. Used by the
// self-service "change password" flow and by an admin resetting another user.
// In cluster mode the caller must run this on the leader so the new hash
// replicates out via the account snapshot (ON CONFLICT updates password_hash).
func SetPassword(d *db.DB, userID int64, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := d.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(hash), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such user")
	}
	return nil
}

// CheckPassword verifies a plaintext password against a user's stored hash by
// user id (the self-change "current password" confirmation). It deliberately
// does NOT touch the login throttle or the disabled flag — it is a re-auth of an
// already-authenticated session, not a login.
func CheckPassword(d *db.DB, userID int64, password string) bool {
	var hash string
	if err := d.QueryRow(`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ---- API keys ------------------------------------------------------------

// NewAPIKey mints a key: the plaintext (shown once) and its storage fields.
// Format: "vdx_<prefix>_<secret>". Only the SHA-256 hash is persisted.
func NewAPIKey() (plaintext, prefix, hash string) {
	prefix = randHex(4)
	secret := randHex(24)
	plaintext = "vdx_" + prefix + "_" + secret
	hash = HashAPIKey(plaintext)
	return
}

// HashAPIKey returns the hex SHA-256 of a presented key for lookup.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TokenFromRequest returns the raw session token from the cookie, if present.
func TokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// StartSession creates a web session row and sets the cookie.
func StartSession(d *db.DB, w http.ResponseWriter, userID int64) error {
	token := randToken()
	expires := time.Now().Add(sessionTTL)
	_, err := d.Exec(`INSERT INTO web_sessions(token, user_id, expires_at) VALUES(?,?,?)`,
		token, userID, expires.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	return nil
}

// EndSession deletes the current session and clears the cookie.
func EndSession(d *db.DB, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_, _ = d.Exec(`DELETE FROM web_sessions WHERE token=?`, c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
}

// FromRequest resolves the authenticated user from the session cookie, or nil.
// UserByName loads a user by username (for the cluster-admin reverse-proxy, which
// acts as a named, already-authenticated admin from another node).
func UserByName(d *db.DB, username string) (*User, error) {
	var u User
	err := d.QueryRow(`SELECT id, username, role FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func FromRequest(d *db.DB, r *http.Request) *User {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	var u User
	var expires string
	err = d.QueryRow(`
		SELECT u.id, u.username, u.role, s.expires_at
		FROM web_sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token = ?`, c.Value).Scan(&u.ID, &u.Username, &u.Role, &expires)
	if err != nil {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, expires); err == nil && time.Now().After(t) {
		_, _ = d.Exec(`DELETE FROM web_sessions WHERE token=?`, c.Value)
		return nil
	}
	return &u
}
