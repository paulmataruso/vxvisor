package broker

import (
	"database/sql"
	"time"

	"vdxclone/internal/db"
)

// Pool is a desktop pool definition.
type Pool struct {
	ID         int64
	OrgID      int64
	Name       string
	ImageName  string
	Kind       string
	AssignMode string // pooled | persistent
	CPUs       int
	MemoryMB   int
	DiskGB     int
	MinSize    int
	MaxSize    int
	CreatedAt  string
}

// PoolStore is the data model for desktop pools and their VM membership.
type PoolStore struct{ db *db.DB }

func NewPoolStore(d *db.DB) *PoolStore { return &PoolStore{db: d} }

func (s *PoolStore) Create(p Pool) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO desktop_pools
		(org_id,name,image_name,kind,assign_mode,cpus,memory_mb,disk_gb,min_size,max_size)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		p.OrgID, p.Name, p.ImageName, p.Kind, p.AssignMode, p.CPUs, p.MemoryMB, p.DiskGB, p.MinSize, p.MaxSize)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *PoolStore) Delete(orgID, id int64) error {
	_, err := s.db.Exec(`DELETE FROM desktop_pools WHERE id=? AND org_id=?`, id, orgID)
	return err
}

func (s *PoolStore) List(orgID int64) ([]Pool, error) {
	rows, err := s.db.Query(`SELECT id,org_id,name,image_name,kind,assign_mode,cpus,memory_mb,disk_gb,min_size,max_size,created_at
		FROM desktop_pools WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPools(rows)
}

// AllPools returns every pool across all orgs (for the warm-pool worker).
func (s *PoolStore) AllPools() ([]Pool, error) {
	rows, err := s.db.Query(`SELECT id,org_id,name,image_name,kind,assign_mode,cpus,memory_mb,disk_gb,min_size,max_size,created_at
		FROM desktop_pools ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPools(rows)
}

// FreeCount returns how many unassigned (free) VMs a pool currently has ready.
func (s *PoolStore) FreeCount(poolID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE pool_id=? AND assigned_to IS NULL AND deleted_at IS NULL`, poolID).Scan(&n)
	return n, err
}

func (s *PoolStore) Get(id int64) (Pool, error) {
	row := s.db.QueryRow(`SELECT id,org_id,name,image_name,kind,assign_mode,cpus,memory_mb,disk_gb,min_size,max_size,created_at
		FROM desktop_pools WHERE id=?`, id)
	var p Pool
	err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.ImageName, &p.Kind, &p.AssignMode,
		&p.CPUs, &p.MemoryMB, &p.DiskGB, &p.MinSize, &p.MaxSize, &p.CreatedAt)
	return p, err
}

func scanPools(rows *sql.Rows) ([]Pool, error) {
	var out []Pool
	for rows.Next() {
		var p Pool
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.ImageName, &p.Kind, &p.AssignMode,
			&p.CPUs, &p.MemoryMB, &p.DiskGB, &p.MinSize, &p.MaxSize, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- grants --------------------------------------------------------------

func (s *PoolStore) Grant(poolID, userID int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO pool_grants(pool_id,user_id) VALUES(?,?)`, poolID, userID)
	return err
}

func (s *PoolStore) Revoke(poolID, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM pool_grants WHERE pool_id=? AND user_id=?`, poolID, userID)
	return err
}

func (s *PoolStore) GrantedUsers(poolID int64) ([]int64, error) {
	rows, err := s.db.Query(`SELECT user_id FROM pool_grants WHERE pool_id=?`, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// PoolsForUser returns the pools a user may draw a desktop from.
func (s *PoolStore) PoolsForUser(userID int64) ([]Pool, error) {
	rows, err := s.db.Query(`SELECT p.id,p.org_id,p.name,p.image_name,p.kind,p.assign_mode,p.cpus,p.memory_mb,p.disk_gb,p.min_size,p.max_size,p.created_at
		FROM desktop_pools p JOIN pool_grants g ON g.pool_id=p.id
		WHERE g.user_id=? ORDER BY p.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPools(rows)
}

// ---- VM membership / leasing --------------------------------------------

// CountVMs returns how many VMs currently belong to a pool.
func (s *PoolStore) CountVMs(poolID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE pool_id=? AND deleted_at IS NULL`, poolID).Scan(&n)
	return n, err
}

// FreeVM returns the id of a free (unassigned) VM in a pool, or "" if none.
func (s *PoolStore) FreeVM(poolID int64) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM sessions WHERE pool_id=? AND assigned_to IS NULL AND deleted_at IS NULL ORDER BY created_at LIMIT 1`, poolID).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// PersistentVM returns a user's dedicated VM id in a pool, or "" if none yet.
func (s *PoolStore) PersistentVM(poolID, userID int64) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM sessions WHERE pool_id=? AND assigned_to=? AND deleted_at IS NULL LIMIT 1`, poolID, userID).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return id, err
}

// AddToPool marks a freshly-created VM as belonging to a pool but unleased.
func (s *PoolStore) AddToPool(sessionID string, poolID int64) error {
	_, err := s.db.Exec(`UPDATE sessions SET pool_id=?, assigned_to=NULL, leased_at=NULL WHERE id=?`, poolID, sessionID)
	return err
}

// Assign marks a VM leased to a user.
func (s *PoolStore) Assign(sessionID string, poolID, userID int64) error {
	_, err := s.db.Exec(`UPDATE sessions SET pool_id=?, assigned_to=?, leased_at=? WHERE id=?`,
		poolID, userID, time.Now().UTC().Format(time.RFC3339), sessionID)
	return err
}

// Release returns a pooled VM to the free set (keeps the row; clears the lease).
func (s *PoolStore) Release(sessionID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET assigned_to=NULL, leased_at=NULL WHERE id=?`, sessionID)
	return err
}

// Touch records desktop activity for idle-reclaim accounting.
func (s *PoolStore) Touch(sessionID string) {
	_, _ = s.db.Exec(`UPDATE sessions SET last_activity=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), sessionID)
}

// IdleLeased returns leased pooled VMs whose last activity is older than idle
// (or that have no recorded activity and were leased before the cutoff).
func (s *PoolStore) IdleLeased(idle time.Duration) ([]string, error) {
	cut := time.Now().Add(-idle).UTC().Format(time.RFC3339)
	rows, err := s.db.Query(`SELECT id FROM sessions
		WHERE pool_id IS NOT NULL AND assigned_to IS NOT NULL AND deleted_at IS NULL
		  AND COALESCE(last_activity, leased_at, '') < ?`, cut)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// AssignedVMs returns a user's currently-held VM ids (persistent + pooled).
func (s *PoolStore) AssignedVMs(userID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM sessions WHERE assigned_to=? AND deleted_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}
