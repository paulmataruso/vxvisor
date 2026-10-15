package broker



// Published apps: entries an admin surfaces on the end-user portal. A 'desktop'
// or 'remoteapp' app is backed by a VDI pool and inherits that pool's per-user
// grants; a 'web' app is a link tile available to everyone in the org.

type App struct {
	ID       int64
	OrgID    int64
	PoolID   int64
	Name     string
	Kind     string // desktop | remoteapp | web
	Target   string // web: URL; remoteapp: program (|| alias or path)
	Args     string
	Icon     string
	PoolName string // joined for display (pool apps)
	CreatedAt string
}

func (s *PoolStore) appScan(rows interface{ Scan(...any) error }) (App, error) {
	var a App
	err := rows.Scan(&a.ID, &a.OrgID, &a.PoolID, &a.Name, &a.Kind, &a.Target, &a.Args, &a.Icon, &a.CreatedAt)
	return a, err
}

func (s *PoolStore) CreateApp(a App) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO published_apps(org_id,pool_id,name,kind,target,args,icon)
		VALUES(?,?,?,?,?,?,?)`, a.OrgID, a.PoolID, a.Name, a.Kind, a.Target, a.Args, a.Icon)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *PoolStore) DeleteApp(orgID, id int64) error {
	_, err := s.db.Exec(`DELETE FROM published_apps WHERE id=? AND org_id=?`, id, orgID)
	return err
}

func (s *PoolStore) GetApp(id int64) (App, error) {
	return s.appScan(s.db.QueryRow(`SELECT id,org_id,pool_id,name,kind,target,args,icon,created_at
		FROM published_apps WHERE id=?`, id))
}

// ListApps returns every published app in an org (admin view).
func (s *PoolStore) ListApps(orgID int64) ([]App, error) {
	rows, err := s.db.Query(`SELECT a.id,a.org_id,a.pool_id,a.name,a.kind,a.target,a.args,a.icon,a.created_at,
		COALESCE(p.name,'') FROM published_apps a LEFT JOIN desktop_pools p ON p.id=a.pool_id
		WHERE a.org_id=? ORDER BY a.name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.OrgID, &a.PoolID, &a.Name, &a.Kind, &a.Target, &a.Args, &a.Icon, &a.CreatedAt, &a.PoolName); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AppsForUser returns the apps a user may launch: web apps across their org(s),
// plus pool-backed apps whose pool the user is granted.
func (s *PoolStore) AppsForUser(userID int64) ([]App, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT a.id,a.org_id,a.pool_id,a.name,a.kind,a.target,a.args,a.icon,a.created_at,COALESCE(p.name,'')
		FROM published_apps a
		LEFT JOIN desktop_pools p ON p.id=a.pool_id
		WHERE
		  (a.kind='web' AND a.org_id IN (SELECT org_id FROM org_members WHERE user_id=?))
		  OR
		  (a.pool_id IN (SELECT pool_id FROM pool_grants WHERE user_id=?))
		ORDER BY a.name`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		if err := rows.Scan(&a.ID, &a.OrgID, &a.PoolID, &a.Name, &a.Kind, &a.Target, &a.Args, &a.Icon, &a.CreatedAt, &a.PoolName); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

