package netdrv

// Persistence for bonds and vSwitches (the host plumbing is in vswitch.go).

// Bond is a stored NIC bond (link aggregation).
type Bond struct {
	ID        int64
	Name      string
	Mode      string // lacp | etherchannel | active-backup
	Members   []string
	CreatedAt string
}

// VSwitch is a stored vSwitch (VLAN-filtering bridge + uplink).
type VSwitch struct {
	ID        int64
	Name      string
	Bridge    string
	Uplink    string
	CreatedAt string
}

func (s *Store) AddBond(name, mode string, members []string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO net_bonds(name,mode,members) VALUES(?,?,?)`,
		name, mode, JoinMembers(members))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Bonds() ([]Bond, error) {
	rows, err := s.db.Query(`SELECT id,name,mode,members,created_at FROM net_bonds ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Bond
	for rows.Next() {
		var b Bond
		var mem string
		if err := rows.Scan(&b.ID, &b.Name, &b.Mode, &mem, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.Members = SplitMembers(mem)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) BondByName(name string) (Bond, error) {
	var b Bond
	var mem string
	err := s.db.QueryRow(`SELECT id,name,mode,members,created_at FROM net_bonds WHERE name=?`, name).
		Scan(&b.ID, &b.Name, &b.Mode, &mem, &b.CreatedAt)
	b.Members = SplitMembers(mem)
	return b, err
}

func (s *Store) RemoveBond(name string) error {
	_, err := s.db.Exec(`DELETE FROM net_bonds WHERE name=?`, name)
	return err
}

func (s *Store) AddVSwitch(name, bridge, uplink string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO net_vswitches(name,bridge,uplink) VALUES(?,?,?)`, name, bridge, uplink)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) VSwitches() ([]VSwitch, error) {
	rows, err := s.db.Query(`SELECT id,name,bridge,uplink,created_at FROM net_vswitches ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VSwitch
	for rows.Next() {
		var v VSwitch
		if err := rows.Scan(&v.ID, &v.Name, &v.Bridge, &v.Uplink, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) VSwitchByBridge(bridge string) (VSwitch, error) {
	var v VSwitch
	err := s.db.QueryRow(`SELECT id,name,bridge,uplink,created_at FROM net_vswitches WHERE bridge=?`, bridge).
		Scan(&v.ID, &v.Name, &v.Bridge, &v.Uplink, &v.CreatedAt)
	return v, err
}

func (s *Store) RemoveVSwitch(name string) error {
	_, err := s.db.Exec(`DELETE FROM net_vswitches WHERE name=?`, name)
	return err
}
