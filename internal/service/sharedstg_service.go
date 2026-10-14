package service

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/sharedstg"
)

// Shared storage (NFS/CIFS/Ceph mounts + iSCSI sessions). A HARD RULE applies:
// every network storage backend must ride a dedicated storage interface, and its
// target must live on that interface's subnet — never the management network.

// SharedCaps reports which backends the host can mount (for conditional UI).
type SharedCaps struct{ NFS, CIFS, Ceph, ISCSI bool }

func (s *Service) SharedCaps(p *Principal) SharedCaps {
	if p == nil || !p.IsAdmin {
		return SharedCaps{}
	}
	return SharedCaps{
		NFS:   sharedstg.NFSAvailable(),
		CIFS:  sharedstg.CIFSAvailable(),
		Ceph:  sharedstg.CephAvailable(),
		ISCSI: sharedstg.ISCSIAvailable(),
	}
}

// ---- storage interface designation ---------------------------------------

func (s *Service) StorageIface() string {
	var v string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key='storage_iface'`).Scan(&v)
	return v
}

func (s *Service) SetStorageIface(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	// Refuse the management NIC — storage must be on its own interface.
	if name != "" && name == s.mgmtIface() {
		return fmt.Errorf("the management interface cannot also be the storage interface")
	}
	if _, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES('storage_iface',?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "storage.iface.set", "settings", "storage_iface", ip, map[string]any{"iface": name})
	return nil
}

// storageNet resolves the designated storage interface to its IPv4 address and
// subnet. Returns an error (used to refuse backend operations) when no storage
// interface is set, or it is down / has no address.
func (s *Service) storageNet() (iface, ipStr string, subnet *net.IPNet, err error) {
	name := s.StorageIface()
	if name == "" {
		return "", "", nil, errors.New("no dedicated storage interface is configured — set one under Storage network first")
	}
	ifaces, _ := hostinfo.Interfaces()
	for _, it := range ifaces {
		if it.Name != name {
			continue
		}
		for _, a := range it.Addrs {
			ip, ipnet, e := net.ParseCIDR(a)
			if e == nil && ip.To4() != nil {
				return name, ip.String(), ipnet, nil
			}
		}
	}
	return name, "", nil, fmt.Errorf("storage interface %s is down or has no IPv4 address", name)
}

// guardStorageTarget enforces that a backend target is on the storage subnet.
func (s *Service) guardStorageTarget(host string) (iface, ipStr string, err error) {
	iface, ipStr, subnet, err := s.storageNet()
	if err != nil {
		return "", "", err
	}
	ip := net.ParseIP(host)
	if ip == nil { // a hostname — resolve best-effort
		if addrs, e := net.LookupHost(host); e == nil && len(addrs) > 0 {
			ip = net.ParseIP(addrs[0])
		}
	}
	if ip != nil && !subnet.Contains(ip) {
		return "", "", fmt.Errorf("target %s is not on the storage subnet %s — storage backends must stay on the dedicated storage network", host, subnet.String())
	}
	return iface, ipStr, nil
}

func hostOf(spec string) string { // "server:/export" / "ip:port" -> host part
	if i := indexColon(spec); i >= 0 {
		return spec[:i]
	}
	return spec
}
func indexColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// ---- mounts (NFS/CIFS/Ceph) -----------------------------------------------

type SharedMount struct {
	ID         int64
	Kind       string
	Name       string
	Spec       string
	Options    string
	Mountpoint string
	Status     string
	CreatedAt  string
}

func (s *Service) ListSharedMounts(p *Principal) ([]SharedMount, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,kind,name,spec,options,mountpoint,status,created_at FROM shared_mounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SharedMount
	for rows.Next() {
		var m SharedMount
		if rows.Scan(&m.ID, &m.Kind, &m.Name, &m.Spec, &m.Options, &m.Mountpoint, &m.Status, &m.CreatedAt) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *Service) mountpointFor(name string) string {
	return filepath.Join(s.cfg.Paths.DataDir, "mounts", name)
}

func (s *Service) recordMount(p *Principal, kind, name, spec, opts, mp, ip string) error {
	if _, err := s.db.Exec(`INSERT INTO shared_mounts(kind,name,spec,options,mountpoint,status) VALUES(?,?,?,?,?,'mounted')`,
		kind, name, spec, opts, mp); err != nil {
		_ = sharedstg.Unmount(mp)
		return err
	}
	_ = s.stg.UpsertPool(name, kind, mp) // make it a selectable VM storage pool
	s.audit(p, p.OrgID, "sharedstg.mount", kind, name, ip, map[string]any{"spec": spec})
	return nil
}

// AddNFS mounts an NFS export over the storage NIC and registers it as a pool.
func (s *Service) AddNFS(p *Principal, name, server, export, opts, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	_, clientAddr, err := s.guardStorageTarget(server)
	if err != nil {
		return err
	}
	mp := s.mountpointFor(name)
	if err := sharedstg.NFSMount(server, export, mp, clientAddr, opts); err != nil {
		return err
	}
	return s.recordMount(p, "nfs", name, server+":"+export, opts, mp, ip)
}

// AddCIFS mounts an SMB/CIFS share over the storage NIC.
func (s *Service) AddCIFS(p *Principal, name, unc, username, password, opts, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	// UNC is //host/share — extract host for the subnet guard.
	host := unc
	host = trimUNC(host)
	if _, _, err := s.guardStorageTarget(host); err != nil {
		return err
	}
	mp := s.mountpointFor(name)
	if err := sharedstg.CIFSMount(unc, mp, username, password, opts); err != nil {
		return err
	}
	return s.recordMount(p, "cifs", name, unc, opts, mp, ip)
}

// AddCeph mounts CephFS over the storage NIC.
func (s *Service) AddCeph(p *Principal, name, mons, path, cephName, secret, opts, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	first := mons
	if i := indexColon(mons); i >= 0 {
		first = mons[:i]
	}
	if c := indexComma(first); c >= 0 {
		first = first[:c]
	}
	_, srcAddr, err := s.guardStorageTarget(first)
	if err != nil {
		return err
	}
	mp := s.mountpointFor(name)
	if err := sharedstg.CephMount(mons, path, mp, cephName, secret, srcAddr, opts); err != nil {
		return err
	}
	return s.recordMount(p, "ceph", name, mons+":"+path, opts, mp, ip)
}

// UnmountShared unmounts a shared mount and removes its pool registration.
func (s *Service) UnmountShared(p *Principal, id int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var name, mp string
	if err := s.db.QueryRow(`SELECT name,mountpoint FROM shared_mounts WHERE id=?`, id).Scan(&name, &mp); err != nil {
		return err
	}
	_ = sharedstg.Unmount(mp)
	_ = s.stg.DeletePool(name)
	if _, err := s.db.Exec(`DELETE FROM shared_mounts WHERE id=?`, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "sharedstg.unmount", "mount", name, ip, nil)
	return nil
}

// ---- iSCSI ----------------------------------------------------------------

type ISCSISession struct {
	ID        int64
	Portal    string
	Target    string
	Status    string
	CreatedAt string
}

func (s *Service) ListISCSI(p *Principal) ([]ISCSISession, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT id,portal,target,status,created_at FROM iscsi_targets ORDER BY portal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ISCSISession
	for rows.Next() {
		var t ISCSISession
		if rows.Scan(&t.ID, &t.Portal, &t.Target, &t.Status, &t.CreatedAt) == nil {
			out = append(out, t)
		}
	}
	return out, nil
}

// ISCSIDiscover lists targets at a portal (must be on the storage subnet).
func (s *Service) ISCSIDiscover(p *Principal, portal string) ([]string, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	if _, _, err := s.guardStorageTarget(hostOf(portal)); err != nil {
		return nil, err
	}
	return sharedstg.ISCSIDiscover(portal)
}

// ISCSILogin logs into a target over the storage NIC; the LUN then appears as a
// host disk usable for ZFS/LVM pools.
func (s *Service) ISCSILogin(p *Principal, portal, target, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	iface, _, err := s.guardStorageTarget(hostOf(portal))
	if err != nil {
		return err
	}
	if err := sharedstg.ISCSILogin(portal, target, iface); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO iscsi_targets(portal,target,status) VALUES(?,?,'loggedin')
		ON CONFLICT(portal,target) DO UPDATE SET status='loggedin'`, portal, target); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "iscsi.login", "iscsi", target, ip, map[string]any{"portal": portal})
	return nil
}

func (s *Service) ISCSILogout(p *Principal, id int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var portal, target string
	if err := s.db.QueryRow(`SELECT portal,target FROM iscsi_targets WHERE id=?`, id).Scan(&portal, &target); err != nil {
		return err
	}
	_ = sharedstg.ISCSILogout(portal, target)
	if _, err := s.db.Exec(`DELETE FROM iscsi_targets WHERE id=?`, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "iscsi.logout", "iscsi", target, ip, nil)
	return nil
}

func trimUNC(s string) string {
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	if i := indexSlash(s); i >= 0 {
		return s[:i]
	}
	return s
}
func indexSlash(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
func indexComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}
