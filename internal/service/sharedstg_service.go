package service

import (
	"errors"
	"fmt"
	"net"
	osuser "os/user"
	"path/filepath"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/sharedstg"
)

// joinCSV joins two comma-separated option strings, dropping empties.
func joinCSV(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "," + b
	}
}

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
	if err := s.guardMgmt(name); err != nil { // fails closed when mgmt is unknown
		return err
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
func (s *Service) AddNFS(p *Principal, name, server, export, vers, opts, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	_, clientAddr, err := s.guardStorageTarget(server)
	if err != nil {
		return err
	}
	mp := s.mountpointFor(name)
	if err := sharedstg.NFSMount(server, export, mp, clientAddr, vers, opts); err != nil {
		return err
	}
	return s.recordMount(p, "nfs", name, server+":"+export, opts, mp, ip)
}

// AddCIFS mounts an SMB/CIFS share over the storage NIC.
func (s *Service) AddCIFS(p *Principal, name, unc, username, password, domain, vers, opts, ip string) error {
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
	// CIFS/SMB has no real per-file ownership — the whole mount is mapped to one
	// uid/gid. Map it to the VM run-as user so a dropped-privilege QEMU can open
	// (write) its disk file; otherwise every VM on a CIFS pool fails to start with
	// "Permission denied". User-supplied opts win (appended last).
	mopts := opts
	if ru := s.cfg.VM.RunAs; ru != "" {
		if u, err := osuser.Lookup(ru); err == nil {
			mopts = joinCSV(fmt.Sprintf("uid=%s,gid=%s,file_mode=0660,dir_mode=0770", u.Uid, u.Gid), opts)
		}
	}
	if err := sharedstg.CIFSMount(unc, mp, username, password, domain, vers, mopts); err != nil {
		return err
	}
	return s.recordMount(p, "cifs", name, unc, mopts, mp, ip)
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
	Live      bool // currently logged in per the kernel (iscsiadm -m session)
	Persisted bool // recorded in the DB (re-logs on demand; survives this list)
}

// ListISCSI returns the UNION of live kernel iSCSI sessions and DB-recorded
// targets, so an admin always sees what is actually attached — even a LUN that
// was logged in outside the UI (e.g. the OCFS2-backed shared pool). Each row is
// annotated Live (kernel has it) and Persisted (DB has it); a live-but-unsaved
// session can be adopted, a saved-but-offline one re-attached or removed.
func (s *Service) ListISCSI(p *Principal) ([]ISCSISession, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	type key struct{ portal, target string }
	byKey := map[key]*ISCSISession{}
	var order []key

	rows, err := s.db.Query(`SELECT id,portal,target,status,created_at FROM iscsi_targets ORDER BY portal`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t ISCSISession
		if rows.Scan(&t.ID, &t.Portal, &t.Target, &t.Status, &t.CreatedAt) == nil {
			t.Persisted = true
			k := key{t.Portal, t.Target}
			cp := t
			byKey[k] = &cp
			order = append(order, k)
		}
	}
	// Overlay the authoritative kernel session list.
	if live, _ := sharedstg.ISCSISessions(); live != nil {
		for _, ls := range live {
			k := key{ls.Portal, ls.Target}
			if e, ok := byKey[k]; ok {
				e.Live = true
			} else {
				byKey[k] = &ISCSISession{Portal: ls.Portal, Target: ls.Target, Status: "loggedin", Live: true}
				order = append(order, k)
			}
		}
	}
	out := make([]ISCSISession, 0, len(order))
	for _, k := range order {
		e := byKey[k]
		if !e.Live && e.Persisted {
			e.Status = "offline" // recorded but not currently attached
		}
		out = append(out, *e)
	}
	return out, nil
}

// ISCSIAdopt records an already-live iSCSI session in the DB so it is tracked and
// can be re-attached later. It does not re-run the subnet guard (the session is
// already attached); it only persists what the kernel already has.
func (s *Service) ISCSIAdopt(p *Principal, portal, target, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if portal == "" || target == "" {
		return errors.New("portal and target are required")
	}
	if _, err := s.db.Exec(`INSERT INTO iscsi_targets(portal,target,status) VALUES(?,?,'loggedin')
		ON CONFLICT(portal,target) DO UPDATE SET status='loggedin'`, portal, target); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "iscsi.adopt", "iscsi", target, ip, map[string]any{"portal": portal})
	return nil
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
func (s *Service) ISCSILogin(p *Principal, portal, target string, chap sharedstg.CHAP, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	iface, _, err := s.guardStorageTarget(hostOf(portal))
	if err != nil {
		return err
	}
	if err := sharedstg.ISCSILogin(portal, target, iface, chap); err != nil {
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
