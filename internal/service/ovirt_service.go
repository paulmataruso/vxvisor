package service

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/auth"
	"vdxclone/internal/ovirtapi"
	"vdxclone/internal/qemu"
	"vdxclone/internal/session"
	"vdxclone/internal/vmbackup"
)

// OvirtBackend implements ovirtapi.Backend — the oVirt-compatible backup API
// ([ovirt] in the config) — over the service layer, so that API gets the same
// authorization and audit trail as the web UI. Only instance admins may use
// it (a backup application needs every VM of every org); see
// docs/VEEAM-OVIRT-API.md for the "backup operator" role this could narrow to.
type OvirtBackend struct {
	s    *Service
	host string // the host name / IP clients reach the API on

	sizeMu sync.Mutex
	sizes  map[string]ovirtSize

	verOnce sync.Once
	qemuVer string
}

type ovirtSize struct {
	virt   int64
	compat string
	at     time.Time
}

// ovirtCall is the API's per-request caller: an instance-admin principal in
// the provider org, and the client address for audit records.
type ovirtCall struct {
	p  *Principal
	ip string
}

// NewOvirtBackend builds the backend; publicHost is the address clients reach
// the API (and the imageio server) on.
func (s *Service) NewOvirtBackend(publicHost string) *OvirtBackend {
	return &OvirtBackend{s: s, host: publicHost, sizes: map[string]ovirtSize{}}
}

var _ ovirtapi.Backend = (*OvirtBackend)(nil)

// ---- authentication ---------------------------------------------------------

func (b *OvirtBackend) Login(user, password, ip string) (ovirtapi.Caller, error) {
	u, err := auth.Authenticate(b.s.db, user, password)
	if err != nil {
		b.s.AuditAuth(0, user, "ovirt.login_failed", ip, map[string]any{"username": user})
		return nil, ovirtapi.ErrForbidden
	}
	if u.Role != "admin" {
		b.s.AuditAuth(u.ID, u.Username, "ovirt.login_denied", ip, map[string]any{"reason": "not an instance admin"})
		return nil, ovirtapi.ErrForbidden
	}
	p, err := b.principal(u)
	if err != nil {
		return nil, err
	}
	b.s.AuditAuth(u.ID, u.Username, "ovirt.login", ip, nil)
	return &ovirtCall{p: p, ip: ip}, nil
}

// principal is an instance admin acting in the provider org (admins reach
// every org's VMs; see sessionInOrg).
func (b *OvirtBackend) principal(u *auth.User) (*Principal, error) {
	provider, err := b.s.store.DefaultOrgID()
	if err != nil {
		return nil, err
	}
	orgs, _ := b.s.store.UserOrgs(u.ID, true)
	role, _ := b.s.store.OrgRole(provider, u.ID)
	return &Principal{User: u, OrgID: provider, OrgRole: role, IsAdmin: true, ProviderAdmin: true,
		Orgs: orgs, ActorKind: "user"}, nil
}

func (b *OvirtBackend) Bind(c ovirtapi.Caller, ip string) (ovirtapi.Caller, error) {
	cc, ok := c.(*ovirtCall)
	if !ok || cc == nil || cc.p == nil || cc.p.User == nil {
		return nil, ovirtapi.ErrForbidden
	}
	var role string
	var disabled int
	err := b.s.db.QueryRow(`SELECT role, disabled FROM users WHERE id=?`, cc.p.User.ID).Scan(&role, &disabled)
	if err != nil || disabled != 0 || role != "admin" {
		return nil, ovirtapi.ErrForbidden
	}
	return &ovirtCall{p: cc.p, ip: ip}, nil
}

func call(c ovirtapi.Caller) (*ovirtCall, error) {
	cc, ok := c.(*ovirtCall)
	if !ok || cc == nil || cc.p == nil || !cc.p.IsAdmin {
		return nil, ovirtapi.ErrForbidden
	}
	return cc, nil
}

// ovErr classifies a service/session error for the API's fault mapping.
func ovErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ovirtapi.ErrNotFound), errors.Is(err, ovirtapi.ErrConflict),
		errors.Is(err, ovirtapi.ErrForbidden), errors.Is(err, ovirtapi.ErrBadRequest):
		return err
	case errors.Is(err, ErrNotFound), errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("%w: %v", ovirtapi.ErrNotFound, err)
	case errors.Is(err, ErrUnauthorized):
		return fmt.Errorf("%w: %v", ovirtapi.ErrForbidden, err)
	case errors.Is(err, session.ErrBackupBusy):
		return fmt.Errorf("%w: %v", ovirtapi.ErrConflict, err)
	}
	return err
}

func (b *OvirtBackend) Audit(c ovirtapi.Caller, action, targetType, targetID, ip string, detail map[string]any) {
	cc, err := call(c)
	if err != nil {
		return
	}
	if ip == "" {
		ip = cc.ip
	}
	org := cc.p.OrgID
	if targetType == "session" {
		var o int64
		if b.s.db.QueryRow(`SELECT org_id FROM sessions WHERE id=?`, targetID).Scan(&o) == nil {
			org = o
		}
	}
	b.s.audit(cc.p, org, action, targetType, targetID, ip, detail)
}

func (b *OvirtBackend) audit(cc *ovirtCall, org int64, action, typ, id string, detail map[string]any) {
	if org == 0 {
		org = cc.p.OrgID
	}
	b.s.audit(cc.p, org, action, typ, id, cc.ip, detail)
}

// ---- inventory --------------------------------------------------------------

func (b *OvirtBackend) Host(c ovirtapi.Caller) (ovirtapi.Host, error) {
	if _, err := call(c); err != nil {
		return ovirtapi.Host{}, err
	}
	h := ovirtapi.Host{Address: b.host, CPUs: runtime.NumCPU(), Sockets: 1}
	h.Name, _ = os.Hostname()
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		sockets := map[string]bool{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			switch strings.TrimSpace(k) {
			case "model name":
				if h.CPUModel == "" {
					h.CPUModel = strings.TrimSpace(v)
				}
			case "physical id":
				sockets[strings.TrimSpace(v)] = true
			}
		}
		f.Close()
		if len(sockets) > 0 {
			h.Sockets = len(sockets)
		}
	}
	h.MemoryMB, h.FreeMB = meminfoMB()
	if v, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.KernelVer = strings.TrimSpace(string(v))
	}
	h.OSVersion = osPrettyName()
	b.verOnce.Do(func() {
		out, _ := exec.Command("qemu-system-x86_64", "--version").Output()
		if m := regexp.MustCompile(`version ([0-9][0-9.]*)`).FindSubmatch(out); m != nil {
			b.qemuVer = string(m[1])
		}
	})
	h.QEMUVer = b.qemuVer
	ids, _ := b.s.mgr.RunningIDs()
	h.VMsRunning = len(ids)
	return h, nil
}

func meminfoMB() (total, avail int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var k string
		var v int64
		if n, _ := fmt.Sscanf(sc.Text(), "%s %d", &k, &v); n == 2 {
			switch k {
			case "MemTotal:":
				total = v >> 10
			case "MemAvailable:":
				avail = v >> 10
			}
		}
	}
	return total, avail
}

func osPrettyName() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(ln, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func statfs(dir string) (avail, used int64, ok bool) {
	var st syscall.Statfs_t
	if dir == "" || syscall.Statfs(dir, &st) != nil {
		return 0, 0, false
	}
	bs := int64(st.Bsize)
	return int64(st.Bavail) * bs, int64(st.Blocks-st.Bfree) * bs, true
}

// pool is a storage pool with the directory staged disks go to ("" when the
// pool is not file-backed).
type ovirtPool struct {
	ovirtapi.StoragePool
	dir string
}

func (b *OvirtBackend) pools() ([]ovirtPool, error) {
	out := []ovirtPool{{StoragePool: ovirtapi.StoragePool{PoolID: 0, Name: "default", Kind: "dir", Uploadable: true},
		dir: b.s.cfg.Paths.DiskDir}}
	rows, err := b.s.db.Query(`SELECT id, name, kind, COALESCE(path,'') FROM storage_pools ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ovirtPool
		var path string
		if err := rows.Scan(&p.PoolID, &p.Name, &p.Kind, &path); err != nil {
			return nil, err
		}
		// lvm (vg/thinpool) and rbd (a Ceph pool name) are not directories.
		if p.Kind != "lvm" && p.Kind != "rbd" && path != "" {
			if st, err := os.Stat(path); err == nil && st.IsDir() {
				p.dir, p.Uploadable = path, true
			}
		}
		out = append(out, p)
	}
	for i := range out {
		if a, u, ok := statfs(out[i].dir); ok {
			out[i].Available, out[i].Used = a, u
		}
	}
	return out, rows.Err()
}

func (b *OvirtBackend) StoragePools(c ovirtapi.Caller) ([]ovirtapi.StoragePool, error) {
	if _, err := call(c); err != nil {
		return nil, err
	}
	ps, err := b.pools()
	if err != nil {
		return nil, err
	}
	out := make([]ovirtapi.StoragePool, len(ps))
	for i, p := range ps {
		out[i] = p.StoragePool
	}
	return out, nil
}

// Networks lists every org's port groups (oVirt networks are per data
// center, and this host is the one data center). Tenant port groups are
// named "<org-slug>/<name>"; NetID 0 is the Default org's NAT network.
func (b *OvirtBackend) Networks(c ovirtapi.Caller) ([]ovirtapi.Network, error) {
	if _, err := call(c); err != nil {
		return nil, err
	}
	provider, err := b.s.store.DefaultOrgID()
	if err != nil {
		return nil, err
	}
	orgs, err := b.s.store.ListOrgs()
	if err != nil {
		return nil, err
	}
	out := []ovirtapi.Network{{NetID: 0, Name: "vxvisor-nat", OrgID: provider}}
	for _, o := range orgs {
		nets, err := b.s.vmPortGroups(o.ID)
		if err != nil {
			return nil, err
		}
		for _, n := range nets {
			name := n.Name
			if o.ID != provider {
				name = o.Slug + "/" + n.Name
			}
			out = append(out, ovirtapi.Network{NetID: n.ID, Name: name, VLAN: n.VLANID, OrgID: o.ID})
		}
	}
	return out, nil
}

// localVMs maps every live VM hosted on this node to its storage pool and the
// API disk attached to it (if one was).
type vmExtra struct {
	poolID           int64
	diskID, diskName string
}

func (b *OvirtBackend) localVMs() (map[string]vmExtra, error) {
	rows, err := b.s.db.Query(`SELECT s.id, COALESCE(s.storage_pool_id,0), COALESCE(d.id,''), COALESCE(d.name,'')
		FROM sessions s LEFT JOIN ovirt_disks d ON d.vm_id = s.id
		WHERE s.deleted_at IS NULL
		  AND (s.node_id IS NULL OR s.node_id = (SELECT id FROM nodes WHERE role='local'))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]vmExtra{}
	for rows.Next() {
		var id string
		var x vmExtra
		if err := rows.Scan(&id, &x.poolID, &x.diskID, &x.diskName); err != nil {
			return nil, err
		}
		out[id] = x
	}
	return out, rows.Err()
}

func (b *OvirtBackend) VMs(c ovirtapi.Caller) ([]ovirtapi.VM, error) {
	if _, err := call(c); err != nil {
		return nil, err
	}
	local, err := b.localVMs()
	if err != nil {
		return nil, err
	}
	orgs, err := b.s.store.ListOrgs()
	if err != nil {
		return nil, err
	}
	var out []ovirtapi.VM
	for _, o := range orgs {
		list, err := b.s.mgr.List(o.ID)
		if err != nil {
			return nil, err
		}
		for _, sess := range list {
			if x, ok := local[sess.ID]; ok {
				out = append(out, b.vm(sess, x))
			}
		}
	}
	return out, nil
}

func (b *OvirtBackend) VM(c ovirtapi.Caller, id string) (ovirtapi.VM, error) {
	if _, err := call(c); err != nil {
		return ovirtapi.VM{}, err
	}
	sess, x, err := b.session(id)
	if err != nil {
		return ovirtapi.VM{}, err
	}
	return b.vm(sess, x), nil
}

func (b *OvirtBackend) session(id string) (*session.Session, vmExtra, error) {
	local, err := b.localVMs()
	if err != nil {
		return nil, vmExtra{}, err
	}
	x, ok := local[id]
	if !ok {
		return nil, vmExtra{}, fmt.Errorf("%w: VM %s", ovirtapi.ErrNotFound, id)
	}
	sess, err := b.s.mgr.Get(id)
	if err != nil {
		return nil, vmExtra{}, fmt.Errorf("%w: VM %s", ovirtapi.ErrNotFound, id)
	}
	return sess, x, nil
}

func (b *OvirtBackend) vm(sess *session.Session, x vmExtra) ovirtapi.VM {
	v := ovirtapi.VM{ID: sess.ID, Name: sess.Name, OrgID: sess.OrgID, Status: "down", CPUs: sess.CPUs,
		MemoryMB: sess.MemoryMB, Firmware: sess.Firmware, SecureBoot: sess.SecureBoot, MachineType: sess.MachineType,
		OSType: sess.OSType, DiskBus: sess.DiskBus, NICModel: sess.NICModel, VGA: sess.VGA,
		GuestAgent: sess.GuestAgent, TPM: sess.TPM, NetID: sess.NetworkID, MAC: sess.MAC}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, sess.CreatedAt); err == nil {
			v.Created = t
			break
		}
	}
	switch {
	case b.s.mgr.MigrationBusy(sess.ID):
		v.Status = "migrating"
	case b.s.mgr.Running(sess):
		v.Status = "up"
	}
	if sess.DiskPath != "" {
		d := b.vmDisk(sess, x)
		v.Disk = &d
	}
	return v
}

func diskFormat(backend string) string {
	if backend == "" || backend == "qcow2" {
		return "qcow2"
	}
	return "raw"
}

func (b *OvirtBackend) vmDisk(sess *session.Session, x vmExtra) ovirtapi.Disk {
	d := ovirtapi.Disk{ID: x.diskID, Name: x.diskName, VMID: sess.ID, Path: sess.DiskPath,
		Format: diskFormat(sess.DiskBackend), PoolID: x.poolID}
	if d.ID == "" {
		d.ID = ovirtapi.DiskIDForVM(sess.ID)
	}
	if d.Name == "" {
		d.Name = sess.Name + "_disk0"
	}
	d.Provisioned, d.Actual, d.Incremental = b.diskSize(sess.DiskPath, d.Format, sess.DiskGB)
	return d
}

// diskSize is a disk's virtual and allocated size, and whether it can carry
// checkpoints (qcow2 v3). qemu-img answers are cached: listing VMs must stay
// cheap, and a virtual size only changes on resize (which changes sizeGB).
func (b *OvirtBackend) diskSize(path, format string, sizeGB int) (virt, actual int64, incremental bool) {
	switch {
	case strings.HasPrefix(path, "rbd:"):
		return int64(sizeGB) << 30, int64(sizeGB) << 30, false
	case strings.HasPrefix(path, "/dev/"):
		if f, err := os.Open(path); err == nil {
			virt, _ = f.Seek(0, io.SeekEnd)
			f.Close()
		}
		return virt, virt, false
	}
	var st syscall.Stat_t
	if syscall.Stat(path, &st) == nil {
		actual = st.Blocks * 512
	}
	key := fmt.Sprintf("%s|%d", path, sizeGB)
	b.sizeMu.Lock()
	e, ok := b.sizes[key]
	b.sizeMu.Unlock()
	if !ok || time.Since(e.at) > 10*time.Minute {
		info, err := qemu.ImageInfo(path)
		if err != nil {
			return int64(sizeGB) << 30, actual, false
		}
		e = ovirtSize{virt: info.VirtualSize, compat: info.Compat, at: time.Now()}
		b.sizeMu.Lock()
		b.sizes[key] = e
		b.sizeMu.Unlock()
	}
	return e.virt, actual, format == "qcow2" && e.compat == "1.1"
}

func (b *OvirtBackend) GuestIPs(c ovirtapi.Caller, vmID string) []string {
	if _, err := call(c); err != nil {
		return nil
	}
	sess, err := b.s.mgr.Get(vmID)
	if err != nil || !b.s.mgr.Running(sess) {
		return nil
	}
	var out []string
	gi := b.s.mgr.GuestAgentInfo(vmID)
	for _, nic := range gi.Interfaces {
		for _, a := range nic.IPs {
			ip := net.ParseIP(strings.SplitN(a, "/", 2)[0])
			if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				out = append(out, ip.String())
			}
		}
	}
	if len(out) == 0 {
		if ip := b.s.guestPrimaryIP(sess); ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// ---- backups & checkpoints -----------------------------------------------------

// diskDesc describes a VM's disk for vmbackup (no pin).
func (b *OvirtBackend) diskDesc(sess *session.Session) vmbackup.Disk {
	uid, gid := b.s.mgr.QEMUOwner()
	return vmbackup.Disk{VMID: sess.ID, Path: sess.DiskPath, Format: diskFormat(sess.DiskBackend),
		Running: b.s.mgr.Running(sess), QMPSocket: sess.QMPSocket, Device: "disk0", UID: uid, GID: gid}
}

func (b *OvirtBackend) BackupDisk(c ovirtapi.Caller, vmID string) (vmbackup.Disk, func(), error) {
	if _, err := call(c); err != nil {
		return vmbackup.Disk{}, nil, err
	}
	if _, _, err := b.session(vmID); err != nil {
		return vmbackup.Disk{}, nil, err
	}
	release, err := b.s.mgr.PinBackup(vmID)
	if err != nil {
		return vmbackup.Disk{}, nil, fmt.Errorf("%w: %v", ovirtapi.ErrConflict, err)
	}
	// Re-read under the pin: the state a backup acts on can't change now
	// (except a Stop, which only fails this backup).
	sess, err := b.s.mgr.Get(vmID)
	if err != nil {
		release()
		return vmbackup.Disk{}, nil, ovErr(err)
	}
	if sess.DiskPath == "" {
		release()
		return vmbackup.Disk{}, nil, fmt.Errorf("%w: the VM has no disk", ovirtapi.ErrBadRequest)
	}
	return b.diskDesc(sess), release, nil
}

func (b *OvirtBackend) Checkpoints(c ovirtapi.Caller, vmID string) ([]ovirtapi.Checkpoint, error) {
	if _, err := call(c); err != nil {
		return nil, err
	}
	rows, err := b.s.db.Query(`SELECT id, vm_id, parent_id, description, created_at FROM ovirt_checkpoints
		WHERE vm_id=? ORDER BY created_at, rowid`, vmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ovirtapi.Checkpoint
	for rows.Next() {
		var cp ovirtapi.Checkpoint
		var created string
		if err := rows.Scan(&cp.ID, &cp.VMID, &cp.ParentID, &cp.Description, &created); err != nil {
			return nil, err
		}
		cp.Created, _ = time.Parse(time.RFC3339, created)
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	// A checkpoint is only as good as its bitmap: flag ones that are gone (a
	// disk swap) or inconsistent (QEMU was killed). Best effort — a probe
	// that fails leaves them as recorded.
	if sess, err := b.s.mgr.Get(vmID); err == nil && sess.DiskPath != "" {
		if bms, err := vmbackup.Checkpoints(b.diskDesc(sess)); err == nil {
			ok := map[string]bool{}
			for _, bm := range bms {
				ok[bm.CheckpointID] = !bm.Inconsistent
			}
			for i := range out {
				out[i].Invalid = !ok[out[i].ID]
			}
		}
	}
	return out, nil
}

func (b *OvirtBackend) AddCheckpoint(c ovirtapi.Caller, cp ovirtapi.Checkpoint) error {
	if _, err := call(c); err != nil {
		return err
	}
	created := cp.Created
	if created.IsZero() {
		created = time.Now()
	}
	_, err := b.s.db.Exec(`INSERT INTO ovirt_checkpoints(id, vm_id, parent_id, description, created_at) VALUES(?,?,?,?,?)`,
		cp.ID, cp.VMID, cp.ParentID, cp.Description, created.UTC().Format(time.RFC3339))
	return err
}

func (b *OvirtBackend) RemoveCheckpoint(c ovirtapi.Caller, vmID, id string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	sess, _, err := b.session(vmID)
	if err != nil {
		return err
	}
	release, err := b.s.mgr.PinBackup(vmID)
	if err != nil {
		return fmt.Errorf("%w: %v", ovirtapi.ErrConflict, err)
	}
	defer release()
	if sess, err = b.s.mgr.Get(vmID); err != nil {
		return ovErr(err)
	}
	if sess.DiskPath != "" {
		if err := vmbackup.RemoveCheckpoint(b.diskDesc(sess), id); err != nil {
			return err
		}
	}
	res, err := b.s.db.Exec(`DELETE FROM ovirt_checkpoints WHERE id=? AND vm_id=?`, id, vmID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: checkpoint %s", ovirtapi.ErrNotFound, id)
	}
	b.audit(cc, sess.OrgID, "ovirt.checkpoint.remove", "session", vmID, map[string]any{"checkpoint": id})
	return nil
}

// ---- staged disks ---------------------------------------------------------------

func (b *OvirtBackend) Disks(c ovirtapi.Caller) ([]ovirtapi.Disk, error) {
	if _, err := call(c); err != nil {
		return nil, err
	}
	rows, err := b.s.db.Query(`SELECT id, name, path, format, pool_id, size FROM ovirt_disks WHERE vm_id IS NULL ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ovirtapi.Disk
	for rows.Next() {
		var d ovirtapi.Disk
		if err := rows.Scan(&d.ID, &d.Name, &d.Path, &d.Format, &d.PoolID, &d.Provisioned); err != nil {
			return nil, err
		}
		var st syscall.Stat_t
		if syscall.Stat(d.Path, &st) == nil {
			d.Actual = st.Blocks * 512
		}
		d.Incremental = d.Format == "qcow2"
		out = append(out, d)
	}
	return out, rows.Err()
}

func (b *OvirtBackend) CreateDisk(c ovirtapi.Caller, spec ovirtapi.DiskSpec) (ovirtapi.Disk, error) {
	cc, err := call(c)
	if err != nil {
		return ovirtapi.Disk{}, err
	}
	ps, err := b.pools()
	if err != nil {
		return ovirtapi.Disk{}, err
	}
	var pool *ovirtPool
	for i := range ps {
		if ps[i].PoolID == spec.PoolID {
			pool = &ps[i]
		}
	}
	if pool == nil {
		return ovirtapi.Disk{}, fmt.Errorf("%w: storage pool %d", ovirtapi.ErrNotFound, spec.PoolID)
	}
	if !pool.Uploadable {
		return ovirtapi.Disk{}, fmt.Errorf("%w: disks can only be created on a file-backed storage pool (directory, NFS, CIFS, CephFS or a ZFS dataset); %q is %s",
			ovirtapi.ErrBadRequest, pool.Name, pool.Kind)
	}
	if spec.Provisioned <= 0 || spec.Provisioned > 64<<40 {
		return ovirtapi.Disk{}, fmt.Errorf("%w: provisioned_size %d is out of range", ovirtapi.ErrBadRequest, spec.Provisioned)
	}
	size := (spec.Provisioned + 511) &^ 511
	if free, _, ok := statfs(pool.dir); ok && free < 1<<30 {
		return ovirtapi.Disk{}, fmt.Errorf("%w: storage pool %q has less than 1 GiB free", ovirtapi.ErrConflict, pool.Name)
	}
	id := uuid.NewString()
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = "disk-" + id[:8]
	}
	if len(name) > 255 {
		name = name[:255]
	}
	path := filepath.Join(pool.dir, "ovirt-"+id+".qcow2")
	if err := qemu.CreateQcow2Sized(path, size); err != nil {
		return ovirtapi.Disk{}, err
	}
	if _, err := b.s.db.Exec(`INSERT INTO ovirt_disks(id, name, path, format, pool_id, size) VALUES(?,?,?,?,?,?)`,
		id, name, path, "qcow2", pool.PoolID, size); err != nil {
		_ = os.Remove(path)
		return ovirtapi.Disk{}, err
	}
	b.audit(cc, 0, "ovirt.disk.create", "disk", id, map[string]any{"name": name, "size": size, "pool": pool.Name})
	return ovirtapi.Disk{ID: id, Name: name, Path: path, Format: "qcow2", PoolID: pool.PoolID,
		Provisioned: size, Incremental: true}, nil
}

func (b *OvirtBackend) DeleteDisk(c ovirtapi.Caller, id string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	var path string
	var vm sql.NullString
	if err := b.s.db.QueryRow(`SELECT path, vm_id FROM ovirt_disks WHERE id=?`, id).Scan(&path, &vm); err != nil {
		return fmt.Errorf("%w: disk %s", ovirtapi.ErrNotFound, id)
	}
	if vm.Valid {
		return fmt.Errorf("%w: disk %s is attached to VM %s", ovirtapi.ErrConflict, id, vm.String)
	}
	if _, err := b.s.db.Exec(`DELETE FROM ovirt_disks WHERE id=? AND vm_id IS NULL`, id); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	b.audit(cc, 0, "ovirt.disk.delete", "disk", id, map[string]any{"path": path})
	return nil
}

// WritableDisk pins a disk for an upload: a staged disk, or an API-made disk
// already attached to a stopped VM (the VM is pinned so it can't start
// mid-upload). A VM's own (non-API) disk is never overwritten.
func (b *OvirtBackend) WritableDisk(c ovirtapi.Caller, id string) (string, string, func(), error) {
	if _, err := call(c); err != nil {
		return "", "", nil, err
	}
	var path, format string
	var vm sql.NullString
	err := b.s.db.QueryRow(`SELECT path, format, vm_id FROM ovirt_disks WHERE id=?`, id).Scan(&path, &format, &vm)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil, fmt.Errorf("%w: only a disk created through this API can be uploaded to (disk %s)", ovirtapi.ErrConflict, id)
	}
	if err != nil {
		return "", "", nil, err
	}
	if !vm.Valid {
		return path, format, func() {}, nil
	}
	release, err := b.s.mgr.PinBackup(vm.String)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %v", ovirtapi.ErrConflict, err)
	}
	if sess, err := b.s.mgr.Get(vm.String); err != nil || b.s.mgr.Running(sess) || sess.DiskPath != path {
		release()
		return "", "", nil, fmt.Errorf("%w: disk %s is attached to a running VM", ovirtapi.ErrConflict, id)
	}
	return path, format, release, nil
}

// ---- VMs ------------------------------------------------------------------------

func (b *OvirtBackend) CreateVM(c ovirtapi.Caller, spec ovirtapi.VMSpec) (ovirtapi.VM, error) {
	cc, err := call(c)
	if err != nil {
		return ovirtapi.VM{}, err
	}
	name := strings.TrimSpace(spec.Name)
	if name == "" || len(name) > 255 {
		return ovirtapi.VM{}, fmt.Errorf("%w: a VM name of 1-255 characters is required", ovirtapi.ErrBadRequest)
	}
	org := cc.p.OrgID
	if spec.OrgID > 0 {
		if _, err := b.s.store.GetOrg(spec.OrgID); err == nil {
			org = spec.OrgID // a restore lands in the org the VM was backed up from
		}
	}
	var n int
	_ = b.s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE name=? AND deleted_at IS NULL`, name).Scan(&n)
	if n > 0 {
		return ovirtapi.VM{}, fmt.Errorf("%w: a VM named %q already exists", ovirtapi.ErrConflict, name)
	}
	cpus, mem := spec.CPUs, spec.MemoryMB
	if cpus <= 0 || cpus > 512 {
		cpus = 1
	}
	if mem < 64 {
		mem = 1024
	}
	if err := b.s.checkQuotaCreate(org, CreateInput{Kind: "server", CPUs: cpus, MemoryMB: mem}); err != nil {
		return ovirtapi.VM{}, fmt.Errorf("%w: %v", ovirtapi.ErrConflict, err)
	}
	purpose := spec.Purpose
	if purpose != "worker" {
		purpose = "restore"
	}
	sess, err := b.s.mgr.CreateBare(session.CreateOpts{
		OrgID: org, OwnerID: cc.p.User.ID, Name: name, Kind: "server", Firmware: spec.Firmware,
		CPUs: cpus, MemoryMB: mem, MachineType: spec.MachineType, DiskBus: spec.DiskBus, NICModel: spec.NICModel,
		VGA: spec.VGA, GuestAgent: spec.GuestAgent, TPM: spec.TPM, SecureBoot: spec.SecureBoot, OSType: spec.OSType,
	}, spec.UserData)
	if err != nil {
		return ovirtapi.VM{}, ovErr(err)
	}
	if _, err := b.s.db.Exec(`INSERT INTO ovirt_vms(vm_id, purpose) VALUES(?,?)`, sess.ID, purpose); err != nil {
		_ = b.s.mgr.Purge(sess.ID)
		return ovirtapi.VM{}, err
	}
	b.audit(cc, org, "ovirt.vm.create", "session", sess.ID, map[string]any{"name": name, "purpose": purpose,
		"cpus": cpus, "memory_mb": mem, "cloud_init": spec.UserData != ""})
	return b.VM(c, sess.ID)
}

// DeleteVM: a worker the API made is purged outright; any other VM goes to
// Trash, like a delete in the UI. keepDisks (oVirt detach_only) first detaches
// the disk, which then stays as a staged disk.
func (b *OvirtBackend) DeleteVM(c ovirtapi.Caller, id string, keepDisks bool) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	sess, _, err := b.session(id)
	if err != nil {
		return err
	}
	if b.s.mgr.BackupBusy(id) {
		return fmt.Errorf("%w: %v", ovirtapi.ErrConflict, session.ErrBackupBusy)
	}
	if err := b.s.mgr.Stop(id); err != nil {
		return err
	}
	if keepDisks && sess.DiskPath != "" {
		if err := b.detach(cc, sess); err != nil {
			return err
		}
	}
	var purpose string
	_ = b.s.db.QueryRow(`SELECT purpose FROM ovirt_vms WHERE vm_id=?`, id).Scan(&purpose)
	if err := b.s.mgr.Delete(id); err != nil {
		return ovErr(err)
	}
	purged := false
	if purpose == "worker" {
		if err := b.s.mgr.Purge(id); err != nil {
			return err
		}
		purged = true
	}
	b.audit(cc, sess.OrgID, "ovirt.vm.delete", "session", id, map[string]any{"name": sess.Name, "purged": purged,
		"detach_only": keepDisks})
	return nil
}

var diskBuses = map[string]string{"virtio": "virtio-blk", "virtio_scsi": "virtio-scsi", "sata": "sata", "ide": "sata"}
var nicModels = map[string]string{"virtio": "virtio", "e1000": "e1000e", "e1000e": "e1000e", "rtl8139": "rtl8139"}

func hardwareOf(s *session.Session) session.HardwareSpec {
	return session.HardwareSpec{Firmware: s.Firmware, OSType: s.OSType, MachineType: s.MachineType, DiskBus: s.DiskBus,
		NICModel: s.NICModel, VGA: s.VGA, GuestAgent: s.GuestAgent, TPM: s.TPM, SecureBoot: s.SecureBoot,
		PinCPUs: s.PinCPUs, HugePages: s.HugePages}
}

// AttachDisk attaches a staged disk to a stopped VM that has none (a VXVisor
// instance has exactly one disk).
func (b *OvirtBackend) AttachDisk(c ovirtapi.Caller, vmID, diskID, iface string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	sess, _, err := b.session(vmID)
	if err != nil {
		return err
	}
	if sess.DiskPath != "" {
		return fmt.Errorf("%w: VM %s already has a disk (VXVisor instances have exactly one)", ovirtapi.ErrConflict, vmID)
	}
	if b.s.mgr.Running(sess) {
		return fmt.Errorf("%w: stop the VM before attaching a disk", ovirtapi.ErrConflict)
	}
	var path, format string
	var poolID, size int64
	if err := b.s.db.QueryRow(`SELECT path, format, pool_id, size FROM ovirt_disks WHERE id=? AND vm_id IS NULL`, diskID).
		Scan(&path, &format, &poolID, &size); err != nil {
		return fmt.Errorf("%w: no detached disk %s", ovirtapi.ErrNotFound, diskID)
	}
	res, err := b.s.db.Exec(`UPDATE ovirt_disks SET vm_id=? WHERE id=? AND vm_id IS NULL`, vmID, diskID)
	if err != nil {
		return ovErr(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: disk %s was attached concurrently", ovirtapi.ErrConflict, diskID)
	}
	backend := "qcow2"
	if format != "qcow2" {
		backend = "raw"
	}
	if err := b.s.mgr.SetDisk(vmID, path, backend, int((size+(1<<30)-1)>>30), poolID); err != nil {
		_, _ = b.s.db.Exec(`UPDATE ovirt_disks SET vm_id=NULL WHERE id=?`, diskID)
		return ovErr(err)
	}
	if bus, ok := diskBuses[iface]; ok && bus != sess.DiskBus {
		hw := hardwareOf(sess)
		hw.DiskBus = bus
		if err := b.s.mgr.UpdateHardware(vmID, hw); err != nil {
			return err
		}
	}
	b.audit(cc, sess.OrgID, "ovirt.disk.attach", "session", vmID, map[string]any{"disk": diskID, "interface": iface})
	return nil
}

func (b *OvirtBackend) DetachDisk(c ovirtapi.Caller, vmID, diskID string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	sess, x, err := b.session(vmID)
	if err != nil {
		return err
	}
	if sess.DiskPath == "" || b.vmDisk(sess, x).ID != diskID {
		return fmt.Errorf("%w: disk %s is not attached to VM %s", ovirtapi.ErrNotFound, diskID, vmID)
	}
	if b.s.mgr.Running(sess) {
		return fmt.Errorf("%w: stop the VM before detaching its disk", ovirtapi.ErrConflict)
	}
	if err := b.detach(cc, sess); err != nil {
		return err
	}
	b.audit(cc, sess.OrgID, "ovirt.disk.detach", "session", vmID, map[string]any{"disk": diskID})
	return nil
}

// detach turns a stopped VM's disk into a staged disk. Only file-backed qcow2
// disks can be: a staged disk is a file the API can later delete.
func (b *OvirtBackend) detach(cc *ovirtCall, sess *session.Session) error {
	_, x, err := b.session(sess.ID)
	if err != nil {
		return err
	}
	if diskFormat(sess.DiskBackend) != "qcow2" {
		return fmt.Errorf("%w: only a file-backed qcow2 disk can be detached (this one is %s)", ovirtapi.ErrBadRequest, sess.DiskBackend)
	}
	d := b.vmDisk(sess, x)
	if x.diskID != "" {
		_, err = b.s.db.Exec(`UPDATE ovirt_disks SET vm_id=NULL WHERE id=?`, x.diskID)
	} else {
		_, err = b.s.db.Exec(`INSERT INTO ovirt_disks(id, name, path, format, pool_id, size) VALUES(?,?,?,?,?,?)`,
			d.ID, d.Name, d.Path, "qcow2", x.poolID, d.Provisioned)
	}
	if err != nil {
		return err
	}
	if err := b.s.mgr.SetDisk(sess.ID, "", "qcow2", 0, 0); err != nil {
		if x.diskID != "" {
			_, _ = b.s.db.Exec(`UPDATE ovirt_disks SET vm_id=? WHERE id=?`, sess.ID, x.diskID)
		} else {
			_, _ = b.s.db.Exec(`DELETE FROM ovirt_disks WHERE id=?`, d.ID)
		}
		return ovErr(err)
	}
	return nil
}

// SetNIC binds the VM's NIC to the port group behind a vNIC profile, and sets
// its model when the VM is stopped.
func (b *OvirtBackend) SetNIC(c ovirtapi.Caller, vmID, profileID, iface string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	sess, _, err := b.session(vmID)
	if err != nil {
		return err
	}
	if profileID != "" {
		nets, err := b.Networks(c)
		if err != nil {
			return err
		}
		netID := int64(-1)
		for _, n := range nets {
			if ovirtapi.NetUUID(n.NetID) == profileID {
				if n.OrgID != sess.OrgID && n.NetID != 0 {
					return fmt.Errorf("%w: vNIC profile %s belongs to another org than VM %s", ovirtapi.ErrBadRequest, profileID, vmID)
				}
				netID = n.NetID
			}
		}
		if netID < 0 {
			return fmt.Errorf("%w: vNIC profile %s", ovirtapi.ErrNotFound, profileID)
		}
		if netID != sess.NetworkID {
			if _, err := b.s.SetSessionNetwork(cc.p, vmID, netID, cc.ip); err != nil {
				return fmt.Errorf("%w: %v", ovirtapi.ErrBadRequest, err)
			}
		}
	}
	if model, ok := nicModels[iface]; ok && model != sess.NICModel && !b.s.mgr.Running(sess) {
		hw := hardwareOf(sess)
		hw.NICModel = model
		if err := b.s.mgr.UpdateHardware(vmID, hw); err != nil {
			return err
		}
		b.audit(cc, sess.OrgID, "ovirt.nic.model", "session", vmID, map[string]any{"model": model})
	}
	return nil
}

func (b *OvirtBackend) StartVM(c ovirtapi.Caller, id string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	if _, _, err := b.session(id); err != nil {
		return err
	}
	if _, err := b.s.StartSession(cc.p, id, cc.ip); err != nil {
		return ovErr(err)
	}
	return nil
}

func (b *OvirtBackend) StopVM(c ovirtapi.Caller, id string) error {
	cc, err := call(c)
	if err != nil {
		return err
	}
	if _, _, err := b.session(id); err != nil {
		return err
	}
	return ovErr(b.s.StopSession(cc.p, id, cc.ip))
}

// RecoverBackups clears what a crashed or killed vdxd left behind: qemu-nbd
// exports under workRoot, and backup jobs, exports, fleecing nodes and
// temporary bitmaps inside running VMs. Checkpoint bitmaps are kept; one
// whose backup never finalized has no row and is pruned at the next backup.
func (b *OvirtBackend) RecoverBackups(workRoot string) {
	vmbackup.SweepStale(workRoot)
	ids, _ := b.s.mgr.RunningIDs()
	for _, id := range ids {
		sess, err := b.s.mgr.Get(id)
		if err != nil || sess.DiskPath == "" || !b.s.mgr.Running(sess) {
			continue
		}
		d := b.diskDesc(sess)
		d.WorkRoot = workRoot
		if err := vmbackup.Recover(d); err != nil {
			log.Printf("ovirt: recovering backup state of %s: %v", id, err)
		}
	}
}
