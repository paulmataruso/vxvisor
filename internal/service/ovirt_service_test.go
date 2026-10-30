package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/ovirtapi"
	"vdxclone/internal/policy"
	"vdxclone/internal/session"
	"vdxclone/internal/storage"
	"vdxclone/internal/store"
)

func ovirtTestService(t *testing.T) (*Service, *OvirtBackend) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Paths.DataDir, cfg.Paths.DiskDir = dir, filepath.Join(dir, "disks")
	cfg.Paths.ImageDir, cfg.Paths.ISODir, cfg.Paths.BackupDir = dir, dir, dir
	if err := os.MkdirAll(cfg.Paths.DiskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(dir, "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	s := New(cfg, d, store.New(d), storage.New(cfg, d), netdrv.New(d), session.NewManager(cfg, d), policy.NoopEnforcer{})
	return s, s.NewOvirtBackend("198.51.100.7")
}

func auditCount(t *testing.T, s *Service, action string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestOvirtLoginAndBind: only enabled instance admins get in, every attempt
// is audited, and a user disabled after login loses access on the next request.
func TestOvirtLoginAndBind(t *testing.T) {
	s, b := ovirtTestService(t)
	if err := auth.CreateUser(s.db, "root", "pw-root-1", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := auth.CreateUser(s.db, "bob", "pw-bob-1", "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Login("bob", "pw-bob-1", "192.0.2.9"); !errors.Is(err, ovirtapi.ErrForbidden) {
		t.Errorf("non-admin login: %v", err)
	}
	if _, err := b.Login("root", "wrong", "192.0.2.9"); !errors.Is(err, ovirtapi.ErrForbidden) {
		t.Errorf("bad password: %v", err)
	}
	c, err := b.Login("root", "pw-root-1", "192.0.2.9")
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	for _, a := range []string{"ovirt.login", "ovirt.login_denied", "ovirt.login_failed"} {
		if auditCount(t, s, a) != 1 {
			t.Errorf("audit %s missing", a)
		}
	}
	bound, err := b.Bind(c, "192.0.2.10")
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if bound.(*ovirtCall).ip != "192.0.2.10" || !bound.(*ovirtCall).p.IsAdmin {
		t.Errorf("bound caller %+v", bound)
	}
	if _, err := s.db.Exec(`UPDATE users SET disabled=1 WHERE username='root'`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Bind(c, "192.0.2.10"); err == nil {
		t.Error("a disabled user still binds")
	}
	if _, err := b.VMs("not a caller"); !errors.Is(err, ovirtapi.ErrForbidden) {
		t.Errorf("foreign caller: %v", err)
	}
}

// TestOvirtInventoryAndRestoreTarget walks the backend the way a restore does:
// pools and port groups, a disk-less VM, a staged disk attached and detached,
// checkpoints, the backup pin, and a worker purged on delete.
func TestOvirtInventoryAndRestoreTarget(t *testing.T) {
	s, b := ovirtTestService(t)
	if err := auth.CreateUser(s.db, "root", "pw-root-1", "admin"); err != nil {
		t.Fatal(err)
	}
	c, err := b.Login("root", "pw-root-1", "192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	c, _ = b.Bind(c, "192.0.2.9")

	poolDir := t.TempDir()
	mustID(t, s, `INSERT INTO storage_pools(name,kind,path) VALUES('fast','dir',?)`, poolDir)
	mustID(t, s, `INSERT INTO storage_pools(name,kind,path) VALUES('ceph','rbd','rbdpool')`)
	pools, err := b.StoragePools(c)
	if err != nil {
		t.Fatal(err)
	}
	up := map[string]bool{}
	for _, p := range pools {
		up[p.Name] = p.Uploadable
	}
	if !up["default"] || !up["fast"] || up["ceph"] || len(pools) != 3 {
		t.Errorf("pools %+v", pools)
	}

	provider, _ := s.store.DefaultOrgID()
	tenant := mustID(t, s, `INSERT INTO orgs(name,slug) VALUES('Acme','acme')`)
	mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'lan','bridge','br0')`, provider)
	mustID(t, s, `INSERT INTO networks(org_id,name,mode,bridge) VALUES(?,'web','bridge','vdxt9')`, tenant)
	nets, err := b.Networks(c)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, n := range nets {
		names[n.Name] = true
	}
	if !names["vxvisor-nat"] || !names["lan"] || !names["acme/web"] {
		t.Errorf("networks %+v", nets)
	}

	vm, err := b.CreateVM(c, ovirtapi.VMSpec{Name: "restored-1", CPUs: 2, MemoryMB: 1024, Firmware: "bios",
		OSType: "linux", Purpose: "worker"})
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	if vm.Disk != nil || vm.Status != "down" || vm.CPUs != 2 || vm.OrgID != provider {
		t.Errorf("new VM %+v", vm)
	}
	if _, err := b.CreateVM(c, ovirtapi.VMSpec{Name: "restored-1"}); !errors.Is(err, ovirtapi.ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	if err := b.StartVM(c, vm.ID); err == nil || !strings.Contains(err.Error(), "no disk") {
		t.Errorf("start without a disk: %v", err)
	}

	// A staged disk (as CreateDisk leaves it), attached then detached.
	file := filepath.Join(poolDir, "ovirt-d1.qcow2")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustID(t, s, `INSERT INTO ovirt_disks(id,name,path,format,pool_id,size) VALUES('d1','r1',?,'qcow2',1,1073741824)`, file)
	if err := b.AttachDisk(c, vm.ID, "d1", "virtio_scsi"); err != nil {
		t.Fatalf("attach: %v", err)
	}
	got, err := b.VM(c, vm.ID)
	if err != nil || got.Disk == nil || got.Disk.ID != "d1" || got.Disk.Path != file || got.DiskBus != "virtio-scsi" || got.Disk.PoolID != 1 {
		t.Fatalf("after attach: %+v %v", got, err)
	}
	if staged, _ := b.Disks(c); len(staged) != 0 {
		t.Errorf("attached disk still listed as staged: %+v", staged)
	}
	if err := b.AttachDisk(c, vm.ID, "d1", ""); err == nil {
		t.Error("second attach accepted")
	}
	if err := b.DeleteDisk(c, "d1"); !errors.Is(err, ovirtapi.ErrConflict) {
		t.Errorf("delete attached disk: %v", err)
	}

	// Checkpoints are recorded and dropped when the disk changes.
	if err := b.AddCheckpoint(c, ovirtapi.Checkpoint{ID: "c1", VMID: vm.ID}); err != nil {
		t.Fatal(err)
	}
	if cps, _ := b.Checkpoints(c, vm.ID); len(cps) != 1 || cps[0].ID != "c1" {
		t.Errorf("checkpoints %+v", cps)
	}

	// A backup pin blocks deletion and disk changes.
	release, err := s.mgr.PinBackup(vm.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteVM(c, vm.ID, false); !errors.Is(err, ovirtapi.ErrConflict) {
		t.Errorf("delete while pinned: %v", err)
	}
	if err := b.DetachDisk(c, vm.ID, "d1"); err == nil {
		t.Error("detach while pinned accepted")
	}
	release()

	if err := b.DetachDisk(c, vm.ID, "d1"); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if cps, _ := b.Checkpoints(c, vm.ID); len(cps) != 0 {
		t.Errorf("checkpoints survived a disk change: %+v", cps)
	}
	if staged, _ := b.Disks(c); len(staged) != 1 || staged[0].ID != "d1" {
		t.Errorf("detached disk not staged: %+v", staged)
	}

	// A worker is purged on delete; its (detached) disk stays staged.
	if err := b.DeleteVM(c, vm.ID, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=?`, vm.ID).Scan(&n)
	if n != 0 {
		t.Error("worker not purged")
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("staged disk file removed with the worker: %v", err)
	}
	if err := b.DeleteDisk(c, "d1"); err != nil {
		t.Fatalf("delete staged disk: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("staged disk file kept: %v", err)
	}
	for _, a := range []string{"ovirt.vm.create", "ovirt.disk.attach", "ovirt.disk.detach", "ovirt.vm.delete", "ovirt.disk.delete"} {
		if auditCount(t, s, a) != 1 {
			t.Errorf("audit %s: %d", a, auditCount(t, s, a))
		}
	}

	// A restore VM goes to Trash, not away.
	vm2, err := b.CreateVM(c, ovirtapi.VMSpec{Name: "restored-2", Firmware: "bios", Purpose: "restore"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteVM(c, vm2.ID, false); err != nil {
		t.Fatal(err)
	}
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=? AND deleted_at IS NOT NULL`, vm2.ID).Scan(&n)
	if n != 1 {
		t.Error("restore VM not in Trash")
	}
	if _, err := b.VM(c, vm2.ID); !errors.Is(err, ovirtapi.ErrNotFound) {
		t.Errorf("trashed VM still listed: %v", err)
	}
}
