package service

import (
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/session"
)

// containerTestService wires a Service over a fresh DB with the Default org
// (migration 3) and one tenant org. No host devices are touched: the only
// "existing" bridge used is lo, read from sysfs.
func containerTestService(t *testing.T) (*Service, int64, int64) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	s := &Service{db: d, net: netdrv.New(d), mgr: session.NewManager(&config.Config{}, d)}
	var def int64
	if err := d.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&def); err != nil {
		t.Fatalf("default org: %v", err)
	}
	res, err := d.Exec(`INSERT INTO orgs(name,slug) VALUES('Acme','acme')`)
	if err != nil {
		t.Fatalf("tenant org: %v", err)
	}
	ten, _ := res.LastInsertId()
	return s, def, ten
}

func ctPG(t *testing.T, s *Service, org int64, name, bridge string, vlan int) int64 {
	t.Helper()
	res, err := s.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id) VALUES(?,?,?,?,?)`,
		org, name, map[bool]string{true: "bridge", false: "user"}[bridge != ""], bridge, vlan)
	if err != nil {
		t.Fatalf("port group %s: %v", name, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// TestResolveContainerNIC: the bridge (+ VLAN) comes from a port group the
// container's org owns — never from the request — and lxcbr0 (shared by every
// container on the host) is the Default org's only.
func TestResolveContainerNIC(t *testing.T) {
	s, def, ten := containerTestService(t)
	own := ctPG(t, s, ten, "web", "lo", 20)
	gone := ctPG(t, s, ten, "gone", "vdxnope0", 0)
	nat := ctPG(t, s, ten, "nat", "", 0)
	prov := ctPG(t, s, def, "prov", "lo", 0)

	if _, err := s.resolveContainerNIC(ten, 0); !errors.Is(err, errTenantNoContainerPG) {
		t.Errorf("tenant on lxcbr0: got %v", err)
	}
	if nic, err := s.resolveContainerNIC(def, 0); err != nil || nic.Bridge != "lxcbr0" || nic.NetworkID != 0 {
		t.Errorf("Default org fallback: %+v err=%v", nic, err)
	}
	if _, err := s.resolveContainerNIC(ten, prov); err == nil {
		t.Errorf("tenant used another org's port group")
	}
	if _, err := s.resolveContainerNIC(ten, nat); err == nil {
		t.Errorf("bridgeless port group accepted")
	}
	if _, err := s.resolveContainerNIC(ten, gone); err == nil {
		t.Errorf("port group whose bridge isn't on this host accepted")
	}
	nic, err := s.resolveContainerNIC(ten, own)
	if err != nil || nic.Bridge != "lo" || nic.VLAN != 20 || nic.NetworkID != own || nic.MTU != 0 {
		t.Errorf("own port group: %+v err=%v", nic, err)
	}
}

// TestCheckContainerAttach is the start-time backstop.
func TestCheckContainerAttach(t *testing.T) {
	s, def, ten := containerTestService(t)
	pg := ctPG(t, s, ten, "web", "vdxt5", 0)
	mk := func(name string, org int64, bridge string, nid int64) ContainerRow {
		res, err := s.db.Exec(`INSERT INTO containers(name,org_id,bridge,network_id) VALUES(?,?,?,?)`, name, org, bridge, nid)
		if err != nil {
			t.Fatalf("container %s: %v", name, err)
		}
		id, _ := res.LastInsertId()
		return ContainerRow{ID: id, Name: name, OrgID: org, Bridge: bridge, NetworkID: nid}
	}

	legacyDef := mk("d1", def, "vdxbr0", 0)
	if err := s.checkContainerAttach(&legacyDef); err != nil {
		t.Errorf("Default org legacy container refused: %v", err)
	}
	adopt := mk("t1", ten, "vdxt5", 0)
	if err := s.checkContainerAttach(&adopt); err != nil || adopt.NetworkID != pg {
		t.Errorf("legacy tenant container on its own bridge not adopted: nid=%d err=%v", adopt.NetworkID, err)
	}
	var stored int64
	_ = s.db.QueryRow(`SELECT network_id FROM containers WHERE id=?`, adopt.ID).Scan(&stored)
	if stored != pg {
		t.Errorf("adoption not persisted: %d", stored)
	}
	foreign := mk("t2", ten, "vdxbr0", 0)
	if err := s.checkContainerAttach(&foreign); err == nil {
		t.Errorf("tenant container on a bridge it has no port group for was started")
	}
	moved := mk("t3", ten, "vdxt9", pg)
	if err := s.checkContainerAttach(&moved); err == nil {
		t.Errorf("container whose config bridge no longer matches its port group was started")
	}
	ok := mk("t4", ten, "vdxt5", pg)
	if err := s.checkContainerAttach(&ok); err != nil {
		t.Errorf("bound tenant container refused: %v", err)
	}
}

func TestContainerPortGroupsScope(t *testing.T) {
	s, def, ten := containerTestService(t)
	ctPG(t, s, ten, "web", "vdxt5", 0)
	ctPG(t, s, ten, "nat", "", 0)
	member := &Principal{OrgID: ten, OrgRole: "member"}
	pgs, err := s.ContainerPortGroups(member, ten)
	if err != nil || len(pgs) != 1 || pgs[0].Name != "web" {
		t.Errorf("own org: %+v err=%v (want only the bridged port group)", pgs, err)
	}
	if _, err := s.ContainerPortGroups(member, def); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("member listed another org's port groups: %v", err)
	}
	if _, err := s.ContainerPortGroups(&Principal{OrgID: def, IsAdmin: true}, ten); err != nil {
		t.Errorf("instance admin: %v", err)
	}
}

func TestCheckContainerLimits(t *testing.T) {
	if err := checkContainerLimits(1, 512); err != nil {
		t.Errorf("1 vCPU / 512 MB: %v", err)
	}
	if checkContainerLimits(runtime.NumCPU()+1, 512) == nil {
		t.Errorf("more vCPUs than host CPUs accepted")
	}
	if checkContainerLimits(1, 32) == nil {
		t.Errorf("32 MB accepted")
	}
}
