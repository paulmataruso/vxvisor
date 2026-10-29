package session

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/config"
	"vdxclone/internal/db"
)

// testManager opens a fresh DB (Default org seeded by migration 3) plus a
// tenant org, and returns the manager and both org ids. No devices, no root.
func testManager(t *testing.T, mode string) (*Manager, int64, int64) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := &config.Config{}
	cfg.Network.Mode = mode
	cfg.Cluster.Bridge = "vdxbr0"
	cfg.Cluster.Subnet = "10.77.0.0/16"
	cfg.Cluster.Gateway = "10.77.0.1"
	m := NewManager(cfg, d)
	var def int64
	if err := d.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&def); err != nil {
		t.Fatalf("default org: %v", err)
	}
	res, err := d.Exec(`INSERT INTO orgs(name,slug) VALUES('Acme','acme')`)
	if err != nil {
		t.Fatalf("tenant org: %v", err)
	}
	ten, _ := res.LastInsertId()
	return m, def, ten
}

func mkPG(t *testing.T, m *Manager, org int64, name, mode, bridge string, vlan int, cidr, gw, ps, pe string) int64 {
	t.Helper()
	res, err := m.db.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr,gateway,pool_start,pool_end) VALUES(?,?,?,?,?,?,?,?,?)`,
		org, name, mode, bridge, vlan, cidr, gw, ps, pe)
	if err != nil {
		t.Fatalf("mk port group %s: %v", name, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// TestCheckPortGroup: "no port group" stays available to the Default org only;
// a tenant must use one of its OWN vSwitch-backed port groups.
func TestCheckPortGroup(t *testing.T) {
	m, def, ten := testManager(t, "user")
	if m.IsTenantOrg(def) || !m.IsTenantOrg(ten) || !m.IsTenantOrg(9999) {
		t.Fatalf("IsTenantOrg: default=%v tenant=%v unknown=%v", m.IsTenantOrg(def), m.IsTenantOrg(ten), m.IsTenantOrg(9999))
	}
	own := mkPG(t, m, ten, "web", "bridge", "vdxt5", 0, "", "", "", "")
	nat := mkPG(t, m, ten, "nat", "user", "", 0, "", "", "", "")
	other := mkPG(t, m, def, "prov", "bridge", "vdxbr0", 0, "", "", "", "")

	if err := m.CheckPortGroup(def, 0); err != nil {
		t.Errorf("Default org, no port group: %v", err)
	}
	if err := m.CheckPortGroup(ten, 0); !errors.Is(err, ErrTenantNoPortGroup) {
		t.Errorf("tenant, no port group: got %v", err)
	}
	if err := m.CheckPortGroup(ten, other); err == nil {
		t.Errorf("tenant attached to another org's port group")
	}
	if err := m.CheckPortGroup(ten, nat); err == nil {
		t.Errorf("tenant attached to a bridgeless (SLIRP) port group")
	}
	if err := m.CheckPortGroup(ten, own); err != nil {
		t.Errorf("tenant, own port group: %v", err)
	}
}

// TestPlanNIC: a VM bound to a bridged port group always gets a tap, even when
// the global mode is user (SLIRP); only unattached VMs follow the global mode,
// and a tenant VM with no (or a vanished) port group is refused at launch.
func TestPlanNIC(t *testing.T) {
	m, def, ten := testManager(t, "user")
	pg := mkPG(t, m, def, "lan", "bridge", "vdxsw1", 30, "", "", "", "")
	other := mkPG(t, m, ten, "t", "bridge", "vdxt9", 0, "", "", "", "")

	plan, err := m.planNIC(&Session{OrgID: def, NetworkID: pg})
	if err != nil || plan.UserNet || plan.Bridge != "vdxsw1" || plan.VLAN != 30 {
		t.Errorf("bridged PG in user mode: %+v err=%v (want tap on vdxsw1 VLAN 30)", plan, err)
	}
	if plan, err = m.planNIC(&Session{OrgID: def}); err != nil || !plan.UserNet {
		t.Errorf("Default org, no PG, user mode: %+v err=%v (want SLIRP)", plan, err)
	}
	if _, err = m.planNIC(&Session{OrgID: ten}); !errors.Is(err, ErrTenantNoPortGroup) {
		t.Errorf("tenant, no PG: got %v", err)
	}
	if _, err = m.planNIC(&Session{OrgID: ten, NetworkID: 424242}); !errors.Is(err, ErrTenantNoPortGroup) {
		t.Errorf("tenant, deleted PG: got %v", err)
	}
	if _, err = m.planNIC(&Session{OrgID: def, NetworkID: other}); err == nil {
		t.Errorf("VM on another org's port group was planned")
	}

	m.cfg.Network.Mode = "bridge"
	if plan, err = m.planNIC(&Session{OrgID: def}); err != nil || plan.UserNet || plan.Bridge != "vdxbr0" {
		t.Errorf("Default org, no PG, bridge mode: %+v err=%v (want cluster bridge)", plan, err)
	}
}

// TestGuestAddressingPool: a static address comes from the VM's own port group
// pool (never the cluster subnet); two isolated segments with the same CIDR
// allocate independently; two port groups on one segment never collide; and a
// purge frees the address.
func TestGuestAddressingPool(t *testing.T) {
	m, def, ten := testManager(t, "bridge")
	a := mkPG(t, m, ten, "a", "bridge", "vdxt5", 0, "10.5.0.0/24", "10.5.0.1", "10.5.0.10", "10.5.0.11")
	b := mkPG(t, m, def, "b", "bridge", "vdxt6", 0, "10.5.0.0/24", "10.5.0.1", "10.5.0.10", "10.5.0.11")
	a2 := mkPG(t, m, ten, "a2", "bridge", "vdxt5", 0, "10.5.0.0/24", "10.5.0.1", "10.5.0.10", "10.5.0.20")

	ip, gw, dhcp, err := m.guestAddressing(ten, a, "s1", "52:54:00:00:00:01")
	if err != nil || ip != "10.5.0.10/24" || gw != "10.5.0.1" || dhcp {
		t.Fatalf("first lease: ip=%q gw=%q dhcp=%v err=%v", ip, gw, dhcp, err)
	}
	if again, _, _, _ := m.guestAddressing(ten, a, "s1", "52:54:00:00:00:01"); again != ip {
		t.Errorf("not idempotent: %q then %q", ip, again)
	}
	if ip, _, _, err = m.guestAddressing(def, b, "s2", ""); err != nil || ip != "10.5.0.10/24" {
		t.Errorf("isolated segment with the same CIDR: ip=%q err=%v (want its own .10)", ip, err)
	}
	if ip, _, _, err = m.guestAddressing(ten, a2, "s3", ""); err != nil || ip != "10.5.0.11/24" {
		t.Errorf("second port group on the same segment: ip=%q err=%v (want .11, .10 is taken)", ip, err)
	}
	if _, _, _, err = m.guestAddressing(ten, a, "s4", ""); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("exhausted pool: err=%v", err)
	}
	m.releaseLeases("s1")
	if ip, _, _, err = m.guestAddressing(ten, a, "s4", ""); err != nil || ip != "10.5.0.10/24" {
		t.Errorf("after release: ip=%q err=%v (want the freed .10)", ip, err)
	}
	if _, _, _, err = m.guestAddressing(ten, b, "s5", ""); err == nil {
		t.Errorf("addressed from another org's port group")
	}

	// A bridged port group without a pool: DHCP from the segment, no lease.
	dh := mkPG(t, m, ten, "dh", "bridge", "vdxt7", 0, "10.6.0.0/24", "10.6.0.1", "", "")
	if ip, _, dhcp, err = m.guestAddressing(ten, dh, "s6", ""); err != nil || ip != "" || !dhcp {
		t.Errorf("pool-less port group: ip=%q dhcp=%v err=%v (want DHCP)", ip, dhcp, err)
	}
}

func TestAllocLeaseRejectsBadPool(t *testing.T) {
	m, _, ten := testManager(t, "bridge")
	for _, c := range []struct{ cidr, s, e string }{
		{"10.5.0.0/24", "10.6.0.10", "10.6.0.20"}, // outside the CIDR
		{"10.5.0.0/24", "10.5.0.20", "10.5.0.10"}, // empty
		{"10.5.0.0/31", "", ""},                   // no host addresses
		{"fd00::/64", "", ""},                     // not IPv4
	} {
		id := mkPG(t, m, ten, "p"+c.cidr+c.s, "bridge", "vdxt8", 0, c.cidr, "", c.s, c.e)
		if _, err := m.allocLease(id, "x", "", c.cidr, "", c.s, c.e, false); err == nil {
			t.Errorf("pool %s %s-%s accepted", c.cidr, c.s, c.e)
		}
	}
}

func TestArgParsers(t *testing.T) {
	args := []string{"qemu", "-netdev", "tap,id=n0,ifname=vdxt1,vhost=on", "-device", "virtio-net-pci,netdev=n0,host_mtu=1450"}
	if got := hostMTUFromArgs(args); got != 1450 {
		t.Errorf("hostMTUFromArgs = %d", got)
	}
	if user, known := userNetFromArgs(args); user || !known {
		t.Errorf("tap argv read as user=%v known=%v", user, known)
	}
	if user, known := userNetFromArgs([]string{"-netdev", "user,id=n0"}); !user || !known {
		t.Errorf("SLIRP argv read as user=%v known=%v", user, known)
	}
	if _, known := userNetFromArgs(nil); known {
		t.Errorf("empty argv reported as known")
	}
	if hostMTUFromArgs([]string{"-device", "virtio-net-pci,netdev=n0"}) != 0 {
		t.Errorf("host_mtu found where there is none")
	}
}

func TestRandVNCPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw := randVNCPassword()
		if len(pw) != 8 {
			t.Fatalf("len %d (VNC auth uses exactly 8 characters)", len(pw))
		}
		for _, c := range pw {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				t.Fatalf("unexpected character %q in %q", c, pw)
			}
		}
		seen[pw] = true
	}
	if len(seen) < 195 {
		t.Errorf("only %d distinct passwords in 200 draws", len(seen))
	}
}
