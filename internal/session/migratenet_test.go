package session

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"vdxclone/internal/qemu"
)

// Two managers on two fresh DBs stand in for two cluster nodes: org ids agree
// (replicated), networks row ids don't.

const migVM = "0b9d3f5e-7c41-4a2e-9d0a-5f6e7a8b9c01"

func lease(t *testing.T, m *Manager, netID int64, sid, ip string) {
	t.Helper()
	if _, err := m.db.Exec(`INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,?,?,'52:54:00:00:00:01')`, netID, sid, ip); err != nil {
		t.Fatal(err)
	}
}

func leasesOf(t *testing.T, m *Manager, sid string) []string {
	t.Helper()
	rows, err := m.db.Query(`SELECT network_id||' '||ip FROM ip_leases WHERE session_id=? ORDER BY id`, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

// TestPortGroupRefResolvesToLocalRow: the destination binds its OWN row with the
// same identity, never the source's id (which names another row there).
func TestPortGroupRefResolvesToLocalRow(t *testing.T) {
	src, _, ten := testManager(t, "user")
	dst, _, ten2 := testManager(t, "user")
	if ten != ten2 {
		t.Fatalf("org ids differ across test nodes: %d vs %d", ten, ten2)
	}
	mkPG(t, src, ten, "pad", "bridge", "vdxt1", 0, "", "", "", "") // shift ids on the source
	web := mkPG(t, src, ten, "web", "bridge", "vdxt9", 10, "10.5.0.0/24", "10.5.0.1", "10.5.0.10", "10.5.0.50")
	lease(t, src, web, migVM, "10.5.0.12/24")

	ref, err := src.PortGroupRefFor(&Session{ID: migVM, OrgID: ten, NetworkID: web})
	if err != nil {
		t.Fatal(err)
	}
	want := qemu.PortGroupRef{OrgID: ten, Name: "web", VLAN: 10, CIDR: "10.5.0.0/24", Lease: "10.5.0.12/24"}
	if *ref != want {
		t.Fatalf("ref = %+v, want %+v", *ref, want)
	}

	// On the destination the source's id is another org's row; the match is "web".
	mkPG(t, dst, 1, "prov", "bridge", "vdxbr0", 0, "", "", "", "")
	other := mkPG(t, dst, 1, "prov2", "bridge", "vdxbr0", 5, "", "", "", "")
	local := mkPG(t, dst, ten, "web", "bridge", "vdxt3", 10, "10.5.0.0/24", "10.5.0.1", "10.5.0.10", "10.5.0.50")
	if other != web {
		t.Fatalf("test setup: want the source id %d to name another row on the destination, got %d", web, other)
	}
	got, err := dst.resolvePortGroupRef(ref)
	if err != nil || got != local {
		t.Fatalf("resolve = %d, %v; want %d", got, err, local)
	}
}

// TestPortGroupRefRefusesLookAlikes: same name but another VLAN, VNI, subnet or
// org is not a match, and two matches are ambiguous.
func TestPortGroupRefRefusesLookAlikes(t *testing.T) {
	dst, def, ten := testManager(t, "user")
	ref := &qemu.PortGroupRef{OrgID: ten, Name: "web", VLAN: 10, CIDR: "10.5.0.0/24"}

	mkPG(t, dst, ten, "web", "bridge", "vdxt3", 20, "10.5.0.0/24", "", "", "") // other VLAN
	mkPG(t, dst, ten, "web", "bridge", "vdxt3", 10, "10.6.0.0/24", "", "", "") // other subnet
	mkPG(t, dst, def, "web", "bridge", "vdxt3", 10, "10.5.0.0/24", "", "", "") // other org
	vx := mkPG(t, dst, ten, "web", "vxlan", "vdxvx", 10, "10.5.0.0/24", "", "", "")
	if _, err := dst.db.Exec(`UPDATE networks SET vni=5001 WHERE id=?`, vx); err != nil { // other VNI
		t.Fatal(err)
	}
	if _, err := dst.resolvePortGroupRef(ref); err == nil || !strings.Contains(err.Error(), "no port group") {
		t.Fatalf("look-alikes: got %v, want a no-match error", err)
	}

	a := mkPG(t, dst, ten, "web", "bridge", "vdxt3", 10, "10.5.0.0/24", "", "", "")
	if got, err := dst.resolvePortGroupRef(ref); err != nil || got != a {
		t.Fatalf("one match: %d, %v", got, err)
	}
	mkPG(t, dst, ten, "web", "bridge", "vdxt4", 10, "10.5.0.0/24", "", "", "")
	if _, err := dst.resolvePortGroupRef(ref); err == nil || !strings.Contains(err.Error(), "rename all but one") {
		t.Fatalf("two matches: got %v, want ambiguous", err)
	}
}

// TestMigratedNetworkWithoutRef: a record from an older node is accepted only
// when the VM had no port group; a tenant VM always needs one.
func TestMigratedNetworkWithoutRef(t *testing.T) {
	dst, def, ten := testManager(t, "user")
	if _, err := dst.migratedNetwork(&Session{ID: migVM, OrgID: ten, NetworkID: 7}); !errors.Is(err, errOldMigrationPeer) {
		t.Fatalf("bound VM, no ref: %v", err)
	}
	if id, err := dst.migratedNetwork(&Session{ID: migVM, OrgID: def}); err != nil || id != 0 {
		t.Fatalf("unbound VM, no ref: %d, %v", id, err)
	}
	if _, err := dst.migratedNetwork(&Session{ID: migVM, OrgID: ten, PortGroup: &qemu.PortGroupRef{OrgID: def, Name: "x"}}); err == nil {
		t.Fatalf("ref org differs from the VM's: accepted")
	}
	if err := dst.CheckMigrationTarget(&Session{ID: migVM, OrgID: ten, PortGroup: &qemu.PortGroupRef{OrgID: ten}}); !errors.Is(err, ErrTenantNoPortGroup) {
		t.Fatalf("tenant VM with no port group: %v", err)
	}
}

// TestReserveMigratedLease: the guest keeps its address only if no other
// instance holds it on the destination segment (any port group on the same
// bridge + VLAN); a stale lease of its own is replaced.
func TestReserveMigratedLease(t *testing.T) {
	dst, _, ten := testManager(t, "user")
	web := mkPG(t, dst, ten, "web", "bridge", "vdxt3", 10, "10.5.0.0/24", "", "", "")
	twin := mkPG(t, dst, ten, "web-b", "bridge", "vdxt3", 10, "10.5.0.0/24", "", "", "")
	old := mkPG(t, dst, ten, "old", "bridge", "vdxt8", 0, "10.9.0.0/24", "", "", "")
	lease(t, dst, twin, "someone-else", "10.5.0.12/24")
	lease(t, dst, old, migVM, "10.9.0.4/24")

	s := &Session{ID: migVM, OrgID: ten, PortGroup: &qemu.PortGroupRef{OrgID: ten, Name: "web", VLAN: 10, CIDR: "10.5.0.0/24", Lease: "10.5.0.12/24"}}
	if err := dst.CheckMigrationTarget(s); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("precheck, address taken on the segment: %v", err)
	}
	if err := dst.reserveMigratedLease(web, migVM, "m", "10.5.0.12/24"); err == nil {
		t.Fatalf("reserve, address taken: accepted")
	}
	if got := leasesOf(t, dst, migVM); len(got) != 1 {
		t.Fatalf("a refused reserve changed the leases: %v", got)
	}

	s.PortGroup.Lease = "10.5.0.13/24"
	if err := dst.CheckMigrationTarget(s); err != nil {
		t.Fatalf("precheck, free address: %v", err)
	}
	if err := dst.reserveMigratedLease(web, migVM, "m", "10.5.0.13/24"); err != nil {
		t.Fatal(err)
	}
	if got := leasesOf(t, dst, migVM); len(got) != 1 || !strings.HasSuffix(got[0], "10.5.0.13/24") || !strings.HasPrefix(got[0], itoa(web)+" ") {
		t.Fatalf("leases = %v, want only %d 10.5.0.13/24", got, web)
	}
}

// TestAttachReceiverNICUserNet: a receiver needs the shipped ref; a SLIRP NIC
// keeps SLIRP (no tap) but still reserves its address; a bridged source NIC is
// never turned into SLIRP.
func TestAttachReceiverNICUserNet(t *testing.T) {
	dst, def, ten := testManager(t, "user")
	if _, err := dst.attachReceiverNIC(&qemu.Spec{ID: migVM, UserNet: true}); !errors.Is(err, errOldMigrationPeer) {
		t.Fatalf("no ref: %v", err)
	}
	nat := mkPG(t, dst, def, "nat", "user", "", 0, "10.0.2.0/24", "", "", "")
	spec := &qemu.Spec{ID: migVM, UserNet: true, MAC: "52:54:00:12:34:56",
		PortGroup: &qemu.PortGroupRef{OrgID: def, Name: "nat", CIDR: "10.0.2.0/24", Lease: "10.0.2.15/24"}}
	rn, err := dst.attachReceiverNIC(spec)
	if err != nil {
		t.Fatal(err)
	}
	if rn.NetID != nat || rn.Tap != "" || spec.TapName != "" || rn.Lease != "10.0.2.15/24" {
		t.Fatalf("rn = %+v, tap %q", rn, spec.TapName)
	}
	dst.detachReceiverNIC(migVM, rn)
	if got := leasesOf(t, dst, migVM); len(got) != 0 {
		t.Fatalf("detach left leases: %v", got)
	}

	bridged := &qemu.Spec{ID: migVM, PortGroup: &qemu.PortGroupRef{OrgID: def}}
	if _, err := dst.attachReceiverNIC(bridged); err == nil || !strings.Contains(err.Error(), "user-mode NAT") {
		t.Fatalf("bridged source onto SLIRP: %v", err)
	}
	if _, err := dst.attachReceiverNIC(&qemu.Spec{ID: migVM, UserNet: true, PortGroup: &qemu.PortGroupRef{OrgID: ten}}); !errors.Is(err, ErrTenantNoPortGroup) {
		t.Fatalf("tenant receiver with no port group: %v", err)
	}
}

// TestAdoptBindsLocalPortGroup: live and cold adopts record the destination's
// row, not the shipped (source-node) network_id; an abort frees the address.
func TestAdoptBindsLocalPortGroup(t *testing.T) {
	dst, _ := snapTestManager(t)
	ten := int64(0)
	if err := dst.db.QueryRow(`SELECT id FROM orgs WHERE slug='acme'`).Scan(&ten); err != nil {
		t.Fatal(err)
	}
	nat := mkPG(t, dst, ten, "pad", "user", "", 0, "", "", "", "")
	local := mkPG(t, dst, ten, "web", "bridge", "vdxt3", 0, "10.5.0.0/24", "", "", "")
	ref := &qemu.PortGroupRef{OrgID: ten, Name: "web", CIDR: "10.5.0.0/24", Lease: "10.5.0.20/24"}
	shipped := nat // the source's id names an unrelated row here

	// Live: the receiver's attachment is what the adopt records.
	self, _ := os.FindProcess(os.Getpid())
	dst.trackIncoming(migVM, self, receiverNet{NetID: local, Lease: ref.Lease})
	live := &Session{ID: migVM, Name: "vm", OrgID: ten, OwnerID: 1, ImageName: "img", DiskPath: "/d", Kind: "server",
		Firmware: "bios", MAC: "52:54:00:aa:bb:cc", NetworkID: shipped, PortGroup: ref, DiskBackend: "qcow2"}
	if err := dst.AdoptMigrated(live); err != nil {
		t.Fatal(err)
	}
	var got int64
	_ = dst.db.QueryRow(`SELECT COALESCE(network_id,0) FROM sessions WHERE id=?`, migVM).Scan(&got)
	if got != local {
		t.Fatalf("live adopt network_id = %d, want %d (shipped %d)", got, local, shipped)
	}

	// Cold: resolved from the record, the lease kept, the shipped id ignored.
	coldID := "1c2d3e4f-5a6b-4c7d-8e9f-a0b1c2d3e4f5"
	disk := filepath.Join(t.TempDir(), "d.qcow2")
	if err := os.WriteFile(disk, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cold := *live
	cold.ID, cold.DiskPath = coldID, disk
	cold.PortGroup = &qemu.PortGroupRef{OrgID: ten, Name: "web", CIDR: "10.5.0.0/24", Lease: "10.5.0.21/24"}
	if err := dst.AdoptColdMigrated(&cold); err != nil {
		t.Fatal(err)
	}
	_ = dst.db.QueryRow(`SELECT COALESCE(network_id,0) FROM sessions WHERE id=?`, coldID).Scan(&got)
	if got != local {
		t.Fatalf("cold adopt network_id = %d, want %d", got, local)
	}
	if l := leasesOf(t, dst, coldID); len(l) != 1 || l[0] != itoa(local)+" 10.5.0.21/24" {
		t.Fatalf("cold adopt leases = %v", l)
	}

	// A cold record whose port group doesn't exist here is refused, nothing written.
	bad := cold
	bad.ID = "2d3e4f5a-6b7c-4d8e-9fa0-b1c2d3e4f5a6"
	bad.PortGroup = &qemu.PortGroupRef{OrgID: ten, Name: "nope"}
	if err := dst.AdoptColdMigrated(&bad); err == nil {
		t.Fatalf("cold adopt onto a missing port group: accepted")
	}
	var n int
	_ = dst.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id=?`, bad.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("refused cold adopt wrote a row")
	}

	// Abort: the reserved address goes with the receiver.
	abortID := "3e4f5a6b-7c8d-4e9f-a0b1-c2d3e4f5a6b7"
	lease(t, dst, local, abortID, "10.5.0.22/24")
	dst.trackIncoming(abortID, nil, receiverNet{NetID: local, Lease: "10.5.0.22/24"})
	dst.AbortIncoming(abortID)
	if l := leasesOf(t, dst, abortID); len(l) != 0 {
		t.Fatalf("abort left leases: %v", l)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
