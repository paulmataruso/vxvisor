package netdrv

import (
	"path/filepath"
	"strings"
	"testing"

	"vdxclone/internal/db"
)

func TestRenderOverlayPlan(t *testing.T) {
	plan := RenderOverlayPlan(OverlayConfig{
		Bridge: "vdxbr0", VNI: 42, Underlay: "eth0", Gateway: "10.77.0.1", GatewayCIDR: 16,
	})
	joined := make([]string, len(plan))
	for i, c := range plan {
		joined[i] = strings.Join(c, " ")
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"ip link add vdxbr0 type bridge",
		"ip link add vdxvx42 type vxlan id 42 dev eth0 dstport 4789",
		"ip link set vdxvx42 master vdxbr0",
		"ip addr add 10.77.0.1/16 dev vdxbr0",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("overlay plan missing %q\n%s", want, all)
		}
	}
}

func TestIPAMAllocate(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// Migration 3 seeds the default org (id=1); allocate a network under it.
	res, err := d.Exec(`INSERT INTO networks(org_id,name,mode,bridge,vlan_id,cidr,gateway,pool_start,pool_end)
		VALUES(1,'n','overlay','vdxbr0',0,'10.77.0.0/16','10.77.0.1','','')`)
	if err != nil {
		t.Fatal(err)
	}
	netID, _ := res.LastInsertId()
	s := New(d)

	a, err := s.AllocLease(netID, "sess-a", "52:54:00:aa:bb:cc", "10.77.0.0/16", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// First free host address, skipping .0 (network) and .1 (gateway).
	if a != "10.77.0.2/16" {
		t.Errorf("first lease = %q, want 10.77.0.2/16", a)
	}
	// Idempotent for the same session.
	if again, _ := s.AllocLease(netID, "sess-a", "", "10.77.0.0/16", "10.77.0.1"); again != a {
		t.Errorf("lease not idempotent: %q vs %q", again, a)
	}
	// A different session gets the next address.
	b, _ := s.AllocLease(netID, "sess-b", "", "10.77.0.0/16", "10.77.0.1")
	if b != "10.77.0.3/16" {
		t.Errorf("second lease = %q, want 10.77.0.3/16", b)
	}
	if got := s.LeaseFor("sess-b"); got != "10.77.0.3" {
		t.Errorf("LeaseFor = %q, want 10.77.0.3", got)
	}
	// Releasing frees it for reuse.
	s.ReleaseLease("sess-a")
	c, _ := s.AllocLease(netID, "sess-c", "", "10.77.0.0/16", "10.77.0.1")
	if c != "10.77.0.2/16" {
		t.Errorf("post-release lease = %q, want reused 10.77.0.2/16", c)
	}
}
