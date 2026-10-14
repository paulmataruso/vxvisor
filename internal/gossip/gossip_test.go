package gossip

import (
	"fmt"
	"testing"
	"time"
)

// TestSingleNodeCluster verifies a node forms a cluster of one and advertises
// its live capacity through gossip metadata — the decentralized path with no
// seeds and no coordinator.
func TestSingleNodeCluster(t *testing.T) {
	c, err := Start(Config{
		NodeName:  "test-node",
		BindAddr:  "127.0.0.1",
		BindPort:  0, // ephemeral
		MDNS:      false,
		Advertise: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Shutdown()

	if c.NumMembers() != 1 {
		t.Fatalf("expected 1 member, got %d", c.NumMembers())
	}
	c.UpdateLocal(8, 4096, 16384)
	time.Sleep(100 * time.Millisecond)

	members := c.Members()
	if len(members) != 1 {
		t.Fatalf("Members() = %d, want 1", len(members))
	}
	m := members[0]
	if m.Name != "test-node" {
		t.Errorf("name = %q, want test-node", m.Name)
	}
	if m.CPUs != 8 || m.MemFreeMB != 4096 || m.MemTotal != 16384 {
		t.Errorf("capacity not gossiped: %+v", m)
	}
	if !m.Alive {
		t.Errorf("local member should be alive")
	}
}

// TestTwoNodeJoin verifies two nodes gossip into one cluster via a static seed,
// each seeing the other's advertised capacity — membership replication with no
// central coordinator.
func TestTwoNodeJoin(t *testing.T) {
	a, err := Start(Config{NodeName: "node-a", BindAddr: "127.0.0.1", BindPort: 17946, Advertise: "127.0.0.1"})
	if err != nil {
		t.Fatalf("start a: %v", err)
	}
	defer a.Shutdown()
	a.UpdateLocal(4, 2048, 8192)

	b, err := Start(Config{
		NodeName: "node-b", BindAddr: "127.0.0.1", BindPort: 17947, Advertise: "127.0.0.1",
		Seeds: []string{"127.0.0.1:17946"},
	})
	if err != nil {
		t.Fatalf("start b: %v", err)
	}
	defer b.Shutdown()
	b.UpdateLocal(16, 9000, 32768)

	// Allow gossip to converge.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a.NumMembers() == 2 && b.NumMembers() == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if a.NumMembers() != 2 || b.NumMembers() != 2 {
		t.Fatalf("convergence failed: a=%d b=%d", a.NumMembers(), b.NumMembers())
	}
	// node-a should see node-b's gossiped capacity.
	var sawB bool
	for _, m := range a.Members() {
		if m.Name == "node-b" {
			sawB = true
			if m.CPUs != 16 || m.MemFreeMB != 9000 {
				t.Errorf("node-a sees stale capacity for b: %+v", m)
			}
		}
	}
	if !sawB {
		t.Errorf("node-a does not see node-b: %v", fmt.Sprint(a.Members()))
	}
}
