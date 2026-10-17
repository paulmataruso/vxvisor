package remoteprov

import (
	"strings"
	"testing"
)

func TestRenderJoinNetplan(t *testing.T) {
	got := RenderJoinNetplan(JoinConfig{
		MgmtIface: "eno1", MgmtCIDR: "172.16.0.170/24", Gateway: "172.16.0.1",
		DNS: []string{"1.1.1.1", "8.8.8.8"}, ClusterIface: "eno2", ClusterCIDR: "10.10.0.5/24",
	})
	for _, want := range []string{
		"version: 2", "eno1:", "addresses: [172.16.0.170/24]",
		"to: default", "via: 172.16.0.1", "addresses: [1.1.1.1, 8.8.8.8]",
		"eno2:", "addresses: [10.10.0.5/24]", "accept-ra: no",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("netplan missing %q\n---\n%s", want, got)
		}
	}
	// Cluster iface equal to mgmt must not be emitted twice.
	g2 := RenderJoinNetplan(JoinConfig{MgmtIface: "eno1", MgmtCIDR: "1.2.3.4/24", ClusterIface: "eno1"})
	if strings.Count(g2, "eno1:") != 1 {
		t.Errorf("mgmt==cluster should emit one iface:\n%s", g2)
	}
}

// mockRunner records SudoRun/Run invocations and lets a test assert the arming
// order (rollback must be armed BEFORE netplan apply).
type mockRunner struct {
	cmds   []string
	failOn string // substring; SudoRun returns code 1 when cmd contains it
}

func (m *mockRunner) Run(cmd string, _ []byte) (string, string, int, error) {
	m.cmds = append(m.cmds, "run:"+cmd)
	if strings.Contains(cmd, "ip -j link") {
		return `[{"ifname":"lo","link_type":"loopback"},{"ifname":"eno1","link_type":"ether"},{"ifname":"eno2","link_type":"ether"}]`, "", 0, nil
	}
	return "", "", 0, nil
}
func (m *mockRunner) SudoRun(cmd string, _ []byte) (string, string, int, error) {
	m.cmds = append(m.cmds, "sudo:"+cmd)
	if m.failOn != "" && strings.Contains(cmd, m.failOn) {
		return "", "boom", 1, nil
	}
	return "", "", 0, nil
}
func (m *mockRunner) Close() error { return nil }

func TestArmBeforeApply(t *testing.T) {
	m := &mockRunner{}
	if err := ArmAndApply(m, "net: x", 300); err != nil {
		t.Fatalf("ArmAndApply: %v", err)
	}
	armIdx, applyIdx := -1, -1
	for i, c := range m.cmds {
		if strings.Contains(c, "start vdx-join-rollback.timer") {
			armIdx = i
		}
		if strings.Contains(c, "netplan generate && netplan apply") {
			applyIdx = i
		}
	}
	if armIdx < 0 || applyIdx < 0 {
		t.Fatalf("missing arm/apply steps: %v", m.cmds)
	}
	if armIdx > applyIdx {
		t.Fatalf("rollback was armed AFTER apply (unsafe): arm=%d apply=%d", armIdx, applyIdx)
	}
	// Existing netplan must be MOVED aside, and the apply must be detached.
	joined := strings.Join(m.cmds, "\n")
	if !strings.Contains(joined, "mv /etc/netplan/*.yaml") {
		t.Errorf("existing netplan not moved aside:\n%s", joined)
	}
	if !strings.Contains(joined, "systemd-run") || !strings.Contains(joined, "--no-block") {
		t.Errorf("apply not detached:\n%s", joined)
	}
}

func TestPreflightRejectsSameIface(t *testing.T) {
	if err := Preflight(&mockRunner{}, "eno1", "eno1"); err == nil {
		t.Error("expected error when mgmt==cluster iface")
	}
	if err := Preflight(&mockRunner{}, "eno9", "eno2"); err == nil {
		t.Error("expected error for unknown mgmt iface")
	}
	if err := Preflight(&mockRunner{}, "eno1", "eno2"); err != nil {
		t.Errorf("valid ifaces should pass: %v", err)
	}
}
