package netdrv

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func joinCmds(cmds [][]string) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = strings.Join(c, " ")
	}
	return out
}

// TestVSwitchVlanCmds pins the exact sequence for the management vSwitch: VID 1
// stays PVID + untagged on the bridge and the uplink (management traffic is
// unchanged), port-group VIDs ride the uplink tagged, filtering goes on last.
func TestVSwitchVlanCmds(t *testing.T) {
	got := joinCmds(VSwitchVlanCmds("vSwitch0", "bond0", []int{20}, nil))
	want := []string{
		"bridge vlan add dev vSwitch0 vid 1 pvid untagged self",
		"bridge vlan add dev bond0 vid 1 pvid untagged",
		"bridge vlan add dev bond0 vid 20",
		"ip link set dev vSwitch0 type bridge vlan_filtering 1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vSwitch0/bond0 + VLAN 20:\n got %q\nwant %q", got, want)
	}

	// No tagged port groups: still filtering (guest-tagged frames are dropped),
	// with only the VID 1 defaults.
	got = joinCmds(VSwitchVlanCmds("vSwitch0", "bond0", nil, nil))
	want = []string{
		"bridge vlan add dev vSwitch0 vid 1 pvid untagged self",
		"bridge vlan add dev bond0 vid 1 pvid untagged",
		"ip link set dev vSwitch0 type bridge vlan_filtering 1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vSwitch0/bond0 untagged only:\n got %q\nwant %q", got, want)
	}

	// VIDs are sorted + de-duplicated; VID 1 (the untagged native) and invalid
	// VIDs are never added tagged; a host VLAN interface on the bridge keeps its
	// VID on the bridge itself and on the uplink.
	got = joinCmds(VSwitchVlanCmds("vdsprod", "eno3", []int{30, 1, 20, 30, 0, 4095}, []int{40}))
	want = []string{
		"bridge vlan add dev vdsprod vid 1 pvid untagged self",
		"bridge vlan add dev vdsprod vid 40 self",
		"bridge vlan add dev eno3 vid 1 pvid untagged",
		"bridge vlan add dev eno3 vid 20",
		"bridge vlan add dev eno3 vid 30",
		"bridge vlan add dev eno3 vid 40",
		"ip link set dev vdsprod type bridge vlan_filtering 1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalization:\n got %q\nwant %q", got, want)
	}

	// Internal-only vSwitch: no uplink commands at all.
	got = joinCmds(VSwitchVlanCmds("vdslab", "", []int{20}, nil))
	want = []string{
		"bridge vlan add dev vdslab vid 1 pvid untagged self",
		"ip link set dev vdslab type bridge vlan_filtering 1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("internal-only:\n got %q\nwant %q", got, want)
	}
}

// TestEnsureVSwitchVlansStopsBeforeFiltering: a membership that fails to apply
// must leave filtering off (never filter against a half-built VLAN table).
func TestEnsureVSwitchVlansStopsBeforeFiltering(t *testing.T) {
	var ran []string
	old := runCmd
	t.Cleanup(func() { runCmd = old })
	runCmd = func(args ...string) error {
		ran = append(ran, strings.Join(args, " "))
		if strings.Contains(ran[len(ran)-1], "dev bond0 vid 20") {
			return errors.New("boom")
		}
		return nil
	}
	if err := EnsureVSwitchVlans("vSwitch0", "bond0", []int{20}, nil); err == nil {
		t.Fatal("a failed membership must be reported")
	}
	for _, c := range ran {
		if strings.Contains(c, "vlan_filtering") {
			t.Fatalf("filtering must not be enabled after a failed membership: %q", ran)
		}
	}
	ran = nil
	runCmd = func(args ...string) error { ran = append(ran, strings.Join(args, " ")); return nil }
	if err := EnsureVSwitchVlans("vSwitch0", "bond0", []int{20}, nil); err != nil || len(ran) != 4 {
		t.Fatalf("want 4 commands, got %v (%q)", err, ran)
	}
	if err := EnsureVSwitchVlans("", "bond0", nil, nil); err == nil {
		t.Fatal("an empty bridge name must be refused")
	}
}

func TestParseVlanConfig(t *testing.T) {
	const cfg = `VLAN Dev name	 | VLAN ID
Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD
bond0.100      | 100  | bond0
vSwitch0.30    | 30  | vSwitch0
vSwitch0.10    | 10  | vSwitch0
vdxt7.20       | 20  | vdxt7
`
	if got := parseVlanConfig(cfg, "vSwitch0"); !reflect.DeepEqual(got, []int{10, 30}) {
		t.Fatalf("vSwitch0 uppers: %v", got)
	}
	if got := parseVlanConfig(cfg, "eno1"); got != nil {
		t.Fatalf("eno1 has no uppers: %v", got)
	}
}
