package service

import (
	"strings"
	"testing"

	"vdxclone/internal/vrouter"
)

// mac constants for the test topology.
const (
	macA1 = "02:00:00:00:00:01" // net 1
	macA2 = "02:00:00:00:00:02" // net 1
	macC  = "02:00:00:00:00:03" // net 2
	macD  = "02:00:00:00:00:04" // net 2
)

func testMaps() fwMaps {
	return fwMaps{
		netToMACs: map[int64][]string{1: {macA1, macA2}, 2: {macC, macD}},
		macToNet:  map[string]int64{macA1: 1, macA2: 1, macC: 2, macD: 2},
	}
}

// North-South: a whole-PG group on the vRouter's internal leg, allowed out to
// External on tcp/80, must compile to iifname eth1 oifname eth0 tcp dport 80 accept.
func TestCompileNorthSouth_WholePGToExternal(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups:  []FWGroup{{ID: "gw", Name: "Web", Zone: ZoneInternal, Networks: []int64{1}}},
		RulesNS: []FWRule{{From: "gw", To: ZoneExternal, Action: "allow", Proto: "tcp", DPort: "80"}},
	}
	legs := []vrouter.Leg{
		{Idx: 0, Kind: vrouter.LegTransit, IfaceName: "eth0"},
		{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", NetworkID: 1},
	}
	fw := compileVRouterFW(f, testMaps(), legs)
	if !fw.Enabled {
		t.Fatal("expected the vRouter firewall to be enabled (it has a policy)")
	}
	if len(fw.Policies) != 1 {
		t.Fatalf("expected 1 compiled policy, got %d: %+v", len(fw.Policies), fw.Policies)
	}
	out := vrouter.RenderFirewall(vrouter.VRouter{}, legs, fw)
	for _, want := range []string{
		"table inet vdxfw {",
		"policy drop;",
		`iifname "eth1" oifname "eth0" tcp dport 80 accept`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered ruleset missing %q\n---\n%s", want, out)
		}
	}
}

// A vRouter that no rule governs must compile to an EMPTY (disabled) ruleset —
// never a default-drop chain with no allow rule (which would blackhole it).
func TestCompileNorthSouth_NoRulesStaysOpen(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups:  []FWGroup{{ID: "gd", Name: "DB", Zone: ZoneInternal, MACs: []string{macC}}}, // net 2, not a leg
		RulesNS: []FWRule{{From: "gd", To: ZoneExternal, Action: "allow", Proto: "any"}},
	}
	legs := []vrouter.Leg{
		{Idx: 0, Kind: vrouter.LegTransit, IfaceName: "eth0"},
		{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", NetworkID: 1}, // net 1 only
	}
	fw := compileVRouterFW(f, testMaps(), legs)
	if fw.Enabled {
		t.Fatal("expected disabled firewall (no policy applies to this vRouter)")
	}
	if out := vrouter.RenderFirewall(vrouter.VRouter{}, legs, fw); out != "" {
		t.Errorf("expected empty ruleset, got:\n%s", out)
	}
}

// Per-MAC source narrowing when a group is a subset of a port group.
func TestCompileNorthSouth_SubsetNarrowsSource(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups:  []FWGroup{{ID: "g1", Name: "One", Zone: ZoneInternal, MACs: []string{macA1}}}, // only A1 of net 1
		RulesNS: []FWRule{{From: "g1", To: ZoneExternal, Action: "allow", Proto: "any"}},
	}
	legs := []vrouter.Leg{
		{Idx: 0, Kind: vrouter.LegTransit, IfaceName: "eth0"},
		{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", NetworkID: 1},
	}
	fw := compileVRouterFW(f, testMaps(), legs)
	out := vrouter.RenderFirewall(vrouter.VRouter{}, legs, fw)
	if !strings.Contains(out, "ether saddr "+macA1) {
		t.Errorf("expected per-MAC source narrowing for %s\n---\n%s", macA1, out)
	}
}

// North-South with an explicit From-VM narrows the source to exactly that MAC,
// even when the group is a whole port group.
func TestCompileNorthSouth_FromVM(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups:  []FWGroup{{ID: "gw", Name: "Web", Zone: ZoneInternal, Networks: []int64{1}}},
		RulesNS: []FWRule{{From: "gw", FromVM: macA2, To: ZoneExternal, Action: "allow", Proto: "any"}},
	}
	legs := []vrouter.Leg{
		{Idx: 0, Kind: vrouter.LegTransit, IfaceName: "eth0"},
		{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", NetworkID: 1},
	}
	out := vrouter.RenderFirewall(vrouter.VRouter{}, legs, compileVRouterFW(f, testMaps(), legs))
	if !strings.Contains(out, "ether saddr "+macA2) {
		t.Errorf("expected source narrowed to %s\n---\n%s", macA2, out)
	}
	if strings.Contains(out, macA1) {
		t.Errorf("did not expect the other VM %s to appear\n---\n%s", macA1, out)
	}
}

// East-West with a To-VM narrows the destination MAC on the segment.
func TestCompileEastWest_ToVM(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups: []FWGroup{
			{ID: "gc", Name: "C", Zone: ZoneInternal, MACs: []string{macC}},
			{ID: "all", Name: "All", Zone: ZoneInternal, Networks: []int64{2}}, // whole net 2
		},
		RulesEW: []FWRule{{From: "gc", To: "all", ToVM: macD, Action: "deny", Proto: "any"}},
	}
	zones, pols := compileNetEW(f, testMaps(), 2)
	out := renderBridgeFW([]PGFirewall{{Enabled: true, Zones: zones, Policies: pols}})
	if !strings.Contains(out, "ether saddr "+macC+" ether daddr "+macD+" drop") {
		t.Errorf("expected destination narrowed to %s\n---\n%s", macD, out)
	}
}

// East-West: two groups on the SAME network compile to a bridge deny.
func TestCompileEastWest_SameSegment(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups: []FWGroup{
			{ID: "gc", Name: "C", Zone: ZoneInternal, MACs: []string{macC}},
			{ID: "gd", Name: "D", Zone: ZoneInternal, MACs: []string{macD}},
		},
		RulesEW: []FWRule{{From: "gc", To: "gd", Action: "deny", Proto: "any"}},
	}
	zones, pols := compileNetEW(f, testMaps(), 2)
	if len(pols) != 1 {
		t.Fatalf("expected 1 east-west policy on net 2, got %d", len(pols))
	}
	out := renderBridgeFW([]PGFirewall{{Enabled: true, Zones: zones, Policies: pols}})
	for _, want := range []string{"table bridge vdxdfw {", "policy accept;", "ether saddr " + macC + " ether daddr " + macD + " drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered bridge ruleset missing %q\n---\n%s", want, out)
		}
	}
}

// East-West across DIFFERENT segments emits nothing (that traffic is routed).
func TestCompileEastWest_CrossSegmentSkipped(t *testing.T) {
	f := &OrgFirewall{
		Enabled: true,
		Groups: []FWGroup{
			{ID: "ga", Name: "A", Zone: ZoneInternal, MACs: []string{macA1}}, // net 1
			{ID: "gc", Name: "C", Zone: ZoneInternal, MACs: []string{macC}},  // net 2
		},
		RulesEW: []FWRule{{From: "ga", To: "gc", Action: "deny", Proto: "any"}},
	}
	if _, pols := compileNetEW(f, testMaps(), 1); len(pols) != 0 {
		t.Errorf("net 1 should have no policy (gc has no members there), got %d", len(pols))
	}
	if _, pols := compileNetEW(f, testMaps(), 2); len(pols) != 0 {
		t.Errorf("net 2 should have no policy (ga has no members there), got %d", len(pols))
	}
}
