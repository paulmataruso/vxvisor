package service

import (
	"strings"
	"testing"
)

func TestRenderBridgeFW(t *testing.T) {
	fws := []PGFirewall{{
		Enabled: true,
		Zones: []PGZone{
			{Name: "Web", MACs: []string{"aa:bb:cc:00:00:01"}},
			{Name: "DB", MACs: []string{"de:ad:be:ef:00:01", "de:ad:be:ef:00:02"}},
		},
		Policies: []PGPolicy{
			{From: "Web", To: "DB", Action: "deny", Proto: "tcp", DPort: "3306"},
			{From: "DB", To: "Web", Action: "allow", Proto: "any"},
		},
	}}
	out := renderBridgeFW(fws)
	t.Log("\n" + out)
	want := []string{
		"table bridge vdxdfw {",
		"type filter hook forward priority -200; policy accept;",
		"ether saddr aa:bb:cc:00:00:01 ether daddr { de:ad:be:ef:00:01, de:ad:be:ef:00:02 } ether type ip tcp dport 3306 drop",
		"ether saddr { de:ad:be:ef:00:01, de:ad:be:ef:00:02 } ether daddr aa:bb:cc:00:00:01 accept",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing: %q", w)
		}
	}
	if renderBridgeFW([]PGFirewall{{Enabled: false}}) != "" {
		t.Error("disabled should render empty")
	}
	// zone with no MACs → policy skipped
	empty := renderBridgeFW([]PGFirewall{{Enabled: true, Zones: []PGZone{{Name: "A"}, {Name: "B"}}, Policies: []PGPolicy{{From: "A", To: "B", Action: "deny", Proto: "any"}}}})
	if empty != "" {
		t.Errorf("policy over empty zones should render nothing, got: %q", empty)
	}
}
