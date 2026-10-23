package vrouter

import "testing"

func TestRenderFirewallZBFW(t *testing.T) {
	legs := []Leg{
		{Idx: 0, Kind: LegTransit, IfaceName: "eth0"},
		{Idx: 1, Kind: LegInternal, IfaceName: "eth1"},
		{Idx: 2, Kind: LegInternal, IfaceName: "eth2"},
	}
	fw := VRFirewall{
		Enabled: true, AllowIntra: true,
		Zones: []VRZone{
			{Name: "External", Builtin: true},
			{Name: "App", Legs: []int{1}},
			{Name: "DB", Legs: []int{2}},
		},
		Policies: []VRPolicy{
			{From: "App", To: "External", Action: "allow", Proto: "tcp", DPort: "80"},
			{From: "DB", To: "App", Action: "allow", Proto: "tcp", DPort: "5432", Src: "aa:bb:cc:dd:ee:ff"},
			{From: "App", To: "DB", Action: "deny", Proto: "any"},
		},
	}
	out := RenderFirewall(VRouter{}, legs, fw)
	t.Log("\n" + out)
	must := []string{
		"table inet vdxfw {",
		"type filter hook forward priority filter; policy drop;",
		"ct state invalid drop",
		"ct state established,related accept",
		`iifname "eth0" oifname "eth0" accept`, // External intra (resolves to transit)
		`iifname "eth1" oifname "eth1" accept`,
		`iifname "eth1" oifname "eth0" tcp dport 80 accept`,
		`iifname "eth2" oifname "eth1" ether saddr aa:bb:cc:dd:ee:ff tcp dport 5432 accept`,
		`iifname "eth1" oifname "eth2" drop`,
	}
	for _, m := range must {
		if !contains(out, m) {
			t.Errorf("missing line: %q", m)
		}
	}
	// disabled → empty
	if RenderFirewall(VRouter{}, legs, VRFirewall{Enabled: false}) != "" {
		t.Error("disabled firewall should render empty")
	}
	// validation
	bad := VRPolicy{From: "App", To: "DB", Action: "allow", Proto: "tcp", DPort: "99999"}
	if ValidatePolicy(&fw, bad) == nil {
		t.Error("expected invalid port to be rejected")
	}
	if ValidatePolicy(&fw, VRPolicy{From: "Nope", To: "DB", Action: "allow"}) == nil {
		t.Error("expected unknown zone to be rejected")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
