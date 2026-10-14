package netdrv

import (
	"regexp"
	"strings"
	"testing"
)

func TestGenMACLocallyAdministered(t *testing.T) {
	re := regexp.MustCompile(`^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)
	for i := 0; i < 50; i++ {
		m := GenMAC()
		if !re.MatchString(m) {
			t.Fatalf("bad MAC: %s", m)
		}
	}
}

// TestTapNameLength guards the Linux IFNAMSIZ (15-char) limit.
func TestTapNameLength(t *testing.T) {
	n := TapName("2a3c9eb0-c73b-4fbc-b482-4b0a67537cc2")
	if len(n) > 15 {
		t.Errorf("tap name too long (%d): %s", len(n), n)
	}
	if !strings.HasPrefix(n, "vdxt") {
		t.Errorf("tap name prefix: %s", n)
	}
	// Deterministic for the same session.
	if TapName("abc") != TapName("abc") {
		t.Errorf("tap name not deterministic")
	}
}

func TestRenderNFT(t *testing.T) {
	rs := RenderNFT("vdx_net1", []FirewallRule{
		{Action: "accept", Proto: "tcp", DPort: "22"},
		{Action: "accept", Proto: "tcp", DPort: "443", Source: "10.0.0.0/8"},
	})
	for _, want := range []string{
		"table inet vdx_net1 {",
		"type filter hook forward priority 0; policy drop;",
		"ct state established,related accept",
		"tcp dport 22 accept",
		"tcp dport 443 ip saddr 10.0.0.0/8 accept",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
}
