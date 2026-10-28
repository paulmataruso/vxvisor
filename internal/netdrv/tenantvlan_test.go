package netdrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderTenantGuard checks both forward-chain shapes and, where nft is
// available, that the ruleset parses (nft -c: check only, never applied).
func TestRenderTenantGuard(t *testing.T) {
	for _, bridgeNF := range []bool{false, true} {
		rs := RenderTenantGuard([]string{"vdxt12", "vdxt12.10"}, bridgeNF)
		if !strings.Contains(rs, `elements = { "vdxt12", "vdxt12.10" }`) {
			t.Fatalf("set elements missing:\n%s", rs)
		}
		if !strings.Contains(rs, "iifname @tbr udp dport 67 accept") || !strings.Contains(rs, "    iifname @tbr drop\n") ||
			strings.Contains(rs, "dport 53") {
			t.Fatalf("input guard missing:\n%s", rs)
		}
		crossOnly := strings.Contains(rs, "iifname @tbr oifname != @tbr drop")
		if crossOnly != bridgeNF {
			t.Fatalf("bridgeNF=%v but cross-only forward rule present=%v:\n%s", bridgeNF, crossOnly, rs)
		}
		checkNft(t, rs)
	}
	// No tenant interfaces: an empty, valid table.
	rs := RenderTenantGuard(nil, false)
	if strings.Contains(rs, "@tbr") {
		t.Fatalf("empty guard must not reference the set:\n%s", rs)
	}
	checkNft(t, rs)
}

func checkNft(t *testing.T, ruleset string) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil || os.Geteuid() != 0 {
		return
	}
	f := filepath.Join(t.TempDir(), "g.nft")
	if err := os.WriteFile(f, []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nft", "-c", "-f", f).CombinedOutput(); err != nil {
		t.Fatalf("nft -c rejected the guard: %v: %s\n%s", err, out, ruleset)
	}
}
