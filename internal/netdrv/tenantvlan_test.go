package netdrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderTenantGuard checks the host guard and, where nft is available, that
// the ruleset parses (nft -c: check only, never applied).
func TestRenderTenantGuard(t *testing.T) {
	rs := RenderTenantGuard([]string{"vdxt12", "vdxt12.10"})
	if !strings.Contains(rs, `elements = { "vdxt12", "vdxt12.10" }`) {
		t.Fatalf("set elements missing:\n%s", rs)
	}
	if !strings.Contains(rs, "iifname @tbr udp dport 67 accept") || !strings.Contains(rs, "    iifname @tbr drop\n") ||
		strings.Contains(rs, "dport 53") {
		t.Fatalf("input guard missing:\n%s", rs)
	}
	// Forward: only same-interface (bridged) traffic passes, whatever the
	// br_netfilter state — never a packet routed between two interfaces.
	if !strings.Contains(rs, `elements = { "vdxt12" . "vdxt12", "vdxt12.10" . "vdxt12.10" }`) ||
		!strings.Contains(rs, "iifname @tbr iifname . oifname != @tself drop") ||
		!strings.Contains(rs, "oifname @tbr iifname . oifname != @tself drop") {
		t.Fatalf("forward guard missing:\n%s", rs)
	}
	checkNft(t, rs)
	// No tenant interfaces: an empty, valid table.
	rs = RenderTenantGuard(nil)
	if strings.Contains(rs, "@tbr") {
		t.Fatalf("empty guard must not reference the set:\n%s", rs)
	}
	checkNft(t, rs)
}

// TestRenderTenantL2Guard: rogue DHCP / RA / BPDUs are dropped from untrusted
// ports of tenant bridges only, and the ruleset parses.
func TestRenderTenantL2Guard(t *testing.T) {
	rs := RenderTenantL2Guard([]string{"vdxt12"}, []string{"bond0.100", "vrh3e1"})
	for _, want := range []string{
		"table bridge vdxtenantl2 {", `elements = { "vdxt12" }`, `elements = { "bond0.100", "vrh3e1" }`,
		"meta ibrname != @tbr accept", "iifname @trusted accept",
		"ether daddr { 01:80:c2:00:00:00, 01:00:0c:cc:cc:cd } drop",
		"udp sport 67 udp dport 68 drop", "udp sport 547 udp dport 546 drop", "icmpv6 type nd-router-advert drop",
	} {
		if !strings.Contains(rs, want) {
			t.Fatalf("L2 guard missing %q:\n%s", want, rs)
		}
	}
	if strings.Index(rs, "iifname @trusted accept") > strings.Index(rs, "udp sport 67") {
		t.Fatalf("trusted ports must be accepted before the drops:\n%s", rs)
	}
	checkNft(t, rs)
	// No trusted ports: no empty set is rendered.
	rs = RenderTenantL2Guard([]string{"vdxt12"}, nil)
	if strings.Contains(rs, "@trusted") {
		t.Fatalf("no trusted ports must not reference the set:\n%s", rs)
	}
	checkNft(t, rs)
	rs = RenderTenantL2Guard(nil, nil)
	if strings.Contains(rs, "@tbr") || strings.Contains(rs, "drop") {
		t.Fatalf("no tenant bridges: an empty table:\n%s", rs)
	}
	checkNft(t, rs)
	checkNft(t, RenderTenantGuard([]string{"vdxt12"})+RenderTenantL2Guard([]string{"vdxt12"}, []string{"eth9"}))
	if err := ApplyTenantGuard([]string{"vdxt1\n"}, nil, nil); err == nil {
		t.Fatalf("a non-interface name must be refused before nft runs")
	}
}

// TestRenderTenantDHCPConf: values are written normalized, and anything that
// doesn't parse — above all a newline carrying a dnsmasq directive — is refused.
func TestRenderTenantDHCPConf(t *testing.T) {
	conf, err := RenderTenantDHCPConf("vdxt7", "10.50.0.1", "10.50.0.100,10.50.0.200", "255.255.255.0", "1.1.1.1, 8.8.8.8",
		"/run/vdx-tnet/vdxt7.leases", "/run/vdx-tnet/vdxt7.pid")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"interface=vdxt7\n", "port=0\n", "dhcp-range=10.50.0.100,10.50.0.200,255.255.255.0,12h\n",
		"dhcp-option=3,10.50.0.1\n", "dhcp-option=6,1.1.1.1,8.8.8.8\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("conf missing %q:\n%s", want, conf)
		}
	}
	const inj = "\ndhcp-script=/tmp/x"
	for _, tc := range []struct{ bridge, gw, rng, mask, dns string }{
		{"vdxt7", "10.50.0.1" + inj, "10.50.0.100,10.50.0.200", "", ""},
		{"vdxt7", "10.50.0.1", "10.50.0.100,10.50.0.200" + inj, "", ""},
		{"vdxt7", "10.50.0.1", "10.50.0.100,10.50.0.200", "255.255.255.0" + inj, ""},
		{"vdxt7", "10.50.0.1", "10.50.0.100,10.50.0.200", "", "1.1.1.1" + inj},
		{"vdxt7" + inj, "10.50.0.1", "10.50.0.100,10.50.0.200", "", ""},
		{"vdxt7", "10.50.0.1", "10.50.0.200,10.50.0.100", "", ""}, // start > end
		{"vdxt7", "10.50.0.1", "10.50.0.100", "", ""},             // not start,end
		{"vdxt7", "10.50.0.1", "10.50.0.100,10.50.0.200", "255.0.255.0", ""},
		{"vdxt7", "fe80::1", "10.50.0.100,10.50.0.200", "", ""},
		{"vdxt7", "10.50.0.1", "10.50.0.100,10.50.0.200", "", "dns.example"},
		{"../etc", "10.50.0.1", "10.50.0.100,10.50.0.200", "", ""},
	} {
		if out, err := RenderTenantDHCPConf(tc.bridge, tc.gw, tc.rng, tc.mask, tc.dns, "/run/x.leases", "/run/x.pid"); err == nil {
			t.Fatalf("%+v must be refused, rendered:\n%s", tc, out)
		}
	}
	if err := StartTenantDHCP("vxtestdhcp9", "10.50.0.1"+inj, "10.50.0.100,10.50.0.200", "", ""); err == nil {
		t.Fatalf("StartTenantDHCP must refuse an injected gateway before writing anything")
	}
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
