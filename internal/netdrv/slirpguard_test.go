package netdrv

import (
	"strings"
	"testing"
)

// TestRenderSlirpGuard checks the guard drops NEW QEMU connections to host
// loopback (v4 + v6) for both identities, allows only DNS, and is an atomic
// replace of its own table.
func TestRenderSlirpGuard(t *testing.T) {
	rs, err := RenderSlirpGuard(999, 996)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet vdxslirp\ndelete table inet vdxslirp\ntable inet vdxslirp {",
		"type filter hook output priority filter; policy accept;",
		"meta skuid 999 ct state new jump qemu_loopback",
		"meta skgid 996 ct state new jump qemu_loopback",
		"ip daddr 127.0.0.0/8 udp dport 53 return",
		"ip daddr 127.0.0.0/8 tcp dport 53 return",
		"ip daddr 127.0.0.0/8 drop",
		"ip6 daddr ::1 udp dport 53 return",
		"ip6 daddr ::1 drop",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("missing %q in:\n%s", want, rs)
		}
	}
	// DNS exceptions must come before the drop in the jump target.
	if strings.Index(rs, "udp dport 53 return") > strings.Index(rs, "127.0.0.0/8 drop") {
		t.Errorf("DNS exception after the drop:\n%s", rs)
	}
	// Only NEW connections are matched, so replies into QEMU's listeners pass.
	if strings.Contains(rs, "jump qemu_loopback") && strings.Count(rs, "ct state new jump") != 2 {
		t.Errorf("jump rules must match ct state new only:\n%s", rs)
	}
}

// TestRenderSlirpGuardIdentity: a zero id is never rendered (that would match
// root/vdxd itself), and no identity at all is an error rather than an empty guard.
func TestRenderSlirpGuardIdentity(t *testing.T) {
	rs, err := RenderSlirpGuard(0, 996)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rs, "skuid") {
		t.Errorf("uid 0 must not be matched:\n%s", rs)
	}
	rs, err = RenderSlirpGuard(999, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rs, "skgid") {
		t.Errorf("gid 0 must not be matched:\n%s", rs)
	}
	if _, err := RenderSlirpGuard(0, 0); err == nil {
		t.Errorf("no identity must be an error")
	}
}

func TestSysfsIfaceOK(t *testing.T) {
	for _, ok := range []string{"vdxbr0", "vdxt12", "bond0.20", "br_lan-1"} {
		if !sysfsIfaceOK(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "../etc", "a b", "way-too-long-name0", "br\n0"} {
		if sysfsIfaceOK(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}
