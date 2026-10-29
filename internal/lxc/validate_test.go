package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestManagedBlockRefusesInjection: a bridge (or any NIC value) carrying a
// newline would append arbitrary lxc.* keys — lxc.hook.* runs host commands as
// root — so the sink must refuse it, and anything that isn't an interface name.
func TestManagedBlockRefusesInjection(t *testing.T) {
	for _, br := range []string{
		"vdxbr0\nlxc.hook.pre-start = /bin/sh -c id",
		"br0\r",
		"../../etc",
		"a b",
		"way-too-long-bridge0",
	} {
		if _, err := managedBlock("web1", br, "", 0, 0, 1, 512); err == nil {
			t.Errorf("bridge %q accepted", br)
		}
	}
	if _, err := managedBlock("web1", "vdxt7", "52:54:00:aa:bb:cc\nlxc.hook.mount = x", 0, 0, 1, 512); err == nil {
		t.Errorf("MAC with a newline accepted")
	}
	if _, err := managedBlock("web1", "vdxt7", "", 4095, 0, 1, 512); err == nil {
		t.Errorf("VLAN 4095 accepted")
	}
}

// TestManagedBlockVLANAndMTU: a tagged port group becomes the veth's untagged
// PVID (lxc.net.0.veth.vlan.id) and a sub-1500 bridge its MTU; untagged writes
// neither key.
func TestManagedBlockVLANAndMTU(t *testing.T) {
	b, err := managedBlock("web1", "vdxt7", "52:54:00:AA:BB:CC", 20, 1450, 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"lxc.net.0.type = veth\n", "lxc.net.0.link = vdxt7\n", "lxc.net.0.veth.pair = " + VethName("web1") + "\n",
		"lxc.net.0.hwaddr = 52:54:00:aa:bb:cc\n", "lxc.net.0.veth.vlan.id = 20\n", "lxc.net.0.mtu = 1450\n",
		"lxc.cgroup2.cpuset.cpus = 0-1\n",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
	b, _ = managedBlock("web1", "lxcbr0", "", 0, 0, 1, 512)
	if strings.Contains(b, "vlan.id") || strings.Contains(b, ".mtu") {
		t.Errorf("untagged/default NIC should write no vlan/mtu key:\n%s", b)
	}
}

func TestValidNameAndTemplateArgs(t *testing.T) {
	for _, ok := range []string{"web1", "web-01", "db.prod_2", "A"} {
		if ValidName(ok) != nil {
			t.Errorf("name %q refused", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "../x", "-n", "a/b", "web 1", "x\ny", strings.Repeat("a", 65)} {
		if ValidName(bad) == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	for _, ok := range []string{"ubuntu", "noble", "3.24", "9-Stream", "amd64", "edge"} {
		if ValidTemplateArg("release", ok) != nil {
			t.Errorf("template arg %q refused", ok)
		}
	}
	for _, bad := range []string{"", "../../etc", "a..b", "a/b", "--dist", "x y"} {
		if ValidTemplateArg("release", bad) == nil {
			t.Errorf("template arg %q accepted", bad)
		}
	}
}

// TestUpdateManaged rewrites the NIC keys in place: link swapped, a VLAN/MTU
// added then removed again, nothing else (MAC, veth pair) disturbed, and a
// malicious bridge refused before the file is touched.
func TestUpdateManaged(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "web1"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "web1", "config")
	orig := "lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\n# --- managed by vdxd ---\nlxc.net.0.veth.pair = vdxabc\nlxc.net.0.hwaddr = 52:54:00:00:00:01\n"
	if err := os.WriteFile(cfg, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateManaged("web1", dir, "vdxt9", 30, 1450, 2, 1024); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg)
	s := string(got)
	for _, want := range []string{"lxc.net.0.link = vdxt9", "lxc.net.0.veth.vlan.id = 30", "lxc.net.0.mtu = 1450",
		"lxc.net.0.hwaddr = 52:54:00:00:00:01", "lxc.net.0.veth.pair = vdxabc"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "link = lxcbr0") {
		t.Errorf("old link kept:\n%s", s)
	}
	if err := UpdateManaged("web1", dir, "vdxt9", 0, 0, 2, 1024); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(cfg)
	if strings.Contains(string(got), "vlan.id") || strings.Contains(string(got), "net.0.mtu") {
		t.Errorf("untagged move should drop vlan/mtu keys:\n%s", got)
	}
	before := string(got)
	if err := UpdateManaged("web1", dir, "vdxbr0\nlxc.hook.start = /bin/id", 0, 0, 1, 512); err == nil {
		t.Fatalf("malicious bridge accepted")
	}
	if after, _ := os.ReadFile(cfg); string(after) != before {
		t.Errorf("config changed by a refused update")
	}
}
