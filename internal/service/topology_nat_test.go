package service

import (
	"net"
	"slices"
	"testing"

	"vdxclone/internal/hostinfo"
)

// TestNATUplink: a portless bridge whose subnet the host masquerades (LXC's
// lxcbr0) gets the default-route interface as a NAT uplink, with that
// interface's adapters as members; a bridge outside every masqueraded network,
// or the default-route bridge itself, gets none.
func TestNATUplink(t *testing.T) {
	ruleset := `table inet lxc {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip6 saddr fc42:5009:ba4b:5ab0::/64 ip6 daddr != fc42:5009:ba4b:5ab0::/64 counter packets 0 bytes 0 masquerade
		ip saddr 10.0.3.0/24 ip daddr != 10.0.3.0/24 counter packets 3 bytes 184 masquerade
	}
}
table inet vdxtenant {
	chain forward { ip saddr 10.9.0.0/24 drop }
}`
	nets := parseMasqueradeSources(ruleset)
	if len(nets) != 2 || nets[0].String() != "fc42:5009:ba4b:5ab0::/64" || nets[1].String() != "10.0.3.0/24" {
		t.Fatalf("masquerade sources: %v", nets)
	}
	old := defaultRouteIfaces
	defer func() { defaultRouteIfaces = old }()
	defaultRouteIfaces = func() []string { return []string{"vSwitch0"} }
	ifaces := []hostinfo.Iface{
		{Name: "vSwitch0", Type: "bridge", State: "up", Addrs: []string{"192.168.10.163/24"}},
		{Name: "bond0", Type: "bond", Master: "vSwitch0"},
		{Name: "vdx0a1b2c3d4e", Type: "tap", Master: "vSwitch0"},
		{Name: "lxcbr0", Type: "bridge", Addrs: []string{"10.0.3.1/24", "fe80::1/64"}},
		{Name: "vdxt27", Type: "bridge", Addrs: []string{"10.9.0.1/24"}},
	}
	u, ok := natUplink(ifaces[3], ifaces, nets)
	if !ok || u.Kind != "nat" || u.Name != "vSwitch0" || u.State != "up" || !slices.Equal(u.Members, []string{"bond0"}) {
		t.Fatalf("lxcbr0 NAT uplink = %+v, %v", u, ok)
	}
	if _, ok := natUplink(ifaces[4], ifaces, nets); ok {
		t.Fatal("an isolated tenant bridge isn't NATed")
	}
	if _, ok := natUplink(ifaces[0], ifaces, append(nets, mustNet(t, "192.168.10.0/24"))); ok {
		t.Fatal("the default-route bridge isn't its own NAT uplink")
	}
}

func mustNet(t *testing.T, c string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(c)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
