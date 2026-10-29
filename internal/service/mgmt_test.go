package service

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"vdxclone/internal/config"
	"vdxclone/internal/hostinfo"
)

// fakeHost is the kernel's view, for tests: interfaces, default-route devices,
// and what exists. stubHost wires it into the service's host hooks.
type fakeHost struct {
	ifs      []hostinfo.Iface
	defaults []string
}

func stubHost(t *testing.T, h *fakeHost) {
	t.Helper()
	oldIfs, oldDef, oldExists := hostIfaces, defaultRouteIfaces, ifaceExists
	t.Cleanup(func() { hostIfaces, defaultRouteIfaces, ifaceExists = oldIfs, oldDef, oldExists })
	hostIfaces = func() ([]hostinfo.Iface, error) { return slices.Clone(h.ifs), nil }
	defaultRouteIfaces = func() []string { return h.defaults }
	ifaceExists = func(n string) bool {
		return slices.ContainsFunc(h.ifs, func(it hostinfo.Iface) bool { return it.Name == n })
	}
}

// mgmtHost is the test host's layout: vSwitch0 (the admin IP) over bond0 over
// eno1+eno2, plus a free eno3.
func mgmtHost() *fakeHost {
	return &fakeHost{
		ifs: []hostinfo.Iface{
			{Name: "bond0", Type: "bond", Master: "vSwitch0"},
			{Name: "eno1", Type: "physical", Master: "bond0"},
			{Name: "eno2", Type: "physical", Master: "bond0"},
			{Name: "eno3", Type: "physical"},
			{Name: "lo", Type: "loopback", Addrs: []string{"127.0.0.1/8"}},
			{Name: "vSwitch0", Type: "bridge", Addrs: []string{"172.16.0.163/24", "fe80::1/64"}},
		},
		defaults: []string{"vSwitch0"},
	}
}

// TestMgmtDetection: a specific listener IP names its interface; a wildcard,
// loopback, empty or unknown listen address falls back to the default-route
// interface(s); with neither, the guards fail closed.
func TestMgmtDetection(t *testing.T) {
	h := mgmtHost()
	stubHost(t, h)
	s := &Service{cfg: &config.Config{}}
	for _, addr := range []string{"172.16.0.163:8766", "0.0.0.0:8766", ":8766", "[::]:8766", "127.0.0.1:8766", "", "10.9.9.9:8766", "vxhost.example:8766"} {
		s.cfg.Server.Addr = addr
		if got := s.mgmtIfaces(); !reflect.DeepEqual(got, []string{"vSwitch0"}) {
			t.Fatalf("addr %q: mgmt = %v, want [vSwitch0]", addr, got)
		}
	}
	if (&Service{}).mgmtIface() != "vSwitch0" {
		t.Fatalf("a nil config is a wildcard listener, not a crash")
	}

	s.cfg.Server.Addr = "0.0.0.0:8766"
	if err := s.guardMgmt("vSwitch0"); err == nil {
		t.Fatalf("the management bridge must be refused")
	}
	if err := s.guardMgmt("eno3", ""); err != nil {
		t.Fatalf("a free NIC passes: %v", err)
	}
	if !s.isMgmtBridgeUplink("bond0") || s.isMgmtBridgeUplink("eno3") || s.isMgmtBridgeUplink("eno1") {
		t.Fatalf("only bond0 is the management bridge's uplink")
	}
	if err := s.guardIfaceInUse("bond0", "bond"); err == nil {
		t.Fatalf("the management bond must be in use")
	}

	// Two default routes (e.g. IPv6 out another NIC): both are management.
	h.defaults = []string{"vSwitch0", "eno3"}
	if err := s.guardMgmt("eno3"); err == nil {
		t.Fatalf("every default-route interface is management")
	}

	// No default route and a wildcard listener: management is unknown — fail closed.
	h.defaults = nil
	if s.mgmtIface() != "" {
		t.Fatalf("no default route + wildcard = unknown")
	}
	if err := s.guardMgmt("eno3"); !errors.Is(err, errMgmtUnknown) {
		t.Fatalf("guardMgmt must fail closed, got %v", err)
	}
	if err := s.guardMgmt(""); err != nil {
		t.Fatalf("an empty optional NIC isn't management-sensitive: %v", err)
	}
	if err := s.guardIfaceInUse("vxspare9", "bond"); !errors.Is(err, errMgmtUnknown) {
		t.Fatalf("guardIfaceInUse must fail closed, got %v", err)
	}
	if _, err := s.TransitCandidates(&Principal{IsAdmin: true}); !errors.Is(err, errMgmtUnknown) {
		t.Fatalf("transit candidates must fail closed, got %v", err)
	}
	// ...but a specific listener IP still identifies it.
	s.cfg.Server.Addr = "172.16.0.163:8766"
	if err := s.guardMgmt("vSwitch0"); err == nil || errors.Is(err, errMgmtUnknown) {
		t.Fatalf("a specific listener IP identifies management without a default route, got %v", err)
	}
}

func TestParseDefaultRoutes(t *testing.T) {
	const v4 = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
ens33	00000000	010010AC	0003	0	0	100	00000000	0	0	0
ens33	000010AC	00000000	0001	0	0	100	00FFFFFF	0	0	0
eth9	00000000	01000A0A	0003	0	0	50	00000000	0	0	0
eth8	00000000	01000A0A	0203	0	0	10	00000000	0	0	0
eth7	00000000	01000A0A	0002	0	0	10	00000000	0	0	0
`
	if got := parseDefaultRoutesV4(v4); !reflect.DeepEqual(got, []string{"eth9", "ens33"}) {
		t.Fatalf("v4 defaults by metric (reject / down skipped): %v", got)
	}
	const v6 = `2602f7e3000000030000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000001 00000000 00400001    ens33
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000020573fffefeadc1 00000064 0000000b 00000000 00400003    ens33
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
`
	if got := parseDefaultRoutesV6(v6); !reflect.DeepEqual(got, []string{"ens33"}) {
		t.Fatalf("v6 defaults (lo reject skipped): %v", got)
	}
}
