package vrouter

import (
	"strings"
	"testing"

	"vdxclone/internal/routing"
)

func tenantLegs() []Leg {
	return []Leg{
		{Idx: 1, Kind: LegInternal, IfaceName: "eth1", CIDR: "10.60.0.1/24", NetworkCIDR: "10.60.0.0/24"},
		{Idx: 2, Kind: LegInternal, IfaceName: "eth2", CIDR: "10.70.0.1/24"}, // no recorded PG subnet: the leg's own
		{Idx: 3, Kind: LegUplink, IfaceName: "eth3", CIDR: "203.0.113.10/29", UpstreamGW: "203.0.113.9"},
	}
}

// TestConstrainTenant: neighbors only on connected subnets, every one with the
// export prefix-list; networks only the downlinks; EIGRP off; downlinks
// passive while there is an external interface.
func TestConstrainTenant(t *testing.T) {
	cfg := routing.Config{
		PrefixLists: []routing.PrefixList{{Name: "MINE", Seq: 5, Action: "permit", Prefix: "any"}},
		BGP: routing.BGP{Enabled: true, ASN: 65010, Neighbors: []routing.Neighbor{
			{Addr: "203.0.113.9", RemoteAS: 65000, RouteMapOut: "LEAK"},
			{Addr: "198.51.100.1", RemoteAS: 65000}, // not connected
			{Addr: "203.0.113.10", RemoteAS: 65000}, // the router's own address
		}, Networks: []string{"10.60.0.0/24", "10.60.0.128/25", "0.0.0.0/0", "8.8.8.0/24", "203.0.113.8/29"}},
		OSPF: routing.OSPF{Enabled: true, Networks: []routing.OSPFNet{
			{CIDR: "10.60.0.0/24", Area: "0"}, {CIDR: "203.0.113.8/29", Area: "0"}, {CIDR: "0.0.0.0/0", Area: "0"}}},
		EIGRP: routing.EIGRP{Enabled: true, ASN: 100, Networks: []string{"10.60.0.0/24"}},
	}
	out, dropped := ConstrainTenant(cfg, tenantLegs())
	if len(out.BGP.Neighbors) != 1 || out.BGP.Neighbors[0].Addr != "203.0.113.9" ||
		out.BGP.Neighbors[0].PrefixListOut != TenantExportList || out.BGP.Neighbors[0].RouteMapOut != "" {
		t.Errorf("neighbors: %+v", out.BGP.Neighbors)
	}
	if got := strings.Join(out.BGP.Networks, ","); got != "10.60.0.0/24,10.60.0.128/25" {
		t.Errorf("bgp networks: %s", got)
	}
	if len(out.OSPF.Networks) != 2 {
		t.Errorf("ospf networks: %+v", out.OSPF.Networks)
	}
	if out.EIGRP.Enabled {
		t.Error("EIGRP must be off on a tenant gateway")
	}
	if strings.Join(out.OSPF.Passive, ",") != "eth1,eth2" {
		t.Errorf("passive: %v", out.OSPF.Passive)
	}
	var names []string
	for _, pl := range out.PrefixLists {
		names = append(names, pl.Name+" "+pl.Prefix)
		if pl.Name != TenantExportList {
			t.Errorf("custom prefix-list survived: %+v", pl)
		}
	}
	if strings.Join(names, ",") != TenantExportList+" 10.60.0.0/24,"+TenantExportList+" 10.70.0.0/24" {
		t.Errorf("export list: %v", names)
	}
	if len(dropped) < 6 {
		t.Errorf("dropped: %v", dropped)
	}
	if len(cfg.BGP.Neighbors) != 3 || cfg.BGP.Neighbors[0].PrefixListOut != "" {
		t.Error("ConstrainTenant modified its input")
	}
	conf, err := RenderForVRouter(VRouter{Name: "t1"}, tenantLegs(), out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"neighbor 203.0.113.9 prefix-list VDX-TENANT-EXPORT out", "ip prefix-list VDX-TENANT-EXPORT seq 5 permit 10.60.0.0/24 le 32", "ip route 0.0.0.0/0 203.0.113.9"} {
		if !strings.Contains(conf, want) {
			t.Errorf("render missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "router eigrp") || strings.Contains(conf, "MINE") || strings.Contains(conf, "8.8.8.0") {
		t.Errorf("render leaked a dropped entry:\n%s", conf)
	}

	// No downlinks: the export list is a deny-all, so nothing is advertised.
	noDown, _ := ConstrainTenant(routing.Config{BGP: routing.BGP{Enabled: true, ASN: 1}}, tenantLegs()[2:])
	if len(noDown.PrefixLists) != 1 || noDown.PrefixLists[0].Action != "deny" || noDown.PrefixLists[0].Prefix != "any" {
		t.Errorf("no-downlink export list: %+v", noDown.PrefixLists)
	}
	// Without an external interface the downlinks aren't made passive.
	if inner, _ := ConstrainTenant(cfg, tenantLegs()[:2]); len(inner.OSPF.Passive) != 0 {
		t.Errorf("passive without an external interface: %v", inner.OSPF.Passive)
	}
	// A huge leg prefix never makes "connected" cover the address space.
	wide := []Leg{{Idx: 1, Kind: LegInternal, IfaceName: "eth1", CIDR: "10.0.0.1/1", NetworkCIDR: "0.0.0.0/1"}}
	if w, _ := ConstrainTenant(cfg, wide); len(w.BGP.Neighbors) != 0 || len(w.BGP.Networks) != 0 {
		t.Errorf("a /1 leg must not admit neighbors or networks: %+v", w.BGP)
	}
}

// TestDnsmasqConfRefusesInjection: dnsmasq runs as root and a config line can
// name a script, so nothing that isn't a clean token may be written.
func TestDnsmasqConfRefusesInjection(t *testing.T) {
	ok := Leg{IfaceName: "eth1", CIDR: "10.60.0.1/24", DHCP: true, DHCPRange: "10.60.0.100-200", DHCPDNS: "1.1.1.1, 8.8.8.8"}
	conf, err := DnsmasqConf(ok)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"interface=eth1\n", "dhcp-range=10.60.0.100,10.60.0.200,255.255.255.0,12h\n", "dhcp-option=3,10.60.0.1\n", "dhcp-option=6,1.1.1.1,8.8.8.8\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	for name, mut := range map[string]func(*Leg){
		"dns script":   func(l *Leg) { l.DHCPDNS = "1.1.1.1\ndhcp-script=/tmp/x" },
		"dns hostname": func(l *Leg) { l.DHCPDNS = "dns.example" },
		"range":        func(l *Leg) { l.DHCPRange = "10.60.0.100,10.60.0.200\ndhcp-script=/tmp/x" },
		"range order":  func(l *Leg) { l.DHCPRange = "10.60.0.200,10.60.0.100" },
		"iface":        func(l *Leg) { l.IfaceName = "eth1\nconf-file=/tmp/x" },
		"cidr":         func(l *Leg) { l.CIDR = "10.60.0.1/24\nx" },
	} {
		l := ok
		mut(&l)
		if out, err := DnsmasqConf(l); err == nil {
			t.Errorf("%s: rendered:\n%s", name, out)
		}
	}
}

func TestDHCPHelpers(t *testing.T) {
	if s, e, err := ParseDHCPRange(" 10.0.0.5 , 10.0.0.9 "); err != nil || s.String() != "10.0.0.5" || e.String() != "10.0.0.9" {
		t.Errorf("ParseDHCPRange: %v %v %v", s, e, err)
	}
	for _, bad := range []string{"", "10.0.0.5", "a,b", "10.0.0.9,10.0.0.5", "::1,::2"} {
		if _, _, err := ParseDHCPRange(bad); err == nil {
			t.Errorf("ParseDHCPRange(%q) accepted", bad)
		}
	}
	if d, err := NormalizeDNS("1.1.1.1 8.8.8.8"); err != nil || d != "1.1.1.1,8.8.8.8" {
		t.Errorf("NormalizeDNS: %q %v", d, err)
	}
	if d, err := NormalizeDNS(""); err != nil || d != "" {
		t.Errorf("NormalizeDNS empty: %q %v", d, err)
	}
	if _, err := NormalizeDNS("1.1.1.1,1.1.1.2,1.1.1.3,1.1.1.4,1.1.1.5,1.1.1.6,1.1.1.7,1.1.1.8,1.1.1.9"); err == nil {
		t.Error("more than 8 DNS servers accepted")
	}
}

// TestDenyAllFirewall: the fail-closed ruleset drops all forwarding.
func TestDenyAllFirewall(t *testing.T) {
	rs := DenyAllFirewall()
	if !strings.Contains(rs, "table inet "+FWTable) || !strings.Contains(rs, "hook forward priority filter; policy drop;") || strings.Contains(rs, "accept") {
		t.Errorf("deny-all ruleset:\n%s", rs)
	}
}
