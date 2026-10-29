package routing

import (
	"strings"
	"testing"
)

// TestValidateRejectsInjection: every field the renderers emit must be one
// token of the expected shape — a newline or space would splice config.
func TestValidateRejectsInjection(t *testing.T) {
	base := func() Config {
		return Config{
			Static:   []Route{{Dest: "10.30.0.0/24", NextHop: "10.0.0.1"}},
			Firewall: []FirewallRule{{Action: "accept", Proto: "tcp", DPort: "443", Source: "10.0.0.0/8"}},
			OSPF:     OSPF{Enabled: true, RouterID: "1.1.1.1", Networks: []OSPFNet{{CIDR: "10.0.0.0/24", Area: "0"}}},
			BGP: BGP{Enabled: true, ASN: 65001, RouterID: "1.1.1.1",
				Neighbors: []Neighbor{{Addr: "10.0.0.2", RemoteAS: 4200000000}}, Networks: []string{"10.60.0.0/24"}},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"static dest newline":   func(c *Config) { c.Static[0].Dest = "10.30.0.0/24\nline vty" },
		"static nexthop space":  func(c *Config) { c.Static[0].NextHop = "10.0.0.1 blackhole" },
		"static dest ipv6":      func(c *Config) { c.Static[0].Dest = "::/0" },
		"router-id":             func(c *Config) { c.OSPF.RouterID = "1.1.1.1\n!" },
		"router-id not v4":      func(c *Config) { c.BGP.RouterID = "abc" },
		"area":                  func(c *Config) { c.OSPF.Networks[0].Area = "0\nrouter bgp 1" },
		"area too big":          func(c *Config) { c.OSPF.Networks[0].Area = "4294967296" },
		"ospf network":          func(c *Config) { c.OSPF.Networks[0].CIDR = "10.0.0.0/24 area 1" },
		"asn zero":              func(c *Config) { c.BGP.ASN = 0 },
		"asn too big":           func(c *Config) { c.BGP.ASN = 4294967296 },
		"neighbor":              func(c *Config) { c.BGP.Neighbors[0].Addr = "10.0.0.2 password x" },
		"neighbor remote as":    func(c *Config) { c.BGP.Neighbors[0].RemoteAS = -1 },
		"route-map name":        func(c *Config) { c.BGP.Neighbors[0].RouteMapIn = "RM in\nexit" },
		"prefix-list out":       func(c *Config) { c.BGP.Neighbors[0].PrefixListOut = "X Y" },
		"bgp network":           func(c *Config) { c.BGP.Networks[0] = "10.60.0.0/24\nexit" },
		"bgp network default":   func(c *Config) { c.BGP.Networks[0] = "default" },
		"firewall action":       func(c *Config) { c.Firewall[0].Action = "accept; flush ruleset" },
		"firewall port":         func(c *Config) { c.Firewall[0].DPort = "443 }" },
		"firewall source":       func(c *Config) { c.Firewall[0].Source = "10.0.0.0/8 accept" },
		"firewall port no prot": func(c *Config) { c.Firewall[0].Proto = "" },
		"uplink":                func(c *Config) { c.Uplink = `eth0" accept` },
		"hostname":              func(c *Config) { c.Hostname = "h\nline vty" },
		"iface prefix":          func(c *Config) { c.Prefixes = []IfPrefix{{Iface: "eth1", CIDR: "10.0.0.1/24\n"}} },
		"iface name":            func(c *Config) { c.Prefixes = []IfPrefix{{Iface: "eth 1", CIDR: "10.0.0.1/24"}} },
		"passive":               func(c *Config) { c.OSPF.Passive = []string{"eth1\n"} },
		"nat cidr":              func(c *Config) { c.InternalCIDRs = []string{"10.0.0.0/8 oifname x"} },
		"prefix-list ge": func(c *Config) {
			c.PrefixLists = []PrefixList{{Name: "P", Seq: 5, Action: "permit", Prefix: "10.0.0.0/8", Ge: 4}}
		},
		"route-map action": func(c *Config) { c.RouteMaps = []RouteMapClause{{Name: "R", Seq: 10, Action: "permit\nx"}} },
	} {
		c := base()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
		if out, err := RenderFRR(c); err == nil {
			t.Errorf("%s: rendered:\n%s", name, out)
		}
		if _, err := RenderNAT(c); err == nil && (strings.HasPrefix(name, "firewall") || name == "uplink" || name == "nat cidr") {
			t.Errorf("%s: NAT rendered", name)
		}
	}
	// A disabled protocol's leftovers never reach the file, so they don't block.
	c := base()
	c.EIGRP = EIGRP{Enabled: false, ASN: 0, Networks: []string{"junk"}}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled EIGRP leftovers must not fail validation: %v", err)
	}
}

// TestSanitizeDropsOnlyBadEntries: a stored config with one bad entry keeps
// every good one (so later CRUD isn't wedged), and the result always validates.
func TestSanitizeDropsOnlyBadEntries(t *testing.T) {
	c := Config{
		Uplink: "eth 0",
		Static: []Route{{Dest: "default", NextHop: "10.0.0.1"}, {Dest: "10.1.0.0/16\nx", NextHop: "10.0.0.1"}, {Dest: " 10.2.0.0/16 ", NextHop: "10.0.0.1"}},
		BGP: BGP{Enabled: true, ASN: 65001, RouterID: "bad",
			Neighbors: []Neighbor{{Addr: "10.0.0.2", RemoteAS: 65002}, {Addr: "x y", RemoteAS: 1}},
			Networks:  []string{"10.60.0.0/24", "evil\n"}},
		OSPF:  OSPF{Enabled: true, Networks: []OSPFNet{{CIDR: "10.0.0.0/24", Area: "0"}, {CIDR: "10.0.0.0/24", Area: "x"}}},
		EIGRP: EIGRP{Enabled: true, ASN: 70000},
	}
	out, dropped := Sanitize(c)
	if err := out.Validate(); err != nil {
		t.Fatalf("sanitized config must validate: %v", err)
	}
	if out.Uplink != "" || len(out.Static) != 2 || out.Static[0].Dest != "0.0.0.0/0" || out.Static[1].Dest != "10.2.0.0/16" {
		t.Errorf("static/uplink: %+v %q", out.Static, out.Uplink)
	}
	if len(out.BGP.Neighbors) != 1 || len(out.BGP.Networks) != 1 || out.BGP.RouterID != "" || !out.BGP.Enabled {
		t.Errorf("bgp: %+v", out.BGP)
	}
	if len(out.OSPF.Networks) != 1 || out.EIGRP.Enabled {
		t.Errorf("ospf/eigrp: %+v %+v", out.OSPF, out.EIGRP)
	}
	if len(dropped) < 6 {
		t.Errorf("expected every dropped entry to be reported, got %v", dropped)
	}
	// The input is not modified.
	if c.Static[0].Dest != "default" || len(c.BGP.Networks) != 2 {
		t.Error("Sanitize modified its input")
	}
}

// TestRenderFRRExportAndPassive: the tenant policy fields render as FRR
// expects; "default" becomes 0.0.0.0/0; passive only while OSPF is on.
func TestRenderFRRExportAndPassive(t *testing.T) {
	c := Config{
		Prefixes:    []IfPrefix{{Iface: "eth1", CIDR: "10.60.0.1/24"}, {Iface: "eth2", CIDR: "203.0.113.10/29"}},
		Static:      []Route{{Dest: "default", NextHop: "203.0.113.9"}},
		PrefixLists: []PrefixList{{Name: "VDX-TENANT-EXPORT", Seq: 5, Action: "permit", Prefix: "10.60.0.0/24", Le: 32}},
		OSPF:        OSPF{Enabled: true, Networks: []OSPFNet{{CIDR: "10.60.0.0/24", Area: "0"}}, Passive: []string{"eth1"}},
		BGP: BGP{Enabled: true, ASN: 65010, Neighbors: []Neighbor{{Addr: "203.0.113.9", RemoteAS: 65000, PrefixListOut: "VDX-TENANT-EXPORT"}},
			Networks: []string{"10.60.0.0/24"}},
	}
	out, err := RenderFRR(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip route 0.0.0.0/0 203.0.113.9\n",
		"interface eth1\n ip address 10.60.0.1/24\n ip ospf passive\nexit",
		"interface eth2\n ip address 203.0.113.10/29\nexit",
		"ip prefix-list VDX-TENANT-EXPORT seq 5 permit 10.60.0.0/24 le 32\n",
		"  neighbor 203.0.113.9 prefix-list VDX-TENANT-EXPORT out\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	c.OSPF.Enabled = false
	if out, _ := RenderFRR(c); strings.Contains(out, "ip ospf passive") {
		t.Error("passive must not render while OSPF is off")
	}
}

func TestValidHelpers(t *testing.T) {
	for _, s := range []string{"0", "4294967295", "0.0.0.0", "10.1.2.3"} {
		if ValidArea(s) != nil {
			t.Errorf("area %q refused", s)
		}
	}
	for _, s := range []string{"", "-1", "1.2.3", "a"} {
		if ValidArea(s) == nil {
			t.Errorf("area %q accepted", s)
		}
	}
	if ValidNextHop("eth0") != nil || ValidNextHop("10.0.0.1") != nil || ValidNextHop("10.0.0.1/24") == nil || ValidNextHop("") == nil {
		t.Error("ValidNextHop")
	}
	if p, err := CanonPrefix("10.30.0.5/24"); err != nil || p != "10.30.0.0/24" {
		t.Errorf("CanonPrefix = %q, %v", p, err)
	}
	if IsIPv4("::ffff:10.0.0.1") || !IsIPv4("10.0.0.1") {
		t.Error("IsIPv4")
	}
	if ValidPorts("8000-8100") != nil || ValidPorts("0") == nil || ValidPorts("90-80") == nil || ValidPorts("65536") == nil {
		t.Error("ValidPorts")
	}
}
