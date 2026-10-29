package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/routing"
	"vdxclone/internal/service"
	"vdxclone/internal/vrouter"
)

// TestL3PagesRender executes the gateways, host routing and firewall pages with
// a Tier-0 provider gateway (provider link, an owned and an attached downlink,
// ignored routing entries) and a Tier-1 tenant gateway, so the new labels and
// controls can't ship as a template error or a truncated page.
func TestL3PagesRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	core := service.VRouterView{
		VRouter: vrouter.VRouter{ID: 5, Name: "core", Runtime: vrouter.RuntimeLXC, Status: "running"}, LiveState: "running",
		Legs: []vrouter.Leg{
			{Idx: 0, Kind: vrouter.LegTransit, IfaceName: "eth0", PhysIface: "eno3", CIDR: "198.51.100.2/30"},
			{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", NetworkID: 21, NetworkName: "core-app", CIDR: "10.80.0.1/24", NetworkCIDR: "10.80.0.0/24"},
			{Idx: 2, Kind: vrouter.LegInternal, IfaceName: "eth2", NetworkID: 22, NetworkName: "acme/web", CIDR: "10.81.0.1/24", NetworkCIDR: "10.81.0.0/24"},
		},
		Owned:   map[int64]bool{21: true},
		Ignored: []string{"BGP neighbor 192.0.2.1 (not on a connected network)"},
	}
	edge := service.VRouterView{
		VRouter: vrouter.VRouter{ID: 6, Name: "edge", Runtime: vrouter.RuntimeNetns, Status: "running"}, Tenant: true,
		Legs: []vrouter.Leg{{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", NetworkID: 30, NetworkName: "acme/app", CIDR: "10.60.0.1/24"}},
	}
	u := &auth.User{ID: 1, Username: "root"}
	admin := &service.Principal{User: u, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	tenant := &service.Principal{User: u, OrgID: 2, OrgRole: "owner"}

	for _, p := range []*service.Principal{admin, tenant} {
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, "vrouters.html", map[string]any{"P": p, "CSRF": "tok", "Active": "vrouters",
			"VRouters": []service.VRouterView{core, edge}, "Available": true, "InstAdmin": p.IsAdmin,
			"Runtimes": map[string]bool{vrouter.RuntimeNetns: true, vrouter.RuntimeLXC: true},
			"Transit":  []service.TransitIface{{Name: "eno4", State: "up", Carrier: true}},
		}); err != nil {
			t.Fatalf("vrouters.html (admin=%v): %v", p.IsAdmin, err)
		}
		out := b.String()
		for _, want := range []string{">Tier-0</span>", ">Tier-1</span>", "Saved but not applied: BGP neighbor 192.0.2.1",
			"EIGRP isn't available", `data-modal="m-tr-6"`, "</html>"} {
			if want == `data-modal="m-tr-6"` && !p.IsAdmin {
				continue
			}
			if !strings.Contains(out, want) {
				t.Errorf("vrouters.html (admin=%v) missing %q", p.IsAdmin, want)
			}
		}
		// The owned downlink is removed (deleting its port group); the attached one only detached.
		owned := strings.Index(out, "Remove port group core-app?")
		attached := strings.Index(out, "Detach acme\\/web from this gateway?")
		if owned < 0 || attached < 0 {
			t.Errorf("vrouters.html (admin=%v): owned remove=%d attached detach=%d", p.IsAdmin, owned, attached)
		}
		// Provider-link controls are instance-admin only, and a Tier-0 gateway isn't offered a second one.
		if got := strings.Contains(out, `action="/vrouters/5/transit/delete"`); got != p.IsAdmin {
			t.Errorf("vrouters.html (admin=%v): provider-link remove shown=%v", p.IsAdmin, got)
		}
		if strings.Contains(out, `data-modal="m-tr-5"`) {
			t.Error("a Tier-0 gateway is offered a second provider link")
		}
		if strings.Contains(out, "recommended") {
			t.Error("a runtime option is still marked recommended")
		}
	}

	var b bytes.Buffer
	cfg := routing.Config{Static: []routing.Route{{Dest: "10.60.0.0/24", NextHop: "10.50.0.2"}},
		OSPF: routing.OSPF{Enabled: true, Networks: []routing.OSPFNet{{CIDR: "10.50.0.0/30", Area: "0"}}}}
	if err := tm.ExecuteTemplate(&b, "routing.html", map[string]any{"P": admin, "CSRF": "tok", "Active": "routing",
		"Cfg": cfg, "Status": "", "FRRReady": true, "Transit": []service.TransitIface{{Name: "eno4"}}}); err != nil {
		t.Fatalf("routing.html: %v", err)
	}
	if out := b.String(); !strings.Contains(out, "Tier-0 uplinks") || !strings.Contains(out, "available on the host and provider gateways only") || !strings.Contains(out, "</html>") {
		t.Error("routing.html is missing the provider-link / EIGRP wording or is truncated")
	}

	b.Reset()
	fw := service.OrgFirewallView{Enabled: true, HasVRouter: true, ColorOf: map[string]string{}, NameOf: map[string]string{}}
	if err := tm.ExecuteTemplate(&b, "vfirewall.html", map[string]any{"P": tenant, "CSRF": "tok", "Active": "vfirewall",
		"FW": fw, "Protos": []string{"any", "tcp", "udp", "icmp"}}); err != nil {
		t.Fatalf("vfirewall.html: %v", err)
	}
	if out := b.String(); !strings.Contains(out, "Gateway firewall (North-South)") || !strings.Contains(out, "Distributed firewall (East-West)") || !strings.Contains(out, "</html>") {
		t.Error("vfirewall.html is missing the gateway / distributed firewall sections or is truncated")
	}
}
