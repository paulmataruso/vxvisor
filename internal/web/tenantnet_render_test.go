package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
	"vdxclone/internal/vrouter"
)

// TestTenantNetworkPagesRender executes the networks + vRouters pages with tenant
// vSwitch / port-group / uplink-leg data, as a tenant org admin and as an
// instance admin, so a template error can't ship as a blank or truncated page.
func TestTenantNetworkPagesRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tnets := []service.TenantNetwork{
		{ID: 1, Name: "default", NetworkID: 7, Bridge: "vdxt7", CIDR: "10.3.0.0/24", Gateway: "10.3.0.1", IsDefault: true,
			State: "applied", UplinkID: 4, UplinkName: "wan", UplinkMode: "qinq", DefaultCarried: true, VMs: 2,
			PortGroups: []service.TenantPortGroup{
				{ID: 1, TnetID: 1, Name: "web", VLAN: 10, NetworkID: 8, CIDR: "10.60.0.0/24", Gateway: "10.60.0.1", DHCP: true, Carried: true},
				{ID: 2, TnetID: 1, Name: "db", VLAN: 20, NetworkID: 9, CIDR: "10.70.0.0/24", VRouterID: 3, VRouterName: "edge"},
			}},
		{ID: 2, Name: "lab", NetworkID: 11, Bridge: "vdxt11", State: "applied"},
	}
	legs := []vrouter.Leg{
		{Idx: 1, Kind: vrouter.LegInternal, IfaceName: "eth1", Bridge: "vdxt7", VLAN: 20, CIDR: "10.70.0.1/24", NetworkID: 9, NetworkName: "default/db"},
		{Idx: 2, Kind: vrouter.LegUplink, IfaceName: "eth2", Bridge: "vdxt7", VLAN: 10, CIDR: "203.0.113.10/29", UpstreamGW: "203.0.113.9", SNAT: true, NetworkName: "default/web"},
	}
	views := []service.VRouterView{{VRouter: vrouter.VRouter{ID: 3, Name: "edge", Runtime: vrouter.RuntimeNetns, Status: "running"}, Legs: legs, LiveState: "running"}}

	u := &auth.User{ID: 1, Username: "root"}
	for _, p := range []*service.Principal{
		{User: u, OrgID: 2, OrgRole: "owner", TenantView: true, ProviderAdmin: true},
		{User: u, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true},
	} {
		base := map[string]any{"P": p, "CSRF": "tok", "Active": "networks"}
		with := func(extra map[string]any) map[string]any {
			m := map[string]any{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range extra {
				m[k] = v
			}
			return m
		}
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, "networks.html", with(map[string]any{
			"Networks": []netdrv.Network{}, "TenantNetworks": tnets,
			"Uplinks": []service.UplinkView{{ID: 5, Name: "wan2", Mode: "access"}},
		})); err != nil {
			t.Fatalf("networks.html (admin=%v): %v", p.IsAdmin, err)
		}
		out := b.String()
		for _, want := range []string{`id="m-tpg-1"`, `action="/networks/tenant/1/native"`, `↗ uplink`, `routed`, `class="susp"`, "</html>"} {
			if !strings.Contains(out, want) {
				t.Fatalf("networks.html (admin=%v) missing %q", p.IsAdmin, want)
			}
		}
		b.Reset()
		if err := tm.ExecuteTemplate(&b, "vrouters.html", with(map[string]any{
			"VRouters": views, "Segments": []service.TenantNetwork{}, "Available": true, "InstAdmin": p.IsAdmin,
			"Runtimes":   map[string]bool{vrouter.RuntimeNetns: true},
			"PortGroups": []service.TenantPortGroup{{ID: 9, Name: "app", VLAN: 30}},
			"UplinkLegs": []service.UplinkLegChoice{{TnetID: 1, VLAN: 10, Label: "default / web"}},
		})); err != nil {
			t.Fatalf("vrouters.html (admin=%v): %v", p.IsAdmin, err)
		}
		out = b.String()
		if !strings.Contains(out, `id="m-pga-3"`) || !strings.Contains(out, `/vrouters/3/uplink/detach`) || !strings.Contains(out, "</html>") {
			t.Fatalf("vrouters.html (admin=%v) missing port-group/uplink-leg controls", p.IsAdmin)
		}
		if strings.Contains(out, `data-modal="m-upl-3"`) {
			t.Fatalf("vrouters.html offers a second uplink leg on a router that has one")
		}
	}
}
