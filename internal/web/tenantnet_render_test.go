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
		{ID: 1, Name: "default", NetName: "default", NetworkID: 7, Bridge: "vdxt7", CIDR: "10.3.0.0/24", Gateway: "10.3.0.1", IsDefault: true,
			State: "applied", UplinkID: 4, UplinkName: "wan", UplinkMode: "qinq", DefaultCarried: true, VMs: 2, AddrLocked: true,
			PortGroups: []service.TenantPortGroup{
				{ID: 1, TnetID: 1, Name: "web", VLAN: 10, NetworkID: 8, CIDR: "10.60.0.0/24", Gateway: "10.60.0.1", DHCP: true, Carried: true,
					DHCPRange: "10.60.0.100,10.60.0.200", DNS: "1.1.1.1", ExtRouter: "edge", AddrLocked: true},
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
		for _, want := range []string{`id="m-tpg"`, `data-modal="m-tpg"`, `action="/networks/tenant/portgroups"`, `action="/networks/tenant/1/native"`,
			`↗ external`, `routed`, `class="susp"`, `id="topo"`, `/api/topology`, "</html>",
			// Edit / Make default: every Edit button has its modal.
			`data-modal="m-tnet-edit-1"`, `id="m-tnet-edit-1"`, `action="/networks/tenant/1/edit"`,
			`data-modal="m-tnet-edit-2"`, `id="m-tnet-edit-2"`, `action="/networks/tenant/2/default"`,
			`data-modal="m-tpg-edit-1"`, `id="m-tpg-edit-1"`, `action="/networks/portgroups/1/edit"`,
			`data-modal="m-tpg-edit-2"`, `id="m-tpg-edit-2"`, `value="10.60.0.100-10.60.0.200"`} {
			if !strings.Contains(out, want) {
				t.Fatalf("networks.html (admin=%v) missing %q", p.IsAdmin, want)
			}
		}
		// The default vSwitch can't be deleted (nor made default again); the
		// other one can.
		if strings.Contains(out, `action="/networks/tenant/1/delete"`) || strings.Contains(out, `action="/networks/tenant/1/default"`) ||
			!strings.Contains(out, `action="/networks/tenant/2/delete"`) {
			t.Fatalf("networks.html (admin=%v): default vSwitch delete / make-default controls wrong", p.IsAdmin)
		}
		// Addressing is locked on the untagged port group (2 VMs) and absent on
		// the routed one.
		edit1 := out[strings.Index(out, `id="m-tnet-edit-1"`):]
		edit1 = edit1[:strings.Index(edit1, "</form>")]
		if !strings.Contains(edit1, `name="cidr" value="10.3.0.0/24" placeholder="10.50.0.0/24" readonly`) {
			t.Fatalf("networks.html: a vSwitch with instances must show its subnet read-only:\n%s", edit1)
		}
		pg2 := out[strings.Index(out, `id="m-tpg-edit-2"`):]
		pg2 = pg2[:strings.Index(pg2, "</form>")]
		if strings.Contains(pg2, `name="cidr"`) || strings.Contains(pg2, `name="l3"`) {
			t.Fatalf("networks.html: a routed port group's edit form must not carry addressing:\n%s", pg2)
		}
		if hostOnly := strings.Contains(out, `id="iftable"`) || strings.Contains(out, `data-modal="m-bond"`); hostOnly != p.IsAdmin {
			t.Fatalf("networks.html (admin=%v): host interfaces / uplinks shown=%v", p.IsAdmin, hostOnly)
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
