package web

import (
	"bytes"
	"html/template"
	"regexp"
	"strings"
	"testing"

	"vdxclone/internal/auth"
	"vdxclone/internal/fabric"
	"vdxclone/internal/service"
)

func fabricTestView() service.FabricView {
	in := fabric.Intent{Version: 4,
		Fabrics: []fabric.Spec{{UUID: "f1", Name: "prod", ASN: 65100, MTU: 1550, Orgs: []int64{2},
			Hosts: []fabric.Host{{Node: "n1", Iface: "enp9s0", TEP: "10.250.0.1/24"}, {Node: "n2", Iface: "enp9s0", VLAN: 40, TEP: "10.250.0.2/24"}}}},
		PGs: []fabric.PortGroup{
			{UUID: "pa", Fabric: "f1", Org: 2, Name: "web", VNI: 2000001, CIDR: "10.10.1.0/24", Gateway: "10.10.1.1"},
			{UUID: "pb", Fabric: "f1", Org: 2, Name: "db", VNI: 2000002, CIDR: "10.10.2.0/24", Gateway: "10.10.2.1", Span: []string{"n2"}, DNS: []string{"1.1.1.1"}},
			{UUID: "pc", Fabric: "f1", Org: 2, Name: "san", VNI: 2000003},
		},
		VRFs:  []fabric.VRF{{Fabric: "f1", Org: 2, L3VNI: 4000001, Egress: "10.10.1.254"}},
		Rules: []fabric.Rule{{UUID: "r1", Fabric: "f1", Org: 2, Src: "pa", Dst: "pb", Proto: "tcp", Ports: "5432"}, {UUID: "r2", Fabric: "f1", Org: 2, Src: "pa", Dst: fabric.External, Proto: "any", Off: true}},
	}
	return service.FabricView{Intent: in, Self: "n1", Admin: true, Build: map[string]bool{"f1": true}, OrgID: 2,
		Nodes: []string{"n1", "n2", "n3"}, Networks: map[string]int64{"pa": 11}, Leases: map[string]int{"pa": 3},
		Egress: map[string]string{"f1": "10.10.1.254"}, VRF: map[string]fabric.VRF{"f1": in.VRFs[0]}}
}

// TestFabricPageRender executes the Fabric page as an instance admin (hosts with
// health, every modal, the wizard, a deploy's check list) and as an org admin
// (no host management, no wizard): every data-modal needs its modal.
func TestFabricPageRender(t *testing.T) {
	tm, err := template.New("root").Funcs(tmplFuncs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	names := map[int64]string{1: "default", 2: "acme"}
	health := map[string]service.FabricNodeStatus{
		"n1": {Node: "n1", State: "ok", BFD: true, DupAddrs: []string{"52:54:00:aa:bb:cc"}, Drops: 7, VNIs: []service.FabricVNI{{VNI: 2000001, Type: "L2", VRF: "vxfvrf2", MACs: 3, Remotes: 1}}, BGP: []service.FabricBGPPeer{{Peer: "10.250.0.2", State: "Established", Uptime: "01:02:03"}}},
		"n2": {Node: "n2", State: "unreachable", Error: "dial timeout"},
	}
	render := func(p *service.Principal, v service.FabricView, checks *fabricChecksEntry) string {
		var h map[string]service.FabricNodeStatus
		if p.IsAdmin {
			h = health
		}
		data := map[string]any{"P": p, "CSRF": "tok", "Active": "fabric", "V": v,
			"Cards": fabricCards(p, v, names, h), "Orgs": []service.OrgLite{{ID: 1, Name: "default"}, {ID: 2, Name: "acme"}},
			"NICsJSON": template.JS(`{"n1":[{"name":"enp9s0","kind":"physical","mtu":9000,"carrier":true,"free":true}]}`), "Checks": checks,
			"Routers": []service.FabricRouterChoice{{ID: 5, Name: "edge"}},
			"MgmtJSON": template.JS(`{"n1":{"node":"n1","iface":"vSwitch0","endpoint":"172.16.0.11","mtu":1500}}`), "WGPort": fabric.WGPort}
		var b bytes.Buffer
		if err := tm.ExecuteTemplate(&b, "fabric.html", data); err != nil {
			t.Fatalf("fabric.html: %v", err)
		}
		out := b.String()
		for _, m := range regexp.MustCompile(`data-modal="([^"]+)"`).FindAllStringSubmatch(out, -1) {
			if !strings.Contains(out, `id="`+m[1]+`"`) {
				t.Fatalf("data-modal=%q has no modal", m[1])
			}
		}
		if !strings.Contains(out, "</html>") {
			t.Fatalf("page truncated")
		}
		return out
	}

	admin := &service.Principal{User: &auth.User{ID: 1, Username: "root"}, OrgID: 1, OrgRole: "owner", IsAdmin: true, ProviderAdmin: true}
	av := fabricTestView()
	av.OrgID, av.Egress, av.VRF = 1, nil, nil // the admin acts in its own org
	out := render(admin, av, &fabricChecksEntry{OK: false, Checks: []service.FabricCheck{{Node: "n2", Check: "underlay", Detail: "enp9s0 MTU 1500 < 1550"}}})
	for _, want := range []string{`id="m-deploy"`, `action="/fabric/deploy"`, `id="m-host-f1"`, `action="/fabric/f/f1/host-remove"`,
		`name="evict" value="1"`, "up 01:02:03", "Deploy failed", "enp9s0 MTU 1500 &lt; 1550", "enp9s0.40", "⚠ 1 duplicate", "7 dropped", "<summary>1</summary>", `<td class="mono">vxfvrf2</td>`,
		`id="m-pgedit-pb"`, `action="/fabric/rule/r2/on"`, "✓ tcp 5432",
		`<option>n3</option>`, `value="2" checked`} {
		if !strings.Contains(out, want) {
			t.Fatalf("admin page missing %q", want)
		}
	}
	// n1 is ok: no Evict on it; a host already in the fabric isn't offered again.
	if strings.Count(out, `name="evict"`) != 1 || strings.Contains(out, `<option>n1</option>`) {
		t.Fatalf("evict/host picker wrong")
	}

	// A fabric over management: the tunnel over the management interface, its
	// sessions, and an add-host form with no interface or VLAN.
	mv := fabricTestView()
	mv.OrgID, mv.Egress, mv.VRF = 1, nil, nil
	pub := "x2FvQ2fF1PDcVv2yrUQLxwpB1ZLsKBX7uIvjLHzG2VY="
	mv.Intent.Fabrics[0].Underlay, mv.Intent.Fabrics[0].MTU = fabric.UnderlayMgmt, 1440
	mv.Intent.Fabrics[0].Hosts = []fabric.Host{{Node: "n1", Iface: "vSwitch0", TEP: "10.250.0.1/24", Endpoint: "172.16.0.11", WGPub: pub},
		{Node: "n2", Iface: "vSwitch0", TEP: "10.250.0.2/24", Endpoint: "172.16.0.12", WGPub: "Fq4bxRrDj3WpjsHrRtUHtN8xKWRSmzRo9k8LSI9o+Vo="}}
	health["n1"] = service.FabricNodeStatus{Node: "n1", State: "ok", BFD: true, WG: []service.FabricWGPeer{{Node: "n2", Endpoint: "172.16.0.12"}}}
	out = render(admin, mv, nil)
	for _, want := range []string{"over management · WireGuard", "MTU 1440 → guests 1390", "vxfwg0", "over vSwitch0 · 172.16.0.11", "↔ n2", "no handshake · never",
		`"endpoint":"172.16.0.11"`, "rides over management"} {
		if !strings.Contains(out, want) {
			t.Fatalf("management fabric page missing %q", want)
		}
	}
	if strings.Contains(out, `id="h-f1"`) {
		t.Fatalf("add-host on a fabric over management offers an interface")
	}

	// An org admin builds on the fabric but never sees hosts or the wizard.
	tenant := &service.Principal{User: &auth.User{ID: 2, Username: "ann"}, OrgID: 2, OrgRole: "admin"}
	v := fabricTestView()
	v.Admin, v.Nodes = false, nil
	out = render(tenant, v, nil)
	for _, bad := range []string{`id="m-deploy"`, `id="m-host-f1"`, "host-remove", "10.250.0.1"} {
		if strings.Contains(out, bad) {
			t.Fatalf("tenant page shows %q", bad)
		}
	}
	for _, want := range []string{`id="m-pg-f1"`, `id="m-rule-f1"`, `<option value="external">External</option>`, `action="/fabric/f/f1/egress"`,
		`action="/fabric/f/f1/gateway"`, `<option value="5">edge</option>`, "Who can reach whom"} {
		if !strings.Contains(out, want) {
			t.Fatalf("tenant page missing %q", want)
		}
	}
	// A connected router replaces both forms with its Disconnect.
	v.Gateways = map[string]service.FabricGateway{"f1": {VRouterID: 5, VRouter: "edge", PG: "pa", Addr: "10.10.1.254"}}
	out = render(tenant, v, nil)
	if !strings.Contains(out, `action="/fabric/f/f1/gateway-disconnect"`) || !strings.Contains(out, "router <strong>edge</strong> at <span class=\"mono\">10.10.1.254</span> on web") ||
		strings.Contains(out, `action="/fabric/f/f1/egress"`) {
		t.Fatalf("connected gateway not shown")
	}
}
