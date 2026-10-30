package routing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFabric() *Fabric {
	return &Fabric{ASN: 65010, TEP: "10.99.0.1", Peers: []string{"10.99.0.2", "10.99.0.3"},
		Password: "a1b2c3d4", BFD: true, VRFs: []FabricVRF{{Name: "vdxv12", VNI: 4000012}}}
}

// block returns the text from the first line starting with start up to the
// next line equal to end.
func block(conf, start, end string) string {
	i := strings.Index(conf, start)
	if i < 0 {
		return ""
	}
	j := strings.Index(conf[i:], "\n"+end+"\n")
	if j < 0 {
		return conf[i:]
	}
	return conf[i : i+j]
}

func TestRenderFabricOnly(t *testing.T) {
	conf, err := RenderFRR(Config{Fabric: testFabric()})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"vrf vdxv12\n vni 4000012\nexit-vrf\n",
		"router bgp 65010\n bgp router-id 10.99.0.1\n no bgp default ipv4-unicast\n",
		" neighbor VXFABRIC peer-group\n neighbor VXFABRIC remote-as internal\n neighbor VXFABRIC update-source 10.99.0.1\n",
		" neighbor VXFABRIC password a1b2c3d4\n neighbor VXFABRIC bfd\n",
		" neighbor 10.99.0.2 peer-group VXFABRIC\n neighbor 10.99.0.3 peer-group VXFABRIC\n",
		" address-family l2vpn evpn\n  neighbor VXFABRIC activate\n  advertise-all-vni\n exit-address-family\n",
		"router bgp 65010 vrf vdxv12\n bgp router-id 10.99.0.1\n",
		"  advertise ipv4 unicast\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	// Fabric peers carry EVPN only: never activated for IPv4 unicast.
	if af := block(conf, " address-family ipv4 unicast", " exit-address-family"); strings.Contains(af, "VXFABRIC") || strings.Contains(af, "10.99.0.") {
		t.Errorf("fabric activated in ipv4 unicast:\n%s", af)
	}
	// Egress: the VRF's own default route, inside its vrf block.
	f := testFabric()
	f.VRFs[0].Egress = "10.20.0.254"
	if conf, _ := RenderFRR(Config{Fabric: f}); !strings.Contains(conf, "vrf vdxv12\n vni 4000012\n ip route 0.0.0.0/0 10.20.0.254\nexit-vrf\n") {
		t.Errorf("egress route missing:\n%s", conf)
	}
	// The VRF definition precedes the BGP instances that use it.
	if strings.Index(conf, "vrf vdxv12\n") > strings.Index(conf, "router bgp 65010\n") {
		t.Errorf("vrf block after router bgp")
	}
}

func TestRenderHostAndFabricCompose(t *testing.T) {
	c := Config{
		BGP: BGP{Enabled: true, ASN: 65010, Neighbors: []Neighbor{{Addr: "192.0.2.1", RemoteAS: 64512, RouteMapIn: "IN"}},
			Networks: []string{"10.20.0.0/24"}},
		RouteMaps: []RouteMapClause{{Name: "IN", Action: "permit", Seq: 10}},
		Fabric:    testFabric(),
	}
	conf, err := RenderFRR(c)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(conf, "router bgp 65010\n"); n != 1 {
		t.Fatalf("%d default BGP instances, want 1:\n%s", n, conf)
	}
	af := block(conf, " address-family ipv4 unicast", " exit-address-family")
	for _, want := range []string{"  network 10.20.0.0/24", "  neighbor 192.0.2.1 activate", "  neighbor 192.0.2.1 route-map IN in"} {
		if !strings.Contains(af, want) {
			t.Errorf("ipv4 unicast lacks %q:\n%s", want, af)
		}
	}
	if !strings.Contains(conf, " bgp router-id 10.99.0.1\n") {
		t.Errorf("router-id not pinned to the TEP")
	}

	bad := func(name string, mut func(*Config)) {
		t.Helper()
		cc := c
		f := *c.Fabric
		cc.Fabric = &f
		cc.BGP.Neighbors = append([]Neighbor(nil), c.BGP.Neighbors...)
		mut(&cc)
		if _, err := RenderFRR(cc); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	bad("other AS", func(c *Config) { c.BGP.ASN = 65011 })
	bad("other router-id", func(c *Config) { c.BGP.RouterID = "1.1.1.1" })
	bad("neighbor is a fabric peer", func(c *Config) { c.BGP.Neighbors[0].Addr = "10.99.0.2" })
	bad("neighbor is the TEP", func(c *Config) { c.BGP.Neighbors[0].Addr = "10.99.0.1" })

	// The host's own router-id may be the TEP; a disabled host BGP's leftovers
	// don't constrain the fabric.
	ok := c
	ok.BGP.RouterID = "10.99.0.1"
	if _, err := RenderFRR(ok); err != nil {
		t.Errorf("host router-id = TEP: %v", err)
	}
	off := c
	off.BGP.Enabled, off.BGP.ASN = false, 1
	if conf, err := RenderFRR(off); err != nil || strings.Contains(conf, "192.0.2.1") {
		t.Errorf("disabled host BGP: %v\n%s", err, conf)
	}
}

func TestRenderHostBGPActivatesExplicitly(t *testing.T) {
	conf, err := RenderFRR(Config{BGP: BGP{Enabled: true, ASN: 64600, RouterID: "10.0.0.9",
		Neighbors: []Neighbor{{Addr: "10.0.0.1", RemoteAS: 64601}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{" no bgp default ipv4-unicast\n", " neighbor 10.0.0.1 remote-as 64601\n", "  neighbor 10.0.0.1 activate\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "l2vpn") || strings.Contains(conf, "VXFABRIC") {
		t.Errorf("fabric config without a fabric:\n%s", conf)
	}
}

func TestFabricValidate(t *testing.T) {
	cases := map[string]func(*Fabric){
		"bad AS":            func(f *Fabric) { f.ASN = 0 },
		"bad TEP":           func(f *Fabric) { f.TEP = "10.99.0.1\n neighbor 6.6.6.6 remote-as 1" },
		"v6 TEP":            func(f *Fabric) { f.TEP = "fd00::1" },
		"bad peer":          func(f *Fabric) { f.Peers = []string{"10.99.0.2 remote-as 1"} },
		"dup peer":          func(f *Fabric) { f.Peers = []string{"10.99.0.2", "10.99.0.2"} },
		"peer is TEP":       func(f *Fabric) { f.Peers = []string{"10.99.0.1"} },
		"password inject":   func(f *Fabric) { f.Password = "x\nrouter bgp 1" },
		"password space":    func(f *Fabric) { f.Password = "a b" },
		"vrf name":          func(f *Fabric) { f.VRFs = []FabricVRF{{Name: "v x", VNI: 1}} },
		"vni zero":          func(f *Fabric) { f.VRFs = []FabricVRF{{Name: "vdxv1", VNI: 0}} },
		"vni too big":       func(f *Fabric) { f.VRFs = []FabricVRF{{Name: "vdxv1", VNI: MaxVNI + 1}} },
		"duplicate vrf":     func(f *Fabric) { f.VRFs = []FabricVRF{{Name: "vdxv1", VNI: 5}, {Name: "vdxv1", VNI: 6}} },
		"duplicate vrf vni": func(f *Fabric) { f.VRFs = []FabricVRF{{Name: "vdxv1", VNI: 5}, {Name: "vdxv2", VNI: 5}} },
		"egress inject":     func(f *Fabric) { f.VRFs[0].Egress = "10.1.1.1\nip route 0.0.0.0/0 6.6.6.6" },
	}
	for name, mut := range cases {
		f := testFabric()
		mut(f)
		if _, err := RenderFRR(Config{Fabric: f}); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if err := testFabric().Validate(); err != nil {
		t.Fatalf("valid fabric: %v", err)
	}
}

func TestFabricNeverStored(t *testing.T) {
	b, _ := json.Marshal(Config{Fabric: testFabric()})
	if strings.Contains(string(b), "10.99.0.1") || strings.Contains(strings.ToLower(string(b)), "fabric") {
		t.Fatalf("fabric serialized into routing_config: %s", b)
	}
}

func TestBGPGuard(t *testing.T) {
	c := Config{BGP: BGP{Enabled: true, ASN: 65010, Neighbors: []Neighbor{{Addr: "192.0.2.1", RemoteAS: 1}, {Addr: "10.99.0.2", RemoteAS: 1}}},
		Fabric: testFabric()}
	peers := c.BGPPeers()
	if strings.Join(peers, ",") != "192.0.2.1,10.99.0.2,10.99.0.3" {
		t.Fatalf("peers = %v", peers)
	}
	rs, err := RenderBGPGuard(peers)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet vdxbgp {}\ndelete table inet vdxbgp\n",
		"elements = { 192.0.2.1, 10.99.0.2, 10.99.0.3 }",
		"tcp dport 179 ip saddr @peers accept\n    tcp dport 179 drop\n",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("guard lacks %q:\n%s", want, rs)
		}
	}
	// Disabled host BGP contributes no peers; with none at all, 179 is closed.
	if p := (Config{BGP: BGP{Neighbors: []Neighbor{{Addr: "192.0.2.1"}}}}).BGPPeers(); len(p) != 0 {
		t.Fatalf("disabled BGP peers = %v", p)
	}
	if rs, _ := RenderBGPGuard(nil); strings.Contains(rs, "elements") || !strings.Contains(rs, "tcp dport 179 drop") {
		t.Fatalf("empty guard:\n%s", rs)
	}
	if _, err := RenderBGPGuard([]string{"1.2.3.4 }; chain x {"}); err == nil {
		t.Fatalf("injected peer rendered")
	}
}

// TestDumpForFRRCheck writes sample configs for checking with the real FRR /
// nft on a host (vtysh -C -f, nft -c -f). Env-gated.
func TestDumpForFRRCheck(t *testing.T) {
	dir := os.Getenv("VX_FRR_DUMP")
	if dir == "" {
		t.Skip("host check only")
	}
	host := Config{BGP: BGP{Enabled: true, ASN: 65010, Neighbors: []Neighbor{{Addr: "192.0.2.1", RemoteAS: 64512, RouteMapIn: "IN", PrefixListOut: "OUT"}},
		Networks: []string{"10.20.0.0/24"}},
		PrefixLists: []PrefixList{{Name: "OUT", Seq: 5, Action: "permit", Prefix: "10.20.0.0/24"}},
		RouteMaps:   []RouteMapClause{{Name: "IN", Action: "permit", Seq: 10}},
		OSPF:        OSPF{Enabled: true, RouterID: "10.99.0.1", Networks: []OSPFNet{{CIDR: "10.30.0.0/24", Area: "0"}}},
		Static:      []Route{{Dest: "10.40.0.0/24", NextHop: "192.0.2.254"}}}
	samples := map[string]Config{"fabric-only.conf": {Fabric: testFabric()}, "host-only.conf": host}
	both := host
	both.Fabric = testFabric()
	samples["host-and-fabric.conf"] = both
	for name, c := range samples {
		conf, err := RenderFRR(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(conf), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, _ := RenderBGPGuard(both.BGPPeers())
	if err := os.WriteFile(filepath.Join(dir, "bgp-guard.nft"), []byte(rs), 0o644); err != nil {
		t.Fatal(err)
	}
}
