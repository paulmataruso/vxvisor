package service

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"vdxclone/internal/auth"
	"vdxclone/internal/config"
	"vdxclone/internal/db"
	"vdxclone/internal/fabric"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/store"
)

// Live E2E for a single-host fabric. Runs ONLY as root on a host with
// VDX_E2E_DB + VDX_E2E_FABRIC=1 and a running vdxd: this process commits the
// changes to the live DB the way the web UI does, and the DAEMON realizes them
// (its 60 s reconcile), so what's checked is the real daemon's work. The
// underlay is a dummy NIC made here. Everything is torn down again.
func TestE2EFabric(t *testing.T) {
	k := newE2E(t)
	s, p, d, org := k.s, k.p, k.d, k.org
	sh, must, check, waitFor := k.sh, k.must, k.check, k.waitFor
	const ip, dummy = "e2e-test", "vxe2e0"
	self := s.selfNode()

	frrMarks := func() string { return sh(`grep -cE 'advertise-all-vni|VXFABRIC|vrf vxfvrf' /etc/frr/frr.conf`) }
	initialFRR := frrMarks()
	check(sh(`ip -br link | grep -c '^vxf'`) == "0", "no fabric devices before the test", sh(`ip -br link | grep '^vxf'`))

	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()

	sh("ip link del " + dummy + " 2>/dev/null")
	must(exec.Command("sh", "-c", "ip link add "+dummy+" type dummy && ip link set "+dummy+" mtu 9000 up").Run(), "make the dummy underlay")
	cleanups = append(cleanups, func() { sh("ip link del " + dummy) })

	// ---- A. preflight + deploy ----
	fi := FabricInput{Name: "e2e", Orgs: []int64{org}, Hosts: []FabricHostInput{{Node: self, Iface: dummy, TEP: "10.251.77.1/24"}}}
	checks, err := s.PreflightFabric(p, fi)
	must(err, "preflight")
	check(!FabricChecksFailed(checks), "preflight passes", checkText(checks))
	fu, checks, err := s.CreateFabric(p, fi, ip)
	must(err, "create fabric: "+checkText(checks))
	cleanups = append(cleanups, func() {
		must(s.DeleteFabric(p, fu, ip), "cleanup: delete fabric")
		waitFor("every fabric device removed", func() bool { return sh(`ip -br link | grep -c '^vxf'`) == "0" })
		waitFor("fabric nft tables removed", func() bool { return !strings.Contains(sh("nft list tables"), "vdxfabric") })
		waitFor("TEP removed from the underlay", func() bool { return !strings.Contains(sh("ip -4 -br addr show "+dummy), "10.251.77.1") })
		waitFor("FRR fabric config removed", func() bool { return frrMarks() == initialFRR })
		var n int
		d.QueryRow(`SELECT count(*) FROM fabric_underlay`).Scan(&n)
		check(n == 0, "fabric_underlay empty")
		d.QueryRow(`SELECT count(*) FROM networks WHERE mode='fabric'`).Scan(&n)
		check(n == 0, "fabric networks rows removed")
		check(sh("ls /run/vdxclone/fabric/dnsmasq-*.pid 2>/dev/null | wc -l") == "0", "fabric DHCP stopped")
	})
	check(strings.Contains(sh("ip -4 -br addr show "+dummy), "10.251.77.1/24"), "TEP on the underlay", sh("ip -4 -br addr show "+dummy))
	check(strings.Contains(sh("nft list tables"), "inet vdxfabric"), "firewall table loaded")
	check(strings.Contains(sh("nft list tables"), "bridge vdxfabric"), "bridge guard loaded")
	check(sh("sysctl -n net.ipv4.tcp_l3mdev_accept net.ipv4.udp_l3mdev_accept | tr -d '\\n'") == "00", "l3mdev accept off")
	check(strings.Contains(sh("cat /etc/frr/frr.conf"), "advertise-all-vni"), "EVPN in frr.conf")

	// ---- B. a routed port group: VRF, anycast gateway, DHCP, EVPN ----
	web, err := s.CreateFabricPG(p, FabricPGInput{Fabric: fu, Name: "web", CIDR: "10.252.77.0/24", PoolStart: "10.252.77.100", PoolEnd: "10.252.77.150"}, ip)
	must(err, "create PG web")
	cleanups = append(cleanups, func() { must(s.DeleteFabricPG(p, web, ip), "cleanup: delete PG web") })
	in, _ := s.fabricIntent()
	wpg, vrf := in.PG(web), fabric.VRFName(org)
	br := fabric.SegBridge(wpg.VNI)
	waitFor("web's anycast gateway on "+br, func() bool { return strings.Contains(sh("ip -4 -br addr show "+br), "10.252.77.1/24") })
	check(strings.HasSuffix(sh("readlink /sys/class/net/"+br+"/master"), "/"+vrf), br+" in "+vrf)
	vx := sh("ip -d link show " + fabric.SegVXLAN(wpg.VNI))
	check(strings.Contains(vx, "vxlan id "+strconv.Itoa(wpg.VNI)) && strings.Contains(vx, "nolearning"), "VXLAN "+fabric.SegVXLAN(wpg.VNI), vx)
	check(sh("cat /proc/sys/net/ipv4/conf/"+br+"/arp_accept") == "1", "arp_accept on the gateway bridge")
	var netID int64
	d.QueryRow(`SELECT network_id FROM fabric_pg_networks WHERE pg_uuid=?`, web).Scan(&netID)
	var mode, nbr string
	d.QueryRow(`SELECT mode, bridge FROM networks WHERE id=?`, netID).Scan(&mode, &nbr)
	check(mode == "fabric" && nbr == br, "networks row for web", mode, nbr)
	waitFor("DHCP for "+vrf, func() bool { return dnsmasqAlive("/run/vdxclone/fabric/dnsmasq-" + vrf + ".pid") })
	waitFor("zebra knows VNI "+strconv.Itoa(wpg.VNI), func() bool { return strings.Contains(sh(`vtysh -c "show evpn vni"`), strconv.Itoa(wpg.VNI)) })
	check(strings.Contains(sh("cat /etc/frr/frr.conf"), "vrf "+vrf), "VRF "+vrf+" in frr.conf")

	// ---- C. an L2-only port group: no address, no forwarding ----
	san, err := s.CreateFabricPG(p, FabricPGInput{Fabric: fu, Name: "san"}, ip)
	must(err, "create PG san")
	cleanups = append(cleanups, func() { must(s.DeleteFabricPG(p, san, ip), "cleanup: delete PG san") })
	in, _ = s.fabricIntent()
	sbr := fabric.SegBridge(in.PG(san).VNI)
	waitFor("L2-only bridge "+sbr, func() bool { return netdrv.IfaceExists(sbr) })
	check(sh("ip -4 -br addr show "+sbr+" | awk '{print $3}'") == "", "no address on "+sbr)
	check(sh("cat /proc/sys/net/ipv4/conf/"+sbr+"/forwarding") == "0", "no forwarding on "+sbr)

	// ---- D. a second routed PG + a rule: the firewall follows ----
	dbpg, err := s.CreateFabricPG(p, FabricPGInput{Fabric: fu, Name: "db", CIDR: "10.252.78.0/24"}, ip)
	must(err, "create PG db")
	cleanups = append(cleanups, func() { must(s.DeleteFabricPG(p, dbpg, ip), "cleanup: delete PG db") })
	must(s.AddFabricRule(p, FabricRuleInput{Fabric: fu, Src: web, Dst: dbpg, Proto: "tcp", Ports: "5432"}, ip), "add rule")
	in, _ = s.fabricIntent()
	var rule string
	for _, r := range in.Rules {
		if r.Src == web && r.Dst == dbpg {
			rule = r.UUID
		}
	}
	cleanups = append(cleanups, func() { must(s.DeleteFabricRule(p, rule, ip), "cleanup: delete rule") })
	waitFor("rule web→db tcp/5432 in the firewall", func() bool {
		fw := sh("nft list table inet vdxfabric")
		return strings.Contains(fw, "10.252.77.0/24") && strings.Contains(fw, "10.252.78.0/24") && strings.Contains(fw, "5432")
	})

	// ---- D2. a netns router as the org's gateway: egress + routes back ----
	vr, err := s.CreateVRouter(p, VRouterInput{Name: "e2e-fabgw", Runtime: "netns"}, ip)
	must(err, "create router")
	cleanups = append(cleanups, func() { must(s.DeleteVRouter(p, vr, ip), "cleanup: delete router") })
	waitFor("router provisioned", func() bool {
		var st string
		d.QueryRow(`SELECT status FROM vrouters WHERE id=?`, vr).Scan(&st)
		return st == "stopped" || st == "running"
	})
	must(s.StartVRouter(p, vr, ip), "start router")
	var ns string
	d.QueryRow(`SELECT netns_name FROM vrouters WHERE id=?`, vr).Scan(&ns)
	must(s.ConnectFabricGateway(p, vr, web, "10.252.77.254", ip), "connect gateway")
	gwConnected := true
	cleanups = append(cleanups, func() {
		if gwConnected {
			must(s.DisconnectFabricGateway(p, fu, ip), "cleanup: disconnect gateway")
		}
	})
	nsh := func(c string) string { return sh("ip netns exec " + ns + " " + c) }
	check(strings.Contains(nsh("ip -4 -br addr"), "10.252.77.254/24"), "router leg address", nsh("ip -4 -br addr"))
	rt := nsh("ip route show 10.252.78.0/24")
	check(strings.Contains(rt, "via 10.252.77.1 dev eth1"), "router's route to db via the anycast gateway", rt)
	in, _ = s.fabricIntent()
	check(in.VRFOf(fu, org) != nil && in.VRFOf(fu, org).Egress == "10.252.77.254", "egress set to the router")
	waitFor("VRF default route via the router", func() bool {
		return strings.Contains(sh("ip route show vrf "+vrf+" default"), "via 10.252.77.254")
	})
	time.Sleep(65 * time.Second) // a full daemon reconcile re-asserts the unreachable default
	check(strings.Contains(sh("ip route show vrf "+vrf+" default"), "via 10.252.77.254"), "VRF default route survives a reconcile", sh("ip route show vrf "+vrf+" default"))
	check(strings.Contains(nsh("ping -c1 -W2 10.252.77.1"), " 0% packet loss"), "router reaches web's anycast gateway")
	check(strings.Contains(nsh("ping -c1 -W2 10.252.78.1"), " 0% packet loss"), "router reaches db's gateway (routed through the fabric)")
	check(s.DeleteVRouter(p, vr, ip) != nil, "deleting the gateway router is refused")
	check(s.SetFabricEgress(p, fu, "10.252.77.253", ip) != nil, "a free-text egress is refused while a router is connected")
	must(s.DisconnectFabricGateway(p, fu, ip), "disconnect gateway")
	gwConnected = false
	check(!strings.Contains(nsh("ip -4 -br addr"), "10.252.77.254"), "router leg removed")
	waitFor("VRF default route removed", func() bool { return !strings.Contains(sh("ip route show vrf "+vrf+" default"), "via 10.252.77.254") })

	// ---- E. a fabric-wide lease reaches the DHCP config, and is released ----
	addr, err := s.FabricIPAM().Lease(netID, "e2e-session", "52:54:00:e2:e2:01")
	must(err, "lease")
	check(strings.HasPrefix(addr, "10.252.77.1") && strings.HasSuffix(addr, "/24"), "lease from the pool", addr)
	conf := "/run/vdxclone/fabric/dnsmasq-" + vrf + ".conf"
	waitFor("lease in "+vrf+"'s DHCP", func() bool { return strings.Contains(sh("cat "+conf), "52:54:00:e2:e2:01") })
	s.FabricIPAM().Release("e2e-session")
	in, _ = s.fabricIntent()
	check(len(in.Leases) == 0, "lease released")

	waitFor("node status ok at the latest version", func() bool {
		st, err := s.nodeFabricStatus(self)
		return err == nil && st.State == "ok"
	})
}

// e2eKit is a live E2E's service (on the live DB, as an instance admin) and
// its check helpers.
type e2eKit struct {
	t   *testing.T
	s   *Service
	p   *Principal
	d   *db.DB
	org int64
}

func newE2E(t *testing.T) *e2eKit {
	t.Helper()
	dbPath := os.Getenv("VDX_E2E_DB")
	if dbPath == "" || os.Getenv("VDX_E2E_FABRIC") != "1" || os.Geteuid() != 0 {
		t.Skip("live E2E: run as root with VDX_E2E_DB and VDX_E2E_FABRIC=1")
	}
	cfg, err := config.Load("/etc/vdxclone/config.toml")
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	k := &e2eKit{t: t, d: d, s: &Service{cfg: cfg, db: d, store: store.New(d), net: netdrv.New(d)}}
	var uid int64
	d.QueryRow(`SELECT id FROM orgs ORDER BY id LIMIT 1`).Scan(&k.org)
	d.QueryRow(`SELECT id FROM users ORDER BY id LIMIT 1`).Scan(&uid)
	k.p = &Principal{User: &auth.User{ID: uid}, OrgID: k.org, OrgRole: "owner", IsAdmin: true}
	return k
}

func (k *e2eKit) sh(c string) string {
	out, _ := exec.Command("sh", "-c", c).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func (k *e2eKit) must(err error, what string) {
	k.t.Helper()
	if err != nil {
		k.t.Fatalf("%s: %v", what, err)
	}
}

func (k *e2eKit) check(ok bool, what string, detail ...string) {
	k.t.Helper()
	if !ok {
		k.t.Errorf("FAIL %s %v", what, detail)
	} else {
		k.t.Logf("ok   %s", what)
	}
}

// waitFor polls until the daemon has realized a step (it reconciles every 60 s).
func (k *e2eKit) waitFor(what string, cond func() bool) bool {
	k.t.Helper()
	start := time.Now()
	for time.Since(start) < 100*time.Second {
		if cond() {
			k.t.Logf("ok   %s (%.0fs)", what, time.Since(start).Seconds())
			return true
		}
		time.Sleep(time.Second)
	}
	k.t.Errorf("FAIL %s: not realized within 100 s", what)
	return false
}

func checkText(cs []FabricCheck) string {
	var b strings.Builder
	for _, c := range cs {
		if !c.OK {
			b.WriteString(c.Node + " " + c.Check + ": " + c.Detail + "; ")
		}
	}
	return b.String()
}

func TestFRRConfHasFabric(t *testing.T) {
	single := "router bgp 65100\n neighbor VXFABRIC peer-group\n neighbor VXFABRIC remote-as internal\nexit\n"
	vrfOnly := "frr version 10.5\n!\nvrf vxfvrf3\n vni 4000003\nexit-vrf\n"
	host := "router bgp 65001\n neighbor 192.0.2.1 remote-as 65002\nexit\n!\nvrf mgmt\nexit-vrf\n"
	if !frrConfHasFabric(single) || !frrConfHasFabric(vrfOnly) || frrConfHasFabric(host) {
		t.Fatal("frrConfHasFabric")
	}
}

// Live E2E for a single-host fabric over management (same rules as
// TestE2EFabric): the TEP rides WireGuard on vxfwg0, the node's own key and
// endpoint reach the intent, and the management interface comes out exactly as
// it went in — link, addresses and routes — both while the fabric runs and
// after it is gone.
func TestE2EFabricMgmt(t *testing.T) {
	k := newE2E(t)
	s, p := k.s, k.p
	const ip = "e2e-test"
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wireguard-tools isn't installed")
	}
	info := s.FabricLocalWG()
	if info.Problem != "" {
		t.Skipf("this host can't ride over management: %s", info.Problem)
	}
	mgmtState := func() string {
		return k.sh("ip -o link show dev " + info.Iface + "; ip -o addr show dev " + info.Iface + "; ip -4 route show dev " + info.Iface)
	}
	before := mgmtState()
	k.check(k.sh(`ip -br link | grep -c '^vxf'`) == "0", "no fabric devices before the test")

	fi := FabricInput{Name: "e2e-mgmt", Underlay: fabric.UnderlayMgmt, Orgs: []int64{k.org},
		Hosts: []FabricHostInput{{Node: s.selfNode(), TEP: "10.251.78.1/24"}}}
	checks, err := s.PreflightFabric(p, fi)
	k.must(err, "preflight")
	k.check(!FabricChecksFailed(checks), "preflight passes", checkText(checks))
	fu, checks, err := s.CreateFabric(p, fi, ip)
	k.must(err, "create fabric: "+checkText(checks))
	defer func() {
		k.must(s.DeleteFabric(p, fu, ip), "cleanup: delete fabric")
		k.waitFor("WireGuard device removed", func() bool { return !netdrv.IfaceExists(fabric.WGDev) })
		k.waitFor("fabric nft tables removed", func() bool { return !strings.Contains(k.sh("nft list tables"), "vdxfabric") })
		var n int
		k.d.QueryRow(`SELECT count(*) FROM fabric_underlay`).Scan(&n)
		k.check(n == 0, "fabric_underlay empty")
		k.check(mgmtState() == before, "management interface unchanged after teardown", before, mgmtState())
	}()

	in, _ := s.fabricIntent()
	f, h := in.HostOf(s.selfNode())
	k.check(f != nil && f.OverMgmt() && f.MTU == fabric.MgmtMTU && f.GuestMTU() == 1390, "over management, MTU 1440, guests 1390")
	k.check(h != nil && h.Iface == info.Iface && h.Endpoint == info.Endpoint && h.WGPub == info.Pub, "host entry is what the node reports", info.Iface, info.Endpoint)
	k.check(strings.Contains(k.sh("ip -4 -br addr show dev "+fabric.WGDev), "10.251.78.1/24"), "TEP on vxfwg0", k.sh("ip -4 -br addr show dev "+fabric.WGDev))
	k.check(strings.Contains(k.sh("ip -o link show dev "+fabric.WGDev), "mtu 1440"), "vxfwg0 MTU 1440")
	k.check(k.sh("wg show "+fabric.WGDev+" listen-port") == strconv.Itoa(fabric.WGPort), "tunnel on UDP 51871")
	k.check(k.sh("wg show "+fabric.WGDev+" public-key") == info.Pub, "the kernel holds the key in the intent")
	k.check(k.sh("cat "+s.fabricWGKeyPath()+" | wg pubkey") == info.Pub, "wg derives the same public key as vdxd")
	k.check(k.sh("stat -c %a "+s.fabricWGKeyPath()) == "600", "private key file is 0600")
	k.check(k.sh("ls "+fabric.WGConfDir+"/"+fabric.WGDev+"-*.conf 2>/dev/null | wc -l") == "0", "no config with the private key left behind")
	fw := k.sh("nft list table inet vdxfabric")
	k.check(strings.Contains(fw, "udp dport 51871 counter"), "tunnel port shut to everyone (single host)")
	k.check(strings.Contains(fw, "ip dscp set cs1"), "tunnel packets marked CS1")
	k.check(strings.Contains(fw, `iifname != { "vxfwg0", "lo" }`), "TEP sources only out of the tunnel")
	k.check(mgmtState() == before, "management interface unchanged", before, mgmtState())

	// A routed port group: its VXLAN ends on the tunnel's TEP at guest MTU.
	web, err := s.CreateFabricPG(p, FabricPGInput{Fabric: fu, Name: "web", CIDR: "10.252.78.0/24"}, ip)
	k.must(err, "create PG web")
	defer func() { k.must(s.DeleteFabricPG(p, web, ip), "cleanup: delete PG web") }()
	in, _ = s.fabricIntent()
	vx := fabric.SegVXLAN(in.PG(web).VNI)
	k.waitFor("VXLAN "+vx+" on the tunnel's TEP", func() bool {
		d := k.sh("ip -d -o link show dev " + vx)
		return strings.Contains(d, "local 10.251.78.1") && strings.Contains(d, "mtu 1390")
	})
	k.check(mgmtState() == before, "management interface unchanged with a port group", before, mgmtState())
	k.waitFor("node status ok", func() bool { st := s.FabricLocalStatus(); return st.State == "ok" && st.Underlay == fabric.WGDev })
}
