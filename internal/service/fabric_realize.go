package service

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/fabric"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/routing"
)

// ReconcileFabric brings this host to its share of the fabric intent: desired
// state, idempotent, safe to run at any time (docs/FABRIC.md §14 D9). Order:
// guards first (nothing guest-facing exists unguarded), then the underlay, the
// kernel devices, local port group rows, DHCP, and FRR last. A host that is in
// no fabric gets everything fabric-shaped removed (Prune only ever touches vxf*
// devices) and its underlay restored.

// fabricRunDir holds the per-VRF dnsmasq configs, pids and lease files.
var fabricRunDir = "/run/vdxclone/fabric"

// fabricExec runs host commands for the fabric (a seam for tests).
var fabricExec fabric.Runner = fabric.Exec{}

// KickFabric schedules a reconcile (coalesced; never blocks).
func (s *Service) KickFabric() {
	select {
	case s.fabricRT().kick <- struct{}{}:
	default:
	}
}

// RunFabric is the worker loop (after the boot reconcile): reconcile on every
// change and every minute (re-asserting kernel state someone changed by hand);
// sync from the other members and retry failed lease releases every 30 s.
func (s *Service) RunFabric(stop <-chan struct{}) {
	rt := s.fabricRT()
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	n := 0
	for {
		select {
		case <-stop:
			return
		case <-rt.kick:
		case <-tick.C:
			s.SyncFabric()
			s.retryFabricReleases()
			if n++; n%2 != 0 {
				continue
			}
		}
		if err := s.ReconcileFabric(); err != nil {
			log.Printf("fabric: %v", err)
		}
		s.refreshFabricGateways()
	}
}

// ReconcileFabric realizes this node's share of the intent.
func (s *Service) ReconcileFabric() error {
	rt := s.fabricRT()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	in, err := rt.mem.Current()
	if err != nil {
		return err
	}
	self := s.selfNode()
	f, h := in.HostOf(self)
	plan, member := in.HostPlan(self)
	if !member && !s.fabricLeftovers() {
		return nil // never in a fabric: touch nothing
	}
	var errs []string
	note := func(what string, err error) {
		if err != nil {
			errs = append(errs, what+": "+err.Error())
		}
	}

	if routing.NFTAvailable() {
		fw, err := fabric.Firewall(&in, self)
		if err == nil {
			err = netdrv.ApplyNFT(fw)
		}
		note("firewall", err)
		guard := "table bridge vdxfabric {}\ndelete table bridge vdxfabric\n"
		var gerr error
		if member {
			guard, gerr = fabric.BridgeGuard(in.Guard(self))
		}
		if gerr == nil {
			gerr = netdrv.ApplyNFT(guard)
		}
		note("bridge guard", gerr)
		note("VXLAN guard", s.applyVXLANGuard())
	}
	if member {
		note("l3mdev", assertL3mdev())
		note("underlay", s.ensureUnderlay(f, *h))
	}
	note("stale underlay", s.teardownUnderlays(f))
	if member {
		note("devices", fabric.Realize(fabricExec, plan))
	}
	if gone, err := fabric.Prune(fabricExec, plan); err != nil {
		note("prune", err)
	} else if len(gone) > 0 {
		log.Printf("fabric: removed %s", strings.Join(gone, ", "))
	}
	note("port groups", s.syncFabricNetworks(in, self))
	note("DHCP", s.syncFabricDHCP(in, self))
	note("FRR", s.syncFabricFRR())

	state, msg := "ok", ""
	if len(errs) > 0 {
		state, msg = "error", strings.Join(errs, "; ")
		log.Printf("fabric: reconcile v%d: %s", in.Version, msg)
	}
	if member {
		_, _ = s.db.Exec(`UPDATE fabric_underlay SET state=?, error=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE fabric_uuid=?`,
			state+"@"+strconv.FormatInt(in.Version, 10), msg, f.UUID)
	}
	if msg != "" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// fabricLeftovers reports whether anything of a former fabric membership is
// still on this host (so a host that left must be cleaned, while a host that
// was never in a fabric isn't touched at all).
func (s *Service) fabricLeftovers() bool {
	var n int
	_ = s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM fabric_underlay) + (SELECT COUNT(*) FROM fabric_pg_networks)`).Scan(&n)
	if n > 0 {
		return true
	}
	if ents, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range ents {
			if fabric.IsFabricDevice(e.Name()) {
				return true
			}
		}
	}
	return frrHasFabric()
}

func frrHasFabric() bool {
	b, err := os.ReadFile("/etc/frr/frr.conf")
	return err == nil && frrConfHasFabric(string(b))
}

// frrConfHasFabric reports whether an frr.conf carries a fabric section: its
// peer-group (present even with no peers, on a single-host fabric) or a VRF.
func frrConfHasFabric(conf string) bool {
	return strings.Contains(conf, " neighbor "+routing.FabricPeerGroup+" peer-group") || strings.Contains(conf, "\nvrf vxfvrf")
}

// assertL3mdev keeps host sockets from accepting connections that arrive in a
// fabric VRF (a guest must never reach the host's own services that way).
func assertL3mdev() error {
	for _, k := range []string{"tcp_l3mdev_accept", "udp_l3mdev_accept"} {
		p := "/proc/sys/net/ipv4/" + k
		if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "0" {
			log.Printf("fabric: net.ipv4.%s was %s; setting 0", k, strings.TrimSpace(string(b)))
			if err := os.WriteFile(p, []byte("0"), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- underlay ----------------------------------------------------------------

// ensureUnderlay puts this host's TEP on its underlay: the dedicated NIC (MTU
// raised to the fabric's, its original recorded once) or a VLAN subinterface
// vdxd creates (the parent is never changed).
func (s *Service) ensureUnderlay(f *fabric.Spec, h fabric.Host) error {
	dev := h.UnderlayDev()
	var have struct {
		dev, tep string
	}
	recorded := s.db.QueryRow(`SELECT dev, tep FROM fabric_underlay WHERE fabric_uuid=?`, f.UUID).Scan(&have.dev, &have.tep) == nil
	if recorded && (have.dev != dev || have.tep != h.TEP) {
		if err := s.teardownUnderlay(f.UUID); err != nil {
			return err
		}
		recorded = false
	}
	if !recorded {
		orig := 0
		if h.VLAN == 0 {
			orig = netdrv.LinkMTU(h.Iface)
		}
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO fabric_underlay(fabric_uuid, iface, dev, tep, made_vlan, orig_mtu) VALUES(?,?,?,?,?,?)`,
			f.UUID, h.Iface, dev, h.TEP, boolInt(h.VLAN > 0), orig); err != nil {
			return err
		}
	}
	run := func(args ...string) error { _, err := fabricExec.Run(args...); return err }
	if err := run("ip", "link", "set", h.Iface, "up"); err != nil {
		return err
	}
	if h.VLAN > 0 && !netdrv.IfaceExists(dev) {
		if err := run("ip", "link", "add", "link", h.Iface, "name", dev, "type", "vlan", "id", strconv.Itoa(h.VLAN)); err != nil {
			return err
		}
	}
	if netdrv.LinkMTU(dev) != f.MTU {
		if err := run("ip", "link", "set", dev, "mtu", strconv.Itoa(f.MTU)); err != nil {
			return err
		}
	}
	_ = run("sysctl", "-qw", "net.ipv6.conf."+dev+".disable_ipv6=1")
	out, err := fabricExec.Run("ip", "-4", "-o", "addr", "show", "dev", dev)
	if err != nil {
		return err
	}
	if !strings.Contains(" "+out+" ", " "+h.TEP+" ") {
		if err := run("ip", "addr", "add", h.TEP, "dev", dev); err != nil {
			return err
		}
	}
	return run("ip", "link", "set", dev, "up")
}

// teardownUnderlays restores every underlay this host set up for a fabric it is
// no longer in (keep = the current one, nil = none).
func (s *Service) teardownUnderlays(keep *fabric.Spec) error {
	rows, err := s.db.Query(`SELECT fabric_uuid FROM fabric_underlay`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && (keep == nil || id != keep.UUID) {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if err := s.teardownUnderlay(id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) teardownUnderlay(fabricUUID string) error {
	var iface, dev, tep string
	var made bool
	var orig int
	if err := s.db.QueryRow(`SELECT iface, dev, tep, made_vlan, orig_mtu FROM fabric_underlay WHERE fabric_uuid=?`, fabricUUID).
		Scan(&iface, &dev, &tep, &made, &orig); err != nil {
		return nil
	}
	if netdrv.IfaceExists(dev) {
		_, _ = fabricExec.Run("ip", "addr", "del", tep, "dev", dev)
		if made {
			if _, err := fabricExec.Run("ip", "link", "del", dev); err != nil {
				return err
			}
		} else if orig > 0 && netdrv.LinkMTU(dev) != orig {
			if _, err := fabricExec.Run("ip", "link", "set", dev, "mtu", strconv.Itoa(orig)); err != nil {
				return err
			}
		}
	}
	_, err := s.db.Exec(`DELETE FROM fabric_underlay WHERE fabric_uuid=?`, fabricUUID)
	log.Printf("fabric: restored underlay %s (TEP %s removed)", dev, tep)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// refenceFabric re-applies what a host routing apply resets: rewriting the
// global ip_forward resets every interface's forwarding flag, and an L2-only
// fabric port group's bridge must never route.
func (s *Service) refenceFabric() {
	in, err := s.fabricIntent()
	if err != nil {
		return
	}
	plan, ok := in.HostPlan(s.selfNode())
	if !ok {
		return
	}
	for _, sg := range plan.Segments {
		if sg.Gateway == "" && netdrv.IfaceExists(fabric.SegBridge(sg.VNI)) {
			_, _ = fabricExec.Run("sysctl", "-qw", "net.ipv4.conf."+fabric.SegBridge(sg.VNI)+".forwarding=0")
		}
	}
}

// ---- local port group rows -------------------------------------------------------

// syncFabricNetworks keeps one local networks row (mode 'fabric', bridge
// vxfb<vni>) per fabric port group this host spans — the row VMs, containers
// and vRouter legs attach to through the ordinary path — and removes rows of
// port groups that left (only when nothing here uses them).
func (s *Service) syncFabricNetworks(in fabric.Intent, self string) error {
	want := map[string]fabric.PortGroup{}
	for _, pg := range in.PGs {
		if in.Spans(pg, self) {
			want[pg.UUID] = pg
		}
	}
	rows, err := s.db.Query(`SELECT pg_uuid, network_id FROM fabric_pg_networks`)
	if err != nil {
		return err
	}
	have := map[string]int64{}
	for rows.Next() {
		var u string
		var id int64
		if rows.Scan(&u, &id) == nil {
			have[u] = id
		}
	}
	rows.Close()
	var errs []string
	for u, pg := range want {
		gw, pool0, pool1 := "", "", ""
		if pg.Routed() {
			gw, pool0, pool1 = pg.Gateway, pg.PoolStart, pg.PoolEnd
		}
		if id, ok := have[u]; ok {
			if _, err := s.db.Exec(`UPDATE networks SET org_id=?, name=?, mode='fabric', bridge=?, vlan_id=0, cidr=?, gateway=?,
				pool_start=?, pool_end=?, vni=? WHERE id=?`, pg.Org, pg.Name, fabric.SegBridge(pg.VNI), pg.CIDR, gw, pool0, pool1, pg.VNI, id); err != nil {
				errs = append(errs, err.Error())
			}
			continue
		}
		tx, err := s.db.Begin()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		res, err := tx.Exec(`INSERT INTO networks(org_id, name, mode, bridge, vlan_id, cidr, gateway, pool_start, pool_end, vni)
			VALUES(?,?, 'fabric', ?, 0, ?,?,?,?,?)`, pg.Org, pg.Name, fabric.SegBridge(pg.VNI), pg.CIDR, gw, pool0, pool1, pg.VNI)
		if err == nil {
			id, _ := res.LastInsertId()
			_, err = tx.Exec(`INSERT INTO fabric_pg_networks(pg_uuid, network_id) VALUES(?,?)`, u, id)
		}
		if err != nil {
			_ = tx.Rollback()
			errs = append(errs, "port group "+pg.Name+": "+err.Error())
			continue
		}
		if err := tx.Commit(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for u, id := range have {
		if _, ok := want[u]; ok {
			continue
		}
		var org int64
		_ = s.db.QueryRow(`SELECT org_id FROM networks WHERE id=?`, id).Scan(&org)
		if n, err := s.net.GetNetwork(org, id); err == nil {
			if err := s.fabricPGInUse(n); err != nil {
				errs = append(errs, err.Error())
				continue
			}
		}
		if _, err := s.db.Exec(`DELETE FROM fabric_pg_networks WHERE pg_uuid=?`, u); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		_, _ = s.db.Exec(`DELETE FROM networks WHERE id=?`, id)
	}
	// Fabric leases on this node's rows mirror the intent.
	for u, id := range have {
		if _, ok := want[u]; !ok {
			continue
		}
		_, _ = s.db.Exec(`DELETE FROM ip_leases WHERE network_id=? AND session_id NOT IN (SELECT id FROM sessions)`, id)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// ---- DHCP ---------------------------------------------------------------------

// syncFabricDHCP runs one dnsmasq per org VRF this host routes for, restarting
// it when its config changes, and stops the rest.
func (s *Service) syncFabricDHCP(in fabric.Intent, self string) error {
	want := in.DHCP(self)
	if err := os.MkdirAll(fabricRunDir, 0o755); err != nil {
		return err
	}
	var errs []string
	for org, segs := range want {
		vrf := fabric.VRFName(org)
		if !netdrv.IfaceExists(vrf) {
			continue // Realize failed; reported there
		}
		conf, err := fabric.DNSMasqConfig(org, segs, fabricRunDir)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		path := filepath.Join(fabricRunDir, "dnsmasq-"+vrf+".conf")
		pid := filepath.Join(fabricRunDir, "dnsmasq-"+vrf+".pid")
		if old, _ := os.ReadFile(path); string(old) == conf && dnsmasqAlive(pid) {
			continue
		}
		stopDNSMasq(pid)
		if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if _, err := fabricExec.Run(fabric.DNSMasqArgs(org, path)...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	pids, _ := filepath.Glob(filepath.Join(fabricRunDir, "dnsmasq-vxfvrf*.pid"))
	for _, p := range pids {
		org, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "dnsmasq-vxfvrf"), ".pid"), 10, 64)
		if err != nil {
			continue
		}
		if _, ok := want[org]; !ok {
			stopDNSMasq(p)
			base := strings.TrimSuffix(p, ".pid")
			_ = os.Remove(base + ".conf")
			_ = os.Remove(base + ".leases")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func dnsmasqPID(pidFile string) int {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 1 {
		return 0
	}
	if comm, err := os.ReadFile("/proc/" + strconv.Itoa(n) + "/comm"); err != nil || strings.TrimSpace(string(comm)) != "dnsmasq" {
		return 0
	}
	return n
}

func dnsmasqAlive(pidFile string) bool { return dnsmasqPID(pidFile) > 0 }

func stopDNSMasq(pidFile string) {
	if n := dnsmasqPID(pidFile); n > 0 {
		if p, err := os.FindProcess(n); err == nil {
			_ = p.Kill()
			for i := 0; i < 20 && dnsmasqAlive(pidFile); i++ {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}
	_ = os.Remove(pidFile)
}

// ---- FRR -----------------------------------------------------------------------

// syncFabricFRR re-applies the host routing config (which composes the fabric
// section in) when the fabric section changed, or when frr.conf still carries a
// fabric this host left.
func (s *Service) syncFabricFRR() error {
	rt := s.fabricRT()
	key := ""
	if r := s.fabricRouting(); r != nil {
		b, _ := json.Marshal(r)
		key = string(b)
	}
	if rt.frrSet && key == rt.lastFRR {
		return nil
	}
	if key == "" && rt.lastFRR == "" && !frrHasFabric() {
		rt.lastFRR, rt.frrSet = "", true
		return nil
	}
	hostRoutingMu.Lock()
	err := applyHostRoutingFn(s, s.loadHostRouting())
	hostRoutingMu.Unlock()
	if err != nil {
		return err
	}
	rt.lastFRR, rt.frrSet = key, true
	return nil
}

// fabricVXLANListeners adds the fabric's VNIs to the host VXLAN ingress guard:
// each is accepted only from the other members' TEPs.
func (s *Service) fabricVXLANListeners() []netdrv.VXLANListener {
	in, err := s.fabricIntent()
	if err != nil {
		return nil
	}
	self := s.selfNode()
	plan, ok := in.HostPlan(self)
	if !ok {
		return nil
	}
	peers := in.Peers(self)
	var out []netdrv.VXLANListener
	for _, sg := range plan.Segments {
		out = append(out, netdrv.VXLANListener{Port: fabric.VXLANPort, VNI: sg.VNI, Peers: peers})
	}
	for _, v := range plan.VRFs {
		out = append(out, netdrv.VXLANListener{Port: fabric.VXLANPort, VNI: v.L3VNI, Peers: peers})
	}
	return out
}
