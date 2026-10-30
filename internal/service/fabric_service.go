package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"vdxclone/internal/fabric"
	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/peer"
	"vdxclone/internal/routing"
)

// VXVisor Fabric (docs/FABRIC.md §14): the service side. The replicated intent
// (fabric.Intent) is changed only through fabricChange — a unanimous two-phase
// commit across every fabric member (fabric.Coordinator) — and each node
// realizes its own share in ReconcileFabric (fabric_realize.go).
//
// Authorization: instance admins own the physical layer (fabrics, hosts, TEPs,
// underlay). Org admins build port groups, rules and egress for their own org on
// a fabric the provider opened to that org; every org-level object carries the
// org id and every read is filtered by it.

// fabricRT is the service's fabric runtime.
type fabricRT struct {
	once  sync.Once
	mem   *fabric.Member
	coord *fabric.Coordinator
	kick  chan struct{}

	mu      sync.Mutex // one reconcile at a time
	lastFRR string     // fabric FRR section last applied ("" = none)
	frrSet  bool

	relMu   sync.Mutex
	release map[string]int64 // session → network id (0 = all) whose lease release failed; retried
}

// selfNode is this node's name in the fabric intent (the cluster node name).
func (s *Service) selfNode() string {
	if s.role != nil {
		return s.role.SelfName()
	}
	if s.cfg != nil && s.cfg.Cluster.NodeName != "" {
		return s.cfg.Cluster.NodeName
	}
	h, _ := os.Hostname()
	return h
}

func (s *Service) fabricRT() *fabricRT {
	s.fab.once.Do(func() {
		s.fab.kick = make(chan struct{}, 1)
		s.fab.release = map[string]int64{}
		s.fab.mem = &fabric.Member{
			Store:   fabricDB{s},
			Check:   s.fabricCheck,
			Applied: func(fabric.Intent) { s.KickFabric() },
		}
		s.fab.coord = &fabric.Coordinator{
			Self:  s.selfNode(),
			Local: s.fab.mem,
			Net:   fabricPeers{s},
			Alive: s.fabricAlive,
		}
	})
	return &s.fab
}

// fabricIntent is this node's current intent.
func (s *Service) fabricIntent() (fabric.Intent, error) { return s.fabricRT().mem.Current() }

// fabricChange commits a change on every member. exclude names an evicted host.
func (s *Service) fabricChange(exclude []string, mutate func(*fabric.Intent) error) (fabric.Intent, error) {
	in, lagging, err := s.fabricRT().coord.Change(exclude, mutate)
	if err != nil {
		return fabric.Intent{}, err
	}
	if len(lagging) > 0 {
		log.Printf("fabric: version %d committed; %s missed the commit and will catch up on its next sync", in.Version, strings.Join(lagging, ", "))
	}
	return in, nil
}

// fabricAlive lists the cluster nodes reachable right now.
func (s *Service) fabricAlive() map[string]bool {
	if s.role == nil {
		return map[string]bool{}
	}
	out := map[string]bool{}
	for _, p := range s.role.Peers() {
		out[p.Name] = p.Alive && (p.Self || p.ClusterAddr != "")
	}
	return out
}

// fabricSecret is a fabric's BGP MD5 password: derived on each node from the
// shared cluster key, so it is identical everywhere and never replicated.
func (s *Service) fabricSecret(fabricUUID string) string {
	key, err := s.adKey()
	if err != nil || len(key) == 0 {
		return ""
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("vxvisor-fabric-bgp-md5/" + fabricUUID))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// fabricRouting is this node's fabric section for the host FRR config (nil when
// it isn't in a fabric). BFD rides only when bfdd runs.
func (s *Service) fabricRouting() *routing.Fabric {
	in, err := s.fabricIntent()
	if err != nil {
		log.Printf("fabric: read intent: %v", err)
		return nil
	}
	f, _ := in.HostOf(s.selfNode())
	if f == nil {
		return nil
	}
	r := in.Routing(s.selfNode(), s.fabricSecret(f.UUID))
	r.BFD = bfddRunning()
	return r
}

func bfddRunning() bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil && strings.TrimSpace(string(b)) == "bfdd" {
			if cmd, _ := os.ReadFile("/proc/" + e.Name() + "/cmdline"); !strings.Contains(string(cmd), "\x00-N\x00") {
				return true // the host's own bfdd, not a netns vRouter's
			}
		}
	}
	return false
}

// ---- persistence -------------------------------------------------------------

type fabricDB struct{ s *Service }

func (f fabricDB) Load() (fabric.Intent, error) {
	var v int64
	var body string
	if err := f.s.db.QueryRow(`SELECT version, body FROM fabric_intent WHERE id=1`).Scan(&v, &body); err != nil {
		return fabric.Intent{}, fmt.Errorf("read fabric intent: %w", err)
	}
	var in fabric.Intent
	if err := json.Unmarshal([]byte(body), &in); err != nil {
		return fabric.Intent{}, fmt.Errorf("fabric intent is unreadable: %w", err)
	}
	in.Version = v
	return in, nil
}

func (f fabricDB) Save(base int64, next fabric.Intent) error {
	body, err := json.Marshal(next)
	if err != nil {
		return err
	}
	res, err := f.s.db.Exec(`UPDATE fabric_intent SET version=?, body=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
		WHERE id=1 AND version=?`, next.Version, string(body), base)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fabric.StaleError{Base: base}
	}
	return nil
}

// ---- transport over the signed peer API --------------------------------------

type fabricPeers struct{ s *Service }

func (t fabricPeers) base(node string) (string, error) {
	if t.s.role == nil || t.s.peerc == nil {
		return "", fmt.Errorf("this node isn't in a cluster")
	}
	for _, p := range t.s.role.Peers() {
		if p.Name == node && p.ClusterAddr != "" {
			if !p.Alive {
				return "", fmt.Errorf("%s is down", node)
			}
			return peer.BaseURL(p.ClusterAddr, peer.APIPort), nil
		}
	}
	return "", fmt.Errorf("%s isn't a cluster member", node)
}

// peerErr turns a peer reply into an error carrying the peer's own message.
func peerErr(node string, body []byte, code int, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", node, err)
	}
	if code == 200 {
		return nil
	}
	if code == 404 {
		return fmt.Errorf("%s runs an older VXVisor without the fabric — update every node first", node)
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	return fmt.Errorf("%s answered %d", node, code)
}

func (t fabricPeers) Fetch(node string) (fabric.Intent, error) {
	base, err := t.base(node)
	if err != nil {
		return fabric.Intent{}, err
	}
	body, code, err := t.s.peerc.Get(base, "/cluster/v1/fabric/intent")
	if err := peerErr(node, body, code, err); err != nil {
		return fabric.Intent{}, err
	}
	var in fabric.Intent
	if err := json.Unmarshal(body, &in); err != nil {
		return fabric.Intent{}, fmt.Errorf("%s: unreadable fabric intent: %w", node, err)
	}
	return in, nil
}

func (t fabricPeers) Prepare(node string, p fabric.Proposal) error {
	base, err := t.base(node)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	body, code, err := t.s.peerc.PostBody(base, "/cluster/v1/fabric/prepare", raw)
	return peerErr(node, body, code, err)
}

func (t fabricPeers) Commit(node, id string) error {
	base, err := t.base(node)
	if err != nil {
		return err
	}
	body, code, err := t.s.peerc.Post(base, "/cluster/v1/fabric/commit?id="+id)
	return peerErr(node, body, code, err)
}

func (t fabricPeers) Abort(node, id string) {
	if base, err := t.base(node); err == nil {
		_, _, _ = t.s.peerc.Post(base, "/cluster/v1/fabric/abort?id="+id)
	}
}

// Peer API handlers (the web layer routes /cluster/v1/fabric/* here).

// FabricPeerIntent returns this node's intent for a peer's sync.
func (s *Service) FabricPeerIntent() (fabric.Intent, error) { return s.fabricIntent() }

// FabricPeerPrepare holds a proposal from a coordinating peer.
func (s *Service) FabricPeerPrepare(p fabric.Proposal) error { return s.fabricRT().mem.Prepare(p) }

// FabricPeerCommit applies the held proposal id.
func (s *Service) FabricPeerCommit(id string) error { return s.fabricRT().mem.Commit(id) }

// FabricPeerAbort drops the held proposal id.
func (s *Service) FabricPeerAbort(id string) { s.fabricRT().mem.Abort(id) }

// SyncFabric adopts the newest intent among the reachable fabric members (the
// worker runs it periodically; a node that missed a commit catches up here).
func (s *Service) SyncFabric() {
	rt := s.fabricRT()
	in, err := rt.mem.Current()
	if err != nil || s.role == nil {
		return
	}
	alive := s.fabricAlive()
	for _, n := range in.Nodes() {
		if n == s.selfNode() || !alive[n] {
			continue
		}
		if other, err := (fabricPeers{s}).Fetch(n); err == nil {
			if _, err := rt.mem.Adopt(other); err != nil {
				log.Printf("fabric: sync from %s: %v", n, err)
			}
		}
	}
}

// ---- the node-local veto -------------------------------------------------------

// fabricCheck is this node's veto on a proposed intent: what only this node can
// know (its interfaces, its legacy VXLANs, its instances).
func (s *Service) fabricCheck(cur, next fabric.Intent) error {
	self := s.selfNode()
	nf, nh := next.HostOf(self)
	cf, ch := cur.HostOf(self)
	if nh != nil && (ch == nil || cf.UUID != nf.UUID || *ch != *nh) {
		if err := s.checkUnderlay(nf, *nh); err != nil {
			return fmt.Errorf("%s: %w", self, err)
		}
	}
	if nh != nil {
		hc := s.loadHostRouting()
		hc.Fabric = next.Routing(self, "x")
		if err := hc.Validate(); err != nil {
			return fmt.Errorf("%s: this host's routing (Routing page) conflicts with the fabric: %w", self, err)
		}
		legacy := s.legacyVNIs()
		plan, _ := next.HostPlan(self)
		for _, sg := range plan.Segments {
			if what, ok := legacy[sg.VNI]; ok {
				return fmt.Errorf("%s: VNI %d is already used by %s on this host", self, sg.VNI, what)
			}
		}
		for _, v := range plan.VRFs {
			if what, ok := legacy[v.L3VNI]; ok {
				return fmt.Errorf("%s: VNI %d is already used by %s on this host", self, v.L3VNI, what)
			}
		}
	}
	// Port groups leaving this node must have nothing attached here.
	for _, pg := range cur.PGs {
		if !cur.Spans(pg, self) {
			continue
		}
		if np := next.PG(pg.UUID); np != nil && next.Spans(*np, self) {
			continue
		}
		if n, ok := s.fabricNetwork(pg.UUID); ok {
			if err := s.fabricPGInUse(n); err != nil {
				return fmt.Errorf("%s: %w", self, err)
			}
		}
	}
	return nil
}

// legacyVNIs maps the VNIs this host's own VXLAN networks and storage overlays
// use to what uses them.
func (s *Service) legacyVNIs() map[int]string {
	out := map[int]string{}
	for _, q := range []struct{ sql, what string }{
		{`SELECT vni, name FROM networks WHERE mode='vxlan' AND vni>0`, "VXLAN network"},
		{`SELECT vni, name FROM storage_overlays WHERE vni>0`, "storage overlay"},
	} {
		rows, err := s.db.Query(q.sql)
		if err != nil {
			continue
		}
		for rows.Next() {
			var v int
			var n string
			if rows.Scan(&v, &n) == nil {
				out[v] = q.what + " " + n
			}
		}
		rows.Close()
	}
	return out
}

// checkUnderlay refuses an underlay interface that can't carry this node's TEP:
// management or any other role, a stacked/enslaved NIC, a TEP subnet that
// overlaps something already on the host, too small an MTU.
func (s *Service) checkUnderlay(f *fabric.Spec, h fabric.Host) error {
	if !netdrv.IfaceExists(h.Iface) {
		return fmt.Errorf("interface %s doesn't exist on this host", h.Iface)
	}
	if h.VLAN == 0 {
		if err := s.guardIfaceInUse(h.Iface, "fabric underlay"); err != nil {
			return err
		}
		if mtu := netdrv.LinkMTU(h.Iface); mtu > 0 && mtu < f.MTU && !raisableMTU(h.Iface, f.MTU) {
			return fmt.Errorf("interface %s can't take MTU %d", h.Iface, f.MTU)
		}
	} else {
		if err := s.guardIfaceRoles(h.Iface, "fabric underlay"); err != nil {
			return err
		}
		if m, err := os.Readlink("/sys/class/net/" + h.Iface + "/master"); err == nil {
			return fmt.Errorf("interface %s is enslaved to %s — a fabric VLAN needs a NIC or bond that isn't in a vSwitch", h.Iface, m[strings.LastIndex(m, "/")+1:])
		}
		if netdrv.IfaceExists(h.UnderlayDev()) {
			return fmt.Errorf("%s already exists on this host", h.UnderlayDev())
		}
		if mtu := netdrv.LinkMTU(h.Iface); mtu < f.MTU {
			return fmt.Errorf("interface %s has MTU %d; the fabric needs %d on its VLAN — raise %s's MTU or lower the fabric's (the parent is never changed)", h.Iface, mtu, f.MTU, h.Iface)
		}
	}
	tep, tnet, _ := net.ParseCIDR(h.TEP)
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	for _, it := range ifs {
		for _, a := range it.Addrs {
			ip, n, err := net.ParseCIDR(a)
			if err != nil || ip.To4() == nil {
				continue
			}
			if ip.Equal(tep) {
				return fmt.Errorf("TEP %s is already on %s", tep, it.Name)
			}
			if n.Contains(tnet.IP) || tnet.Contains(n.IP) {
				return fmt.Errorf("TEP subnet %s overlaps %s on %s — use a dedicated subnet for the fabric", tnet, n, it.Name)
			}
		}
	}
	if !routing.FRRAvailable() {
		return fmt.Errorf("FRR isn't installed — re-run deploy/install.sh")
	}
	return nil
}

// raisableMTU reports whether a NIC accepts mtu (its max_mtu, where known).
func raisableMTU(iface string, mtu int) bool {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/max_mtu")
	if err != nil {
		return true // unknown: try it at realize time
	}
	max, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err != nil || max >= mtu
}

// ---- local port group rows ------------------------------------------------------

// fabricNetwork returns the local networks row of a fabric port group.
func (s *Service) fabricNetwork(pgUUID string) (netdrv.Network, bool) {
	var id, org int64
	if s.db.QueryRow(`SELECT f.network_id, n.org_id FROM fabric_pg_networks f JOIN networks n ON n.id=f.network_id
		WHERE f.pg_uuid=?`, pgUUID).Scan(&id, &org) != nil {
		return netdrv.Network{}, false
	}
	n, err := s.net.GetNetwork(org, id)
	return n, err == nil
}

// fabricPGOf maps a local networks row to its fabric port group ("" if none).
func (s *Service) fabricPGOf(networkID int64) string {
	var u string
	_ = s.db.QueryRow(`SELECT pg_uuid FROM fabric_pg_networks WHERE network_id=?`, networkID).Scan(&u)
	return u
}

// fabricPGInUse is portGroupInUse for a fabric port group's local row (the row
// itself belongs to the fabric, which portGroupInUse refuses on its own).
func (s *Service) fabricPGInUse(n netdrv.Network) error {
	if vms := s.queryNames(instancesOnNetwork+`s.network_id=? ORDER BY s.name`, n.ID); len(vms) > 0 {
		return fmt.Errorf("%d instance(s) use fabric port group %q here (%s) — move them to another port group (or purge them from Trash) first", len(vms), n.Name, nameList(vms))
	}
	if r := s.queryNames(`SELECT r.name FROM vrouter_legs l JOIN vrouters r ON r.id=l.vrouter_id WHERE l.network_id=? ORDER BY r.name`, n.ID); len(r) > 0 {
		return fmt.Errorf("vRouter %q has a leg on fabric port group %q — detach it first", r[0], n.Name)
	}
	if cts := s.queryNames(`SELECT name FROM containers WHERE bridge=? ORDER BY name`, n.Bridge); len(cts) > 0 {
		return fmt.Errorf("container(s) %s are on fabric port group %q — move them first", nameList(cts), n.Name)
	}
	return nil
}

// ---- fabric-wide leases (session.FabricIPAM) -------------------------------------

type fabricIPAM struct{ s *Service }

// FabricIPAM is the session manager's allocator for fabric port groups.
func (s *Service) FabricIPAM() fabricIPAM { return fabricIPAM{s} }

func (f fabricIPAM) Lease(netID int64, sessionID, mac string) (string, error) {
	uuid := f.s.fabricPGOf(netID)
	if uuid == "" {
		return "", fmt.Errorf("this port group isn't on a fabric any more")
	}
	in, err := f.s.fabricIntent()
	if err != nil {
		return "", err
	}
	pg := in.PG(uuid)
	if pg == nil {
		return "", fmt.Errorf("this fabric port group was deleted")
	}
	prefix := pg.GatewayCIDR()[strings.Index(pg.GatewayCIDR(), "/"):]
	for _, l := range in.Leases {
		if l.PG == uuid && l.Session == sessionID {
			return l.IP + prefix, nil
		}
	}
	var got fabric.Lease
	if _, err := f.s.fabricChange(nil, func(in *fabric.Intent) error {
		l, err := in.AllocLease(uuid, sessionID, mac)
		got = l
		return err
	}); err != nil {
		return "", fmt.Errorf("allocate a fabric address: %w", err)
	}
	return got.IP + prefix, nil
}

func (f fabricIPAM) Release(sessionID string) { f.ReleaseOn(sessionID, 0) }

func (f fabricIPAM) ReleaseOn(sessionID string, netID int64) {
	if err := f.s.releaseFabricLease(sessionID, netID); err != nil {
		log.Printf("fabric: release lease of %s: %v (retrying in the background)", sessionID, err)
		rt := f.s.fabricRT()
		rt.relMu.Lock()
		rt.release[sessionID] = netID
		rt.relMu.Unlock()
	}
}

func (s *Service) releaseFabricLease(sessionID string, netID int64) error {
	in, err := s.fabricIntent()
	if err != nil {
		return err
	}
	only := ""
	if netID > 0 {
		if only = s.fabricPGOf(netID); only == "" {
			return nil
		}
	}
	held := false
	for _, l := range in.Leases {
		held = held || (l.Session == sessionID && (only == "" || l.PG == only))
	}
	if !held {
		return nil
	}
	_, err = s.fabricChange(nil, func(in *fabric.Intent) error {
		keep := in.Leases[:0]
		for _, l := range in.Leases {
			if l.Session != sessionID || (only != "" && l.PG != only) {
				keep = append(keep, l)
			}
		}
		in.Leases = keep
		return nil
	})
	return err
}

// retryFabricReleases re-tries lease releases that failed (a member was down).
func (s *Service) retryFabricReleases() {
	rt := s.fabricRT()
	rt.relMu.Lock()
	todo := rt.release
	rt.release = map[string]int64{}
	rt.relMu.Unlock()
	for sid, nid := range todo {
		fabricIPAM{s}.ReleaseOn(sid, nid)
	}
}
