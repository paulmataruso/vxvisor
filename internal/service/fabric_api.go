package service

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/fabric"
	"vdxclone/internal/hostinfo"
	"vdxclone/internal/lldp"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/routing"
)

// The VXVisor Fabric API: the deploy wizard and the admin's physical layer, and
// the org-level port groups, connectivity rules and egress. Every change goes
// through fabricChange (unanimous commit); every mutation is audited.

// FabricHostInput is one host of the deploy wizard.
type FabricHostInput struct {
	Node  string
	Iface string
	VLAN  int
	TEP   string // "10.250.0.1/24"
}

// FabricInput is the deploy wizard's form.
type FabricInput struct {
	Name  string
	ASN   int // 0 = the hosts' BGP AS if they run one, else 65100
	MTU   int // underlay MTU; 0 = 1550 (guests keep 1500)
	Orgs  []int64
	Hosts []FabricHostInput
}

// FabricCheck is one preflight / verification result.
type FabricCheck struct {
	Node   string `json:"node"`
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"` // advisory: never blocks
	Detail string `json:"detail,omitempty"`
}

// FabricChecksFailed reports whether any blocking check failed.
func FabricChecksFailed(cs []FabricCheck) bool {
	for _, c := range cs {
		if !c.OK && !c.Warn {
			return true
		}
	}
	return false
}

func checksError(what string, cs []FabricCheck) error {
	var bad []string
	for _, c := range cs {
		if !c.OK && !c.Warn {
			bad = append(bad, c.Node+": "+c.Check+" — "+c.Detail)
		}
	}
	return fmt.Errorf("%s: %s", what, strings.Join(bad, "; "))
}

// ---- views ---------------------------------------------------------------------

// FabricView is what the Fabric pages show: the intent filtered to what the
// caller may see, plus what they may do.
type FabricView struct {
	Intent   fabric.Intent
	Self     string
	Admin    bool            // may manage fabrics and hosts
	Build    map[string]bool // fabric UUID → may create port groups / rules
	OrgID    int64
	Nodes    []string              // cluster nodes the wizard can add (admin)
	Networks map[string]int64      // fabric PG UUID → this node's networks row
	Leases   map[string]int        // PG UUID → leases on it
	Egress   map[string]string     // fabric UUID → the caller org's egress
	VRF      map[string]fabric.VRF // fabric UUID → the caller org's VRF
}

// GetFabricView returns the Fabric pages' data for p.
func (s *Service) GetFabricView(p *Principal) (FabricView, error) {
	if !p.atLeast("viewer") {
		return FabricView{}, ErrUnauthorized
	}
	in, err := s.fabricIntent()
	if err != nil {
		return FabricView{}, err
	}
	v := FabricView{Self: s.selfNode(), Admin: p.IsAdmin, Build: map[string]bool{}, OrgID: p.OrgID,
		Networks: map[string]int64{}, Leases: map[string]int{}, Egress: map[string]string{}, VRF: map[string]fabric.VRF{}}
	if !p.IsAdmin {
		in = filterIntent(in, p.OrgID)
	}
	for _, f := range in.Fabrics {
		v.Build[f.UUID] = s.canBuild(p, &f)
	}
	for _, pg := range in.PGs {
		if n, ok := s.fabricNetwork(pg.UUID); ok {
			v.Networks[pg.UUID] = n.ID
		}
	}
	for _, l := range in.Leases {
		v.Leases[l.PG]++
	}
	for _, vr := range in.VRFs {
		if vr.Org == p.OrgID {
			v.Egress[vr.Fabric] = vr.Egress
			v.VRF[vr.Fabric] = vr
		}
	}
	v.Intent = in
	if p.IsAdmin {
		v.Nodes = s.clusterNodeNames()
	}
	return v, nil
}

// filterIntent keeps what an org may see: fabrics open to it or carrying its
// port groups (host names only — never interfaces or TEPs), and its own port
// groups, VRF, leases and rules.
func filterIntent(in fabric.Intent, org int64) fabric.Intent {
	out := fabric.Intent{Version: in.Version}
	mine := map[string]bool{}
	for _, pg := range in.PGs {
		if pg.Org == org {
			out.PGs = append(out.PGs, pg)
			mine[pg.UUID] = true
		}
	}
	for _, f := range in.Fabrics {
		on := slices.Contains(f.Orgs, org)
		for _, pg := range out.PGs {
			on = on || pg.Fabric == f.UUID
		}
		if !on {
			continue
		}
		g := fabric.Spec{UUID: f.UUID, Name: f.Name, MTU: f.MTU}
		for _, h := range f.Hosts {
			g.Hosts = append(g.Hosts, fabric.Host{Node: h.Node})
		}
		out.Fabrics = append(out.Fabrics, g)
	}
	for _, v := range in.VRFs {
		if v.Org == org {
			out.VRFs = append(out.VRFs, v)
		}
	}
	for _, l := range in.Leases {
		if mine[l.PG] {
			out.Leases = append(out.Leases, l)
		}
	}
	for _, r := range in.Rules {
		if r.Org == org {
			out.Rules = append(out.Rules, r)
		}
	}
	return out
}

// canBuild: instance admins anywhere; an org admin on a fabric opened to its org.
func (s *Service) canBuild(p *Principal, f *fabric.Spec) bool {
	if p.IsAdmin || p.ProviderAdmin {
		return true
	}
	return p.OrgAdmin() && slices.Contains(f.Orgs, p.OrgID)
}

// clusterNodeNames lists this node and every alive peer.
func (s *Service) clusterNodeNames() []string {
	out := []string{s.selfNode()}
	if s.role != nil {
		for _, p := range s.role.Peers() {
			if !p.Self && p.Alive {
				out = append(out, p.Name)
			}
		}
	}
	sort.Strings(out[1:])
	return out
}

// ---- preflight / verification -------------------------------------------------

// fabricPreflightReq is the peer API's preflight request.
type fabricPreflightReq struct {
	Fabric fabric.Spec `json:"fabric"`
	Host   fabric.Host `json:"host"`
}

// FabricLocalPreflight checks that host h can join fabric f on THIS node.
func (s *Service) FabricLocalPreflight(f fabric.Spec, h fabric.Host) []FabricCheck {
	self := s.selfNode()
	var out []FabricCheck
	add := func(check string, err error, warn bool, okDetail string) {
		c := FabricCheck{Node: self, Check: check, OK: err == nil, Detail: okDetail}
		if err != nil {
			c.Detail, c.Warn = err.Error(), warn
		}
		out = append(out, c)
	}
	add("FRR", func() error {
		if !routing.FRRAvailable() {
			return fmt.Errorf("FRR isn't installed — re-run deploy/install.sh")
		}
		if exec.Command("pgrep", "-x", "bgpd").Run() != nil {
			return fmt.Errorf("bgpd isn't running — enable it in /etc/frr/daemons (install.sh does) and restart FRR")
		}
		return nil
	}(), false, frrVersion())
	add("BFD", func() error {
		if !bfddRunning() {
			return fmt.Errorf("bfdd isn't running: the fabric works without it but BFD stays off until FRR restarts with bfdd enabled (install.sh enables it)")
		}
		return nil
	}(), true, "bfdd running")
	add("kernel", func() error {
		if out, err := exec.Command("modprobe", "-a", "vrf", "vxlan").CombinedOutput(); err != nil {
			return fmt.Errorf("can't load the vrf/vxlan modules: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}(), false, "vrf + vxlan modules")
	add("dnsmasq", func() error {
		_, err := exec.LookPath("dnsmasq")
		return err
	}(), false, "present")
	add("underlay "+h.UnderlayDev(), s.checkUnderlay(&f, h), false, "TEP "+h.TEP+", MTU "+strconv.Itoa(f.MTU))
	add("host routing", func() error {
		hc := s.loadHostRouting()
		hc.Fabric = &routing.Fabric{ASN: f.ASN, TEP: h.TEPIP(), BFD: true}
		return hc.Validate()
	}(), false, "composes with this host's /routing config")
	return out
}

func frrVersion() string {
	out, err := exec.Command("vtysh", "-c", "show version").Output()
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(first)
}

// preflight runs FabricLocalPreflight on each host (locally or over the peer API).
func (s *Service) preflight(f fabric.Spec, hosts []fabric.Host) []FabricCheck {
	var out []FabricCheck
	for _, h := range hosts {
		if h.Node == s.selfNode() {
			out = append(out, s.FabricLocalPreflight(f, h)...)
			continue
		}
		var got []FabricCheck
		err := s.peerJSON(h.Node, "/cluster/v1/fabric/preflight", fabricPreflightReq{Fabric: f, Host: h}, &got)
		if err != nil {
			out = append(out, FabricCheck{Node: h.Node, Check: "reachable", Detail: err.Error()})
			continue
		}
		out = append(out, got...)
	}
	return out
}

// peerJSON posts req to node's peer API and decodes the reply into out.
func (s *Service) peerJSON(node, path string, req, out any) error {
	base, err := (fabricPeers{s}).base(node)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	body, code, err := s.peerc.PostBody(base, path, raw)
	if err := peerErr(node, body, code, err); err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// fabricDFPingReq asks a node to DF-ping TEPs at the fabric's full size.
type fabricDFPingReq struct {
	Fabric string   `json:"fabric"`
	TEPs   []string `json:"teps"`
}

// FabricLocalDFPing pings each TEP from this node's TEP with DF set at the
// fabric's underlay MTU: proves both reachability and that the path carries
// full-size overlay frames.
func (s *Service) FabricLocalDFPing(fabricUUID string, teps []string) []FabricCheck {
	self := s.selfNode()
	in, err := s.fabricIntent()
	if err != nil {
		return []FabricCheck{{Node: self, Check: "DF ping", Detail: err.Error()}}
	}
	f, h := in.HostOf(self)
	if f == nil || f.UUID != fabricUUID {
		return []FabricCheck{{Node: self, Check: "DF ping", Detail: "this host isn't in that fabric (yet)"}}
	}
	var out []FabricCheck
	for _, t := range teps {
		if net.ParseIP(t) == nil {
			continue
		}
		c := FabricCheck{Node: self, Check: "DF ping → " + t}
		// payload = MTU - 20 (IP) - 8 (ICMP)
		res, err := exec.Command("ping", "-M", "do", "-s", strconv.Itoa(f.MTU-28), "-c", "3", "-i", "0.2", "-W", "1",
			"-I", h.UnderlayDev(), t).CombinedOutput()
		if err != nil {
			c.Detail = "no reply at " + strconv.Itoa(f.MTU) + " bytes with DF: check the cabling/VLAN and that every switch port allows MTU " + strconv.Itoa(f.MTU)
			if strings.Contains(string(res), "message too long") || strings.Contains(string(res), "Frag needed") {
				c.Detail = "the path's MTU is below " + strconv.Itoa(f.MTU)
			}
		} else {
			c.OK, c.Detail = true, strconv.Itoa(f.MTU)+" bytes, DF"
		}
		out = append(out, c)
	}
	return out
}

// verifyFabric waits until every host realized version v (or reports an error)
// and runs the DF-ping matrix between their TEPs.
func (s *Service) verifyFabric(f fabric.Spec, v int64) []FabricCheck {
	var out []FabricCheck
	deadline := time.Now().Add(90 * time.Second)
	for _, h := range f.Hosts {
		c := FabricCheck{Node: h.Node, Check: "realized"}
		for {
			st, err := s.nodeFabricStatus(h.Node)
			if err == nil && st.Version >= v && st.State == "error" {
				c.Detail = st.Error
				break
			}
			if err == nil && st.Version >= v && st.State == "ok" {
				c.OK, c.Detail = true, "fabric version "+strconv.FormatInt(st.Version, 10)
				break
			}
			if time.Now().After(deadline) {
				c.Detail = "didn't finish realizing the fabric within 90 s"
				if err != nil {
					c.Detail += " (" + err.Error() + ")"
				}
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		out = append(out, c)
	}
	if FabricChecksFailed(out) {
		return out
	}
	for _, h := range f.Hosts {
		var teps []string
		for _, o := range f.Hosts {
			if o.Node != h.Node {
				teps = append(teps, o.TEPIP())
			}
		}
		if len(teps) == 0 {
			continue
		}
		if h.Node == s.selfNode() {
			out = append(out, s.FabricLocalDFPing(f.UUID, teps)...)
			continue
		}
		var got []FabricCheck
		if err := s.peerJSON(h.Node, "/cluster/v1/fabric/dfping", fabricDFPingReq{Fabric: f.UUID, TEPs: teps}, &got); err != nil {
			out = append(out, FabricCheck{Node: h.Node, Check: "DF ping", Detail: err.Error()})
			continue
		}
		out = append(out, got...)
	}
	return out
}

// ---- status / health ---------------------------------------------------------------

// FabricNodeStatus is one node's realized fabric state.
type FabricNodeStatus struct {
	Node     string          `json:"node"`
	Version  int64           `json:"version"`  // intent version this node holds
	Realized int64           `json:"realized"` // version its last reconcile applied
	State    string          `json:"state"`    // ok | error | "" (not a member)
	Error    string          `json:"error,omitempty"`
	TEP      string          `json:"tep,omitempty"`
	Underlay string          `json:"underlay,omitempty"`
	BFD      bool            `json:"bfd"`
	BGP      []FabricBGPPeer `json:"bgp,omitempty"`
	VNIs     []FabricVNI     `json:"vnis,omitempty"`
	DupAddrs []string        `json:"dup,omitempty"`
	Drops    int64           `json:"drops"` // VXLAN packets dropped by the ingress guard
}

// FabricBGPPeer is one EVPN session.
type FabricBGPPeer struct {
	Peer     string `json:"peer"`
	State    string `json:"state"`
	Uptime   string `json:"uptime"`
	Prefixes int    `json:"pfx"`
}

// FabricVNI is one VNI as zebra sees it.
type FabricVNI struct {
	VNI     int    `json:"vni"`
	Type    string `json:"type"`
	VRF     string `json:"vrf"`
	MACs    int    `json:"macs"`
	ARPs    int    `json:"arps"`
	Remotes int    `json:"remotes"`
}

// FabricLocalStatus reads this node's realized state from the kernel and FRR.
func (s *Service) FabricLocalStatus() FabricNodeStatus {
	st := FabricNodeStatus{Node: s.selfNode()}
	in, err := s.fabricIntent()
	if err != nil {
		st.State, st.Error = "error", err.Error()
		return st
	}
	st.Version = in.Version
	f, h := in.HostOf(st.Node)
	if f == nil {
		return st
	}
	st.TEP, st.Underlay, st.BFD = h.TEP, h.UnderlayDev(), bfddRunning()
	var state, msg string
	if s.db.QueryRow(`SELECT state, error FROM fabric_underlay WHERE fabric_uuid=?`, f.UUID).Scan(&state, &msg) == nil {
		st.State, st.Error = state, msg
		if at := strings.Index(state, "@"); at > 0 {
			st.State = state[:at]
			st.Realized, _ = strconv.ParseInt(state[at+1:], 10, 64)
		}
	}
	if st.Realized < st.Version && st.State == "ok" {
		st.State = "" // the current version isn't realized yet
	}
	st.BGP = evpnPeers()
	st.VNIs = evpnVNIs()
	st.DupAddrs = evpnDups()
	st.Drops = vxlanDrops()
	return st
}

// nodeFabricStatus is FabricLocalStatus of any node.
func (s *Service) nodeFabricStatus(node string) (FabricNodeStatus, error) {
	if node == s.selfNode() {
		st := s.FabricLocalStatus()
		if st.Realized >= st.Version && st.State != "" {
			return st, nil
		}
		st.Version = st.Realized // waiting
		return st, nil
	}
	base, err := (fabricPeers{s}).base(node)
	if err != nil {
		return FabricNodeStatus{}, err
	}
	body, code, err := s.peerc.Get(base, "/cluster/v1/fabric/status")
	if err := peerErr(node, body, code, err); err != nil {
		return FabricNodeStatus{}, err
	}
	var st FabricNodeStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return st, err
	}
	if st.Realized < st.Version {
		st.Version = st.Realized
	}
	return st, nil
}

// FabricHealth is every fabric member's status (instance admin).
func (s *Service) FabricHealth(p *Principal) ([]FabricNodeStatus, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	in, err := s.fabricIntent()
	if err != nil {
		return nil, err
	}
	var out []FabricNodeStatus
	for _, n := range in.Nodes() {
		if n == s.selfNode() {
			out = append(out, s.FabricLocalStatus())
			continue
		}
		base, err := (fabricPeers{s}).base(n)
		if err != nil {
			out = append(out, FabricNodeStatus{Node: n, State: "unreachable", Error: err.Error()})
			continue
		}
		body, code, err := s.peerc.Get(base, "/cluster/v1/fabric/status")
		var st FabricNodeStatus
		if perr := peerErr(n, body, code, err); perr != nil || json.Unmarshal(body, &st) != nil {
			st = FabricNodeStatus{Node: n, State: "unreachable"}
			if perr != nil {
				st.Error = perr.Error()
			}
		}
		out = append(out, st)
	}
	return out, nil
}

func vtyshJSON(cmd string, out any) bool {
	b, err := exec.Command("vtysh", "-c", cmd).Output()
	return err == nil && json.Unmarshal(b, out) == nil
}

func evpnPeers() []FabricBGPPeer {
	var sum struct {
		Peers map[string]struct {
			State          string `json:"state"`
			PeerUptime     string `json:"peerUptime"`
			PfxRcd         int    `json:"pfxRcd"`
			PrefixReceived int    `json:"prefixReceivedCount"`
		} `json:"peers"`
	}
	if !vtyshJSON("show bgp l2vpn evpn summary json", &sum) {
		return nil
	}
	var out []FabricBGPPeer
	for ip, p := range sum.Peers {
		n := p.PfxRcd
		if n == 0 {
			n = p.PrefixReceived
		}
		out = append(out, FabricBGPPeer{Peer: ip, State: p.State, Uptime: p.PeerUptime, Prefixes: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Peer < out[j].Peer })
	return out
}

func evpnVNIs() []FabricVNI {
	var raw map[string]struct {
		VNI        int    `json:"vni"`
		Type       string `json:"type"`
		TenantVrf  string `json:"tenantVrf"`
		NumMacs    int    `json:"numMacs"`
		NumArpNd   int    `json:"numArpNd"`
		NumRemote  int    `json:"numRemoteVteps"`
		NumRemoteS any    `json:"numRemoteVtepsStr"`
	}
	if !vtyshJSON("show evpn vni json", &raw) {
		return nil
	}
	var out []FabricVNI
	for _, v := range raw {
		out = append(out, FabricVNI{VNI: v.VNI, Type: v.Type, VRF: v.TenantVrf, MACs: v.NumMacs, ARPs: v.NumArpNd, Remotes: v.NumRemote})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VNI < out[j].VNI })
	return out
}

func evpnDups() []string {
	b, err := exec.Command("vtysh", "-c", "show evpn mac vni all duplicate").Output()
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 0 {
			if _, err := net.ParseMAC(f[0]); err == nil {
				out = append(out, strings.TrimSpace(l))
			}
		}
	}
	return out
}

// vxlanDrops reads the ingress guard's drop counters on the fabric's port.
func vxlanDrops() int64 {
	b, err := exec.Command("nft", "list", "table", "inet", "vdxvxlan").Output()
	if err != nil {
		return 0
	}
	var n int64
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.Contains(l, "udp dport 4789 counter packets") || !strings.HasSuffix(strings.TrimSpace(l), "drop") {
			continue
		}
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "packets" {
				v, _ := strconv.ParseInt(f[i+1], 10, 64)
				n += v
			}
		}
	}
	return n
}

// ---- fabrics + hosts (instance admin) -----------------------------------------

// hostASN is this host's /routing BGP AS (0 = none).
func (s *Service) hostASN() int {
	if c := s.loadHostRouting(); c.BGP.Enabled {
		return c.BGP.ASN
	}
	return 0
}

func hostsFromInput(hs []FabricHostInput) []fabric.Host {
	var out []fabric.Host
	for _, h := range hs {
		out = append(out, fabric.Host{Node: strings.TrimSpace(h.Node), Iface: strings.TrimSpace(h.Iface), VLAN: h.VLAN, TEP: strings.TrimSpace(h.TEP)})
	}
	return out
}

// fabricSpecFrom builds a new fabric from the wizard's form (defaults filled)
// and checks it against the current intent.
func (s *Service) fabricSpecFrom(fi FabricInput) (fabric.Spec, error) {
	f := fabric.Spec{UUID: fabric.NewUUID(), Name: strings.TrimSpace(fi.Name), ASN: fi.ASN, MTU: fi.MTU, Orgs: fi.Orgs, Hosts: hostsFromInput(fi.Hosts)}
	if f.ASN == 0 {
		if f.ASN = s.hostASN(); f.ASN == 0 {
			f.ASN = 65100
		}
	}
	if f.MTU == 0 {
		f.MTU = 1550
	}
	if len(f.Hosts) == 0 {
		return f, fmt.Errorf("pick at least one host")
	}
	cur, err := s.fabricIntent()
	if err != nil {
		return f, err
	}
	trial := cur.Clone()
	trial.Fabrics = append(trial.Fabrics, f)
	return f, trial.Validate()
}

// PreflightFabric runs the deploy wizard's checks without changing anything.
func (s *Service) PreflightFabric(p *Principal, fi FabricInput) ([]FabricCheck, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	f, err := s.fabricSpecFrom(fi)
	if err != nil {
		return nil, err
	}
	return s.preflight(f, f.Hosts), nil
}

// FabricNIC is an interface the wizard offers for a host's underlay.
type FabricNIC struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // physical | bond
	MTU      int    `json:"mtu"`
	Carrier  bool   `json:"carrier"`
	Speed    int    `json:"speed"`
	Free     bool   `json:"free"` // no addresses, nothing stacked: usable untagged
	Neighbor string `json:"nbr,omitempty"`
	Note     string `json:"note,omitempty"` // why it can only carry a VLAN, or nothing
}

// FabricLocalNICs lists this host's NICs and bonds with no other role.
func (s *Service) FabricLocalNICs() []FabricNIC {
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return nil
	}
	nbrs := lldp.Neighbors()
	var out []FabricNIC
	for _, it := range ifs {
		if (it.Type != "physical" && it.Type != "bond") || it.Master != "" {
			continue
		}
		if s.guardIfaceRoles(it.Name, "interface") != nil {
			continue
		}
		n := FabricNIC{Name: it.Name, Kind: it.Type, MTU: netdrv.LinkMTU(it.Name), Carrier: it.Carrier, Speed: it.SpeedMbps}
		if nb, ok := nbrs[it.Name]; ok {
			n.Neighbor = strings.TrimSpace(nb.SwitchName + " " + nb.PortID)
		}
		if err := s.guardIfaceInUse(it.Name, "interface"); err != nil {
			n.Note = "VLAN only: " + err.Error()
		} else {
			n.Free = true
		}
		out = append(out, n)
	}
	return out
}

// FabricNICChoices lists every cluster node's candidate NICs for the wizard.
func (s *Service) FabricNICChoices(p *Principal) map[string][]FabricNIC {
	out := map[string][]FabricNIC{}
	if !p.IsAdmin {
		return out
	}
	for _, n := range s.clusterNodeNames() {
		if n == s.selfNode() {
			out[n] = s.FabricLocalNICs()
			continue
		}
		base, err := (fabricPeers{s}).base(n)
		if err != nil {
			continue
		}
		body, code, err := s.peerc.Get(base, "/cluster/v1/fabric/nics")
		var nics []FabricNIC
		if peerErr(n, body, code, err) == nil && json.Unmarshal(body, &nics) == nil {
			out[n] = nics
		}
	}
	return out
}

// CreateFabric is the deploy wizard: preflight every host, commit the fabric,
// wait until every host realized it and its TEPs reach each other at full MTU
// with DF set — and undo the whole fabric if any of that fails.
func (s *Service) CreateFabric(p *Principal, fi FabricInput, ip string) (string, []FabricCheck, error) {
	if !p.IsAdmin {
		return "", nil, ErrUnauthorized
	}
	f, err := s.fabricSpecFrom(fi)
	if err != nil {
		return "", nil, err
	}
	checks := s.preflight(f, f.Hosts)
	if FabricChecksFailed(checks) {
		return "", checks, checksError("preflight failed", checks)
	}
	in, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		in.Fabrics = append(in.Fabrics, f)
		return nil
	})
	if err != nil {
		return "", checks, err
	}
	verify := s.verifyFabric(f, in.Version)
	checks = append(checks, verify...)
	if FabricChecksFailed(verify) {
		_, uerr := s.fabricChange(nil, func(in *fabric.Intent) error {
			in.Fabrics = slices.DeleteFunc(in.Fabrics, func(x fabric.Spec) bool { return x.UUID == f.UUID })
			return nil
		})
		err := checksError("the fabric didn't come up, so it was removed again", verify)
		if uerr != nil {
			err = fmt.Errorf("%v — and removing it failed too (%v); delete it on the Fabrics page", err, uerr)
		}
		s.audit(p, p.OrgID, "fabric.create.failed", "fabric", f.Name, ip, map[string]any{"error": err.Error()})
		return "", checks, err
	}
	s.audit(p, p.OrgID, "fabric.create", "fabric", f.Name, ip, map[string]any{"uuid": f.UUID, "asn": f.ASN, "mtu": f.MTU, "hosts": len(f.Hosts)})
	return f.UUID, checks, nil
}

// AddFabricHost adds a host (preflight, commit, verify; removed again on failure).
func (s *Service) AddFabricHost(p *Principal, fabricUUID string, hi FabricHostInput, ip string) ([]FabricCheck, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	cur, err := s.fabricIntent()
	if err != nil {
		return nil, err
	}
	f := cur.Fabric(fabricUUID)
	if f == nil {
		return nil, ErrNotFound
	}
	h := hostsFromInput([]FabricHostInput{hi})[0]
	trial := cur.Clone()
	trial.Fabric(fabricUUID).Hosts = append(trial.Fabric(fabricUUID).Hosts, h)
	if err := trial.Validate(); err != nil {
		return nil, err
	}
	checks := s.preflight(*f, []fabric.Host{h})
	if FabricChecksFailed(checks) {
		return checks, checksError("preflight failed", checks)
	}
	in, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		g := in.Fabric(fabricUUID)
		if g == nil {
			return ErrNotFound
		}
		g.Hosts = append(g.Hosts, h)
		return nil
	})
	if err != nil {
		return checks, err
	}
	verify := s.verifyFabric(*in.Fabric(fabricUUID), in.Version)
	checks = append(checks, verify...)
	if FabricChecksFailed(verify) {
		_, uerr := s.fabricChange(nil, removeHost(fabricUUID, h.Node))
		err := checksError("the host didn't join cleanly, so it was removed again", verify)
		if uerr != nil {
			err = fmt.Errorf("%v — and removing it failed too (%v)", err, uerr)
		}
		return checks, err
	}
	s.audit(p, p.OrgID, "fabric.host.add", "fabric", f.Name, ip, map[string]any{"node": h.Node, "iface": h.UnderlayDev(), "tep": h.TEP})
	return checks, nil
}

// removeHost drops a node from a fabric and from every port group's span. A
// port group spanning only that node would silently widen to every host, so it
// is refused instead.
func removeHost(fabricUUID, node string) func(*fabric.Intent) error {
	return func(in *fabric.Intent) error {
		f := in.Fabric(fabricUUID)
		if f == nil || !f.HasHost(node) {
			return fmt.Errorf("%s isn't in that fabric", node)
		}
		f.Hosts = slices.DeleteFunc(f.Hosts, func(h fabric.Host) bool { return h.Node == node })
		for i := range in.PGs {
			pg := &in.PGs[i]
			if pg.Fabric != fabricUUID || len(pg.Span) == 0 {
				continue
			}
			pg.Span = slices.DeleteFunc(pg.Span, func(n string) bool { return n == node })
			if len(pg.Span) == 0 {
				return fmt.Errorf("port group %s spans only %s — delete it or give it another host first", pg.Name, node)
			}
		}
		return nil
	}
}

// RemoveFabricHost removes a live host (it takes part, and refuses while
// anything there uses a fabric port group).
func (s *Service) RemoveFabricHost(p *Principal, fabricUUID, node, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if _, err := s.fabricChange(nil, removeHost(fabricUUID, node)); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.host.remove", "fabric", fabricUUID, ip, map[string]any{"node": node})
	return nil
}

// EvictFabricHost removes a DEAD host without its consent (it can't answer).
// When it comes back it adopts the newer intent and tears its share down.
func (s *Service) EvictFabricHost(p *Principal, fabricUUID, node, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if node == s.selfNode() {
		return fmt.Errorf("this node is alive — remove it instead of evicting it")
	}
	if s.fabricAlive()[node] {
		return fmt.Errorf("%s is alive — remove it normally (evict is only for a dead host)", node)
	}
	if _, err := s.fabricChange([]string{node}, removeHost(fabricUUID, node)); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.host.evict", "fabric", fabricUUID, ip, map[string]any{"node": node})
	return nil
}

// DeleteFabric removes an empty fabric (no port groups left).
func (s *Service) DeleteFabric(p *Principal, fabricUUID, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var name string
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		f := in.Fabric(fabricUUID)
		if f == nil {
			return ErrNotFound
		}
		name = f.Name
		for _, pg := range in.PGs {
			if pg.Fabric == fabricUUID {
				return fmt.Errorf("fabric %s still has port groups (%s, …) — delete them first", f.Name, pg.Name)
			}
		}
		in.Fabrics = slices.DeleteFunc(in.Fabrics, func(x fabric.Spec) bool { return x.UUID == fabricUUID })
		return in.Normalize(nil)
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.delete", "fabric", name, ip, map[string]any{"uuid": fabricUUID})
	return nil
}

// SetFabricOrgs sets which orgs' admins may build on a fabric.
func (s *Service) SetFabricOrgs(p *Principal, fabricUUID string, orgs []int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	sort.Slice(orgs, func(i, j int) bool { return orgs[i] < orgs[j] })
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		f := in.Fabric(fabricUUID)
		if f == nil {
			return ErrNotFound
		}
		f.Orgs = slices.Compact(orgs)
		return nil
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.orgs", "fabric", fabricUUID, ip, map[string]any{"orgs": orgs})
	return nil
}

// ---- port groups (org admin on an opened fabric, or instance admin) ---------------

// FabricPGInput is the port group form.
type FabricPGInput struct {
	Fabric    string
	Name      string
	CIDR      string // "" = L2-only
	Gateway   string // "" = first host address
	PoolStart string
	PoolEnd   string
	DNS       string // comma-separated
	Span      []string
}

func splitDNS(s string) []string {
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// orgPG loads a port group of the caller's org (instance admins: any).
func orgPG(in *fabric.Intent, p *Principal, uuid string) (*fabric.PortGroup, error) {
	pg := in.PG(uuid)
	if pg == nil || (!p.IsAdmin && pg.Org != p.OrgID) {
		return nil, ErrNotFound
	}
	return pg, nil
}

// CreateFabricPG creates a fabric port group in the caller's org.
func (s *Service) CreateFabricPG(p *Principal, pi FabricPGInput, ip string) (string, error) {
	if !p.OrgAdmin() && !p.IsAdmin {
		return "", ErrUnauthorized
	}
	pg := fabric.PortGroup{UUID: fabric.NewUUID(), Fabric: pi.Fabric, Org: p.OrgID, Name: strings.TrimSpace(pi.Name),
		CIDR: strings.TrimSpace(pi.CIDR), Gateway: strings.TrimSpace(pi.Gateway), PoolStart: strings.TrimSpace(pi.PoolStart),
		PoolEnd: strings.TrimSpace(pi.PoolEnd), DNS: splitDNS(pi.DNS), Span: pi.Span}
	if pg.CIDR != "" {
		_, n, err := net.ParseCIDR(pg.CIDR)
		if err != nil || n.IP.To4() == nil {
			return "", fmt.Errorf("subnet %q must be an IPv4 network like 10.10.1.0/24", pg.CIDR)
		}
		pg.CIDR = n.String()
		if pg.Gateway == "" {
			gw := append(net.IP(nil), n.IP.To4()...)
			gw[3]++
			pg.Gateway = gw.String()
		}
	}
	legacy := s.legacyVNIs()
	var extra []int
	for v := range legacy {
		extra = append(extra, v)
	}
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		f := in.Fabric(pg.Fabric)
		if f == nil {
			return ErrNotFound
		}
		if !s.canBuild(p, f) {
			return ErrUnauthorized
		}
		vni, err := in.AllocVNI(fabric.L2VNIMin, fabric.L2VNIMax, extra)
		if err != nil {
			return err
		}
		pg.VNI = vni
		in.PGs = append(in.PGs, pg)
		return in.Normalize(extra)
	}); err != nil {
		return "", err
	}
	s.audit(p, p.OrgID, "fabric.pg.create", "fabric_pg", pg.Name, ip, map[string]any{"uuid": pg.UUID, "cidr": pg.CIDR, "vni": pg.VNI, "span": pg.Span})
	return pg.UUID, nil
}

// UpdateFabricPG changes a port group's span and DNS servers (its subnet and
// gateway are fixed: guests hold leases in them).
func (s *Service) UpdateFabricPG(p *Principal, uuid string, span []string, dns, ip string) error {
	if !p.OrgAdmin() && !p.IsAdmin {
		return ErrUnauthorized
	}
	var name string
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		pg, err := orgPG(in, p, uuid)
		if err != nil {
			return err
		}
		if f := in.Fabric(pg.Fabric); f == nil || !s.canBuild(p, f) {
			return ErrUnauthorized
		}
		name = pg.Name
		pg.Span = span
		if pg.Routed() {
			pg.DNS = splitDNS(dns)
		}
		return nil
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.pg.update", "fabric_pg", name, ip, map[string]any{"span": span, "dns": dns})
	return nil
}

// DeleteFabricPG deletes a port group (every host refuses while something on it
// uses the port group there).
func (s *Service) DeleteFabricPG(p *Principal, uuid, ip string) error {
	if !p.OrgAdmin() && !p.IsAdmin {
		return ErrUnauthorized
	}
	var name string
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		pg, err := orgPG(in, p, uuid)
		if err != nil {
			return err
		}
		name = pg.Name
		for _, v := range in.VRFs {
			if v.Fabric == pg.Fabric && v.Org == pg.Org && v.Egress != "" && pg.Routed() {
				if _, n, _ := net.ParseCIDR(pg.CIDR); n != nil && n.Contains(net.ParseIP(v.Egress)) {
					return fmt.Errorf("port group %s carries the organization's egress (%s) — clear the egress first", pg.Name, v.Egress)
				}
			}
		}
		in.PGs = slices.DeleteFunc(in.PGs, func(x fabric.PortGroup) bool { return x.UUID == uuid })
		return in.Normalize(nil)
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.pg.delete", "fabric_pg", name, ip, map[string]any{"uuid": uuid})
	return nil
}

// ---- connectivity rules + egress -----------------------------------------------

// FabricRuleInput is one connectivity-table row.
type FabricRuleInput struct {
	Fabric, Src, Dst, Proto, Ports, Note string
	Both                                 bool
}

func (s *Service) orgFabric(p *Principal, in *fabric.Intent, uuid string) (*fabric.Spec, error) {
	if !p.OrgAdmin() && !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	f := in.Fabric(uuid)
	if f == nil {
		return nil, ErrNotFound
	}
	if !s.canBuild(p, f) {
		return nil, ErrUnauthorized
	}
	return f, nil
}

// AddFabricRule allows Src → Dst (both directions with Both).
func (s *Service) AddFabricRule(p *Principal, ri FabricRuleInput, ip string) error {
	r := fabric.Rule{UUID: fabric.NewUUID(), Fabric: ri.Fabric, Org: p.OrgID, Src: ri.Src, Dst: ri.Dst, Both: ri.Both,
		Proto: strings.ToLower(strings.TrimSpace(ri.Proto)), Ports: strings.ReplaceAll(strings.TrimSpace(ri.Ports), " ", ""), Note: strings.TrimSpace(ri.Note)}
	if r.Proto == "" {
		r.Proto = "any"
	}
	var sum string
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		if _, err := s.orgFabric(p, in, r.Fabric); err != nil {
			return err
		}
		in.Rules = append(in.Rules, r)
		sum = fabric.RuleSummary(in, r)
		return nil
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.rule.add", "fabric_rule", r.UUID, ip, map[string]any{"rule": sum})
	return nil
}

// SetFabricRuleOff turns a rule off (or back on) without deleting it.
func (s *Service) SetFabricRuleOff(p *Principal, uuid string, off bool, ip string) error {
	return s.editRule(p, uuid, ip, "fabric.rule.toggle", func(in *fabric.Intent, i int) { in.Rules[i].Off = off })
}

// DeleteFabricRule deletes a rule.
func (s *Service) DeleteFabricRule(p *Principal, uuid, ip string) error {
	return s.editRule(p, uuid, ip, "fabric.rule.delete", func(in *fabric.Intent, i int) {
		in.Rules = append(in.Rules[:i], in.Rules[i+1:]...)
	})
}

func (s *Service) editRule(p *Principal, uuid, ip, action string, f func(*fabric.Intent, int)) error {
	var sum string
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		for i, r := range in.Rules {
			if r.UUID != uuid || (!p.IsAdmin && r.Org != p.OrgID) {
				continue
			}
			if _, err := s.orgFabric(p, in, r.Fabric); err != nil {
				return err
			}
			sum = fabric.RuleSummary(in, r)
			f(in, i)
			return nil
		}
		return ErrNotFound
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, action, "fabric_rule", uuid, ip, map[string]any{"rule": sum})
	return nil
}

// SetFabricEgress sets (or clears, "") the caller org's egress next hop on a
// fabric: its tenant gateway's address on one of its routed port groups.
func (s *Service) SetFabricEgress(p *Principal, fabricUUID, egress, ip string) error {
	egress = strings.TrimSpace(egress)
	if _, err := s.fabricChange(nil, func(in *fabric.Intent) error {
		if _, err := s.orgFabric(p, in, fabricUUID); err != nil {
			return err
		}
		v := in.VRFOf(fabricUUID, p.OrgID)
		if v == nil {
			return fmt.Errorf("the organization has no routed port group on this fabric yet")
		}
		v.Egress = egress
		if egress == "" {
			// Rules to or from External have nothing to use any more.
			in.Rules = slices.DeleteFunc(in.Rules, func(r fabric.Rule) bool {
				return r.Fabric == fabricUUID && r.Org == p.OrgID && (r.Src == fabric.External || r.Dst == fabric.External)
			})
		}
		for _, l := range in.Leases {
			if l.IP == egress && in.PG(l.PG) != nil && in.PG(l.PG).Org == p.OrgID {
				return fmt.Errorf("%s is leased to instance %s", egress, l.Session)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "fabric.egress", "fabric", fabricUUID, ip, map[string]any{"egress": egress})
	return nil
}
