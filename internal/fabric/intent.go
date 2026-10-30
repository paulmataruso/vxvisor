package fabric

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"vdxclone/internal/routing"
)

// Intent is the replicated fabric state (docs/FABRIC.md §14 D3): one versioned
// document, identical on every node at a given version. Every object is keyed by
// a UUID (or by node name / org id), never by a node-local row id. Each node
// realizes its own share of it (HostPlan, Routing) and maps fabric port groups
// to local networks rows.
type Intent struct {
	Version int64       `json:"version"`
	Fabrics []Spec      `json:"fabrics,omitempty"`
	PGs     []PortGroup `json:"pgs,omitempty"`
	VRFs    []VRF       `json:"vrfs,omitempty"`
	Leases  []Lease     `json:"leases,omitempty"`
	Rules   []Rule      `json:"rules,omitempty"`
}

// Spec is one fabric: a set of hosts sharing overlay port groups.
type Spec struct {
	UUID  string  `json:"uuid"`
	Name  string  `json:"name"`
	ASN   int     `json:"asn"`            // iBGP AS, fixed once created
	MTU   int     `json:"mtu"`            // underlay MTU; overlay devices get MTU-50
	Orgs  []int64 `json:"orgs,omitempty"` // orgs whose admins may build on it (instance admins always may)
	Hosts []Host  `json:"hosts"`
}

// Host is one node's membership: its underlay interface and tunnel endpoint.
type Host struct {
	Node  string `json:"node"`           // cluster node name
	Iface string `json:"iface"`          // dedicated NIC or bond
	VLAN  int    `json:"vlan,omitempty"` // 802.1Q tag on Iface (0 = untagged)
	TEP   string `json:"tep"`            // tunnel endpoint with prefix, "10.250.0.1/24"
}

// PortGroup is a fabric-wide network (NSX segment). Routed when CIDR is set
// (anycast gateway, static DHCP, distributed firewall); L2-only otherwise.
type PortGroup struct {
	UUID      string   `json:"uuid"`
	Fabric    string   `json:"fabric"`
	Org       int64    `json:"org"`
	Name      string   `json:"name"`
	VNI       int      `json:"vni"`
	CIDR      string   `json:"cidr,omitempty"`
	Gateway   string   `json:"gw,omitempty"`
	PoolStart string   `json:"pool_start,omitempty"`
	PoolEnd   string   `json:"pool_end,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Span      []string `json:"span,omitempty"` // nodes it is realized on; empty = every fabric host
}

// Routed reports whether the port group has L3 (a subnet and gateway).
func (p PortGroup) Routed() bool { return p.CIDR != "" }

// GatewayCIDR is the anycast gateway as "ip/prefix".
func (p PortGroup) GatewayCIDR() string {
	_, n, err := net.ParseCIDR(p.CIDR)
	if err != nil {
		return ""
	}
	ones, _ := n.Mask.Size()
	return p.Gateway + "/" + strconv.Itoa(ones)
}

// VRF is one org's routing domain on a fabric. Egress, when set, is the next hop
// (an address on one of the org's routed port groups — its tenant gateway's leg)
// every host's VRF sends non-fabric traffic to.
type VRF struct {
	Fabric string `json:"fabric"`
	Org    int64  `json:"org"`
	L3VNI  int    `json:"l3vni"`
	Egress string `json:"egress,omitempty"`
}

// Lease pins one VM NIC's address on a routed port group, fabric-wide.
type Lease struct {
	PG      string `json:"pg"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	Session string `json:"session"`
}

// Rule is one row of the connectivity table: traffic from Src to Dst (port
// group UUIDs, or External) is allowed. Traffic between different port groups
// is otherwise denied; within a port group it is always allowed (a switch).
type Rule struct {
	UUID   string `json:"uuid"`
	Fabric string `json:"fabric"`
	Org    int64  `json:"org"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Both   bool   `json:"both,omitempty"`  // both directions (else Src→Dst, replies allowed)
	Proto  string `json:"proto"`           // any | icmp | tcp | udp
	Ports  string `json:"ports,omitempty"` // tcp/udp: "22,80,8000-8100"
	Off    bool   `json:"off,omitempty"`
	Note   string `json:"note,omitempty"`
}

// External is the Src/Dst of a rule that reaches outside the fabric (via the
// org's VRF egress).
const External = "external"

// VNI ranges the allocator draws from. They sit above the tenant segment
// identity range (200000–1048575) and below nothing else vdxd allocates; a
// legacy VXLAN network an admin numbered by hand inside them is skipped.
const (
	L2VNIMin, L2VNIMax = 2000000, 3999999
	L3VNIMin, L3VNIMax = 4000000, 4999999
)

// Clone deep-copies the intent.
func (in Intent) Clone() Intent {
	b, _ := json.Marshal(in)
	var out Intent
	_ = json.Unmarshal(b, &out)
	return out
}

// NewUUID returns a random RFC 4122 v4 UUID.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ---- lookups ----------------------------------------------------------------

// Fabric returns the fabric with this UUID.
func (in *Intent) Fabric(uuid string) *Spec {
	for i := range in.Fabrics {
		if in.Fabrics[i].UUID == uuid {
			return &in.Fabrics[i]
		}
	}
	return nil
}

// PG returns the port group with this UUID.
func (in *Intent) PG(uuid string) *PortGroup {
	for i := range in.PGs {
		if in.PGs[i].UUID == uuid {
			return &in.PGs[i]
		}
	}
	return nil
}

// VRFOf returns an org's VRF on a fabric.
func (in *Intent) VRFOf(fabric string, org int64) *VRF {
	for i := range in.VRFs {
		if in.VRFs[i].Fabric == fabric && in.VRFs[i].Org == org {
			return &in.VRFs[i]
		}
	}
	return nil
}

// HostOf returns the fabric a node belongs to and its membership (a node is in
// at most one fabric).
func (in *Intent) HostOf(node string) (*Spec, *Host) {
	for i := range in.Fabrics {
		for j := range in.Fabrics[i].Hosts {
			if in.Fabrics[i].Hosts[j].Node == node {
				return &in.Fabrics[i], &in.Fabrics[i].Hosts[j]
			}
		}
	}
	return nil, nil
}

// Nodes lists every node that belongs to any fabric, sorted.
func (in *Intent) Nodes() []string {
	var out []string
	for _, f := range in.Fabrics {
		for _, h := range f.Hosts {
			out = append(out, h.Node)
		}
	}
	sort.Strings(out)
	return out
}

// Spans reports whether a port group is realized on node.
func (in *Intent) Spans(pg PortGroup, node string) bool {
	f := in.Fabric(pg.Fabric)
	if f == nil || !f.HasHost(node) {
		return false
	}
	if len(pg.Span) == 0 {
		return true
	}
	for _, n := range pg.Span {
		if n == node {
			return true
		}
	}
	return false
}

// HasHost reports whether node is a member of the fabric.
func (f *Spec) HasHost(node string) bool {
	for _, h := range f.Hosts {
		if h.Node == node {
			return true
		}
	}
	return false
}

// GuestMTU is the MTU of every overlay device on the fabric.
func (f *Spec) GuestMTU() int { return f.MTU - 50 }

// TEPIP is the host's tunnel endpoint without its prefix.
func (h Host) TEPIP() string { return strings.Split(h.TEP, "/")[0] }

// UnderlayDev is the kernel device that carries the TEP: Iface, or its VLAN
// subinterface.
func (h Host) UnderlayDev() string {
	if h.VLAN == 0 {
		return h.Iface
	}
	return h.Iface + "." + strconv.Itoa(h.VLAN)
}

// ---- validation -------------------------------------------------------------

var (
	reUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reNode   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	rePorts  = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?){0,31}$`)
	reFabNam = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$`)
)

// ValidName checks a port group name (the same rule as host port groups).
func ValidName(n string) error {
	if n == "" || len(n) > 64 {
		return fmt.Errorf("a port group name of 1–64 characters is required")
	}
	for _, r := range n {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("the port group name can't contain control characters")
		}
	}
	return nil
}

func ipv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil || strings.Contains(s, ":") {
		return nil
	}
	return ip.To4()
}

func u32(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

// Validate checks the whole document: every value that reaches a command line,
// a config file or nft, and every cross-reference. Errors say what to change.
func (in *Intent) Validate() error {
	fabrics := map[string]*Spec{}
	names := map[string]bool{}
	nodes := map[string]string{}
	teps := map[string]string{}
	for i := range in.Fabrics {
		f := &in.Fabrics[i]
		if !reUUID.MatchString(f.UUID) || fabrics[f.UUID] != nil {
			return fmt.Errorf("fabric %q has a missing or duplicate id", f.Name)
		}
		fabrics[f.UUID] = f
		if !reFabNam.MatchString(f.Name) {
			return fmt.Errorf("fabric name %q: use 1–32 letters, digits, spaces, . _ -", f.Name)
		}
		if names[strings.ToLower(f.Name)] {
			return fmt.Errorf("a fabric named %q already exists", f.Name)
		}
		names[strings.ToLower(f.Name)] = true
		if err := routing.ValidASN(f.ASN); err != nil {
			return fmt.Errorf("fabric %s: %v", f.Name, err)
		}
		if f.MTU < 1330 || f.MTU > 9216 {
			return fmt.Errorf("fabric %s: underlay MTU %d is out of range — use 1330–9216 (1500 gives guests 1450)", f.Name, f.MTU)
		}
		var subnet *net.IPNet
		for _, h := range f.Hosts {
			if !reNode.MatchString(h.Node) {
				return fmt.Errorf("fabric %s: node name %q is invalid", f.Name, h.Node)
			}
			if other, ok := nodes[h.Node]; ok {
				return fmt.Errorf("host %s is already in fabric %s — a host belongs to one fabric", h.Node, other)
			}
			nodes[h.Node] = f.Name
			if routing.ValidIface(h.Iface) != nil || strings.HasPrefix(h.Iface, "vxf") {
				return fmt.Errorf("host %s: interface %q is not a valid interface name", h.Node, h.Iface)
			}
			if h.VLAN < 0 || h.VLAN == 1 || h.VLAN > 4094 {
				return fmt.Errorf("host %s: VLAN %d is out of range — use 2–4094, or 0 for untagged", h.Node, h.VLAN)
			}
			if len(h.UnderlayDev()) > 15 {
				return fmt.Errorf("host %s: %s is longer than a kernel interface name allows", h.Node, h.UnderlayDev())
			}
			ip, n, err := net.ParseCIDR(h.TEP)
			if err != nil || ip.To4() == nil || ip.Equal(n.IP) || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
				return fmt.Errorf("host %s: TEP %q must be an IPv4 host address with prefix, like 10.250.0.1/24", h.Node, h.TEP)
			}
			if ones, _ := n.Mask.Size(); ones > 30 {
				return fmt.Errorf("host %s: TEP prefix /%d leaves no room for peers — use /30 or wider", h.Node, ones)
			}
			if other, ok := teps[ip.String()]; ok {
				return fmt.Errorf("TEP %s is used by both %s and %s", ip, other, h.Node)
			}
			teps[ip.String()] = h.Node
			if subnet == nil {
				subnet = n
			} else if !subnet.IP.Equal(n.IP) || subnet.Mask.String() != n.Mask.String() {
				return fmt.Errorf("fabric %s: every TEP must be in one subnet (%s), %s's is %s", f.Name, subnet, h.Node, n)
			}
		}
		for _, o := range f.Orgs {
			if o <= 0 {
				return fmt.Errorf("fabric %s: invalid org %d", f.Name, o)
			}
		}
	}

	vnis := map[int]string{}
	pgs := map[string]*PortGroup{}
	pgNames := map[string]bool{}
	type orgKey struct {
		fabric string
		org    int64
	}
	orgNets := map[orgKey][]*net.IPNet{}
	for i := range in.PGs {
		p := &in.PGs[i]
		if !reUUID.MatchString(p.UUID) || pgs[p.UUID] != nil {
			return fmt.Errorf("port group %q has a missing or duplicate id", p.Name)
		}
		pgs[p.UUID] = p
		f := fabrics[p.Fabric]
		if f == nil {
			return fmt.Errorf("port group %s is on a fabric that doesn't exist", p.Name)
		}
		if p.Org <= 0 {
			return fmt.Errorf("port group %s has no organization", p.Name)
		}
		if err := ValidName(p.Name); err != nil {
			return err
		}
		k := p.Fabric + "/" + strconv.FormatInt(p.Org, 10) + "/" + strings.ToLower(p.Name)
		if pgNames[k] {
			return fmt.Errorf("a fabric port group named %q already exists in this organization", p.Name)
		}
		pgNames[k] = true
		if p.VNI < 1 || p.VNI > routing.MaxVNI {
			return fmt.Errorf("port group %s: VNI %d is out of range", p.Name, p.VNI)
		}
		if other, ok := vnis[p.VNI]; ok {
			return fmt.Errorf("VNI %d is used by both %s and %s", p.VNI, other, p.Name)
		}
		vnis[p.VNI] = "port group " + p.Name
		for _, n := range p.Span {
			if !f.HasHost(n) {
				return fmt.Errorf("port group %s spans %s, which isn't a host of fabric %s", p.Name, n, f.Name)
			}
		}
		if !p.Routed() {
			if p.Gateway != "" || p.PoolStart != "" || p.PoolEnd != "" || len(p.DNS) > 0 {
				return fmt.Errorf("port group %s is L2-only: it takes no gateway, pool or DNS", p.Name)
			}
			continue
		}
		if err := validSubnet(p); err != nil {
			return fmt.Errorf("port group %s: %v", p.Name, err)
		}
		_, n, _ := net.ParseCIDR(p.CIDR)
		ok := orgKey{p.Fabric, p.Org}
		for _, o := range orgNets[ok] {
			if o.Contains(n.IP) || n.Contains(o.IP) {
				return fmt.Errorf("port group %s: %s overlaps %s in the same organization", p.Name, n, o)
			}
		}
		orgNets[ok] = append(orgNets[ok], n)
	}

	vrfs := map[orgKey]*VRF{}
	for i := range in.VRFs {
		v := &in.VRFs[i]
		k := orgKey{v.Fabric, v.Org}
		if fabrics[v.Fabric] == nil || v.Org <= 0 || vrfs[k] != nil {
			return fmt.Errorf("VRF for org %d is invalid or listed twice", v.Org)
		}
		vrfs[k] = v
		if v.L3VNI < 1 || v.L3VNI > routing.MaxVNI {
			return fmt.Errorf("VRF for org %d: L3VNI %d is out of range", v.Org, v.L3VNI)
		}
		if other, ok := vnis[v.L3VNI]; ok {
			return fmt.Errorf("VNI %d is used by both %s and org %d's VRF", v.L3VNI, other, v.Org)
		}
		vnis[v.L3VNI] = "a VRF"
		if v.Egress != "" {
			ip := ipv4(v.Egress)
			on := false
			for _, n := range orgNets[k] {
				on = on || (ip != nil && n.Contains(ip))
			}
			if !on {
				return fmt.Errorf("org %d's egress %q must be an address on one of its routed fabric port groups", v.Org, v.Egress)
			}
			for _, p := range in.PGs {
				if p.Fabric == v.Fabric && p.Org == v.Org && p.Routed() && p.Gateway == v.Egress {
					return fmt.Errorf("org %d's egress %s is a port group's own gateway — use the tenant gateway's address", v.Org, v.Egress)
				}
			}
		}
	}
	for _, p := range in.PGs {
		if p.Routed() && vrfs[orgKey{p.Fabric, p.Org}] == nil {
			return fmt.Errorf("routed port group %s has no VRF for its organization", p.Name)
		}
	}

	leaseIP := map[string]bool{}
	leaseSess := map[string]bool{}
	for _, l := range in.Leases {
		p := pgs[l.PG]
		if p == nil || !p.Routed() {
			return fmt.Errorf("lease %s is on a port group that doesn't exist or has no subnet", l.IP)
		}
		ip := ipv4(l.IP)
		_, n, _ := net.ParseCIDR(p.CIDR)
		if ip == nil || !n.Contains(ip) || ip.String() == p.Gateway {
			return fmt.Errorf("lease %s is not a host address of %s", l.IP, p.CIDR)
		}
		if mac, err := net.ParseMAC(l.MAC); err != nil || len(mac) != 6 {
			return fmt.Errorf("lease %s: MAC %q is invalid", l.IP, l.MAC)
		}
		if !reNode.MatchString(l.Session) {
			return fmt.Errorf("lease %s: instance id %q is invalid", l.IP, l.Session)
		}
		if leaseIP[l.PG+"/"+ip.String()] {
			return fmt.Errorf("address %s is leased twice on %s", ip, p.Name)
		}
		if leaseSess[l.PG+"/"+l.Session] {
			return fmt.Errorf("instance %s has two leases on %s", l.Session, p.Name)
		}
		leaseIP[l.PG+"/"+ip.String()], leaseSess[l.PG+"/"+l.Session] = true, true
	}

	ruleIDs := map[string]bool{}
	for _, r := range in.Rules {
		if !reUUID.MatchString(r.UUID) || ruleIDs[r.UUID] {
			return fmt.Errorf("a connectivity rule has a missing or duplicate id")
		}
		ruleIDs[r.UUID] = true
		end := func(id string) error {
			if id == External {
				if v := vrfs[orgKey{r.Fabric, r.Org}]; v == nil || v.Egress == "" {
					return fmt.Errorf("a rule to External needs the organization's egress (its tenant gateway) set first")
				}
				return nil
			}
			p := pgs[id]
			if p == nil || p.Fabric != r.Fabric || p.Org != r.Org || !p.Routed() {
				return fmt.Errorf("a rule names a port group that isn't one of this organization's routed fabric port groups")
			}
			return nil
		}
		if err := end(r.Src); err != nil {
			return err
		}
		if err := end(r.Dst); err != nil {
			return err
		}
		if r.Src == r.Dst {
			return fmt.Errorf("a rule from a port group to itself does nothing — traffic inside a port group is always allowed")
		}
		switch r.Proto {
		case "any", "icmp":
			if r.Ports != "" {
				return fmt.Errorf("ports apply only to TCP or UDP rules")
			}
		case "tcp", "udp":
			if r.Ports != "" {
				if err := validPorts(r.Ports); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("protocol %q: use any, icmp, tcp or udp", r.Proto)
		}
		if strings.ContainsAny(r.Note, "\n\r\"\\") || len(r.Note) > 120 {
			return fmt.Errorf("a rule note is up to 120 characters on one line, without quotes")
		}
	}
	return nil
}

func validSubnet(p *PortGroup) error {
	ip, n, err := net.ParseCIDR(p.CIDR)
	if err != nil || ip.To4() == nil || !ip.Equal(n.IP) {
		return fmt.Errorf("subnet %q must be an IPv4 network like 10.10.1.0/24", p.CIDR)
	}
	ones, _ := n.Mask.Size()
	if ones < 8 || ones > 29 {
		return fmt.Errorf("subnet %s: use a prefix from /8 to /29", p.CIDR)
	}
	gw := ipv4(p.Gateway)
	bcast := u32(n.IP) | ^u32(net.IP(n.Mask))
	if gw == nil || !n.Contains(gw) || gw.Equal(n.IP) || u32(gw) == bcast {
		return fmt.Errorf("gateway %q must be a host address inside %s", p.Gateway, p.CIDR)
	}
	if (p.PoolStart == "") != (p.PoolEnd == "") {
		return fmt.Errorf("give both ends of the address pool, or neither")
	}
	if p.PoolStart != "" {
		s, e := ipv4(p.PoolStart), ipv4(p.PoolEnd)
		if s == nil || e == nil || !n.Contains(s) || !n.Contains(e) || u32(s) > u32(e) ||
			u32(s) == u32(n.IP) || u32(e) == bcast {
			return fmt.Errorf("address pool %s–%s must be host addresses inside %s, low to high", p.PoolStart, p.PoolEnd, p.CIDR)
		}
	}
	if len(p.DNS) > 3 {
		return fmt.Errorf("at most 3 DNS servers")
	}
	for _, d := range p.DNS {
		if ipv4(d) == nil {
			return fmt.Errorf("DNS server %q is not an IPv4 address", d)
		}
	}
	return nil
}

func validPorts(s string) error {
	if !rePorts.MatchString(s) {
		return fmt.Errorf("ports %q: use numbers and ranges like 22,80,8000-8100", s)
	}
	for _, part := range strings.Split(s, ",") {
		lo, hi, _ := strings.Cut(part, "-")
		a, _ := strconv.Atoi(lo)
		b := a
		if hi != "" {
			b, _ = strconv.Atoi(hi)
		}
		if a < 1 || b > 65535 || a > b {
			return fmt.Errorf("port range %s is out of order or out of 1–65535", part)
		}
	}
	return nil
}

// ---- allocation -------------------------------------------------------------

// usedVNIs is every VNI the intent holds, plus extra (node-local legacy VXLAN
// networks and storage overlays the caller knows of).
func (in *Intent) usedVNIs(extra []int) map[int]bool {
	used := map[int]bool{}
	for _, p := range in.PGs {
		used[p.VNI] = true
	}
	for _, v := range in.VRFs {
		used[v.L3VNI] = true
	}
	for _, v := range extra {
		used[v] = true
	}
	return used
}

// AllocVNI returns the lowest free VNI in [lo, hi].
func (in *Intent) AllocVNI(lo, hi int, extra []int) (int, error) {
	used := in.usedVNIs(extra)
	for v := lo; v <= hi; v++ {
		if !used[v] {
			return v, nil
		}
	}
	return 0, fmt.Errorf("no free VNI left in %d–%d", lo, hi)
}

// Normalize gives every org with a routed port group on a fabric a VRF (with a
// fresh L3VNI), and drops VRFs, leases and rules whose port groups are gone.
func (in *Intent) Normalize(extraVNIs []int) error {
	type orgKey struct {
		fabric string
		org    int64
	}
	need := map[orgKey]bool{}
	for _, p := range in.PGs {
		if p.Routed() && in.Fabric(p.Fabric) != nil {
			need[orgKey{p.Fabric, p.Org}] = true
		}
	}
	keep := in.VRFs[:0]
	have := map[orgKey]bool{}
	for _, v := range in.VRFs {
		if k := (orgKey{v.Fabric, v.Org}); need[k] && !have[k] {
			have[k] = true
			keep = append(keep, v)
		}
	}
	in.VRFs = keep
	var add []orgKey
	for k := range need {
		if !have[k] {
			add = append(add, k)
		}
	}
	sort.Slice(add, func(i, j int) bool {
		if add[i].fabric != add[j].fabric {
			return add[i].fabric < add[j].fabric
		}
		return add[i].org < add[j].org
	})
	for _, k := range add {
		vni, err := in.AllocVNI(L3VNIMin, L3VNIMax, extraVNIs)
		if err != nil {
			return err
		}
		in.VRFs = append(in.VRFs, VRF{Fabric: k.fabric, Org: k.org, L3VNI: vni})
	}
	leases := in.Leases[:0]
	for _, l := range in.Leases {
		if p := in.PG(l.PG); p != nil && p.Routed() {
			leases = append(leases, l)
		}
	}
	in.Leases = leases
	rules := in.Rules[:0]
	for _, r := range in.Rules {
		ok := in.Fabric(r.Fabric) != nil
		for _, e := range []string{r.Src, r.Dst} {
			if e != External {
				p := in.PG(e)
				ok = ok && p != nil && p.Routed()
			}
		}
		if ok {
			rules = append(rules, r)
		}
	}
	in.Rules = rules
	return nil
}

// AllocLease returns the lease of session on port group pg, allocating the
// lowest free pool address (the whole subnet when there is no pool) if it has
// none. The intent is modified in place.
func (in *Intent) AllocLease(pg, session, mac string) (Lease, error) {
	p := in.PG(pg)
	if p == nil || !p.Routed() {
		return Lease{}, fmt.Errorf("port group has no subnet to lease from")
	}
	for _, l := range in.Leases {
		if l.PG == pg && l.Session == session {
			return l, nil
		}
	}
	_, n, err := net.ParseCIDR(p.CIDR)
	if err != nil {
		return Lease{}, err
	}
	bcast := u32(n.IP) | ^u32(net.IP(n.Mask))
	lo, hi := u32(n.IP)+1, bcast-1
	if p.PoolStart != "" {
		lo, hi = u32(ipv4(p.PoolStart)), u32(ipv4(p.PoolEnd))
	}
	used := map[uint32]bool{u32(ipv4(p.Gateway)): true}
	for _, l := range in.Leases {
		if l.PG == pg {
			if ip := ipv4(l.IP); ip != nil {
				used[u32(ip)] = true
			}
		}
	}
	for _, v := range in.VRFs {
		if v.Fabric == p.Fabric && v.Org == p.Org && v.Egress != "" {
			used[u32(ipv4(v.Egress))] = true
		}
	}
	for c := lo; c <= hi && c >= lo; c++ {
		if used[c] {
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], c)
		l := Lease{PG: pg, IP: net.IP(b[:]).String(), MAC: strings.ToLower(mac), Session: session}
		in.Leases = append(in.Leases, l)
		return l, nil
	}
	return Lease{}, fmt.Errorf("port group %s's address pool is exhausted", p.Name)
}

// ReleaseLeases drops every lease of session; it reports whether any existed.
func (in *Intent) ReleaseLeases(session string) bool {
	keep := in.Leases[:0]
	for _, l := range in.Leases {
		if l.Session != session {
			keep = append(keep, l)
		}
	}
	gone := len(keep) != len(in.Leases)
	in.Leases = keep
	return gone
}

// ---- this host's share ------------------------------------------------------

// HostPlan is node's kernel state for the intent (zero plan: not in a fabric).
func (in *Intent) HostPlan(node string) (HostPlan, bool) {
	f, h := in.HostOf(node)
	if f == nil {
		return HostPlan{}, false
	}
	p := HostPlan{TEP: h.TEPIP(), AnycastMAC: AnycastMAC(f.UUID), GuestMTU: f.GuestMTU()}
	orgs := map[int64]bool{}
	for _, pg := range in.PGs {
		if pg.Fabric != f.UUID || !in.Spans(pg, node) {
			continue
		}
		s := SegmentPlan{VNI: pg.VNI, Org: pg.Org}
		if pg.Routed() {
			s.Gateway = pg.GatewayCIDR()
			orgs[pg.Org] = true
		}
		p.Segments = append(p.Segments, s)
	}
	for _, v := range in.VRFs {
		if v.Fabric == f.UUID && orgs[v.Org] {
			p.VRFs = append(p.VRFs, VRFPlan{Org: v.Org, L3VNI: v.L3VNI})
		}
	}
	sort.Slice(p.Segments, func(i, j int) bool { return p.Segments[i].VNI < p.Segments[j].VNI })
	sort.Slice(p.VRFs, func(i, j int) bool { return p.VRFs[i].Org < p.VRFs[j].Org })
	return p, true
}

// Routing is node's fabric section of the host FRR config (nil: not in a
// fabric). password is the fabric's BGP MD5 secret (derived per node from the
// shared cluster key, never replicated).
func (in *Intent) Routing(node, password string) *routing.Fabric {
	f, h := in.HostOf(node)
	if f == nil {
		return nil
	}
	r := &routing.Fabric{ASN: f.ASN, TEP: h.TEPIP(), Password: password, BFD: true}
	for _, o := range f.Hosts {
		if o.Node != node {
			r.Peers = append(r.Peers, o.TEPIP())
		}
	}
	sort.Strings(r.Peers)
	plan, _ := in.HostPlan(node)
	for _, v := range plan.VRFs {
		fv := routing.FabricVRF{Name: VRFName(v.Org), VNI: v.L3VNI}
		if vrf := in.VRFOf(f.UUID, v.Org); vrf != nil {
			fv.Egress = vrf.Egress
		}
		r.VRFs = append(r.VRFs, fv)
	}
	return r
}

// DHCP is node's per-org DHCP service: every routed port group it spans, with
// every lease on it (a VM may move here at any time; DHCP never crosses the
// tunnel, so only local VMs are answered).
func (in *Intent) DHCP(node string) map[int64][]DHCPSegment {
	f, _ := in.HostOf(node)
	if f == nil {
		return nil
	}
	out := map[int64][]DHCPSegment{}
	for _, pg := range in.PGs {
		if pg.Fabric != f.UUID || !pg.Routed() || !in.Spans(pg, node) {
			continue
		}
		s := DHCPSegment{VNI: pg.VNI, Gateway: pg.GatewayCIDR(), DNS: pg.DNS, MTU: f.GuestMTU()}
		for _, l := range in.Leases {
			if l.PG == pg.UUID {
				s.Leases = append(s.Leases, DHCPLease{MAC: l.MAC, IP: l.IP})
			}
		}
		out[pg.Org] = append(out[pg.Org], s)
	}
	return out
}

// UnderlayOf is the device carrying node's TEP ("" if it isn't in a fabric).
func (in *Intent) UnderlayOf(node string) string {
	if _, h := in.HostOf(node); h != nil {
		return h.UnderlayDev()
	}
	return ""
}

// Peers lists the other members' TEPs on node's fabric (for the UDP 4789 guard).
func (in *Intent) Peers(node string) []string {
	r := in.Routing(node, "")
	if r == nil {
		return nil
	}
	return r.Peers
}
