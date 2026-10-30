// Package fabric realizes the VXVisor Fabric (docs/FABRIC.md §14) on one host:
// the kernel devices of a BGP EVPN / VXLAN overlay with distributed L3.
//
// Per host, from a HostPlan (desired state, applied idempotently):
//   - per org VRF: a VRF device vxfvrf<org> (table = its L3VNI), and the L3VNI
//     itself: VXLAN vxfl<l3vni> in bridge vxfr<l3vni>, whose MAC is this host's
//     router MAC (unique per VTEP, as symmetric IRB requires);
//   - per fabric port group (L2VNI): VXLAN vxfv<vni> in bridge vxfb<vni>,
//     traditional (vlan_filtering=0), ARP/ND suppressed, no data-plane learning
//     (EVPN programs the FDB). A routed port group's bridge is enslaved to its
//     org's VRF and carries the anycast gateway: the same IP and MAC on every
//     host, so a VM's first hop is always its own host;
//   - an L2-only port group's bridge never forwards IP on the host.
//
// Device names are vxf + a kind letter + a number, a prefix nothing else in
// vdxd uses: Prune deletes only names of exactly that shape that the plan
// doesn't list, never a legacy vxlan<N> or any other device.
//
// Commands go through a Runner, so a test lab can realize the same plan inside
// network namespaces standing in for hosts.
package fabric

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// VXLANPort is the IANA VXLAN UDP port every fabric VTEP uses.
const VXLANPort = 4789

// Runner executes one command on the host (or in a lab namespace).
type Runner interface {
	Run(args ...string) (string, error)
}

// Exec runs commands directly on this host.
type Exec struct{}

func (Exec) Run(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// HostPlan is one host's desired fabric state.
type HostPlan struct {
	TEP        string // this host's tunnel endpoint (IPv4, already on an underlay interface)
	AnycastMAC string // fabric-wide gateway MAC
	GuestMTU   int    // MTU of every overlay device (underlay MTU - 50)
	VRFs       []VRFPlan
	Segments   []SegmentPlan
}

// VRFPlan is one org's routing domain on this host.
type VRFPlan struct {
	Org   int64
	L3VNI int
}

// SegmentPlan is one fabric port group present on this host.
type SegmentPlan struct {
	VNI     int
	Org     int64  // owning org (its VRF, when routed)
	Gateway string // anycast gateway "10.10.1.1/24"; "" = L2-only
}

// Device names.
func VRFName(org int64) string        { return "vxfvrf" + strconv.FormatInt(org, 10) }
func L3VXLAN(l3vni int) string        { return "vxfl" + strconv.Itoa(l3vni) }
func L3Bridge(l3vni int) string       { return "vxfr" + strconv.Itoa(l3vni) }
func SegVXLAN(vni int) string         { return "vxfv" + strconv.Itoa(vni) }
func SegBridge(vni int) string        { return "vxfb" + strconv.Itoa(vni) }
func IsFabricDevice(name string) bool { return reFabricDev.MatchString(name) }

var reFabricDev = regexp.MustCompile(`^vxf(vrf|[vblr])[0-9]{1,9}$`)

// RouterMAC derives this host's stable, locally administered router MAC from
// its TEP (unique per VTEP, the same across reboots).
func RouterMAC(tep string) string {
	h := sha256.Sum256([]byte("vxvisor-fabric-router-mac/" + tep))
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4])
}

// AnycastMAC derives a fabric's gateway MAC from its id.
func AnycastMAC(fabricID string) string {
	h := sha256.Sum256([]byte("vxvisor-fabric-anycast-mac/" + fabricID))
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4])
}

// Validate checks every value Realize puts on a command line.
func (p HostPlan) Validate() error {
	if ip := net.ParseIP(p.TEP); ip == nil || ip.To4() == nil || strings.Contains(p.TEP, ":") {
		return fmt.Errorf("TEP %q is not an IPv4 address", p.TEP)
	}
	if _, err := net.ParseMAC(p.AnycastMAC); err != nil || len(p.AnycastMAC) != 17 {
		return fmt.Errorf("anycast MAC %q is invalid", p.AnycastMAC)
	}
	if p.GuestMTU < 1280 || p.GuestMTU > 9000 {
		return fmt.Errorf("guest MTU %d is out of range 1280-9000", p.GuestMTU)
	}
	vrfs := map[int64]bool{}
	vnis := map[int]bool{}
	for _, v := range p.VRFs {
		if v.Org <= 0 || v.Org > 999999999 || v.L3VNI < 1 || v.L3VNI > 16777215 {
			return fmt.Errorf("VRF org %d / L3VNI %d is out of range", v.Org, v.L3VNI)
		}
		if vrfs[v.Org] || vnis[v.L3VNI] {
			return fmt.Errorf("VRF org %d / L3VNI %d is listed twice", v.Org, v.L3VNI)
		}
		vrfs[v.Org], vnis[v.L3VNI] = true, true
	}
	for _, s := range p.Segments {
		if s.VNI < 1 || s.VNI > 16777215 || vnis[s.VNI] {
			return fmt.Errorf("segment VNI %d is out of range or reused", s.VNI)
		}
		vnis[s.VNI] = true
		if s.Gateway == "" {
			continue
		}
		ip, n, err := net.ParseCIDR(s.Gateway)
		if err != nil || ip.To4() == nil || ip.Equal(n.IP) {
			return fmt.Errorf("segment %d gateway %q must be an IPv4 host address with prefix", s.VNI, s.Gateway)
		}
		if !vrfs[s.Org] {
			return fmt.Errorf("routed segment %d has no VRF for org %d", s.VNI, s.Org)
		}
	}
	return nil
}

// d is a small device-state helper over a Runner.
type d struct{ r Runner }

func (x d) run(args ...string) error { _, err := x.r.Run(args...); return err }

func (x d) exists(name string) bool {
	_, err := x.r.Run("ip", "link", "show", "dev", name)
	return err == nil
}

// Realize brings the host to the plan. It creates and updates; it never
// deletes (Prune does). Idempotent.
func Realize(r Runner, p HostPlan) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("refusing to realize the fabric: %w", err)
	}
	x := d{r}
	mtu := strconv.Itoa(p.GuestMTU)
	for _, v := range p.VRFs {
		if err := x.vrf(p, v, mtu); err != nil {
			return err
		}
	}
	for _, s := range p.Segments {
		if err := x.segment(p, s, mtu); err != nil {
			return err
		}
	}
	return nil
}

func (x d) vxlan(name string, vni int, tep, bridge, mtu string) error {
	if !x.exists(name) {
		if err := x.run("ip", "link", "add", name, "type", "vxlan", "id", strconv.Itoa(vni),
			"local", tep, "dstport", strconv.Itoa(VXLANPort), "nolearning"); err != nil {
			return err
		}
	}
	for _, args := range [][]string{
		{"ip", "link", "set", name, "mtu", mtu},
		{"ip", "link", "set", name, "master", bridge},
		// EVPN programs the FDB and answers ARP/ND from its tables.
		{"bridge", "link", "set", "dev", name, "learning", "off", "neigh_suppress", "on"},
		{"ip", "link", "set", name, "up"},
	} {
		if err := x.run(args...); err != nil {
			return err
		}
	}
	return nil
}

func (x d) bridge(name, mtu string) error {
	if !x.exists(name) {
		if err := x.run("ip", "link", "add", name, "type", "bridge", "stp_state", "0", "vlan_filtering", "0", "mcast_snooping", "0"); err != nil {
			return err
		}
	}
	if err := x.run("ip", "link", "set", name, "mtu", mtu); err != nil {
		return err
	}
	// IPv6 on fabric devices is phase 3; no link-local or SLAAC on them now.
	return x.run("sysctl", "-qw", "net.ipv6.conf."+name+".disable_ipv6=1")
}

func (x d) vrf(p HostPlan, v VRFPlan, mtu string) error {
	vrf := VRFName(v.Org)
	if !x.exists(vrf) {
		if err := x.run("ip", "link", "add", vrf, "type", "vrf", "table", strconv.Itoa(v.L3VNI)); err != nil {
			return err
		}
	}
	if err := x.run("ip", "link", "set", vrf, "up"); err != nil {
		return err
	}
	// A lookup that misses in the VRF must stop there, never fall through to
	// the host's main table.
	if err := x.run("ip", "route", "replace", "unreachable", "default", "metric", "4278198272", "vrf", vrf); err != nil {
		return err
	}
	br := L3Bridge(v.L3VNI)
	if err := x.bridge(br, mtu); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"ip", "link", "set", br, "master", vrf},
		{"ip", "link", "set", br, "address", RouterMAC(p.TEP)},
		{"ip", "link", "set", br, "up"},
	} {
		if err := x.run(args...); err != nil {
			return err
		}
	}
	return x.vxlan(L3VXLAN(v.L3VNI), v.L3VNI, p.TEP, br, mtu)
}

func (x d) segment(p HostPlan, s SegmentPlan, mtu string) error {
	br := SegBridge(s.VNI)
	if err := x.bridge(br, mtu); err != nil {
		return err
	}
	if s.Gateway == "" {
		// L2-only: the host is a switch here, never a router.
		for _, args := range [][]string{
			{"ip", "link", "set", br, "nomaster"},
			{"ip", "addr", "flush", "dev", br},
			{"sysctl", "-qw", "net.ipv4.conf." + br + ".forwarding=0"},
		} {
			if err := x.run(args...); err != nil {
				return err
			}
		}
	} else {
		for _, args := range [][]string{
			{"ip", "link", "set", br, "master", VRFName(s.Org)},
			{"ip", "link", "set", br, "address", p.AnycastMAC},
			{"sysctl", "-qw", "net.ipv4.conf." + br + ".forwarding=1"},
			// Silent hosts: this host ARPs for a VM behind another host, the VM
			// replies to the anycast MAC, and THAT host's gateway absorbs the
			// reply. Accepting it there creates the neighbour entry EVPN then
			// advertises (type-2 MAC/IP), so the route converges.
			{"sysctl", "-qw", "net.ipv4.conf." + br + ".arp_accept=1"},
		} {
			if err := x.run(args...); err != nil {
				return err
			}
		}
		if err := x.gateway(br, s.Gateway); err != nil {
			return err
		}
	}
	if err := x.run("ip", "link", "set", br, "up"); err != nil {
		return err
	}
	return x.vxlan(SegVXLAN(s.VNI), s.VNI, p.TEP, br, mtu)
}

// gateway makes cidr the bridge's only IPv4 address.
func (x d) gateway(br, cidr string) error {
	out, err := x.r.Run("ip", "-4", "-o", "addr", "show", "dev", br)
	if err != nil {
		return err
	}
	have := false
	for _, f := range strings.Fields(out) {
		if strings.Contains(f, "/") && net.ParseIP(strings.Split(f, "/")[0]) != nil {
			if f == cidr {
				have = true
			} else if err := x.run("ip", "addr", "del", f, "dev", br); err != nil {
				return err
			}
		}
	}
	if have {
		return nil
	}
	return x.run("ip", "addr", "add", cidr, "dev", br)
}

// Prune deletes fabric devices the plan doesn't list (only names of the
// fabric's own shape), segments and L3VNIs before VRFs. Returns what it removed.
func Prune(r Runner, p HostPlan) ([]string, error) {
	want := map[string]bool{}
	for _, v := range p.VRFs {
		want[VRFName(v.Org)], want[L3Bridge(v.L3VNI)], want[L3VXLAN(v.L3VNI)] = true, true, true
	}
	for _, s := range p.Segments {
		want[SegBridge(s.VNI)], want[SegVXLAN(s.VNI)] = true, true
	}
	out, err := r.Run("ip", "-o", "link", "show")
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		if IsFabricDevice(name) && !want[name] {
			gone = append(gone, name)
		}
	}
	// Tunnel ports first, then bridges, then VRFs.
	rank := func(n string) int {
		switch {
		case strings.HasPrefix(n, "vxfvrf"):
			return 2
		case strings.HasPrefix(n, "vxfv"), strings.HasPrefix(n, "vxfl"):
			return 0
		}
		return 1
	}
	sort.SliceStable(gone, func(i, j int) bool { return rank(gone[i]) < rank(gone[j]) })
	for _, n := range gone {
		if _, err := r.Run("ip", "link", "del", n); err != nil {
			return gone, err
		}
	}
	return gone, nil
}
