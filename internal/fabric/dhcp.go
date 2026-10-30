package fabric

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// DHCP on fabric port groups: one dnsmasq per org VRF per host, started under
// `ip vrf exec` so its sockets live in the org's VRF (the host's own services
// stay unreachable: tcp/udp_l3mdev_accept stay 0). It hands out STATIC leases
// only (MAC → IP, allocated centrally), so whichever host answers gives the
// same answer; DHCP never crosses the tunnel (bridge guard).

// DHCPSegment is one routed port group's DHCP service.
type DHCPSegment struct {
	VNI     int
	Gateway string // anycast gateway with prefix, "10.10.1.1/24"
	DNS     []string
	MTU     int // advertised (option 26)
	Leases  []DHCPLease
}

// DHCPLease pins one VM NIC's address.
type DHCPLease struct {
	MAC string
	IP  string
}

// DNSMasqConfig renders the dnsmasq config for one org's VRF on this host.
func DNSMasqConfig(org int64, segs []DHCPSegment, runDir string) (string, error) {
	var b strings.Builder
	tag := "vxfvrf" + strconv.FormatInt(org, 10)
	b.WriteString("# vdxd: VXVisor Fabric DHCP for " + tag + " (static leases only)\n")
	b.WriteString("port=0\nbind-interfaces\nexcept-interface=lo\nno-resolv\nno-hosts\ndhcp-authoritative\n")
	fmt.Fprintf(&b, "pid-file=%s/dnsmasq-%s.pid\ndhcp-leasefile=%s/dnsmasq-%s.leases\n", runDir, tag, runDir, tag)
	sort.Slice(segs, func(i, j int) bool { return segs[i].VNI < segs[j].VNI })
	for _, s := range segs {
		gw, n, err := net.ParseCIDR(s.Gateway)
		if err != nil || gw.To4() == nil {
			return "", fmt.Errorf("segment %d: gateway %q is not an IPv4 address with prefix", s.VNI, s.Gateway)
		}
		if s.MTU < 1280 || s.MTU > 9000 {
			return "", fmt.Errorf("segment %d: MTU %d out of range", s.VNI, s.MTU)
		}
		br := SegBridge(s.VNI)
		fmt.Fprintf(&b, "interface=%s\n", br)
		fmt.Fprintf(&b, "dhcp-range=set:%s,%s,static,%s,12h\n", br, n.IP, net.IP(n.Mask))
		fmt.Fprintf(&b, "dhcp-option=tag:%s,option:router,%s\n", br, gw)
		fmt.Fprintf(&b, "dhcp-option=tag:%s,option:mtu,%d\n", br, s.MTU)
		var dns []string
		for _, d := range s.DNS {
			if ip := net.ParseIP(d); ip == nil || ip.To4() == nil {
				return "", fmt.Errorf("segment %d: DNS server %q is not an IPv4 address", s.VNI, d)
			}
			dns = append(dns, d)
		}
		if len(dns) > 0 {
			fmt.Fprintf(&b, "dhcp-option=tag:%s,option:dns-server,%s\n", br, strings.Join(dns, ","))
		}
		for _, l := range s.Leases {
			mac, err := net.ParseMAC(l.MAC)
			ip := net.ParseIP(l.IP)
			if err != nil || len(mac) != 6 || ip == nil || ip.To4() == nil || !n.Contains(ip) || ip.Equal(gw) {
				return "", fmt.Errorf("segment %d: lease %s → %s is not a MAC and an address inside %s", s.VNI, l.MAC, l.IP, n)
			}
			fmt.Fprintf(&b, "dhcp-host=%s,set:%s,%s\n", mac, br, ip)
		}
	}
	return b.String(), nil
}

// DNSMasqArgs is the command that runs an org's DHCP inside its VRF.
func DNSMasqArgs(org int64, confPath string) []string {
	return []string{"ip", "vrf", "exec", VRFName(org), "dnsmasq", "--conf-file=" + confPath}
}

// BridgeGuard is the host's `bridge vdxfabric` table:
//   - DHCP never crosses a tunnel port, either way, whether forwarded or sent
//     by this host's own dnsmasq (each host answers its own VMs; a flooded
//     DISCOVER would draw one OFFER per host);
//   - guests can't send 802.1Q / 802.1ad frames into a fabric bridge (these
//     bridges run vlan_filtering=0, so a tag would otherwise pass through).
//
// The script replaces the table in one transaction.
func BridgeGuard() string {
	return `table bridge vdxfabric {}
delete table bridge vdxfabric
table bridge vdxfabric {
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "vxfv*" udp dport { 67, 68 } drop
    oifname "vxfv*" udp dport { 67, 68 } drop
    iifname != "vxfv*" meta ibrname "vxfb*" ether type { 8021q, 8021ad } drop
  }
  chain output {
    type filter hook output priority -10; policy accept;
    oifname "vxfv*" udp dport { 67, 68 } drop
  }
}
`
}
