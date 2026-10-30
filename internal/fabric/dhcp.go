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

// GuardSegment is one fabric segment bridge on this host, for the bridge guard.
type GuardSegment struct {
	VNI    int
	Routed bool        // has a gateway: guests must use their leased MAC + address
	Leases []DHCPLease // routed: every (MAC, address) allowed on it
}

// GuardPolicePPS is the per-port broadcast / multicast budget on fabric bridges
// (packets per second, with the same again as burst).
const GuardPolicePPS = 1000

// Guard is node's bridge guard input: every segment it hosts.
func (in *Intent) Guard(node string) []GuardSegment {
	f, _ := in.HostOf(node)
	if f == nil {
		return nil
	}
	var out []GuardSegment
	for _, pg := range in.PGs {
		if pg.Fabric != f.UUID || !in.Spans(pg, node) {
			continue
		}
		g := GuardSegment{VNI: pg.VNI, Routed: pg.Routed()}
		for _, l := range in.Leases {
			if l.PG == pg.UUID {
				g.Leases = append(g.Leases, DHCPLease{MAC: l.MAC, IP: l.IP})
			}
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VNI < out[j].VNI })
	return out
}

// BridgeGuard is the host's `bridge vdxfabric` table:
//   - DHCP never crosses a tunnel port, either way, whether forwarded or sent
//     by this host's own dnsmasq (each host answers its own VMs; a flooded
//     DISCOVER would draw one OFFER per host);
//   - guests can't send 802.1Q / 802.1ad frames into a fabric bridge (these
//     bridges run vlan_filtering=0, so a tag would otherwise pass through);
//   - every local port's forwarded broadcast / multicast is policed (GuardPolicePPS);
//   - on a routed segment a guest may only use its leased MAC and address
//     (ARP included; DHCP from 0.0.0.0 allowed), may not answer DHCP or send
//     IPv6 router advertisements. This is checked on the input hook too: a
//     guest's routed traffic is delivered to the anycast gateway, not forwarded.
//
// Router legs (host veth vrh*) are the tenant's own gateways and exempt. The
// script replaces the table in one transaction.
func BridgeGuard(segs []GuardSegment) (string, error) {
	var routed, all, macs, addrs []string
	for _, g := range segs {
		br := SegBridge(g.VNI)
		all = append(all, `"`+br+`"`)
		if !g.Routed {
			continue
		}
		routed = append(routed, `"`+br+`"`)
		for _, l := range g.Leases {
			mac, err := net.ParseMAC(l.MAC)
			ip := net.ParseIP(l.IP).To4()
			if err != nil || len(mac) != 6 || ip == nil {
				return "", fmt.Errorf("lease %s/%s: not a MAC / IPv4 address", l.MAC, l.IP)
			}
			macs = append(macs, `"`+br+`" . `+mac.String())
			addrs = append(addrs, `"`+br+`" . `+mac.String()+" . "+ip.String())
		}
	}
	elems := func(e []string) string {
		if len(e) == 0 {
			return ""
		}
		return "    elements = { " + strings.Join(e, ", ") + " }\n"
	}
	var b strings.Builder
	b.WriteString("table bridge vdxfabric {}\ndelete table bridge vdxfabric\ntable bridge vdxfabric {\n")
	b.WriteString("  set segs {\n    type ifname\n" + elems(all) + "  }\n")
	b.WriteString("  set routed {\n    type ifname\n" + elems(routed) + "  }\n")
	b.WriteString("  set macs {\n    type ifname . ether_addr\n" + elems(macs) + "  }\n")
	b.WriteString("  set addrs {\n    type ifname . ether_addr . ipv4_addr\n" + elems(addrs) + "  }\n")
	b.WriteString("  set bum {\n    type ifname\n    flags dynamic\n    timeout 1m\n    size 4096\n  }\n")
	b.WriteString(`  chain port {
    iifname "vrh*" return
    meta ibrname != @routed return
    meta ibrname . ether saddr != @macs counter drop
    ether type arp arp saddr ip != 0.0.0.0 meta ibrname . arp saddr ether . arp saddr ip != @addrs counter drop
    ether type ip ip saddr != 0.0.0.0 meta ibrname . ether saddr . ip saddr != @addrs counter drop
    ether type ip udp sport 67 counter drop
    ether type ip6 icmpv6 type nd-router-advert counter drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "vxfv*" udp dport { 67, 68 } drop
    oifname "vxfv*" udp dport { 67, 68 } drop
    iifname != "vxfv*" meta ibrname "vxfb*" ether type { 8021q, 8021ad } drop
    iifname != "vxfv*" meta ibrname @segs ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 add @bum { iifname limit rate over ` + strconv.Itoa(GuardPolicePPS) + `/second burst ` + strconv.Itoa(GuardPolicePPS) + ` packets } counter drop
    iifname != "vxfv*" meta ibrname @segs jump port
  }
  chain input {
    type filter hook input priority -10; policy accept;
    iifname != "vxfv*" meta ibrname @segs jump port
  }
  chain output {
    type filter hook output priority -10; policy accept;
    oifname "vxfv*" udp dport { 67, 68 } drop
  }
}
`)
	return b.String(), nil
}
