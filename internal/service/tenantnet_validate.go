package service

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/vrouter"
)

// Validation of what a tenant types for a port group's addressing, and the
// host-subnet overlap guard. Everything here ends up on a host interface or in
// a dnsmasq config, so nothing is accepted that doesn't parse as exactly what it
// claims to be; netdrv.RenderTenantDHCPConf re-checks at the sink.

// defaultTenantDNS is what DHCP hands out when the tenant names no resolvers.
const defaultTenantDNS = "1.1.1.1,8.8.8.8"

// tenantL3 is a port group's addressing: its subnet, the host gateway on it (a
// standalone port group's), and the DHCP the host serves from that gateway.
type tenantL3 struct {
	CIDR, Gateway string
	DHCP          bool
	Range         string // dnsmasq's "start,end"
	DNS           string // "a,b"
}

// parseTenantL3 validates a port group's addressing and returns it normalized:
// an IPv4 subnet; a gateway inside it that isn't its network or broadcast
// address; and, with DHCP, a range inside the subnet (start ≤ end) that doesn't
// include the gateway, plus a list of IPv4 resolvers (default 1.1.1.1, 8.8.8.8).
// The range may be "A.B.C.X-Y", "start-end" or "start,end".
func parseTenantL3(cidr, gateway string, dhcp bool, dhcpRange, dns string) (tenantL3, error) {
	cidr, gateway = strings.TrimSpace(cidr), strings.TrimSpace(gateway)
	if cidr == "" {
		if gateway != "" {
			return tenantL3{}, fmt.Errorf("a gateway needs the subnet (CIDR) it sits in")
		}
		if dhcp {
			return tenantL3{}, fmt.Errorf("DHCP needs a subnet and a gateway (the host serves DHCP from the gateway address)")
		}
		return tenantL3{}, nil
	}
	_, sn, err := net.ParseCIDR(cidr)
	if err != nil || sn.IP.To4() == nil || strings.Contains(cidr, ":") {
		return tenantL3{}, fmt.Errorf("subnet %q isn't an IPv4 CIDR — use the form 10.50.0.0/24", cidr)
	}
	if ip := sn.IP; ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.Equal(net.IPv4bcast) {
		return tenantL3{}, fmt.Errorf("subnet %s is a reserved range — use a private range such as 10.50.0.0/24", sn)
	}
	out := tenantL3{CIDR: sn.String()}
	ones, _ := sn.Mask.Size()
	netAddr, bcast := ipv4Uint(sn.IP), ipv4Uint(sn.IP)|^ipv4Uint(net.IP(sn.Mask))
	hostAddr := func(what, s string) (uint32, error) {
		ip := parseIPv4(s)
		if ip == nil || !sn.Contains(ip) {
			return 0, fmt.Errorf("%s %q is not an IPv4 address inside %s", what, s, sn)
		}
		if v := ipv4Uint(ip); v == netAddr || v == bcast {
			return 0, fmt.Errorf("%s %s is the network or broadcast address of %s — use an address between them", what, s, sn)
		}
		return ipv4Uint(ip), nil
	}
	var gw uint32
	if gateway != "" {
		if ones > 30 {
			return tenantL3{}, fmt.Errorf("a /%d has no room for a gateway — use a /30 or larger subnet", ones)
		}
		if gw, err = hostAddr("gateway", gateway); err != nil {
			return tenantL3{}, err
		}
		out.Gateway = parseIPv4(gateway).String()
	}
	if !dhcp {
		return out, nil
	}
	if out.Gateway == "" {
		return tenantL3{}, fmt.Errorf("DHCP needs a gateway (the host serves DHCP from the gateway address) — set one, or turn DHCP off")
	}
	norm := vrouter.NormalizeDHCPRange(strings.TrimSpace(dhcpRange))
	if norm == "" {
		return tenantL3{}, fmt.Errorf("a DHCP range is required when DHCP is on (e.g. 10.50.0.100-200)")
	}
	parts := strings.Split(norm, ",")
	if len(parts) != 2 {
		return tenantL3{}, fmt.Errorf("DHCP range must be start-end (e.g. 10.50.0.100-200 or 10.50.0.100,10.50.0.200) — got %q", dhcpRange)
	}
	start, err := hostAddr("DHCP range start", strings.TrimSpace(parts[0]))
	if err != nil {
		return tenantL3{}, err
	}
	end, err := hostAddr("DHCP range end", strings.TrimSpace(parts[1]))
	if err != nil {
		return tenantL3{}, err
	}
	if start > end {
		return tenantL3{}, fmt.Errorf("DHCP range %s starts after it ends", dhcpRange)
	}
	if gw >= start && gw <= end {
		return tenantL3{}, fmt.Errorf("DHCP range %s includes the gateway %s — keep the gateway outside the range", dhcpRange, out.Gateway)
	}
	out.DHCP = true
	out.Range = uintIPv4(start).String() + "," + uintIPv4(end).String()
	out.DNS, err = parseDNSList(dns)
	return out, err
}

// parseDNSList normalizes a list of IPv4 resolvers (comma or space separated)
// to "a,b"; empty means the default.
func parseDNSList(dns string) (string, error) {
	f := strings.FieldsFunc(dns, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	if len(f) == 0 {
		return defaultTenantDNS, nil
	}
	if len(f) > 4 {
		return "", fmt.Errorf("at most 4 DNS servers")
	}
	for i, d := range f {
		ip := parseIPv4(d)
		if ip == nil {
			return "", fmt.Errorf("DNS server %q isn't an IPv4 address", d)
		}
		f[i] = ip.String()
	}
	return strings.Join(f, ","), nil
}

// defaultDHCPRange picks a DHCP range inside cidr that leaves out gateway: .100-
// .200 of the subnet when it is a /24 or larger (the long-standing default),
// else its upper half, else its lower half. "" if there's no room.
func defaultDHCPRange(cidr, gateway string) string {
	_, sn, err := net.ParseCIDR(cidr)
	if err != nil || sn.IP.To4() == nil {
		return ""
	}
	ones, _ := sn.Mask.Size()
	if ones > 30 {
		return ""
	}
	netAddr := ipv4Uint(sn.IP)
	bcast := netAddr | ^ipv4Uint(net.IP(sn.Mask))
	var gw uint32
	if ip := parseIPv4(gateway); ip != nil {
		gw = ipv4Uint(ip)
	}
	size := bcast - netAddr + 1
	var cands [][2]uint32
	if size >= 256 {
		cands = append(cands, [2]uint32{netAddr + 100, netAddr + 200})
	}
	cands = append(cands, [2]uint32{netAddr + size/2, bcast - 1}, [2]uint32{netAddr + 1, netAddr + size/2 - 1})
	for _, c := range cands {
		if c[0] > c[1] || (gw >= c[0] && gw <= c[1]) {
			continue
		}
		return uintIPv4(c[0]).String() + "," + uintIPv4(c[1]).String()
	}
	return ""
}

// sameAddr reports whether two addressings have the same subnet and gateway,
// however each was written (an edit form posts back what was saved).
func sameAddr(a, b tenantL3) bool {
	canonNet := func(s string) string {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
			return n.String()
		}
		return strings.TrimSpace(s)
	}
	canonIP := func(s string) string {
		if ip := parseIPv4(strings.TrimSpace(s)); ip != nil {
			return ip.String()
		}
		return strings.TrimSpace(s)
	}
	return canonNet(a.CIDR) == canonNet(b.CIDR) && canonIP(a.Gateway) == canonIP(b.Gateway)
}

// validTenantName checks a vSwitch / port group name.
func validTenantName(name, what string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "/\n\r\t") {
		return "", fmt.Errorf("a %s name is required (up to 64 characters, no '/')", what)
	}
	return name, nil
}

// ---- host subnets ----------------------------------------------------------

// hostSubnet is a subnet the host itself is on (an interface address) or
// routes to, with the interface that has it.
type hostSubnet struct {
	Dev string
	Net *net.IPNet
}

// hostSubnets lists the host's IPv4 subnets. A variable so tests can stand in
// for the machine they run on.
var hostSubnets = listHostSubnets

// listHostSubnets reads every IPv4 interface address and every unicast route
// (all routing tables) on the host, except on tenant interfaces (vdxt*: the
// tenant bridges and port-group interfaces, whose subnets are the tenants'
// own) and the default route.
func listHostSubnets() ([]hostSubnet, error) {
	var out []hostSubnet
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, it := range ifs {
		if strings.HasPrefix(it.Name, "vdxt") {
			continue
		}
		for _, a := range it.Addrs {
			if _, n, err := net.ParseCIDR(a); err == nil && n.IP.To4() != nil {
				out = append(out, hostSubnet{Dev: it.Name, Net: n})
			}
		}
	}
	raw, err := exec.Command("ip", "-j", "-4", "route", "show", "table", "all", "type", "unicast").Output()
	if err != nil {
		return nil, fmt.Errorf("read host routes: %w", err)
	}
	var routes []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("parse host routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst == "default" || r.Dst == "" || strings.HasPrefix(r.Dev, "vdxt") {
			continue
		}
		dst := r.Dst
		if !strings.Contains(dst, "/") {
			dst += "/32"
		}
		if _, n, err := net.ParseCIDR(dst); err == nil && n.IP.To4() != nil {
			if ones, _ := n.Mask.Size(); ones > 0 {
				out = append(out, hostSubnet{Dev: r.Dev, Net: n})
			}
		}
	}
	return out, nil
}

// overlapsHost returns the first host subnet cidr overlaps (nil if none).
func overlapsHost(cidr string, host []hostSubnet) *hostSubnet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	for i := range host {
		if h := host[i].Net; h.Contains(n.IP) || n.Contains(h.IP) {
			return &host[i]
		}
	}
	return nil
}

// checkHostOverlap refuses a tenant subnet that overlaps one the host itself is
// on or routes to — management, storage, cluster, anything outside tenant
// networking. The host holds a standalone port group's gateway on the tenant
// bridge, so an overlap adds a competing connected route (on the management
// subnet: one that can cut the host off). Tenant subnets may overlap each
// other: each lives on its own isolated bridge. detail names the host network
// (instance admins only; a tenant isn't told the host's addressing).
func checkHostOverlap(cidr string, detail bool) error {
	if cidr == "" {
		return nil
	}
	host, err := hostSubnets()
	if err != nil {
		return fmt.Errorf("can't read the host's networks to check %s against them: %w", cidr, err)
	}
	h := overlapsHost(cidr, host)
	if h == nil {
		return nil
	}
	if detail {
		return fmt.Errorf("subnet %s overlaps the host's network %s (on %s) — pick a subnet the host doesn't use", cidr, h.Net, h.Dev)
	}
	return fmt.Errorf("subnet %s overlaps a network the host itself uses — pick a different private range", cidr)
}

func parseIPv4(s string) net.IP {
	if strings.Contains(s, ":") {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4()
	}
	return nil
}

func ipv4Uint(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func uintIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}
