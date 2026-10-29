package routing

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Every value the managed renderers emit (frr.conf via text/template, the nft
// ruleset via string building) must be ONE token of the shape FRR / nft
// expects: a space or a newline in any field would splice arbitrary config into
// the file. The service layer checks input with these same helpers first (for a
// friendly error); Config.Validate is the backstop the renderers run before
// writing anything, and Sanitize cleans a stored config of entries that would
// fail it (so one bad legacy entry can't wedge every later change).

// MaxASN is the largest 4-byte AS number.
const MaxASN = 4294967295

const maxUint32 = 4294967295

var (
	reIface    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	reListName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	reHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	reVersion  = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){0,3}$`)
	rePorts    = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
	reAreaNum  = regexp.MustCompile(`^[0-9]{1,10}$`)
)

// IsIPv4 reports whether s is a dotted-quad IPv4 address (no prefix, no IPv6 or
// IPv4-mapped form).
func IsIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && !strings.Contains(s, ":")
}

// ParsePrefix parses an IPv4 network ("10.30.0.0/24"; "default" means
// 0.0.0.0/0) and returns it in canonical form (host bits cleared).
func ParsePrefix(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "default" {
		s = "0.0.0.0/0"
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil || strings.Contains(s, ":") {
		return nil, fmt.Errorf("%q is not an IPv4 network — use e.g. 10.30.0.0/24", s)
	}
	return n, nil
}

// CanonPrefix returns s as a canonical IPv4 prefix ("10.30.0.5/24" →
// "10.30.0.0/24", "default" → "0.0.0.0/0").
func CanonPrefix(s string) (string, error) {
	n, err := ParsePrefix(s)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

// ValidIfaceAddr checks an interface address in IP/prefix form; unlike a
// network, the host bits are the address and are kept (10.50.0.1/30).
func ValidIfaceAddr(s string) error {
	ip, _, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil || strings.Contains(s, ":") {
		return fmt.Errorf("%q is not an IPv4 address with prefix — use e.g. 10.50.0.1/30", s)
	}
	return nil
}

// ValidIface checks a Linux interface name (≤15 chars, no spaces or slashes).
func ValidIface(s string) error {
	if !reIface.MatchString(s) {
		return fmt.Errorf("%q is not a valid interface name", s)
	}
	return nil
}

// ValidRouterID checks a router ID: empty (FRR picks one) or an IPv4 address.
func ValidRouterID(s string) error {
	if s != "" && !IsIPv4(s) {
		return fmt.Errorf("router ID %q must be an IPv4 address (e.g. 1.1.1.1), or left blank", s)
	}
	return nil
}

// ValidNextHop checks a static route's next hop: an IPv4 gateway address or an
// interface name.
func ValidNextHop(s string) error {
	if IsIPv4(s) || reIface.MatchString(s) {
		return nil
	}
	return fmt.Errorf("next hop %q must be an IPv4 gateway address (e.g. 10.0.0.1) or an interface name", s)
}

// ValidArea checks an OSPF area: a number (0-4294967295) or dotted-quad form.
func ValidArea(s string) error {
	if reAreaNum.MatchString(s) {
		if n, err := strconv.ParseUint(s, 10, 64); err == nil && n <= maxUint32 {
			return nil
		}
	} else if IsIPv4(s) {
		return nil
	}
	return fmt.Errorf("OSPF area %q must be a number (e.g. 0) or dotted-quad (e.g. 0.0.0.0)", s)
}

// ValidASN checks a BGP AS number (1-4294967295).
func ValidASN(n int) error {
	if n < 1 || n > MaxASN {
		return fmt.Errorf("AS number %d is out of range (1-%d)", n, MaxASN)
	}
	return nil
}

// ValidPeer checks a BGP neighbor address (IPv4 or IPv6, no zone or prefix).
func ValidPeer(s string) error {
	if net.ParseIP(s) == nil {
		return fmt.Errorf("neighbor %q must be an IP address (e.g. 10.0.0.2)", s)
	}
	return nil
}

// ValidListName checks a prefix-list / route-map name.
func ValidListName(s string) error {
	if !reListName.MatchString(s) {
		return fmt.Errorf("name %q must be 1-63 letters, digits, dot, dash or underscore", s)
	}
	return nil
}

// ValidPorts checks an nft destination port or range ("443", "8000-8100").
func ValidPorts(s string) error {
	if !rePorts.MatchString(s) {
		return fmt.Errorf("port %q must be a number or range (e.g. 443 or 8000-8100)", s)
	}
	parts := strings.Split(s, "-")
	lo, _ := strconv.Atoi(parts[0])
	hi := lo
	if len(parts) == 2 {
		hi, _ = strconv.Atoi(parts[1])
	}
	if lo < 1 || hi > 65535 || hi < lo {
		return fmt.Errorf("port %q is out of range (1-65535)", s)
	}
	return nil
}

// ValidSource checks an nft source match: an IPv4 network or address.
func ValidSource(s string) error {
	if IsIPv4(s) {
		return nil
	}
	if _, err := ParsePrefix(s); err == nil && s != "default" {
		return nil
	}
	return fmt.Errorf("source %q must be an IPv4 address or network (e.g. 10.0.0.0/8)", s)
}

// ValidPrefixListEntry checks one prefix-list entry the way FRR does.
func ValidPrefixListEntry(pl PrefixList) error {
	if err := ValidListName(pl.Name); err != nil {
		return err
	}
	if pl.Seq < 1 || pl.Seq > maxUint32 {
		return fmt.Errorf("prefix-list %s: sequence %d is out of range (1-%d)", pl.Name, pl.Seq, maxUint32)
	}
	if pl.Action != "permit" && pl.Action != "deny" {
		return fmt.Errorf("prefix-list %s: action must be permit or deny", pl.Name)
	}
	if pl.Prefix == "any" {
		if pl.Ge != 0 || pl.Le != 0 {
			return fmt.Errorf("prefix-list %s: ge/le can't be used with \"any\"", pl.Name)
		}
		return nil
	}
	n, err := ParsePrefix(pl.Prefix)
	if err != nil || pl.Prefix == "default" {
		return fmt.Errorf("prefix-list %s: prefix %q must be an IPv4 network or \"any\"", pl.Name, pl.Prefix)
	}
	ones, _ := n.Mask.Size()
	if pl.Ge < 0 || pl.Ge > 32 || pl.Le < 0 || pl.Le > 32 {
		return fmt.Errorf("prefix-list %s: ge/le must be 1-32", pl.Name)
	}
	if pl.Ge != 0 && pl.Ge <= ones {
		return fmt.Errorf("prefix-list %s: ge must be longer than the prefix length /%d", pl.Name, ones)
	}
	if pl.Le != 0 && pl.Le < ones {
		return fmt.Errorf("prefix-list %s: le can't be shorter than the prefix length /%d", pl.Name, ones)
	}
	if pl.Ge != 0 && pl.Le != 0 && pl.Ge > pl.Le {
		return fmt.Errorf("prefix-list %s: ge can't be greater than le", pl.Name)
	}
	return nil
}

// ValidRouteMapClause checks one route-map clause.
func ValidRouteMapClause(rm RouteMapClause) error {
	if err := ValidListName(rm.Name); err != nil {
		return err
	}
	if rm.Seq < 1 || rm.Seq > 65535 {
		return fmt.Errorf("route-map %s: sequence %d is out of range (1-65535)", rm.Name, rm.Seq)
	}
	if rm.Action != "permit" && rm.Action != "deny" {
		return fmt.Errorf("route-map %s: action must be permit or deny", rm.Name)
	}
	if rm.MatchPrefixList != "" {
		if err := ValidListName(rm.MatchPrefixList); err != nil {
			return fmt.Errorf("route-map %s: match %w", rm.Name, err)
		}
	}
	if rm.SetMetric < 0 || rm.SetMetric > maxUint32 || rm.SetLocalPref < 0 || rm.SetLocalPref > maxUint32 {
		return fmt.Errorf("route-map %s: metric / local-preference must be 0-%d", rm.Name, maxUint32)
	}
	return nil
}

// ValidFirewallRule checks one host edge firewall rule.
func ValidFirewallRule(r FirewallRule) error {
	if r.Action != "accept" && r.Action != "drop" {
		return fmt.Errorf("firewall action must be accept or drop")
	}
	if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("firewall protocol must be tcp, udp or any")
	}
	if r.DPort != "" {
		if r.Proto == "" {
			return fmt.Errorf("a destination port needs protocol tcp or udp")
		}
		if err := ValidPorts(r.DPort); err != nil {
			return err
		}
	}
	if r.Source != "" {
		return ValidSource(r.Source)
	}
	return nil
}

func validStatic(r Route) error {
	if _, err := ParsePrefix(r.Dest); err != nil {
		return fmt.Errorf("destination %w", err)
	}
	return ValidNextHop(r.NextHop)
}

func validNeighbor(nb Neighbor) error {
	if err := ValidPeer(nb.Addr); err != nil {
		return err
	}
	if err := ValidASN(nb.RemoteAS); err != nil {
		return fmt.Errorf("neighbor %s: remote %w", nb.Addr, err)
	}
	for _, n := range []string{nb.RouteMapIn, nb.RouteMapOut, nb.PrefixListOut} {
		if n != "" {
			if err := ValidListName(n); err != nil {
				return fmt.Errorf("neighbor %s: %w", nb.Addr, err)
			}
		}
	}
	return nil
}

func validNetwork(s string) error {
	if _, err := ParsePrefix(s); err != nil || s == "default" {
		return fmt.Errorf("network %q must be an IPv4 network (e.g. 10.0.0.0/24)", s)
	}
	return nil
}

// Validate checks every value the renderers emit. Only rendered sections are
// checked: a disabled protocol's leftover settings never reach the file.
func (c Config) Validate() error {
	if c.Hostname != "" && !reHostname.MatchString(c.Hostname) {
		return fmt.Errorf("hostname %q is not a valid host name", c.Hostname)
	}
	if c.FRRVersion != "" && !reVersion.MatchString(c.FRRVersion) {
		return fmt.Errorf("FRR version %q is not a version number", c.FRRVersion)
	}
	if c.Uplink != "" {
		if err := ValidIface(c.Uplink); err != nil {
			return fmt.Errorf("uplink: %w", err)
		}
	}
	for _, cidr := range c.InternalCIDRs {
		if cidr == "" {
			continue
		}
		if err := validNetwork(cidr); err != nil {
			return fmt.Errorf("NAT %w", err)
		}
	}
	for i, p := range c.Prefixes {
		if p.Iface == "" && p.CIDR == "" {
			continue
		}
		if err := ValidIface(p.Iface); err != nil {
			return fmt.Errorf("interface address %d: %w", i+1, err)
		}
		if err := ValidIfaceAddr(p.CIDR); err != nil {
			return fmt.Errorf("interface %s: %w", p.Iface, err)
		}
	}
	for i, r := range c.Static {
		if err := validStatic(r); err != nil {
			return fmt.Errorf("static route %d: %w", i+1, err)
		}
	}
	for i, r := range c.Firewall {
		if err := ValidFirewallRule(r); err != nil {
			return fmt.Errorf("firewall rule %d: %w", i+1, err)
		}
	}
	for _, pl := range c.PrefixLists {
		if err := ValidPrefixListEntry(pl); err != nil {
			return err
		}
	}
	for _, rm := range c.RouteMaps {
		if err := ValidRouteMapClause(rm); err != nil {
			return err
		}
	}
	if c.OSPF.Enabled {
		if err := ValidRouterID(c.OSPF.RouterID); err != nil {
			return fmt.Errorf("OSPF %w", err)
		}
		for _, n := range c.OSPF.Networks {
			if err := validNetwork(n.CIDR); err != nil {
				return fmt.Errorf("OSPF %w", err)
			}
			if err := ValidArea(n.Area); err != nil {
				return err
			}
		}
		for _, ifc := range c.OSPF.Passive {
			if err := ValidIface(ifc); err != nil {
				return fmt.Errorf("OSPF passive %w", err)
			}
		}
	}
	if c.BGP.Enabled {
		if err := ValidASN(c.BGP.ASN); err != nil {
			return fmt.Errorf("BGP local %w", err)
		}
		if err := ValidRouterID(c.BGP.RouterID); err != nil {
			return fmt.Errorf("BGP %w", err)
		}
		for _, nb := range c.BGP.Neighbors {
			if err := validNeighbor(nb); err != nil {
				return fmt.Errorf("BGP %w", err)
			}
		}
		for _, n := range c.BGP.Networks {
			if err := validNetwork(n); err != nil {
				return fmt.Errorf("BGP %w", err)
			}
		}
	}
	if c.EIGRP.Enabled {
		if c.EIGRP.ASN < 1 || c.EIGRP.ASN > 65535 {
			return fmt.Errorf("EIGRP AS number %d is out of range (1-65535)", c.EIGRP.ASN)
		}
		if err := ValidRouterID(c.EIGRP.RouterID); err != nil {
			return fmt.Errorf("EIGRP %w", err)
		}
		for _, n := range c.EIGRP.Networks {
			if err := validNetwork(n); err != nil {
				return fmt.Errorf("EIGRP %w", err)
			}
		}
	}
	return nil
}

// Sanitize returns a copy of c with surrounding spaces trimmed, "default"
// destinations normalized to 0.0.0.0/0, and every entry Validate would reject
// dropped (an invalid router ID is cleared; a protocol with an invalid AS
// number is turned off). The second result describes what was dropped, for
// the caller to log. Validate always passes on the result.
func Sanitize(c Config) (Config, []string) {
	var dropped []string
	drop := func(format string, a ...any) { dropped = append(dropped, fmt.Sprintf(format, a...)) }
	out := c
	out.Hostname = strings.TrimSpace(c.Hostname)
	if out.Hostname != "" && !reHostname.MatchString(out.Hostname) {
		drop("hostname %q", c.Hostname)
		out.Hostname = ""
	}
	out.FRRVersion = strings.TrimSpace(c.FRRVersion)
	if out.FRRVersion != "" && !reVersion.MatchString(out.FRRVersion) {
		drop("FRR version %q", c.FRRVersion)
		out.FRRVersion = ""
	}
	out.Uplink = strings.TrimSpace(c.Uplink)
	if out.Uplink != "" && ValidIface(out.Uplink) != nil {
		drop("uplink %q", c.Uplink)
		out.Uplink = ""
	}
	out.InternalCIDRs = nil
	for _, s := range c.InternalCIDRs {
		if s = strings.TrimSpace(s); s != "" && validNetwork(s) == nil {
			out.InternalCIDRs = append(out.InternalCIDRs, s)
		} else if s != "" {
			drop("NAT network %q", s)
		}
	}
	out.Prefixes = nil
	for _, p := range c.Prefixes {
		p.Iface, p.CIDR = strings.TrimSpace(p.Iface), strings.TrimSpace(p.CIDR)
		if p.Iface == "" && p.CIDR == "" {
			continue
		}
		if ValidIface(p.Iface) == nil && ValidIfaceAddr(p.CIDR) == nil {
			out.Prefixes = append(out.Prefixes, p)
		} else {
			drop("interface address %q on %q", p.CIDR, p.Iface)
		}
	}
	out.Static = nil
	for _, r := range c.Static {
		r.Dest, r.NextHop = strings.TrimSpace(r.Dest), strings.TrimSpace(r.NextHop)
		if r.Dest == "default" {
			r.Dest = "0.0.0.0/0"
		}
		if validStatic(r) == nil {
			out.Static = append(out.Static, r)
		} else {
			drop("static route %q via %q", r.Dest, r.NextHop)
		}
	}
	out.Firewall = nil
	for _, r := range c.Firewall {
		r.Action, r.Proto = strings.TrimSpace(r.Action), strings.TrimSpace(r.Proto)
		r.DPort, r.Source = strings.TrimSpace(r.DPort), strings.TrimSpace(r.Source)
		if ValidFirewallRule(r) == nil {
			out.Firewall = append(out.Firewall, r)
		} else {
			drop("firewall rule %+v", r)
		}
	}
	out.PrefixLists = nil
	for _, pl := range c.PrefixLists {
		pl.Name, pl.Action, pl.Prefix = strings.TrimSpace(pl.Name), strings.TrimSpace(pl.Action), strings.TrimSpace(pl.Prefix)
		if ValidPrefixListEntry(pl) == nil {
			out.PrefixLists = append(out.PrefixLists, pl)
		} else {
			drop("prefix-list entry %+v", pl)
		}
	}
	out.RouteMaps = nil
	for _, rm := range c.RouteMaps {
		rm.Name, rm.Action, rm.MatchPrefixList = strings.TrimSpace(rm.Name), strings.TrimSpace(rm.Action), strings.TrimSpace(rm.MatchPrefixList)
		if ValidRouteMapClause(rm) == nil {
			out.RouteMaps = append(out.RouteMaps, rm)
		} else {
			drop("route-map clause %+v", rm)
		}
	}

	out.OSPF.RouterID = strings.TrimSpace(c.OSPF.RouterID)
	if ValidRouterID(out.OSPF.RouterID) != nil {
		drop("OSPF router ID %q", c.OSPF.RouterID)
		out.OSPF.RouterID = ""
	}
	out.OSPF.Networks = nil
	for _, n := range c.OSPF.Networks {
		n.CIDR, n.Area = strings.TrimSpace(n.CIDR), strings.TrimSpace(n.Area)
		if validNetwork(n.CIDR) == nil && ValidArea(n.Area) == nil {
			out.OSPF.Networks = append(out.OSPF.Networks, n)
		} else {
			drop("OSPF network %q area %q", n.CIDR, n.Area)
		}
	}
	out.OSPF.Passive = nil
	for _, ifc := range c.OSPF.Passive {
		if ifc = strings.TrimSpace(ifc); ValidIface(ifc) == nil {
			out.OSPF.Passive = append(out.OSPF.Passive, ifc)
		} else {
			drop("OSPF passive interface %q", ifc)
		}
	}

	out.BGP.RouterID = strings.TrimSpace(c.BGP.RouterID)
	if ValidRouterID(out.BGP.RouterID) != nil {
		drop("BGP router ID %q", c.BGP.RouterID)
		out.BGP.RouterID = ""
	}
	if out.BGP.Enabled && ValidASN(out.BGP.ASN) != nil {
		drop("BGP (invalid local AS %d — turned off)", c.BGP.ASN)
		out.BGP.Enabled = false
	}
	out.BGP.Neighbors = nil
	for _, nb := range c.BGP.Neighbors {
		nb.Addr = strings.TrimSpace(nb.Addr)
		nb.RouteMapIn, nb.RouteMapOut = strings.TrimSpace(nb.RouteMapIn), strings.TrimSpace(nb.RouteMapOut)
		nb.PrefixListOut = strings.TrimSpace(nb.PrefixListOut)
		if validNeighbor(nb) == nil {
			out.BGP.Neighbors = append(out.BGP.Neighbors, nb)
		} else {
			drop("BGP neighbor %q (AS %d)", nb.Addr, nb.RemoteAS)
		}
	}
	out.BGP.Networks = nil
	for _, n := range c.BGP.Networks {
		if n = strings.TrimSpace(n); validNetwork(n) == nil {
			out.BGP.Networks = append(out.BGP.Networks, n)
		} else {
			drop("BGP network %q", n)
		}
	}

	out.EIGRP.RouterID = strings.TrimSpace(c.EIGRP.RouterID)
	if ValidRouterID(out.EIGRP.RouterID) != nil {
		drop("EIGRP router ID %q", c.EIGRP.RouterID)
		out.EIGRP.RouterID = ""
	}
	if out.EIGRP.Enabled && (out.EIGRP.ASN < 1 || out.EIGRP.ASN > 65535) {
		drop("EIGRP (invalid AS %d — turned off)", c.EIGRP.ASN)
		out.EIGRP.Enabled = false
	}
	out.EIGRP.Networks = nil
	for _, n := range c.EIGRP.Networks {
		if n = strings.TrimSpace(n); validNetwork(n) == nil {
			out.EIGRP.Networks = append(out.EIGRP.Networks, n)
		} else {
			drop("EIGRP network %q", n)
		}
	}
	return out, dropped
}
