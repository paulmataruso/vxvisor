package vrouter

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"vdxclone/internal/routing"
)

// Zone-based firewall (ZBFW) for a vRouter.
//
// A vRouter already forwards between its internal port groups (eth1..N) and the
// transit/WAN leg (eth0), and each runtime (LXC container / netns) has its OWN
// isolated netfilter instance. That makes the vRouter's `forward` chain the
// natural zone-firewall enforcement point: zones are sets of legs (interfaces),
// and a policy is an iifname→oifname match. We render a single table
// `inet vdxfw` with ONE base chain hooked on `forward` (default drop) and apply
// it inside the runtime via PushFirewall. input/output are untouched, so the
// vRouter's own control plane (BGP/OSPF/vtysh/dnsmasq/SSH) is unaffected.
//
// HOST-SAFETY: like the rest of this package, nothing here touches the host nft
// table `inet vdxclone`. RenderFirewall is pure; the backend applies the string
// only inside the runtime.

// ExternalZone is the built-in zone name for the transit leg (eth0) — the
// WAN/Internet side. It is auto-created and cannot be deleted.
const ExternalZone = "External"

// FWTable is the nftables table name used inside each vRouter runtime.
const FWTable = "vdxfw"

// VRZone is a security zone: a named label owning one or more legs (by idx).
type VRZone struct {
	Name    string `json:"name"`
	Legs    []int  `json:"legs"`    // leg indexes (ethN) that belong to this zone; 0 = transit
	Builtin bool   `json:"builtin"` // the auto-created External zone (not deletable)
}

// VRPolicy is one ordered zone-pair rule (first match wins; default = drop).
type VRPolicy struct {
	From   string `json:"from"`   // source zone name
	To     string `json:"to"`     // destination zone name
	Action string `json:"action"` // allow | deny
	Proto  string `json:"proto"`  // any | tcp | udp | icmp
	DPort  string `json:"dport"`  // "", "80", or "80-90" (tcp/udp only)
	Src    string `json:"src"`    // optional VM-level narrowing: CIDR, IP, or MAC
	Dst    string `json:"dst"`    // optional VM-level narrowing: CIDR or IP
	Desc   string `json:"desc"`
}

// VRFirewall is the whole per-vRouter firewall config (stored in vrouters.fw_json).
type VRFirewall struct {
	Enabled    bool       `json:"enabled"`
	AllowIntra bool       `json:"allow_intra"` // same-zone traffic passes by default
	Zones      []VRZone   `json:"zones"`
	Policies   []VRPolicy `json:"policies"`
}

// ZoneByName returns a pointer to the named zone (case-insensitive), or nil.
func (f *VRFirewall) ZoneByName(name string) *VRZone {
	for i := range f.Zones {
		if strings.EqualFold(f.Zones[i].Name, name) {
			return &f.Zones[i]
		}
	}
	return nil
}

var (
	reDPort    = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)
	reZoneName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$`)
)

// ValidZoneName checks a zone label is a safe, bounded string. Zone names never
// reach nft (we resolve them to ethN ifaces), so the charset is lenient, but we
// still bound length and keep it printable.
func ValidZoneName(name string) error {
	if !reZoneName.MatchString(strings.TrimSpace(name)) {
		return fmt.Errorf("zone name must be 1–32 chars of letters, digits, space, dash, dot or underscore")
	}
	return nil
}

// ValidatePolicy strictly checks a policy BEFORE it is persisted/rendered. The
// only user strings that reach the nft ruleset are DPort/Src/Dst (ifaces are
// derived from leg indexes we control), so those are validated hard to prevent
// ruleset breakage or injection.
func ValidatePolicy(f *VRFirewall, pol VRPolicy) error {
	if strings.TrimSpace(pol.From) == "" || strings.TrimSpace(pol.To) == "" {
		return fmt.Errorf("a policy needs both a source and a destination zone")
	}
	if f.ZoneByName(pol.From) == nil {
		return fmt.Errorf("unknown source zone %q", pol.From)
	}
	if f.ZoneByName(pol.To) == nil {
		return fmt.Errorf("unknown destination zone %q", pol.To)
	}
	switch pol.Action {
	case "allow", "deny":
	default:
		return fmt.Errorf("action must be allow or deny")
	}
	switch pol.Proto {
	case "", "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("protocol must be any, tcp, udp or icmp")
	}
	if dp := strings.TrimSpace(pol.DPort); dp != "" {
		if pol.Proto != "tcp" && pol.Proto != "udp" {
			return fmt.Errorf("a destination port needs protocol tcp or udp")
		}
		if !reDPort.MatchString(dp) {
			return fmt.Errorf("destination port must be a number or range (e.g. 80 or 8000-8100)")
		}
		for _, part := range strings.Split(dp, "-") {
			n, _ := strconv.Atoi(part)
			if n < 1 || n > 65535 {
				return fmt.Errorf("port %s is out of range (1–65535)", part)
			}
		}
	}
	if err := validMatch(pol.Src, true); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if err := validMatch(pol.Dst, false); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	return nil
}

// validMatch accepts "" (any), a CIDR, a bare IP, or (source only) a MAC.
func validMatch(s string, allowMAC bool) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if allowMAC {
		if _, err := net.ParseMAC(s); err == nil {
			return nil
		}
		return fmt.Errorf("%q is not a valid CIDR, IP or MAC address", s)
	}
	return fmt.Errorf("%q is not a valid CIDR or IP address", s)
}

// isMAC reports whether s parses as a hardware address.
func isMAC(s string) bool { _, err := net.ParseMAC(strings.TrimSpace(s)); return err == nil }

// renderablePolicy re-checks, at the sink, the policy fields that reach the nft
// ruleset as text (ValidatePolicy also checks zones, which a compiled policy
// carries as internal leg keys).
func renderablePolicy(pol VRPolicy) error {
	if pol.Action != "allow" && pol.Action != "deny" {
		return fmt.Errorf("action %q must be allow or deny", pol.Action)
	}
	switch pol.Proto {
	case "", "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("protocol %q must be any, tcp, udp or icmp", pol.Proto)
	}
	if dp := strings.TrimSpace(pol.DPort); dp != "" {
		if pol.Proto != "tcp" && pol.Proto != "udp" {
			return fmt.Errorf("a destination port needs protocol tcp or udp")
		}
		if !reDPort.MatchString(dp) {
			return fmt.Errorf("destination port %q must be a number or range", dp)
		}
	}
	if err := validMatch(pol.Src, true); err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if err := validMatch(pol.Dst, false); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	return nil
}

// RenderFirewall builds the `inet vdxfw` ruleset for a vRouter. It returns ""
// when the firewall is disabled or resolves to no enforceable zones (the caller
// then removes the table). Only the forward chain is hooked; policy is drop.
// A policy with a value that isn't a single valid token fails the whole render
// (nothing is pushed) rather than splicing text into the ruleset.
func RenderFirewall(vr VRouter, legs []Leg, f VRFirewall) (string, error) {
	if !f.Enabled {
		return "", nil
	}
	for i, pol := range f.Policies {
		if err := renderablePolicy(pol); err != nil {
			return "", fmt.Errorf("gateway firewall policy %d: %w", i+1, err)
		}
	}
	// Which leg indexes actually exist, and their iface names.
	ifaceByIdx := map[int]string{}
	for _, l := range legs {
		if routing.ValidIface(l.IfaceName) == nil {
			ifaceByIdx[l.Idx] = l.IfaceName
		}
	}
	// Resolve each zone to its set of existing ifaces. The built-in External zone
	// always maps to the transit leg(s), resolved live (so membership is never
	// stale after a transit link is added or changed).
	zoneIfaces := map[string][]string{}
	for _, z := range f.Zones {
		idxs := z.Legs
		if z.Builtin {
			idxs = nil
			for _, l := range legs {
				if l.Kind == LegTransit || l.Kind == LegUplink {
					idxs = append(idxs, l.Idx)
				}
			}
		}
		var ifs []string
		for _, idx := range idxs {
			if name := ifaceByIdx[idx]; name != "" {
				ifs = append(ifs, name)
			}
		}
		if len(ifs) > 0 {
			zoneIfaces[z.Name] = ifs
		}
	}

	var b strings.Builder
	b.WriteString("table inet " + FWTable + " {\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter; policy drop;\n")
	b.WriteString("    ct state invalid drop\n")
	b.WriteString("    ct state established,related accept\n")
	// Same-zone passthrough (VMs in one zone talk freely) when enabled.
	if f.AllowIntra {
		for _, z := range f.Zones {
			ifs := zoneIfaces[z.Name]
			if len(ifs) == 0 {
				continue
			}
			set := ifaceSet(ifs)
			fmt.Fprintf(&b, "    iifname %s oifname %s accept\n", set, set)
		}
	}
	// Ordered policies — first match wins; the chain's drop policy denies the rest.
	for _, pol := range f.Policies {
		from := zoneIfaces[pol.From]
		to := zoneIfaces[pol.To]
		if len(from) == 0 || len(to) == 0 {
			continue // a zone with no (existing) legs can't be enforced
		}
		line := "    iifname " + ifaceSet(from) + " oifname " + ifaceSet(to)
		if src := strings.TrimSpace(pol.Src); src != "" {
			if isMAC(src) {
				line += " ether saddr " + src
			} else {
				line += " ip saddr " + src
			}
		}
		if dst := strings.TrimSpace(pol.Dst); dst != "" {
			line += " ip daddr " + dst
		}
		switch pol.Proto {
		case "tcp", "udp":
			line += " " + pol.Proto
			if dp := strings.TrimSpace(pol.DPort); dp != "" {
				line += " dport " + dp
			}
		case "icmp":
			line += " ip protocol icmp"
		}
		if pol.Action == "deny" {
			line += " drop"
		} else {
			line += " accept"
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// DenyAllFirewall is the ruleset pushed instead when a router's firewall config
// can't be rendered: nothing is forwarded until the config is fixed (input and
// output are untouched, so the router's own control plane keeps working). A
// gateway firewall never fails open.
func DenyAllFirewall() string {
	return "table inet " + FWTable + " {\n  chain forward {\n" +
		"    type filter hook forward priority filter; policy drop;\n  }\n}\n"
}

// ifaceSet renders a single iface as "eth0" and several as { "eth1", "eth2" }.
func ifaceSet(ifs []string) string {
	if len(ifs) == 1 {
		return `"` + ifs[0] + `"`
	}
	q := make([]string, len(ifs))
	for i, s := range ifs {
		q[i] = `"` + s + `"`
	}
	return "{ " + strings.Join(q, ", ") + " }"
}
