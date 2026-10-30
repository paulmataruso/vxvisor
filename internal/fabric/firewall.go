package fabric

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// The distributed firewall (docs/FABRIC.md §14 D5): the connectivity table,
// rendered from the intent on every fabric host as `table inet vdxfabric`.
//
// Routing between port groups happens in the org's VRF on whichever host the
// traffic enters (symmetric IRB: the source host, then the destination host),
// and every host renders the same rules, so each hop enforces them. For a packet
// routed in a VRF the kernel reports the VRF device as the input interface (at
// forward and input alike), so the VRF name selects the org's chain; inside it
// rules match the port groups' subnets. Bridged traffic inside one port group
// never reaches the inet forward hook here (its input interface is a bridge
// port, never a VRF), so it stays allowed: a port group is a switch.
//
// Guests reach the host only for DHCP and ping of their gateway (arriving on the
// VRF); nothing from an L2-only port group's bridge (in no VRF) is delivered.

// FirewallTable is the nft table vdxd owns for the fabric.
const FirewallTable = "vdxfabric"

// Firewall renders node's distributed firewall. It is the empty table (load to
// remove) when the node isn't in a fabric.
func Firewall(in *Intent, node string) (string, error) {
	var b strings.Builder
	b.WriteString("table inet " + FirewallTable + " {}\ndelete table inet " + FirewallTable + "\n")
	f, _ := in.HostOf(node)
	if f == nil {
		return b.String(), nil
	}
	b.WriteString("table inet " + FirewallTable + " {\n")
	b.WriteString(`  chain input {
    type filter hook input priority filter - 5; policy accept;
    iifname "vxfvrf*" jump guest_in
    iifname "vxfb*" counter drop
  }
  chain guest_in {
    ct state established,related accept
    meta nfproto ipv4 udp sport 68 udp dport 67 accept
    meta nfproto ipv4 icmp type echo-request limit rate 50/second burst 100 packets accept
    counter drop
  }
  chain forward {
    type filter hook forward priority filter - 5; policy accept;
    iifname "vxfvrf*" tcp flags syn tcp option maxseg size set rt mtu
    iifname "vxfvrf*" jump routed
  }
  chain routed {
    ct state established,related accept
    ct state invalid drop
`)
	type orgKey = int64
	nets := map[orgKey][]string{}
	pgNet := map[string]string{}
	for _, p := range in.PGs {
		if p.Fabric != f.UUID || !p.Routed() {
			continue
		}
		_, n, err := net.ParseCIDR(p.CIDR)
		if err != nil {
			return "", fmt.Errorf("port group %s: %v", p.Name, err)
		}
		nets[p.Org] = append(nets[p.Org], n.String())
		pgNet[p.UUID] = n.String()
	}
	var orgs []int64
	for _, v := range in.VRFs {
		if v.Fabric == f.UUID {
			orgs = append(orgs, v.Org)
		}
	}
	sort.Slice(orgs, func(i, j int) bool { return orgs[i] < orgs[j] })
	for _, o := range orgs {
		fmt.Fprintf(&b, "    iifname %q jump org%d\n", VRFName(o), o)
	}
	b.WriteString("    counter drop\n  }\n")

	for _, o := range orgs {
		fmt.Fprintf(&b, "  chain org%d {\n", o)
		own := "{ " + strings.Join(sortedUniq(nets[o]), ", ") + " }"
		var rules []Rule
		for _, r := range in.Rules {
			if r.Fabric == f.UUID && r.Org == o && !r.Off {
				rules = append(rules, r)
			}
		}
		for _, r := range rules {
			match := func(src, dst string) string {
				var m []string
				if src == External {
					m = append(m, "ip saddr != "+own)
				} else {
					m = append(m, "ip saddr "+pgNet[src])
				}
				if dst == External {
					m = append(m, "ip daddr != "+own)
				} else {
					m = append(m, "ip daddr "+pgNet[dst])
				}
				switch r.Proto {
				case "icmp":
					m = append(m, "meta l4proto icmp")
				case "tcp", "udp":
					m = append(m, "meta l4proto "+r.Proto)
					if r.Ports != "" {
						m = append(m, r.Proto+" dport { "+strings.ReplaceAll(r.Ports, ",", ", ")+" }")
					}
				}
				return strings.Join(m, " ")
			}
			fmt.Fprintf(&b, "    %s counter accept comment %q\n", match(r.Src, r.Dst), "rule "+r.UUID[:8])
			if r.Both {
				fmt.Fprintf(&b, "    %s counter accept comment %q\n", match(r.Dst, r.Src), "rule "+r.UUID[:8])
			}
		}
		b.WriteString("    counter drop\n  }\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}

func sortedUniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// RuleSummary is a one-line description of a rule for lists and audit.
func RuleSummary(in *Intent, r Rule) string {
	name := func(id string) string {
		if id == External {
			return "External"
		}
		if p := in.PG(id); p != nil {
			return p.Name
		}
		return "?"
	}
	arrow := "→"
	if r.Both {
		arrow = "↔"
	}
	svc := r.Proto
	if r.Ports != "" {
		svc += "/" + r.Ports
	}
	return name(r.Src) + " " + arrow + " " + name(r.Dst) + " (" + svc + ")"
}

// Allowed evaluates the table for one flow: can src port group reach dst on
// proto/port? It is the policy view (the connectivity matrix), not the realized
// one.
func Allowed(in *Intent, src, dst, proto string, port int) bool {
	if src == dst {
		return true
	}
	for _, r := range in.Rules {
		if r.Off {
			continue
		}
		fwd := r.Src == src && r.Dst == dst
		rev := r.Both && r.Src == dst && r.Dst == src
		if !fwd && !rev {
			continue
		}
		switch {
		case r.Proto == "any":
			return true
		case r.Proto != proto:
			continue
		case r.Ports == "" || port == 0:
			return true
		}
		for _, part := range strings.Split(r.Ports, ",") {
			lo, hi, _ := strings.Cut(part, "-")
			a, _ := strconv.Atoi(lo)
			z := a
			if hi != "" {
				z, _ = strconv.Atoi(hi)
			}
			if port >= a && port <= z {
				return true
			}
		}
	}
	return false
}
