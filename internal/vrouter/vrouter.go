// Package vrouter implements NSX-lite virtual routers: per-tenant routing
// instances that route between a "transit link" (a free physical NIC) and one
// or more internal-only port groups that VMs attach to.
//
// A vRouter runs in one of two v1 runtimes behind a common Backend interface:
//   - lxc:   a privileged LXC container running its own FRR
//   - netns: a Linux network namespace running a per-namespace FRR instance
//
// (A third runtime, "vm" — a QEMU appliance from a user-supplied image for a
// future cluster edge-host — is reserved and rejected at the service layer; it
// needs multi-NIC VM support that does not exist yet.)
//
// HOST-SAFETY INVARIANT: nothing in this package may call the host routing
// writers (routing.Apply/ApplyFRR/ApplyNAT/EnableForwarding/FRRStatus). A
// vRouter owns only its own runtime's FRR config and its own bridges/veths; it
// must never touch the host /etc/frr/frr.conf or the host "inet vdxclone" nft
// table. We reuse ONLY the pure renderer routing.RenderFRR.
package vrouter

import (
	"fmt"
	"net"
	"strings"

	"vdxclone/internal/routing"
)

// Runtime kinds.
const (
	RuntimeLXC   = "lxc"
	RuntimeNetns = "netns"
	RuntimeVM    = "vm" // reserved for a later release
)

// Leg roles.
const (
	LegTransit  = "transit"
	LegInternal = "internal"
	// LegUplink is a tenant-networking-v3 external leg backed by an admin uplink
	// (a VLAN subinterface or dedicated NIC enslaved to the leg bridge) rather than
	// a raw physical transit NIC. Kept distinct from LegTransit so the phys-NIC-only
	// guards (tenant can't delete a transit-bearing router; transit teardown keys on
	// phys_iface) don't misfire — a tenant may delete an uplink-backed router.
	LegUplink = "uplink"
)

// VRouter mirrors a vrouters row.
type VRouter struct {
	ID            int64
	OrgID         int64
	OwnerID       int64
	Name          string
	Runtime       string
	ContainerName string
	NetnsName     string
	VMSessionID   string
	Image         string
	LxcPath       string
	Dist          string
	Release       string
	CPUs          int
	MemMB         int
	FRRJSON       string
	FWJSON        string // per-vRouter zone-firewall config (see firewall.go)
	Status        string
	Error         string
}

// Leg mirrors a vrouter_legs row. Idx 0 is the transit leg (eth0); idx 1.. are
// internal legs (eth1..).
type Leg struct {
	ID        int64
	VRouterID int64
	Idx       int
	Kind      string
	Bridge    string
	PhysIface string
	NetworkID int64
	IfaceName string
	CIDR      string
	MAC       string
	DHCP      bool
	DHCPRange string
	DHCPDNS   string // CSV of DNS servers to hand out (dnsmasq option 6); "" = none
	// VLAN is the port group this leg joins on a VLAN-filtering tenant vSwitch
	// (its host veth end becomes an access port of it); 0 = untagged.
	VLAN int
	// Uplink legs only: the upstream next hop (installed as the router's default
	// route) and whether to masquerade traffic leaving this leg.
	UpstreamGW string
	SNAT       bool
	// Joined from the networks row (internal legs) for display/edit pre-fill.
	NetworkName string
	NetworkCIDR string // the port-group subnet (networks.cidr), vs CIDR = the leg's gateway IP/mask
}

// EdgeApplier is implemented by runtimes that apply a router's edge state
// themselves: IPv4 forwarding on, and source NAT out of SNAT uplink legs.
// Idempotent; called after every leg change and on rebuild.
type EdgeApplier interface {
	ApplyEdge(vr VRouter, legs []Leg) error
}

// NATTable is the nftables table (inside the runtime) holding uplink SNAT.
const NATTable = "vdxnat"

// RenderEdgeNAT builds the runtime's SNAT table: masquerade out of every SNAT
// uplink leg. With none it only removes the table (declare-then-delete keeps
// the load idempotent).
func RenderEdgeNAT(legs []Leg) string {
	var b strings.Builder
	b.WriteString("table ip " + NATTable + " {}\ndelete table ip " + NATTable + "\n")
	var out []string
	for _, l := range legs {
		if l.Kind == LegUplink && l.SNAT && l.IfaceName != "" {
			out = append(out, `    oifname "`+l.IfaceName+`" masquerade`)
		}
	}
	if len(out) == 0 {
		return b.String()
	}
	b.WriteString("table ip " + NATTable + " {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	b.WriteString(strings.Join(out, "\n") + "\n  }\n}\n")
	return b.String()
}

// Backend is the per-runtime driver. Implementations live in backend_lxc.go /
// backend_netns.go and operate purely on the VRouter/Leg values passed in.
type Backend interface {
	Kind() string
	// Provision creates the runtime, locates/installs FRR, enables its daemons,
	// and leaves it in the "stopped" state ready for ApplyLegs.
	Provision(vr VRouter, legs []Leg) error
	Start(vr VRouter) error
	Stop(vr VRouter) error
	Destroy(vr VRouter) error
	// ApplyLegs (re)builds the runtime's interfaces for the given legs. It OWNS
	// any restart this requires (an LXC container must be stopped to rewrite its
	// NIC config; a netns can add veths live).
	ApplyLegs(vr VRouter, legs []Leg) error
	// PushFRR writes the rendered frr.conf into the runtime and reloads FRR. It
	// must never touch the host FRR config.
	PushFRR(vr VRouter, frrConf string) error
	// PushFirewall applies the rendered nftables ruleset INSIDE the runtime's own
	// netfilter instance (never the host). An empty ruleset removes the table
	// (firewall disabled). Idempotent — flush-then-load.
	PushFirewall(vr VRouter, ruleset string) error
	// SetDHCP (re)configures dnsmasq for an internal leg inside the runtime.
	SetDHCP(vr VRouter, leg Leg) error
	// Status returns the runtime's live routing state (state, route table, BGP
	// summary, OSPF neighbors). It must use the runtime's own vtysh (lxc-attach /
	// vtysh -N), never host vtysh.
	Status(vr VRouter) (LiveStatus, error)
}

// LiveStatus is a vRouter's live routing state, read from its own FRR.
type LiveStatus struct {
	State         string `json:"state"`
	RouteTable    string `json:"route_table"`
	BGPSummary    string `json:"bgp"`
	OSPFNeighbors string `json:"ospf"`
	Advertised    string `json:"advertised"` // prefixes we originate (show ip bgp, locally-sourced)
}

// For returns the backend for a runtime kind. "vm" is reserved and rejected.
func For(runtime string) (Backend, error) {
	switch runtime {
	case RuntimeLXC:
		return lxcBackend{}, nil
	case RuntimeNetns:
		return netnsBackend{}, nil
	case RuntimeVM:
		return nil, fmt.Errorf("the VM-appliance vRouter runtime is not available yet (reserved for a future release)")
	default:
		return nil, fmt.Errorf("unknown vRouter runtime %q", runtime)
	}
}

// Available reports whether a given runtime can be used on this host.
func Available(runtime string) bool {
	b, err := For(runtime)
	if err != nil {
		return false
	}
	if pr, ok := b.(prober); ok {
		return pr.available()
	}
	return true
}

// available is the per-backend host-capability probe (unexported on Backend to
// keep the public surface small).
type prober interface{ available() bool }

// RenderForVRouter builds the per-vRouter frr.conf. Leg IPs are the single
// source of truth for interface addresses (zebra assigns them), so Prefixes is
// derived from the legs and OVERWRITES anything in the stored config. Uplink /
// InternalCIDRs are forced empty so the vRouter never emits host-style SNAT.
func RenderForVRouter(vr VRouter, legs []Leg, cfg routing.Config) (string, error) {
	cfg.Uplink = ""
	cfg.InternalCIDRs = nil
	if cfg.Hostname == "" {
		cfg.Hostname = sanitizeHostname("vr-" + vr.Name)
	}
	if cfg.FRRVersion == "" {
		cfg.FRRVersion = FRRVersionFor(vr)
	}
	cfg.Prefixes = cfg.Prefixes[:0]
	for _, l := range legs {
		if l.IfaceName == "" || l.CIDR == "" {
			continue
		}
		cfg.Prefixes = append(cfg.Prefixes, routing.IfPrefix{Iface: l.IfaceName, CIDR: l.CIDR})
	}
	// An uplink leg's upstream next hop is the router's default route, unless
	// the operator already set a default static route of their own.
	hasDefault := false
	for _, r := range cfg.Static {
		if r.Dest == "0.0.0.0/0" || r.Dest == "default" {
			hasDefault = true
		}
	}
	if !hasDefault {
		for _, l := range legs {
			if l.Kind == LegUplink && l.UpstreamGW != "" {
				// Copy: cfg.Static may share its backing array with the caller.
				cfg.Static = append(append([]routing.Route(nil), cfg.Static...),
					routing.Route{Dest: "0.0.0.0/0", NextHop: l.UpstreamGW})
				break
			}
		}
	}
	return routing.RenderFRR(cfg)
}

// FRRVersionFor returns the frr.conf version banner for a vRouter's runtime.
// netns uses the host FRR (10.5); lxc runs the FRR from its distro — we target
// a trixie-class release that ships FRR 10.x, so 10.5 is a safe banner there too.
func FRRVersionFor(vr VRouter) string { return "10.5" }

// DnsmasqConf builds a dnsmasq config fragment for an internal leg's DHCP: it
// serves DHCP on the leg interface only, hands out the vRouter leg IP as the
// gateway (option 3) and, if set, DNS servers (option 6). The range accepts
// either "start,end" or a friendlier "start-N" shorthand on the last octet.
func DnsmasqConf(leg Leg) string {
	var b strings.Builder
	b.WriteString("interface=" + leg.IfaceName + "\n")
	b.WriteString("bind-interfaces\n")
	b.WriteString("except-interface=lo\n")
	gw, mask := splitCIDR(leg.CIDR)
	rng := normalizeRange(leg.DHCPRange)
	if rng != "" {
		if mask != "" {
			b.WriteString("dhcp-range=" + rng + "," + mask + ",12h\n")
		} else {
			b.WriteString("dhcp-range=" + rng + ",12h\n")
		}
	}
	if gw != "" {
		b.WriteString("dhcp-option=3," + gw + "\n") // default gateway = the vRouter leg IP
	}
	if dns := strings.TrimSpace(leg.DHCPDNS); dns != "" {
		b.WriteString("dhcp-option=6," + dns + "\n") // DNS servers
	}
	return b.String()
}

// NormalizeDHCPRange is the exported form of normalizeRange for validation.
func NormalizeDHCPRange(r string) string { return normalizeRange(r) }

// normalizeRange turns a friendly "A.B.C.X-Y" into dnsmasq's "A.B.C.X,A.B.C.Y";
// a value already containing a comma is returned trimmed.
func normalizeRange(r string) string {
	r = strings.TrimSpace(r)
	if r == "" || strings.Contains(r, ",") {
		return r
	}
	// "A.B.C.X-Y" → start=A.B.C.X end=A.B.C.Y
	dash := strings.LastIndexByte(r, '-')
	if dash <= 0 {
		return r
	}
	start := r[:dash]
	endTail := r[dash+1:]
	if strings.Contains(endTail, ".") { // full end address after the dash
		return start + "," + endTail
	}
	dot := strings.LastIndexByte(start, '.')
	if dot < 0 {
		return r
	}
	return start + "," + start[:dot+1] + endTail
}

// splitCIDR returns (ip, dotted-netmask) from "ip/prefix"; mask is "" if absent.
func splitCIDR(cidr string) (ip, mask string) {
	cidr = strings.TrimSpace(cidr)
	i := strings.IndexByte(cidr, '/')
	if i < 0 {
		return cidr, ""
	}
	ip = cidr[:i]
	if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
		m := ipnet.Mask
		if len(m) == 4 {
			mask = fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
		}
	}
	return ip, mask
}

func sanitizeHostname(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	h := strings.Trim(b.String(), "-")
	if h == "" {
		h = "vrouter"
	}
	return h
}
