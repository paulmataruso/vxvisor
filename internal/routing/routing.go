// Package routing manages host L3: kernel IP forwarding, nftables NAT/firewall
// at the edge, and FRR (Free Range Routing) for static, OSPF and BGP routing.
//
// vdxd OWNS a single managed FRR config (/etc/frr/frr.conf) and a single
// nftables table ("vdxclone"); operators should not hand-edit them. Static +
// NAT + firewall are the default; OSPF and BGP are opt-in via the Config.
// Every mutating call is admin-gated by the service layer.
package routing

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"text/template"
	"time"
)

const (
	frrConfPath = "/etc/frr/frr.conf"
	frrReloadPy = "/usr/lib/frr/frr-reload.py"
	sysctlPath  = "/etc/sysctl.d/99-vdxclone-forward.conf"
)

// FRRAvailable reports whether FRR is installed.
func FRRAvailable() bool { _, err := exec.LookPath("vtysh"); return err == nil }

// NFTAvailable reports whether nftables is installed.
func NFTAvailable() bool { _, err := exec.LookPath("nft"); return err == nil }

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ---- model ---------------------------------------------------------------

// Route is a static route.
type Route struct {
	Dest    string `json:"dest"`     // CIDR, e.g. 10.30.0.0/24, or "default" (= 0.0.0.0/0)
	NextHop string `json:"next_hop"` // gateway IPv4 address, or an interface name
}

// OSPFNet attaches a network to an OSPF area.
type OSPFNet struct {
	CIDR string `json:"cidr"`
	Area string `json:"area"` // e.g. "0.0.0.0" or "0"
}

// OSPF is the OSPFv2 config (opt-in).
type OSPF struct {
	Enabled  bool      `json:"enabled"`
	RouterID string    `json:"router_id"`
	Networks []OSPFNet `json:"networks"`
	// Passive interfaces are advertised but form no adjacency, so no LSA is
	// accepted on them. Set by the vRouter tenant policy, not the UI.
	Passive []string `json:"passive,omitempty"`
}

// Neighbor is a BGP peer.
type Neighbor struct {
	Addr        string `json:"addr"`
	RemoteAS    int    `json:"remote_as"`
	RouteMapIn  string `json:"route_map_in"`  // optional inbound route-map name
	RouteMapOut string `json:"route_map_out"` // optional outbound route-map name
	// PrefixListOut filters what is advertised to this peer. Set by the vRouter
	// tenant export policy (vrouter.ConstrainTenant), not the UI.
	PrefixListOut string `json:"prefix_list_out,omitempty"`
}

// IfPrefix assigns an IP prefix (CIDR) to a host interface (managed by zebra).
type IfPrefix struct {
	Iface string `json:"iface"`
	CIDR  string `json:"cidr"`
}

// PrefixList is one ip prefix-list entry used for route filtering.
type PrefixList struct {
	Name   string `json:"name"`
	Seq    int    `json:"seq"`
	Action string `json:"action"` // permit | deny
	Prefix string `json:"prefix"` // CIDR, or "any"
	Ge     int    `json:"ge"`     // 0 = unset
	Le     int    `json:"le"`     // 0 = unset
}

// RouteMapClause is one route-map clause (match + set).
type RouteMapClause struct {
	Name            string `json:"name"`
	Seq             int    `json:"seq"`
	Action          string `json:"action"` // permit | deny
	MatchPrefixList string `json:"match_prefix_list"`
	SetMetric       int    `json:"set_metric"`     // 0 = unset
	SetLocalPref    int    `json:"set_local_pref"` // 0 = unset
}

// BGP is the BGP config (opt-in).
type BGP struct {
	Enabled   bool       `json:"enabled"`
	ASN       int        `json:"asn"`
	RouterID  string     `json:"router_id"`
	Neighbors []Neighbor `json:"neighbors"`
	Networks  []string   `json:"networks"` // CIDRs to advertise
}

// EIGRP is the EIGRP config (opt-in; FRR eigrpd). ASN is the autonomous-system
// number shared by all routers in the EIGRP domain (1-65535).
type EIGRP struct {
	Enabled  bool     `json:"enabled"`
	ASN      int      `json:"asn"`
	RouterID string   `json:"router_id"`
	Networks []string `json:"networks"` // CIDRs to run EIGRP on + advertise
}

// FirewallRule is one edge filter rule (applied on the forward chain).
type FirewallRule struct {
	Action string `json:"action"` // accept | drop
	Proto  string `json:"proto"`  // tcp | udp | "" (any)
	DPort  string `json:"dport"`  // "" = any
	Source string `json:"source"` // CIDR or "" = any
}

// Config is the whole managed L3 state vdxd renders and applies.
type Config struct {
	Hostname      string           `json:"hostname"`
	Uplink        string           `json:"uplink"`         // edge NIC for SNAT (e.g. enp0s20f2)
	InternalCIDRs []string         `json:"internal_cidrs"` // networks that get NAT + routing
	Prefixes      []IfPrefix       `json:"prefixes"`       // interface IP assignments
	Static        []Route          `json:"static"`
	Firewall      []FirewallRule   `json:"firewall"`
	PrefixLists   []PrefixList     `json:"prefix_lists"`
	RouteMaps     []RouteMapClause `json:"route_maps"`
	OSPF          OSPF             `json:"ospf"`
	BGP           BGP              `json:"bgp"`
	EIGRP         EIGRP            `json:"eigrp"`
	// FRRVersion is the "frr version X" banner. Empty defaults to the host FRR
	// version ("10.5"); a vRouter backend sets it to the FRR actually running in
	// its runtime (e.g. an LXC container on an older distro) so frr-reload.py
	// doesn't choke on a mismatched banner.
	FRRVersion string `json:"frr_version,omitempty"`
	// Fabric is the VXVisor Fabric's BGP EVPN share of the host config (see
	// fabric.go). Filled at apply time from the fabric's state, never stored.
	Fabric *Fabric `json:"-"`
}

// ---- kernel forwarding ---------------------------------------------------

// EnableForwarding turns on IPv4 forwarding now and persistently.
func EnableForwarding() error {
	if err := os.WriteFile(sysctlPath, []byte("net.ipv4.ip_forward = 1\n"), 0o644); err != nil {
		return err
	}
	_, err := run(5*time.Second, "sysctl", "-w", "net.ipv4.ip_forward=1")
	return err
}

// ---- FRR -----------------------------------------------------------------

var frrTmpl = template.Must(template.New("frr").Parse(`frr version {{.FRRVersion}}
frr defaults traditional
hostname {{.Hostname}}
log syslog informational
!
{{range .IfaceGroups}}interface {{.Iface}}
{{range .CIDRs}} ip address {{.}}
{{end}}{{if .Passive}} ip ospf passive
{{end}}exit
!
{{end}}{{range .Static}}ip route {{.Dest}} {{.NextHop}}
{{end}}!
{{range .PrefixLists}}ip prefix-list {{.Name}} seq {{.Seq}} {{.Action}} {{.Prefix}}{{if .Ge}} ge {{.Ge}}{{end}}{{if .Le}} le {{.Le}}{{end}}
{{end}}!
{{range .RouteMaps}}route-map {{.Name}} {{.Action}} {{.Seq}}
{{if .MatchPrefixList}} match ip address prefix-list {{.MatchPrefixList}}
{{end}}{{if .SetMetric}} set metric {{.SetMetric}}
{{end}}{{if .SetLocalPref}} set local-preference {{.SetLocalPref}}
{{end}}exit
!
{{end}}{{if .OSPF.Enabled}}router ospf
{{if .OSPF.RouterID}} ospf router-id {{.OSPF.RouterID}}
{{end}}{{range .OSPF.Networks}} network {{.CIDR}} area {{.Area}}
{{end}}exit
!
{{end}}{{if .Fabric}}{{range .Fabric.VRFs}}vrf {{.Name}}
 vni {{.VNI}}
exit-vrf
!
{{end}}{{end}}{{if .BGPOn}}router bgp {{.BGPASN}}
{{if .BGPRouterID}} bgp router-id {{.BGPRouterID}}
{{end}} no bgp default ipv4-unicast
{{range .HostNeighbors}} neighbor {{.Addr}} remote-as {{.RemoteAS}}
{{end}}{{with .Fabric}} neighbor {{$.PeerGroup}} peer-group
 neighbor {{$.PeerGroup}} remote-as internal
 neighbor {{$.PeerGroup}} update-source {{.TEP}}
{{if .Password}} neighbor {{$.PeerGroup}} password {{.Password}}
{{end}}{{if .BFD}} neighbor {{$.PeerGroup}} bfd
{{end}}{{range .Peers}} neighbor {{.}} peer-group {{$.PeerGroup}}
{{end}}{{end}} address-family ipv4 unicast
{{range .HostNetworks}}  network {{.}}
{{end}}{{range .HostNeighbors}}  neighbor {{.Addr}} activate
{{if .RouteMapIn}}  neighbor {{.Addr}} route-map {{.RouteMapIn}} in
{{end}}{{if .RouteMapOut}}  neighbor {{.Addr}} route-map {{.RouteMapOut}} out
{{end}}{{if .PrefixListOut}}  neighbor {{.Addr}} prefix-list {{.PrefixListOut}} out
{{end}}{{end}} exit-address-family
{{if .Fabric}} address-family l2vpn evpn
  neighbor {{.PeerGroup}} activate
  advertise-all-vni
 exit-address-family
{{end}}exit
!
{{if .Fabric}}{{range .Fabric.VRFs}}router bgp {{$.BGPASN}} vrf {{.Name}}
 bgp router-id {{$.BGPRouterID}}
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
 address-family l2vpn evpn
  advertise ipv4 unicast
 exit-address-family
exit
!
{{end}}{{end}}{{end}}{{if .EIGRP.Enabled}}router eigrp {{.EIGRP.ASN}}
{{if .EIGRP.RouterID}} eigrp router-id {{.EIGRP.RouterID}}
{{end}}{{range .EIGRP.Networks}} network {{.}}
{{end}}exit
!
{{end}}line vty
!
`))

type ifaceGroup struct {
	Iface   string
	CIDRs   []string
	Passive bool // OSPF passive (only set while OSPF is on)
}

// frrView is Config plus derived data for the template.
type frrView struct {
	Config
	IfaceGroups []ifaceGroup
	// The one `router bgp` block, composed from the host's BGP and the fabric.
	BGPOn         bool
	BGPASN        int
	BGPRouterID   string
	HostNeighbors []Neighbor
	HostNetworks  []string
	PeerGroup     string
}

// RenderFRR produces the full frr.conf for the given config. It renders nothing
// if any value isn't a single token of the expected shape (Config.Validate).
func RenderFRR(c Config) (string, error) {
	if c.Hostname == "" {
		c.Hostname = "vdxclone"
	}
	if c.FRRVersion == "" {
		c.FRRVersion = "10.5" // host FRR default; preserves prior behaviour
	}
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("refusing to render the routing config: %w", err)
	}
	// FRR has no "default" keyword for a static destination.
	if len(c.Static) > 0 {
		st := make([]Route, len(c.Static))
		for i, r := range c.Static {
			if r.Dest == "default" {
				r.Dest = "0.0.0.0/0"
			}
			st[i] = r
		}
		c.Static = st
	}
	passive := map[string]bool{}
	if c.OSPF.Enabled {
		for _, ifc := range c.OSPF.Passive {
			passive[ifc] = true
		}
	}
	// Group interface prefixes so each interface gets a single stanza.
	var groups []ifaceGroup
	idx := map[string]int{}
	for _, p := range c.Prefixes {
		if p.Iface == "" || p.CIDR == "" {
			continue
		}
		if i, ok := idx[p.Iface]; ok {
			groups[i].CIDRs = append(groups[i].CIDRs, p.CIDR)
		} else {
			idx[p.Iface] = len(groups)
			groups = append(groups, ifaceGroup{Iface: p.Iface, CIDRs: []string{p.CIDR}, Passive: passive[p.Iface]})
		}
	}
	v := frrView{Config: c, IfaceGroups: groups, PeerGroup: FabricPeerGroup}
	if c.BGP.Enabled {
		v.BGPOn, v.BGPASN, v.BGPRouterID = true, c.BGP.ASN, c.BGP.RouterID
		v.HostNeighbors, v.HostNetworks = c.BGP.Neighbors, c.BGP.Networks
	}
	if c.Fabric != nil {
		v.BGPOn, v.BGPASN, v.BGPRouterID = true, c.Fabric.ASN, c.Fabric.TEP
	}
	var b bytes.Buffer
	if err := frrTmpl.Execute(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

// ApplyFRR writes the managed frr.conf and reloads FRR (graceful delta reload).
func ApplyFRR(c Config) error {
	if !FRRAvailable() {
		return fmt.Errorf("frr is not installed")
	}
	conf, err := RenderFRR(c)
	if err != nil {
		return err
	}
	// Reconcile interface addresses SAFELY. FRR refuses `no interface <X>` for any
	// live kernel NIC ("only inactive interfaces can be deleted"), so if the
	// managed config simply drops an interface stanza, frr-reload fails. For every
	// interface WE PREVIOUSLY MANAGED (present in our last frr.conf) but no longer
	// do, emit an EMPTY `interface <X>` stanza so frr-reload removes the address
	// with `no ip address` (allowed) and keeps an empty node (FRR hides it later).
	//
	// CRITICAL: the source of "what we managed" is our OWN previous frr.conf, NOT
	// `vtysh show running-config`. FRR's running config can contain addresses we
	// never managed (e.g. the Ceph storage IP 10.77.0.1 on the storage NIC) — if
	// we reconciled against that, an L3 apply would strip those and wedge Ceph.
	desired := map[string]bool{}
	for _, p := range c.Prefixes {
		if p.Iface != "" {
			desired[p.Iface] = true
		}
	}
	var extra strings.Builder
	for _, ifc := range managedIfaces() { // interfaces in our PREVIOUS frr.conf
		if ifc == "" || desired[ifc] {
			continue
		}
		extra.WriteString("interface " + ifc + "\nexit\n!\n")
	}
	if extra.Len() > 0 {
		conf += extra.String()
	}
	// Check the new config with FRR itself (frr-reload --test parses it through
	// vtysh and diffs it against the running config without applying) BEFORE it
	// replaces the live file, so a config FRR rejects never lands on disk and the
	// running routing is untouched. The previous file is kept as .vdxprev.
	_, _ = run(10*time.Second, "systemctl", "start", "frr")
	tmp := frrConfPath + ".vdxnew"
	if err := os.WriteFile(tmp, []byte(conf), 0o640); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := run(30*time.Second, "vtysh", "-C", "-f", tmp); err != nil {
		return fmt.Errorf("FRR rejected the new routing config, nothing was changed: %w", err)
	}
	_, haveReload := os.Stat(frrReloadPy)
	if haveReload == nil {
		if _, err := run(60*time.Second, frrReloadPy, "--test", "--stdout", tmp); err != nil {
			return fmt.Errorf("FRR rejected the new routing config, nothing was changed: %w", err)
		}
	}
	if prev, err := os.ReadFile(frrConfPath); err == nil {
		_ = os.WriteFile(frrConfPath+".vdxprev", prev, 0o640)
	}
	keepOwnership(frrConfPath, tmp) // the swap must not change who can read it
	if err := os.Rename(tmp, frrConfPath); err != nil {
		return err
	}
	if haveReload == nil {
		out, rerr := run(60*time.Second, frrReloadPy, "--reload", "--stdout", frrConfPath)
		if rerr != nil {
			// Tolerate FRR's refusal to delete a stale, non-managed interface node
			// (a live NIC it won't `no interface`): the rest of the config applied,
			// and we must NOT fail the whole operation over a node we don't own.
			if ifaceRemovalOnly(out + " " + rerr.Error()) {
				return nil
			}
			return rerr
		}
		return nil
	}
	_, err = run(45*time.Second, "systemctl", "restart", "frr")
	return err
}

// keepOwnership gives dst the mode and owner of src, when src exists.
func keepOwnership(src, dst string) {
	fi, err := os.Stat(src)
	if err != nil {
		return
	}
	_ = os.Chmod(dst, fi.Mode().Perm())
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(dst, int(st.Uid), int(st.Gid))
	}
}

// ifaceRemovalOnly reports whether a frr-reload failure is only FRR refusing to
// delete an interface node (harmless — the node is a live NIC it keeps).
func ifaceRemovalOnly(out string) bool {
	return strings.Contains(out, "only inactive interfaces can be deleted") ||
		strings.Contains(out, "Failed to execute no interface")
}

// managedIfaces returns the interfaces that appear in OUR previously-written
// frr.conf — i.e. the interfaces the L3 feature itself manages. Reconciliation
// is scoped to these so we never remove an address we didn't put there (e.g. the
// Ceph storage IP on the storage NIC, which lives outside the managed config).
func managedIfaces() []string {
	b, err := os.ReadFile(frrConfPath)
	if err != nil {
		return nil
	}
	var ifs []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface ") {
			ifs = append(ifs, strings.TrimSpace(strings.TrimPrefix(line, "interface ")))
		}
	}
	return ifs
}

// FRRStatus returns a routing summary from FRR.
func FRRStatus() (string, error) {
	if !FRRAvailable() {
		return "frr not installed", nil
	}
	return run(10*time.Second, "vtysh", "-c", "show ip route")
}

// ---- nftables NAT + firewall ---------------------------------------------

// RenderNAT builds the vdxclone nftables table: SNAT (masquerade) for the
// internal CIDRs out the uplink, plus a forward chain applying the firewall
// rules (default accept for established/related, then the operator rules). Like
// RenderFRR it renders nothing if any value isn't a single valid token.
func RenderNAT(c Config) (string, error) {
	if c.Uplink != "" {
		if err := ValidIface(c.Uplink); err != nil {
			return "", fmt.Errorf("refusing to render the NAT table: uplink %w", err)
		}
	}
	for _, cidr := range c.InternalCIDRs {
		if cidr != "" {
			if err := validNetwork(cidr); err != nil {
				return "", fmt.Errorf("refusing to render the NAT table: %w", err)
			}
		}
	}
	for i, r := range c.Firewall {
		if err := ValidFirewallRule(r); err != nil {
			return "", fmt.Errorf("refusing to render the NAT table: firewall rule %d: %w", i+1, err)
		}
	}
	var b strings.Builder
	b.WriteString("table inet vdxclone {\n")
	// NAT postrouting: masquerade internal networks leaving via the uplink.
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n")
	for _, cidr := range c.InternalCIDRs {
		if cidr == "" {
			continue
		}
		if c.Uplink != "" {
			fmt.Fprintf(&b, "    ip saddr %s oifname \"%s\" masquerade\n", cidr, c.Uplink)
		} else {
			fmt.Fprintf(&b, "    ip saddr %s masquerade\n", cidr)
		}
	}
	b.WriteString("  }\n")
	// Forward filter: baseline + operator rules.
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority filter; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	for _, r := range c.Firewall {
		line := "    "
		if r.Source != "" {
			line += "ip saddr " + r.Source + " "
		}
		if r.Proto == "tcp" || r.Proto == "udp" {
			line += r.Proto + " "
			if r.DPort != "" {
				line += "dport " + r.DPort + " "
			}
		}
		line += r.Action + "\n"
		b.WriteString(line)
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// ApplyNAT replaces the vdxclone nftables table with a freshly rendered ruleset.
func ApplyNAT(c Config) error {
	if !NFTAvailable() {
		return fmt.Errorf("nftables is not installed")
	}
	ruleset, err := RenderNAT(c)
	if err != nil {
		return err
	}
	// Replace the table in ONE checked transaction: a ruleset nft rejects leaves
	// the old table in place (deleting first used to leave none on a bad load).
	return nftLoad("table inet vdxclone {}\ndelete table inet vdxclone\n" + ruleset)
}

// Apply enables forwarding and applies the NAT/firewall table, the BGP peer
// guard and FRR. Partial failures are surfaced but it applies as much as it can.
func Apply(c Config) error {
	var errs []string
	if err := EnableForwarding(); err != nil {
		errs = append(errs, "forwarding: "+err.Error())
	}
	if err := ApplyNAT(c); err != nil {
		errs = append(errs, "nat: "+err.Error())
	}
	if err := ApplyBGPGuard(c); err != nil {
		errs = append(errs, "bgp guard: "+err.Error())
	}
	if err := ApplyFRR(c); err != nil {
		errs = append(errs, "frr: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
