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
	Dest    string `json:"dest"`     // CIDR, e.g. 10.30.0.0/24, or "default"
	NextHop string `json:"next_hop"` // gateway IP
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
}

// Neighbor is a BGP peer.
type Neighbor struct {
	Addr        string `json:"addr"`
	RemoteAS    int    `json:"remote_as"`
	RouteMapIn  string `json:"route_map_in"`  // optional inbound route-map name
	RouteMapOut string `json:"route_map_out"` // optional outbound route-map name
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
	SetMetric       int    `json:"set_metric"`      // 0 = unset
	SetLocalPref    int    `json:"set_local_pref"`  // 0 = unset
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

var frrTmpl = template.Must(template.New("frr").Parse(`frr version 10.5
frr defaults traditional
hostname {{.Hostname}}
log syslog informational
!
{{range .IfaceGroups}}interface {{.Iface}}
{{range .CIDRs}} ip address {{.}}
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
{{end}}{{if .BGP.Enabled}}router bgp {{.BGP.ASN}}
{{if .BGP.RouterID}} bgp router-id {{.BGP.RouterID}}
{{end}}{{range .BGP.Neighbors}} neighbor {{.Addr}} remote-as {{.RemoteAS}}
{{end}} address-family ipv4 unicast
{{range .BGP.Networks}}  network {{.}}
{{end}}{{range .BGP.Neighbors}}{{if .RouteMapIn}}  neighbor {{.Addr}} route-map {{.RouteMapIn}} in
{{end}}{{if .RouteMapOut}}  neighbor {{.Addr}} route-map {{.RouteMapOut}} out
{{end}}{{end}} exit-address-family
exit
!
{{end}}{{if .EIGRP.Enabled}}router eigrp {{.EIGRP.ASN}}
{{if .EIGRP.RouterID}} eigrp router-id {{.EIGRP.RouterID}}
{{end}}{{range .EIGRP.Networks}} network {{.}}
{{end}}exit
!
{{end}}line vty
!
`))

type ifaceGroup struct {
	Iface string
	CIDRs []string
}

// frrView is Config plus derived data for the template.
type frrView struct {
	Config
	IfaceGroups []ifaceGroup
}

// RenderFRR produces the full frr.conf for the given config.
func RenderFRR(c Config) (string, error) {
	if c.Hostname == "" {
		c.Hostname = "vdxclone"
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
			groups = append(groups, ifaceGroup{Iface: p.Iface, CIDRs: []string{p.CIDR}})
		}
	}
	var b bytes.Buffer
	if err := frrTmpl.Execute(&b, frrView{Config: c, IfaceGroups: groups}); err != nil {
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
	if err := os.WriteFile(frrConfPath, []byte(conf), 0o640); err != nil {
		return err
	}
	// Make sure frr is running, then apply the delta with frr-reload.py directly.
	// The `systemctl reload frr` wrapper can hang against watchfrr; calling the
	// reload script is fast and reliable. Fall back to a restart if it's absent.
	_, _ = run(10*time.Second, "systemctl", "start", "frr")
	if _, err := os.Stat(frrReloadPy); err == nil {
		_, err = run(60*time.Second, frrReloadPy, "--reload", "--stdout", frrConfPath)
		return err
	}
	_, err = run(45*time.Second, "systemctl", "restart", "frr")
	return err
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
// rules (default accept for established/related, then the operator rules).
func RenderNAT(c Config) string {
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
		action := r.Action
		if action != "accept" && action != "drop" {
			action = "accept"
		}
		line += action + "\n"
		b.WriteString(line)
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

// ApplyNAT replaces the vdxclone nftables table with a freshly rendered ruleset.
func ApplyNAT(c Config) error {
	if !NFTAvailable() {
		return fmt.Errorf("nftables is not installed")
	}
	// Flush our table first (ignore error if absent), then load the new ruleset.
	_, _ = run(5*time.Second, "nft", "delete", "table", "inet", "vdxclone")
	ruleset := RenderNAT(c)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft load: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply enables forwarding and applies both FRR and nftables. Partial failures
// are surfaced but it applies as much as it can.
func Apply(c Config) error {
	var errs []string
	if err := EnableForwarding(); err != nil {
		errs = append(errs, "forwarding: "+err.Error())
	}
	if err := ApplyNAT(c); err != nil {
		errs = append(errs, "nat: "+err.Error())
	}
	if err := ApplyFRR(c); err != nil {
		errs = append(errs, "frr: "+err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
