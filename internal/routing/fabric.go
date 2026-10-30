package routing

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// The VXVisor Fabric's share of the host FRR config (docs/FABRIC.md §14). The
// host runs ONE bgpd instance, so the fabric's EVPN sessions and the operator's
// /routing BGP render into the same `router bgp` block: one AS, one router-id
// (the fabric's TEP), IPv4 unicast never activated by default (each host
// neighbour is activated explicitly; fabric peers carry only l2vpn evpn). The
// fabric section is filled at apply time from the fabric's own state, never
// stored in routing_config, so a /routing edit can't drop it.

// Fabric is the fabric's BGP EVPN config on this host.
type Fabric struct {
	ASN      int         // the fabric's iBGP AS (fixed once the fabric exists)
	TEP      string      // this host's tunnel endpoint: router-id + update-source
	Peers    []string    // the other members' TEPs
	Password string      // BGP MD5 secret, derived locally from cluster.key
	BFD      bool        // BFD on every fabric session (needs bfdd)
	VRFs     []FabricVRF // per-org routing domains (distributed L3)
}

// FabricVRF is one org's routing domain: a kernel VRF device and its L3VNI.
type FabricVRF struct {
	Name string // VRF device, e.g. vdxv12
	VNI  int    // L3VNI (symmetric IRB)
}

// FabricPeerGroup names the fabric's BGP peer-group in frr.conf.
const FabricPeerGroup = "VXFABRIC"

// MaxVNI is the largest 24-bit VXLAN network identifier.
const MaxVNI = 16777215

var reSecret = regexp.MustCompile(`^[A-Za-z0-9]{1,80}$`)

// Validate checks every value the fabric section renders.
func (f *Fabric) Validate() error {
	if err := ValidASN(f.ASN); err != nil {
		return fmt.Errorf("fabric %w", err)
	}
	if !IsIPv4(f.TEP) {
		return fmt.Errorf("fabric TEP %q is not an IPv4 address", f.TEP)
	}
	seen := map[string]bool{f.TEP: true}
	for _, p := range f.Peers {
		if !IsIPv4(p) {
			return fmt.Errorf("fabric peer %q is not an IPv4 address", p)
		}
		if seen[p] {
			return fmt.Errorf("fabric peer %s is listed twice (or is this host's own TEP)", p)
		}
		seen[p] = true
	}
	if f.Password != "" && !reSecret.MatchString(f.Password) {
		return fmt.Errorf("fabric BGP password must be 1-80 letters or digits")
	}
	names, vnis := map[string]bool{}, map[int]bool{}
	for _, v := range f.VRFs {
		if err := ValidIface(v.Name); err != nil {
			return fmt.Errorf("fabric VRF: %w", err)
		}
		if v.VNI < 1 || v.VNI > MaxVNI {
			return fmt.Errorf("fabric VRF %s: VNI %d is out of range 1-%d", v.Name, v.VNI, MaxVNI)
		}
		if names[v.Name] || vnis[v.VNI] {
			return fmt.Errorf("fabric VRF %s / VNI %d is not unique", v.Name, v.VNI)
		}
		names[v.Name], vnis[v.VNI] = true, true
	}
	return nil
}

// validComposition checks that the host's BGP and the fabric can share one
// bgpd instance.
func (c Config) validComposition() error {
	if c.Fabric == nil || !c.BGP.Enabled {
		return nil
	}
	if c.BGP.ASN != c.Fabric.ASN {
		return fmt.Errorf("host BGP must use the fabric's AS %d (it is set to %d) — a host runs one BGP instance", c.Fabric.ASN, c.BGP.ASN)
	}
	if c.BGP.RouterID != "" && c.BGP.RouterID != c.Fabric.TEP {
		return fmt.Errorf("host BGP router-id must be the fabric TEP %s (or empty) — a host runs one BGP instance", c.Fabric.TEP)
	}
	peers := map[string]bool{}
	for _, p := range c.Fabric.Peers {
		peers[p] = true
	}
	for _, nb := range c.BGP.Neighbors {
		if peers[nb.Addr] || nb.Addr == c.Fabric.TEP {
			return fmt.Errorf("BGP neighbor %s is a fabric TEP — the fabric manages that session", nb.Addr)
		}
	}
	return nil
}

// BGPPeers is every address allowed to open a BGP session to this host: the
// host's configured neighbours and the fabric's peers.
func (c Config) BGPPeers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if IsIPv4(a) && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if c.BGP.Enabled {
		for _, nb := range c.BGP.Neighbors {
			add(nb.Addr)
		}
	}
	if c.Fabric != nil {
		for _, p := range c.Fabric.Peers {
			add(p)
		}
	}
	return out
}

// ---- TCP 179 guard -------------------------------------------------------

// BGPGuardFile keeps the rendered guard so frr.service loads it before bgpd
// starts at boot (BGPGuardDropIn), ahead of vdxd.
var (
	BGPGuardFile   = "/etc/vdxclone/bgp-guard.nft"
	BGPGuardDropIn = "/etc/systemd/system/frr.service.d/vdxclone-bgp-guard.conf"
)

// RenderBGPGuard builds the host table `inet vdxbgp`: inbound TCP 179 only from
// the allowed peers, so bgpd's pre-authentication surface (OPEN parsing, MD5
// lookups) is closed to everyone else. Outbound sessions are unaffected (their
// replies arrive on our ephemeral port). The script replaces the table in one
// transaction.
func RenderBGPGuard(peers []string) (string, error) {
	for _, p := range peers {
		if !IsIPv4(p) {
			return "", fmt.Errorf("refusing to render the BGP guard: %q is not an IPv4 address", p)
		}
	}
	var b strings.Builder
	b.WriteString("table inet vdxbgp {}\ndelete table inet vdxbgp\n")
	b.WriteString("table inet vdxbgp {\n")
	b.WriteString("  set peers {\n    type ipv4_addr\n")
	if len(peers) > 0 {
		fmt.Fprintf(&b, "    elements = { %s }\n", strings.Join(peers, ", "))
	}
	b.WriteString("  }\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority filter - 10; policy accept;\n")
	b.WriteString("    tcp dport 179 ip saddr @peers accept\n")
	b.WriteString("    tcp dport 179 drop\n")
	b.WriteString("  }\n}\n")
	return b.String(), nil
}

func nftBin() string {
	if p, err := exec.LookPath("nft"); err == nil {
		return p
	}
	return "/usr/sbin/nft"
}

// nftLoad checks a ruleset (nft -c) and only then loads it.
func nftLoad(ruleset string) error {
	for _, args := range [][]string{{"-c", "-f", "-"}, {"-f", "-"}} {
		cmd := exec.Command("nft", args...)
		cmd.Stdin = strings.NewReader(ruleset)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ApplyBGPGuard loads the TCP 179 guard for c and saves it, with the frr.service
// drop-in that reloads it at boot before bgpd listens.
func ApplyBGPGuard(c Config) error {
	if !NFTAvailable() {
		return fmt.Errorf("nftables is not installed")
	}
	rs, err := RenderBGPGuard(c.BGPPeers())
	if err != nil {
		return err
	}
	if err := nftLoad(rs); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/vdxclone", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(BGPGuardFile, []byte(rs), 0o644); err != nil {
		return err
	}
	unit := "[Service]\n# vdxd: load the BGP (TCP 179) peer guard before bgpd listens.\nExecStartPre=-" + nftBin() + " -f " + BGPGuardFile + "\n"
	if cur, err := os.ReadFile(BGPGuardDropIn); err == nil && bytes.Equal(cur, []byte(unit)) {
		return nil
	}
	if err := os.MkdirAll(strings.TrimSuffix(BGPGuardDropIn, "/vdxclone-bgp-guard.conf"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(BGPGuardDropIn, []byte(unit), 0o644); err != nil {
		return err
	}
	_, err = run(15*time.Second, "systemctl", "daemon-reload")
	return err
}
