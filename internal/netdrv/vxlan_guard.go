package netdrv

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// VXLAN input validation and the host's VXLAN ingress guard.
//
// Every VXLAN value ends up as an `ip` argument AND as text in a systemd unit
// (ExecStart= lines), so each one is validated here at the sink as well as at the
// service layer: a value with a newline would otherwise add its own ExecStart=.
//
// A Linux VXLAN device accepts encapsulated frames from ANY source address that
// reaches its UDP port with its VNI — the peer list only decides where this host
// sends. The guard (nft table inet vdxvxlan) drops VXLAN UDP unless it comes
// from a configured peer of that VNI.

const (
	MinVNI        = 1
	MaxVNI        = 16777215 // 24-bit VXLAN network identifier
	MaxVXLANPeers = 64
)

// VXLANGuardTable is the host nftables table that restricts VXLAN ingress to the
// configured peers. vdxd owns it outright and rebuilds it whole on every change.
const VXLANGuardTable = "vdxvxlan"

// VXLANGuardFile is where the rendered guard is kept so the VXLAN boot units can
// load it (ExecStartPre) before their device comes up, even if vdxd is not
// running yet. A var so tests never write to /etc.
var VXLANGuardFile = "/etc/vdxclone/vxlan-guard.nft"

// VXLANParams are the tunable parts of one VXLAN device.
type VXLANParams struct {
	VNI      int
	DstPort  int
	MTU      int
	Underlay string   // device the encapsulated UDP rides over
	Local    string   // optional underlay source IP
	Peers    []string // remote VTEP addresses (head-end replication)
}

// Validate checks every field against what the kernel and a unit file can take.
// Errors say what to change.
func (v VXLANParams) Validate() error {
	if v.VNI < MinVNI || v.VNI > MaxVNI {
		return fmt.Errorf("VNI %d is out of range — use 1–16777215", v.VNI)
	}
	if v.DstPort < 1024 || v.DstPort > 65535 {
		return fmt.Errorf("UDP port %d is out of range — use 1024–65535 (4789 is the standard VXLAN port)", v.DstPort)
	}
	if v.MTU < 1280 || v.MTU > 9000 {
		return fmt.Errorf("MTU %d is out of range — use 1280–9000 (usually the underlay MTU minus 50)", v.MTU)
	}
	if !ValidIfName(v.Underlay) {
		return fmt.Errorf("underlay %q is not a valid interface name (up to 15 letters, digits, - _ . starting with a letter or digit)", v.Underlay)
	}
	fam := 0
	if v.Local != "" {
		ip := net.ParseIP(v.Local)
		if ip == nil || !usableUnicast(ip) {
			return fmt.Errorf("local IP %q is not a unicast IP address", v.Local)
		}
		fam = ipFamily(ip)
	}
	if len(v.Peers) > MaxVXLANPeers {
		return fmt.Errorf("too many peers (%d) — at most %d", len(v.Peers), MaxVXLANPeers)
	}
	for _, p := range v.Peers {
		ip := net.ParseIP(p)
		if ip == nil || !usableUnicast(ip) {
			return fmt.Errorf("peer %q is not a unicast IP address", p)
		}
		if fam != 0 && ipFamily(ip) != fam {
			return fmt.Errorf("peer %s and the local IP %s are different IP versions", p, v.Local)
		}
		if v.Local != "" && ip.Equal(net.ParseIP(v.Local)) {
			return fmt.Errorf("peer %s is this host's own local IP — list only the other hosts", p)
		}
	}
	return nil
}

// ParsePeerCSV splits a comma-separated peer list, drops blanks and duplicates,
// and returns each peer in canonical form. Any entry that isn't a unicast IP
// address is an error.
func ParsePeerCSV(csv string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil || !usableUnicast(ip) {
			return nil, fmt.Errorf("peer %q is not a unicast IP address — list the other hosts' underlay IPs, comma-separated", p)
		}
		c := ip.String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// ValidIfName reports whether n is a Linux interface name safe to pass to ip(8)
// and to write into a unit file: 1–15 characters of letters, digits, - _ .,
// starting with a letter or digit.
func ValidIfName(n string) bool {
	if n == "" || len(n) > 15 || n == "." || n == ".." {
		return false
	}
	for i, r := range n {
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

func usableUnicast(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.Equal(net.IPv4bcast)
}

func ipFamily(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// validGatewayCIDR checks an "ip/prefix" host gateway (sink backstop).
func validGatewayCIDR(s string) error {
	if _, _, err := net.ParseCIDR(s); err != nil {
		return fmt.Errorf("gateway %q is not an address/prefix", s)
	}
	return nil
}

// IsVXLAN reports whether an existing interface is a VXLAN device.
func IsVXLAN(name string) bool {
	if !ValidIfName(name) {
		return false
	}
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "uevent"))
	return err == nil && strings.Contains(string(b), "DEVTYPE=vxlan")
}

// ---- ingress guard ---------------------------------------------------------

// VXLANListener is one VXLAN identity this host terminates: frames for VNI on
// UDP Port are accepted only from Peers. Open accepts from anywhere — only for a
// VXLAN that has no configured peers by design (the [cluster] overlay learns its
// peers), so filtering it would cut it off.
type VXLANListener struct {
	Port  int
	VNI   int
	Peers []string
	Open  bool
}

// RenderVXLANGuard builds the vdxvxlan table. For every UDP port a managed VXLAN
// uses: frames for each VNI are accepted from that VNI's peers, and everything
// else on the port is dropped. The VNI is read straight from the VXLAN header
// (bytes 4–6 after the 8-byte UDP header = transport-header bits 96–119).
// Invalid ports/VNIs/peers are skipped (the service validated them already).
func RenderVXLANGuard(ls []VXLANListener) string {
	type key struct{ port, vni int }
	peers := map[key]map[string]bool{}
	open := map[key]bool{}
	ports := map[int]bool{}
	for _, l := range ls {
		if l.Port < 1 || l.Port > 65535 || l.VNI < MinVNI || l.VNI > MaxVNI {
			continue
		}
		k := key{l.Port, l.VNI}
		ports[l.Port] = true
		if l.Open {
			open[k] = true
		}
		if peers[k] == nil {
			peers[k] = map[string]bool{}
		}
		for _, p := range l.Peers {
			if ip := net.ParseIP(strings.TrimSpace(p)); ip != nil && usableUnicast(ip) {
				peers[k][ip.String()] = true
			}
		}
	}
	var b strings.Builder
	// Declare-then-delete makes the load atomic and idempotent.
	b.WriteString("table inet " + VXLANGuardTable + " {}\n")
	b.WriteString("delete table inet " + VXLANGuardTable + "\n")
	b.WriteString("table inet " + VXLANGuardTable + " {\n")
	b.WriteString("  chain input {\n    type filter hook input priority filter - 10; policy accept;\n")
	var portList []int
	for p := range ports {
		portList = append(portList, p)
	}
	sort.Ints(portList)
	for _, port := range portList {
		var vnis []int
		for k := range peers {
			if k.port == port {
				vnis = append(vnis, k.vni)
			}
		}
		sort.Ints(vnis)
		for _, vni := range vnis {
			k := key{port, vni}
			match := fmt.Sprintf("udp dport %d @th,96,24 %d", port, vni)
			if open[k] {
				fmt.Fprintf(&b, "    %s accept\n", match)
				continue
			}
			var v4, v6 []string
			for p := range peers[k] {
				if net.ParseIP(p).To4() != nil {
					v4 = append(v4, p)
				} else {
					v6 = append(v6, p)
				}
			}
			sort.Strings(v4)
			sort.Strings(v6)
			if len(v4) > 0 {
				fmt.Fprintf(&b, "    %s ip saddr { %s } accept\n", match, strings.Join(v4, ", "))
			}
			if len(v6) > 0 {
				fmt.Fprintf(&b, "    %s ip6 saddr { %s } accept\n", match, strings.Join(v6, ", "))
			}
		}
		fmt.Fprintf(&b, "    udp dport %d counter drop\n", port)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// ApplyVXLANGuard renders the guard, keeps a copy for the boot units, and loads
// it (replacing any previous version).
func ApplyVXLANGuard(ls []VXLANListener) error {
	rs := RenderVXLANGuard(ls)
	if err := os.MkdirAll(filepath.Dir(VXLANGuardFile), 0o755); err == nil {
		_ = os.WriteFile(VXLANGuardFile, []byte(rs), 0o644)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftables is not installed — VXLAN ingress can't be restricted to the peers")
	}
	return ApplyNFT(rs)
}

// vxlanGuardExecPre is the unit line that loads the saved guard before a VXLAN
// device comes up at boot. The leading '-' keeps the network coming up even if
// the file is missing (vdxd re-applies the guard once it starts).
func vxlanGuardExecPre(nft string) string {
	return "ExecStartPre=-" + nft + " -f " + VXLANGuardFile + "\n"
}

// NFTBin locates nft for unit files (absolute path, as systemd requires).
func NFTBin() string {
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("nft"); err == nil {
		return p
	}
	return "/usr/sbin/nft"
}

// VXLANGuardExecPre is the ExecStartPre= line for a VXLAN boot unit.
func VXLANGuardExecPre() string { return vxlanGuardExecPre(NFTBin()) }
