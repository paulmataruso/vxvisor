package fabric

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// The "ride over management" underlay (docs/FABRIC.md §14 D6, §16). A fabric
// with Underlay = UnderlayMgmt has no dedicated NIC: each host's TEP sits on a
// WireGuard device (WGDev) whose encrypted UDP runs between the hosts' static
// management addresses. The management interface itself is never changed — no
// MTU, no address, no enslaving: WireGuard is one more UDP user of it, and its
// packets leave marked CS1 (below best effort) so management traffic wins
// whenever the link is congested.
//
// Every node generates its own key pair and the private key never leaves it.
// Public keys and endpoints reach the intent from each node itself over the
// signed peer API, and every node vetoes an intent that misstates its own.

const (
	UnderlayMgmt = "mgmt"
	WGDev        = "vxfwg0"
	WGPort       = 51871
	// WGOverhead is what WireGuard adds over IPv4: IP 20 + UDP 8 + header 16 + tag 16.
	WGOverhead  = 60
	WGKeepalive = 25
	// MgmtMTU is the fabric MTU over a 1500-byte management network (guests get 1390).
	MgmtMTU = 1500 - WGOverhead
	// WGConfDir is where the transient `wg syncconf` file goes: the distro's
	// AppArmor profile for wg (Ubuntu) lets it read config only from here.
	WGConfDir = "/etc/wireguard"
)

// OverMgmt reports whether the fabric rides over the management network.
func (f *Spec) OverMgmt() bool { return f.Underlay == UnderlayMgmt }

// NewWGKey returns a fresh private key in WireGuard's base64 form (clamped, as
// `wg genkey` makes them).
func NewWGKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[0] &= 248
	b[31] = b[31]&127 | 64
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

// WGPublic derives the public key of a base64 private key (what `wg pubkey`
// prints for it).
func WGPublic(priv string) (string, error) {
	raw, err := wgKeyBytes(priv)
	if err != nil {
		return "", fmt.Errorf("the WireGuard private key is malformed")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("the WireGuard private key is malformed")
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ValidWGKey reports whether s is a base64 WireGuard key (32 bytes, not zero).
func ValidWGKey(s string) bool {
	_, err := wgKeyBytes(s)
	return err == nil
}

func wgKeyBytes(s string) ([]byte, error) {
	if len(s) != 44 {
		return nil, fmt.Errorf("bad key length")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("bad key")
	}
	for _, c := range b {
		if c != 0 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("zero key")
}

// WGPeer is another fabric host as node's WireGuard device sees it.
type WGPeer struct {
	Node     string
	Pub      string
	Endpoint string // its static management IPv4
	TEP      string // bare IP: the only inner source it may send from
}

// WGPeers lists node's WireGuard peers, sorted by node (nil when node's fabric
// doesn't ride over management).
func (in *Intent) WGPeers(node string) []WGPeer {
	f, _ := in.HostOf(node)
	if f == nil || !f.OverMgmt() {
		return nil
	}
	var out []WGPeer
	for _, h := range f.Hosts {
		if h.Node != node {
			out = append(out, WGPeer{Node: h.Node, Pub: h.WGPub, Endpoint: h.Endpoint, TEP: h.TEPIP()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// WGConfig renders a `wg syncconf` file. Each peer is allowed only its own TEP,
// so one host can never speak for another's.
func WGConfig(priv string, peers []WGPeer) (string, error) {
	if !ValidWGKey(priv) {
		return "", fmt.Errorf("the WireGuard private key is malformed")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", priv, WGPort)
	for _, p := range peers {
		if !ValidWGKey(p.Pub) {
			return "", fmt.Errorf("peer %s: malformed WireGuard public key", p.Node)
		}
		if ipv4(p.Endpoint) == nil {
			return "", fmt.Errorf("peer %s: endpoint %q is not an IPv4 address", p.Node, p.Endpoint)
		}
		if ipv4(p.TEP) == nil {
			return "", fmt.Errorf("peer %s: TEP %q is not an IPv4 address", p.Node, p.TEP)
		}
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = %s/32\nPersistentKeepalive = %d\n",
			p.Pub, ipv4(p.Endpoint), WGPort, ipv4(p.TEP), WGKeepalive)
	}
	return b.String(), nil
}

// EnsureWG brings the WireGuard underlay to its desired state (idempotent): the
// device, its key and peers (`wg syncconf` keeps the live sessions of unchanged
// peers and removes stale ones), MTU, the TEP, up. The config passes through a
// 0600 file in dir (WGConfDir on a host), removed once loaded.
func EnsureWG(r Runner, dir, priv string, peers []WGPeer, tep string, mtu int) error {
	conf, err := WGConfig(priv, peers)
	if err != nil {
		return err
	}
	if ip, _, err := net.ParseCIDR(tep); err != nil || ip.To4() == nil {
		return fmt.Errorf("TEP %q is not an IPv4 address with prefix", tep)
	}
	if mtu < 1280 || mtu > 9216 {
		return fmt.Errorf("WireGuard MTU %d is out of range", mtu)
	}
	link, err := r.Run("ip", "-o", "link", "show", "dev", WGDev)
	if err != nil {
		if _, err := r.Run("ip", "link", "add", WGDev, "type", "wireguard"); err != nil {
			return err
		}
		link = ""
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, WGDev+"-*.conf") // 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.WriteString(conf)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if _, err := r.Run("wg", "syncconf", WGDev, tmp.Name()); err != nil {
		return err
	}
	if linkMTU(link) != mtu {
		if _, err := r.Run("ip", "link", "set", "dev", WGDev, "mtu", strconv.Itoa(mtu)); err != nil {
			return err
		}
	}
	_, _ = r.Run("sysctl", "-qw", "net.ipv6.conf."+WGDev+".disable_ipv6=1")
	if _, err := r.Run("ip", "addr", "replace", tep, "dev", WGDev); err != nil {
		return err
	}
	_, err = r.Run("ip", "link", "set", "dev", WGDev, "up")
	return err
}

// DeleteWG removes the WireGuard underlay device (and with it every session).
func DeleteWG(r Runner) error {
	if _, err := r.Run("ip", "-o", "link", "show", "dev", WGDev); err != nil {
		return nil
	}
	_, err := r.Run("ip", "link", "del", "dev", WGDev)
	return err
}

// linkMTU reads "mtu N" from one line of `ip -o link show` (0 = unknown).
func linkMTU(line string) int {
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "mtu" {
			n, _ := strconv.Atoi(f[i+1])
			return n
		}
	}
	return 0
}

// WGHandshakes reads the latest handshake per peer public key (unix seconds,
// 0 = never) from the device.
func WGHandshakes(r Runner) (map[string]int64, error) {
	out, err := r.Run("wg", "show", WGDev, "latest-handshakes")
	if err != nil {
		return nil, err
	}
	return parseWGHandshakes(out), nil
}

func parseWGHandshakes(out string) map[string]int64 {
	m := map[string]int64{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || !ValidWGKey(f[0]) {
			continue
		}
		if t, err := strconv.ParseInt(f[1], 10, 64); err == nil {
			m[f[0]] = t
		}
	}
	return m
}
