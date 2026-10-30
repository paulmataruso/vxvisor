package fabric

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 7748 §6.1: Alice's X25519 key pair, as WireGuard writes keys.
func rfcKeys(t *testing.T) (priv, pub string) {
	t.Helper()
	p, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	q, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	return base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(q)
}

func TestWGKeys(t *testing.T) {
	priv, pub := rfcKeys(t)
	if got, err := WGPublic(priv); err != nil || got != pub {
		t.Fatalf("WGPublic = %q, %v; want %q", got, err, pub)
	}
	k, err := NewWGKey()
	if err != nil || !ValidWGKey(k) {
		t.Fatalf("NewWGKey = %q, %v", k, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(k)
	if raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Fatalf("key not clamped like wg genkey: %x", raw)
	}
	if k2, _ := NewWGKey(); k2 == k {
		t.Fatalf("two keys alike")
	}
	if p1, _ := WGPublic(k); p1 == "" || !ValidWGKey(p1) {
		t.Fatalf("public of a fresh key: %q", p1)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("A", 43) + "=", base64.StdEncoding.EncodeToString(make([]byte, 31)) + "AAAA",
		base64.StdEncoding.EncodeToString(make([]byte, 32)), "!" + pub[1:]} {
		if ValidWGKey(bad) {
			t.Errorf("ValidWGKey(%q) = true", bad)
		}
	}
	if _, err := WGPublic("nope"); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatalf("a malformed private key must fail without echoing it: %v", err)
	}
}

// mgmtSample is sample() riding over management.
func mgmtSample(t *testing.T) Intent {
	t.Helper()
	in := sample()
	_, pub := rfcKeys(t)
	k2, _ := NewWGKey()
	pub2, _ := WGPublic(k2)
	f := &in.Fabrics[0]
	f.Underlay, f.MTU = UnderlayMgmt, MgmtMTU
	f.Hosts = []Host{
		{Node: "h1", Iface: "vSwitch0", TEP: "10.250.0.1/24", Endpoint: "172.16.0.11", WGPub: pub},
		{Node: "h2", Iface: "bond0", TEP: "10.250.0.2/24", Endpoint: "172.16.0.12", WGPub: pub2},
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("mgmt sample: %v", err)
	}
	return in
}

func TestValidateMgmt(t *testing.T) {
	in := mgmtSample(t)
	if d := in.UnderlayOf("h1"); d != WGDev {
		t.Fatalf("underlay = %q, want %s", d, WGDev)
	}
	if p, _ := in.HostPlan("h1"); p.GuestMTU != 1390 {
		t.Fatalf("guest MTU over management = %d, want 1390", p.GuestMTU)
	}
	for name, mut := range map[string]func(*Spec){
		"unknown underlay":       func(f *Spec) { f.Underlay = "wifi" },
		"VLAN over management":   func(f *Spec) { f.Hosts[0].VLAN = 30 },
		"no key":                 func(f *Spec) { f.Hosts[1].WGPub = "" },
		"bad key":                func(f *Spec) { f.Hosts[1].WGPub = "AAAA" },
		"same key":               func(f *Spec) { f.Hosts[1].WGPub = f.Hosts[0].WGPub },
		"no endpoint":            func(f *Spec) { f.Hosts[0].Endpoint = "" },
		"IPv6 endpoint":          func(f *Spec) { f.Hosts[0].Endpoint = "fd00::1" },
		"loopback endpoint":      func(f *Spec) { f.Hosts[0].Endpoint = "127.0.0.1" },
		"non-canonical endpoint": func(f *Spec) { f.Hosts[0].Endpoint = "172.016.0.11" },
		"same endpoint":          func(f *Spec) { f.Hosts[1].Endpoint = f.Hosts[0].Endpoint },
		"endpoint in TEP subnet": func(f *Spec) { f.Hosts[1].Endpoint = "10.250.0.9" },
		"endpoint on dedicated":  func(f *Spec) { f.Underlay = "" },
	} {
		bad := in.Clone()
		mut(&bad.Fabrics[0])
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A dedicated fabric's hosts carry no WireGuard fields.
	ded := sample()
	ded.Fabrics[0].Hosts[0].WGPub = in.Fabrics[0].Hosts[0].WGPub
	if err := ded.Validate(); err == nil {
		t.Errorf("a key on a dedicated fabric was accepted")
	}
}

func TestWGConfig(t *testing.T) {
	in := mgmtSample(t)
	ded := sample()
	if p := ded.WGPeers("h1"); p != nil {
		t.Fatalf("a dedicated fabric has no WireGuard peers: %v", p)
	}
	peers := in.WGPeers("h1")
	if len(peers) != 1 || peers[0].Node != "h2" || peers[0].TEP != "10.250.0.2" || peers[0].Endpoint != "172.16.0.12" {
		t.Fatalf("peers = %+v", peers)
	}
	priv, _ := rfcKeys(t)
	conf, err := WGConfig(priv, peers)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Interface]\nPrivateKey = " + priv + "\nListenPort = 51871\n", "[Peer]\nPublicKey = " + peers[0].Pub,
		"Endpoint = 172.16.0.12:51871\n", "AllowedIPs = 10.250.0.2/32\n", "PersistentKeepalive = 25\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("config missing %q:\n%s", want, conf)
		}
	}
	for name, p := range map[string]WGPeer{
		"bad key":      {Node: "x", Pub: "AAAA", Endpoint: "172.16.0.12", TEP: "10.250.0.2"},
		"bad endpoint": {Node: "x", Pub: peers[0].Pub, Endpoint: "172.16.0.12\nAllowedIPs = 0.0.0.0/0", TEP: "10.250.0.2"},
		"bad TEP":      {Node: "x", Pub: peers[0].Pub, Endpoint: "172.16.0.12", TEP: "0.0.0.0/0"},
	} {
		if _, err := WGConfig(priv, []WGPeer{p}); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if _, err := WGConfig("x", peers); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("bad private key: %v", err)
	}
}

// wgFake stands in for the host: which devices exist and their MTU.
type wgFake struct {
	cmds []string
	dev  bool
	mtu  string
	conf string // the config wg syncconf was handed (read while it existed)
	mode os.FileMode
}

func (f *wgFake) Run(args ...string) (string, error) {
	c := strings.Join(args, " ")
	f.cmds = append(f.cmds, c)
	switch {
	case c == "ip -o link show dev "+WGDev:
		if !f.dev {
			return "", errors.New("does not exist")
		}
		return "9: vxfwg0: <POINTOPOINT,NOARP,UP> mtu " + f.mtu + " qdisc noqueue\n", nil
	case c == "ip link add "+WGDev+" type wireguard":
		f.dev, f.mtu = true, "1420"
	case c == "ip link del dev "+WGDev:
		f.dev = false
	case strings.HasPrefix(c, "wg syncconf "+WGDev+" "):
		b, err := os.ReadFile(args[3])
		if err != nil {
			return "", err
		}
		st, _ := os.Stat(args[3])
		f.conf, f.mode = string(b), st.Mode().Perm()
	case strings.HasPrefix(c, "ip link set dev "+WGDev+" mtu "):
		f.mtu = args[6]
	}
	return "", nil
}

func TestEnsureWG(t *testing.T) {
	in := mgmtSample(t)
	priv, _ := rfcKeys(t)
	dir := t.TempDir()
	f := &wgFake{}
	if err := EnsureWG(f, dir, priv, in.WGPeers("h1"), "10.250.0.1/24", 1440); err != nil {
		t.Fatal(err)
	}
	want := []string{"ip link add vxfwg0 type wireguard", "wg syncconf vxfwg0 ", "ip link set dev vxfwg0 mtu 1440",
		"ip addr replace 10.250.0.1/24 dev vxfwg0", "ip link set dev vxfwg0 up"}
	at := 0
	for _, c := range f.cmds {
		if at < len(want) && strings.HasPrefix(c, want[at]) {
			at++
		}
	}
	if at != len(want) {
		t.Fatalf("commands %q, want in order %q", f.cmds, want)
	}
	if !strings.Contains(f.conf, "AllowedIPs = 10.250.0.2/32") || f.mode != 0o600 {
		t.Fatalf("config %o:\n%s", f.mode, f.conf)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Fatalf("the config (with the private key) was left behind: %v", left)
	}
	for _, c := range f.cmds {
		if strings.Contains(c, priv) {
			t.Fatalf("the private key reached a command line: %q", c)
		}
	}
	// Again: the device exists at the right MTU, so it is neither re-made nor re-sized.
	f.cmds = nil
	if err := EnsureWG(f, dir, priv, in.WGPeers("h1"), "10.250.0.1/24", 1440); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.cmds {
		if strings.Contains(c, "link add") || strings.Contains(c, " mtu ") {
			t.Fatalf("second run changed the device: %q", f.cmds)
		}
	}
	if err := DeleteWG(f); err != nil || f.dev {
		t.Fatalf("DeleteWG: %v, dev=%v", err, f.dev)
	}
	if err := EnsureWG(f, dir, priv, in.WGPeers("h1"), "10.250.0.1/24", 99999); err == nil {
		t.Fatalf("an out-of-range MTU was applied")
	}
}

func TestParseWGHandshakes(t *testing.T) {
	_, pub := rfcKeys(t)
	m := parseWGHandshakes(pub + "\t1700000000\nnot-a-key\t5\n" + "i" + pub[1:] + "\t0\n\n")
	if m[pub] != 1700000000 || len(m) != 2 {
		t.Fatalf("handshakes = %v", m)
	}
}

func TestFirewallMgmt(t *testing.T) {
	in := mgmtSample(t)
	fw, err := Firewall(&in, "h1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"meta nfproto ipv4 udp dport 51871 ip saddr != { 172.16.0.12 } counter drop\n",
		"meta nfproto ipv6 udp dport 51871 counter drop\n",
		"ip saddr 10.250.0.0/24 iifname != { \"vxfwg0\", \"lo\" } counter drop\n",
		"type filter hook postrouting priority mangle; policy accept;\n    udp sport 51871 counter ip dscp set cs1\n",
	} {
		if !strings.Contains(fw, want) {
			t.Errorf("firewall missing %q:\n%s", want, fw)
		}
	}
	if strings.Index(fw, "51871 ip saddr") > strings.Index(fw, "jump guest_in") {
		t.Errorf("the tunnel filter must come first in input")
	}
	// A single host accepts the tunnel from no one.
	one := in.Clone()
	one.Fabrics[0].Hosts = one.Fabrics[0].Hosts[:1]
	if fw1, _ := Firewall(&one, "h1"); !strings.Contains(fw1, "    udp dport 51871 counter drop\n") {
		t.Errorf("single host:\n%s", fw1)
	}
	ded := sample()
	if fwd, _ := Firewall(&ded, "h1"); strings.Contains(fwd, "51871") || strings.Contains(fwd, "dscp") {
		t.Errorf("a dedicated fabric got the tunnel rules:\n%s", fwd)
	}
	if os.Getenv("VX_NFT_CHECK") == "1" {
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(fw)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("nft -c: %v\n%s\n%s", err, out, fw)
		}
	}
}
