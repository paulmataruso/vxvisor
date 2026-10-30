package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/fabric"
	"vdxclone/internal/netdrv"
)

// The fabric's "ride over management" underlay (docs/FABRIC.md §16): this
// node's WireGuard key, its management endpoint, the checks that keep the
// management interface untouched, and the WireGuard device itself. Nothing here
// ever writes to the management interface: WireGuard only sends UDP over it.

var fabricWGKeyMu sync.Mutex

func (s *Service) fabricWGKeyPath() string {
	return filepath.Join(s.cfg.Paths.DataDir, "fabric-wg.key")
}

// fabricWGKey is this node's WireGuard private key (base64, 0600 in the data
// dir), created on first use. It never leaves this node.
func (s *Service) fabricWGKey() (string, error) {
	fabricWGKeyMu.Lock()
	defer fabricWGKeyMu.Unlock()
	p := s.fabricWGKeyPath()
	b, err := os.ReadFile(p)
	if err == nil {
		if k := strings.TrimSpace(string(b)); fabric.ValidWGKey(k) {
			return k, nil
		}
		return "", fmt.Errorf("%s is malformed — this host's fabric tunnel can't come up", p)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	k, err := fabric.NewWGKey()
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(k + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
		return "", werr
	}
	return k, nil
}

// FabricWGInfo is what a node reports about riding the fabric over its
// management network: where its tunnel ends and its public key.
type FabricWGInfo struct {
	Node     string `json:"node"`
	Iface    string `json:"iface,omitempty"`    // management interface
	Endpoint string `json:"endpoint,omitempty"` // its static management IPv4
	MTU      int    `json:"mtu,omitempty"`      // the management interface's MTU
	Pub      string `json:"pub,omitempty"`
	Problem  string `json:"problem,omitempty"` // why this node can't ride over management
}

// FabricLocalWG reports this node's management endpoint and WireGuard key.
func (s *Service) FabricLocalWG() FabricWGInfo {
	info := FabricWGInfo{Node: s.selfNode()}
	iface, ep, err := s.mgmtEndpoint()
	info.Iface, info.Endpoint = iface, ep
	if iface != "" {
		info.MTU = netdrv.LinkMTU(iface)
	}
	if err != nil {
		info.Problem = err.Error()
		return info
	}
	priv, err := s.fabricWGKey()
	if err == nil {
		info.Pub, err = fabric.WGPublic(priv)
	}
	if err != nil {
		info.Problem = err.Error()
	}
	return info
}

// nodeWG is FabricLocalWG of any node (over the signed peer API: the key and
// endpoint come from the node itself).
func (s *Service) nodeWG(node string) (FabricWGInfo, error) {
	if node == s.selfNode() {
		return s.FabricLocalWG(), nil
	}
	base, err := (fabricPeers{s}).base(node)
	if err != nil {
		return FabricWGInfo{}, err
	}
	body, code, err := s.peerc.Get(base, "/cluster/v1/fabric/wg")
	if err := peerErr(node, body, code, err); err != nil {
		return FabricWGInfo{}, err
	}
	var info FabricWGInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return FabricWGInfo{}, err
	}
	if info.Node != node {
		return FabricWGInfo{}, fmt.Errorf("%s answered as %q", node, info.Node)
	}
	return info, nil
}

// FabricWGChoices is every cluster node's management endpoint, for the wizard.
func (s *Service) FabricWGChoices(p *Principal) map[string]FabricWGInfo {
	out := map[string]FabricWGInfo{}
	if !p.IsAdmin {
		return out
	}
	for _, n := range s.clusterNodeNames() {
		info, err := s.nodeWG(n)
		if err != nil {
			info = FabricWGInfo{Node: n, Problem: err.Error()}
		}
		info.Pub = "" // the wizard doesn't need it; the server fetches it again
		out[n] = info
	}
	return out
}

// fillWGHost completes a host of a fabric over management with what the node
// itself reports: its management interface, endpoint and public key.
func (s *Service) fillWGHost(h *fabric.Host) error {
	info, err := s.nodeWG(h.Node)
	if err != nil {
		return err
	}
	if info.Problem != "" {
		return fmt.Errorf("%s can't ride over management: %s", h.Node, info.Problem)
	}
	h.Iface, h.VLAN, h.Endpoint, h.WGPub = info.Iface, 0, info.Endpoint, info.Pub
	return nil
}

// fabricVIPs are the cluster's floating management addresses as this node
// knows them: never a tunnel endpoint (a VIP moves between nodes).
func (s *Service) fabricVIPs() map[string]bool {
	out := map[string]bool{}
	add := func(v string) {
		if ip := net.ParseIP(strings.Split(strings.TrimSpace(v), "/")[0]); ip != nil {
			out[ip.String()] = true
		}
	}
	if s.cfg != nil {
		add(s.cfg.Cluster.VIP)
	}
	if s.role != nil {
		add(s.role.AcquiredVIP())
		_, _, vip := s.role.LeaderInfo()
		add(vip)
	}
	return out
}

// mgmtEndpoint is this node's management interface and the static IPv4 on it
// that its fabric tunnel ends at: the configured management address, else the
// admin listener's, else the interface's first. A DHCP lease (it can change
// under a running tunnel) or a cluster VIP (it moves) is refused.
func (s *Service) mgmtEndpoint() (string, string, error) {
	iface := s.mgmtIface()
	if iface == "" {
		return "", "", errMgmtUnknown
	}
	addrs, err := readLiveAddrs(iface)
	if err != nil {
		return iface, "", err
	}
	vips := s.fabricVIPs()
	want := ""
	if s.cfg != nil {
		if ip := net.ParseIP(strings.Split(strings.TrimSpace(s.cfg.Cluster.MgmtAddr), "/")[0]); ip != nil {
			want = ip.String()
		} else if ip := listenIP(s.cfg.Server.Addr); ip != nil {
			want = ip.String()
		}
	}
	for _, a := range addrs {
		ip := a.IP.To4()
		if ip == nil || (want != "" && ip.String() != want) || (want == "" && vips[ip.String()]) {
			continue
		}
		switch {
		case vips[ip.String()]:
			return iface, ip.String(), fmt.Errorf("the management address %s is the cluster VIP — set [cluster] mgmt_addr to this node's own address", ip)
		case a.Dynamic:
			return iface, ip.String(), fmt.Errorf("the management address %s on %s is a DHCP lease — a fabric over management needs a static address (a new lease would cut the tunnel)", ip, iface)
		}
		return iface, ip.String(), nil
	}
	if want != "" {
		return iface, "", fmt.Errorf("the management address %s isn't on %s", want, iface)
	}
	return iface, "", fmt.Errorf("%s has no IPv4 address", iface)
}

// checkMgmtUnderlay is checkUnderlay for a fabric over management: WireGuard
// is available, the host entry is what this node itself reports, the
// management MTU carries the tunnel, and the device and port are free. The
// management interface is only read.
func (s *Service) checkMgmtUnderlay(f *fabric.Spec, h fabric.Host) error {
	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("wireguard-tools isn't installed — re-run deploy/install.sh")
	}
	if out, err := exec.Command("modprobe", "wireguard").CombinedOutput(); err != nil {
		return fmt.Errorf("can't load the wireguard module: %s", strings.TrimSpace(string(out)))
	}
	info := s.FabricLocalWG()
	if info.Problem != "" {
		return fmt.Errorf("%s", info.Problem)
	}
	if h.Iface != info.Iface {
		return fmt.Errorf("the management interface here is %s, not %s", info.Iface, h.Iface)
	}
	if h.Endpoint != info.Endpoint {
		return fmt.Errorf("this host's management address is %s, not %s", info.Endpoint, h.Endpoint)
	}
	if h.WGPub != info.Pub {
		return fmt.Errorf("that isn't this host's WireGuard key — run the wizard again")
	}
	if need := f.MTU + fabric.WGOverhead; info.MTU > 0 && info.MTU < need {
		return fmt.Errorf("%s has MTU %d; the tunnel at fabric MTU %d needs %d — lower the fabric MTU to %d (the management interface is never changed)",
			info.Iface, info.MTU, f.MTU, need, info.MTU-fabric.WGOverhead)
	}
	if netdrv.IfaceExists(fabric.WGDev) {
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM fabric_underlay WHERE dev=?`, fabric.WGDev).Scan(&n)
		if n == 0 {
			return fmt.Errorf("%s already exists and vdxd didn't make it", fabric.WGDev)
		}
		return nil
	}
	c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", fabric.WGPort))
	if err != nil {
		return fmt.Errorf("UDP port %d (the fabric tunnel) is in use on this host", fabric.WGPort)
	}
	return c.Close()
}

// ensureWGUnderlay puts this host's TEP on the WireGuard device (desired
// state): the key must still be the one the fabric knows.
func (s *Service) ensureWGUnderlay(f *fabric.Spec, h fabric.Host, peers []fabric.WGPeer) error {
	priv, err := s.fabricWGKey()
	if err != nil {
		return err
	}
	if pub, err := fabric.WGPublic(priv); err != nil || pub != h.WGPub {
		return fmt.Errorf("this host's WireGuard key (%s) isn't the one the fabric has — remove the host from the fabric and add it again", s.fabricWGKeyPath())
	}
	return fabric.EnsureWG(fabricExec, fabric.WGConfDir, priv, peers, h.TEP, f.MTU)
}

// FabricWGPeer is one WireGuard session as this node sees it.
type FabricWGPeer struct {
	Node      string `json:"node"`
	Endpoint  string `json:"endpoint"`
	Handshake int64  `json:"hs"` // unix seconds of the latest handshake, 0 = never
}

// HandshakeAge is how long ago the latest handshake was ("never" when none).
func (p FabricWGPeer) HandshakeAge() string {
	if p.Handshake == 0 {
		return "never"
	}
	return time.Since(time.Unix(p.Handshake, 0)).Round(time.Second).String() + " ago"
}

// Stale reports a session with no handshake for over three minutes (WireGuard
// re-handshakes every two while traffic flows, and keepalives keep it flowing).
func (p FabricWGPeer) Stale() bool {
	return p.Handshake == 0 || time.Since(time.Unix(p.Handshake, 0)) > 3*time.Minute
}

// wgStatus reads this node's tunnel sessions.
func wgStatus(peers []fabric.WGPeer) []FabricWGPeer {
	hs, _ := fabric.WGHandshakes(fabricExec)
	var out []FabricWGPeer
	for _, p := range peers {
		out = append(out, FabricWGPeer{Node: p.Node, Endpoint: p.Endpoint, Handshake: hs[p.Pub]})
	}
	return out
}
