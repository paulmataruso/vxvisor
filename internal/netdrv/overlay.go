package netdrv

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// OverlayConfig describes the VXLAN fabric for one node. Every node in the
// cluster shares the same VNI, so their per-node bridges behave as a single L2
// broadcast domain regardless of the physical network between them.
type OverlayConfig struct {
	Bridge      string // host bridge VM taps enslave to (e.g. vdxbr0)
	VNI         int    // VXLAN network identifier, cluster-wide
	Underlay    string // physical NIC carrying the encapsulated traffic
	Gateway     string // L3 gateway address assigned to the bridge
	GatewayCIDR int    // prefix length for the gateway address (e.g. 16)
}

// vxlanDev is the deterministic VXLAN interface name for a VNI.
func (oc OverlayConfig) vxlanDev() string { return "vdxvx" + strconv.Itoa(oc.VNI) }

// RenderOverlayPlan returns the exact `ip` command lines EnsureOverlay will run,
// as argument slices. It is a pure function so the overlay wiring can be
// unit-tested and reviewed (or dry-run printed) without touching the host.
func RenderOverlayPlan(oc OverlayConfig) [][]string {
	vx := oc.vxlanDev()
	plan := [][]string{
		{"ip", "link", "add", oc.Bridge, "type", "bridge"},
		{"ip", "link", "set", oc.Bridge, "up"},
		{"ip", "link", "add", vx, "type", "vxlan",
			"id", strconv.Itoa(oc.VNI), "dev", oc.Underlay, "dstport", "4789"},
		{"ip", "link", "set", vx, "master", oc.Bridge},
		{"ip", "link", "set", vx, "up"},
	}
	if oc.Gateway != "" && oc.GatewayCIDR > 0 {
		plan = append(plan, []string{"ip", "addr", "add",
			oc.Gateway + "/" + strconv.Itoa(oc.GatewayCIDR), "dev", oc.Bridge})
	}
	return plan
}

// EnsureBridge creates and brings up a plain host bridge (idempotent). This is
// the single-host / flat-LAN path — VM taps enslave here and reach the physical
// network directly, with no encapsulation.
func EnsureBridge(br string) error {
	if !ifaceExists(br) {
		if err := run("ip", "link", "add", br, "type", "bridge"); err != nil {
			return err
		}
	}
	return run("ip", "link", "set", br, "up")
}

// EnsureOverlay builds the VXLAN fabric for this node idempotently: the bridge,
// the VXLAN device enslaved to it, and (optionally) the L3 gateway address. An
// already-present device is left as-is rather than recreated, so it is safe to
// call on every start.
func EnsureOverlay(oc OverlayConfig) error {
	if oc.Underlay == "" {
		return fmt.Errorf("overlay: underlay NIC is required (set [cluster].underlay)")
	}
	if !ValidIfName(oc.Underlay) || !ValidIfName(oc.Bridge) {
		return fmt.Errorf("overlay: [cluster].underlay %q / bridge %q must be valid interface names", oc.Underlay, oc.Bridge)
	}
	if oc.VNI < MinVNI || oc.VNI > MaxVNI {
		return fmt.Errorf("overlay: [cluster].vni %d is out of range (1–16777215)", oc.VNI)
	}
	if err := EnsureBridge(oc.Bridge); err != nil {
		return err
	}
	vx := oc.vxlanDev()
	if !ifaceExists(vx) {
		if err := run("ip", "link", "add", vx, "type", "vxlan",
			"id", strconv.Itoa(oc.VNI), "dev", oc.Underlay, "dstport", "4789"); err != nil {
			return err
		}
		if err := run("ip", "link", "set", vx, "master", oc.Bridge); err != nil {
			return err
		}
	}
	if err := run("ip", "link", "set", vx, "up"); err != nil {
		return err
	}
	if oc.Gateway != "" && oc.GatewayCIDR > 0 {
		// Best effort: adding an address that already exists returns an error we
		// deliberately ignore so the call stays idempotent.
		_ = run("ip", "addr", "add", oc.Gateway+"/"+strconv.Itoa(oc.GatewayCIDR), "dev", oc.Bridge)
	}
	return nil
}

// TeardownOverlay removes the VXLAN device (best effort). The bridge is left in
// place because other VMs may still be attached to it.
func TeardownOverlay(oc OverlayConfig) { _ = run("ip", "link", "del", oc.vxlanDev()) }

// SetupTapOwned creates a tap owned by uid (so a dropped-privilege QEMU can open
// it), brings it up, and enslaves it to the bridge. uid<=0 leaves ownership to
// root (QEMU running as root). It is idempotent across restarts.
func SetupTapOwned(tap, bridge string, uid int) error {
	if !ifaceExists(tap) {
		args := []string{"ip", "tuntap", "add", tap, "mode", "tap"}
		if uid > 0 {
			args = append(args, "user", strconv.Itoa(uid))
		}
		if err := run(args...); err != nil {
			return err
		}
	}
	if err := run("ip", "link", "set", tap, "up"); err != nil {
		return err
	}
	return run("ip", "link", "set", tap, "master", bridge)
}

// ---- IPAM: allocate guest addresses from a network's CIDR -----------------

// AllocLease assigns the lowest free host address in the network's CIDR to a
// session, skipping the network, gateway and broadcast addresses, and records it
// in ip_leases. It is idempotent: an existing lease for the session is returned
// unchanged. The returned string is "ip/prefix" ready for cloud-init.
func (s *Store) AllocLease(networkID int64, sessionID, mac, cidr, gateway string) (string, error) {
	// Already leased? Return it (survives restart / repeated starts).
	var existing string
	if err := s.db.QueryRow(`SELECT ip FROM ip_leases WHERE network_id=? AND session_id=?`,
		networkID, sessionID).Scan(&existing); err == nil && existing != "" {
		return existing, nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("bad network cidr %q: %w", cidr, err)
	}
	prefix, _ := ipnet.Mask.Size()

	used := map[string]bool{}
	rows, err := s.db.Query(`SELECT ip FROM ip_leases WHERE network_id=?`, networkID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			// Stored as ip/prefix; index by bare address.
			used[hostOf(ip)] = true
		}
	}
	rows.Close()
	gw := net.ParseIP(gateway).To4()

	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	ones := uint32(0xFFFFFFFF) >> uint(prefix)
	broadcast := base | ones
	for cand := base + 1; cand < broadcast; cand++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], cand)
		ip := net.IP(b[:])
		if gw != nil && ip.Equal(gw) {
			continue
		}
		if used[ip.String()] {
			continue
		}
		leased := ip.String() + "/" + strconv.Itoa(prefix)
		if _, err := s.db.Exec(`INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,?,?,?)`,
			networkID, sessionID, leased, mac); err != nil {
			return "", err
		}
		return leased, nil
	}
	return "", fmt.Errorf("network %d (%s) exhausted", networkID, cidr)
}

// LeaseFor returns the bare guest IP leased to a session (no prefix), or "" if
// the session has no lease (e.g. user-mode networking).
func (s *Store) LeaseFor(sessionID string) string {
	var ip string
	if err := s.db.QueryRow(`SELECT ip FROM ip_leases WHERE session_id=? LIMIT 1`, sessionID).Scan(&ip); err != nil {
		return ""
	}
	return hostOf(ip)
}

// ReleaseLease frees any address held by a session.
func (s *Store) ReleaseLease(sessionID string) {
	_, _ = s.db.Exec(`DELETE FROM ip_leases WHERE session_id=?`, sessionID)
}

func hostOf(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

// ---- per-network VXLAN segments (general VXLAN, not the single cluster overlay)

// VNINetworkNames returns the deterministic bridge + vxlan device names for a
// user VXLAN network, keyed on the NETWORK ROW ID so they never collide with the
// cluster overlay's vdxvx<VNI> devices or with each other.
func VNINetworkNames(id int64) (bridge, vxdev string) {
	return "vdxubr" + strconv.FormatInt(id, 10), "vdxuvx" + strconv.FormatInt(id, 10)
}

// EnsureVNINetwork idempotently builds one VXLAN L2 segment: a per-network bridge
// with a VXLAN device enslaved to it (VM taps enslave to the bridge). Peers get
// static head-end FDB entries (unicast BUM replication) so the segment spans
// nodes without multicast. Optional gatewayCIDR puts an L3 gateway on the bridge.
func EnsureVNINetwork(id int64, underlay, local string, vni, dstport, mtu int, peers []string, gatewayCIDR string) error {
	if underlay == "" {
		return fmt.Errorf("vxlan network: underlay NIC is required")
	}
	if vni <= 0 {
		return fmt.Errorf("vxlan network: a VNI is required")
	}
	if dstport <= 0 {
		dstport = 4789
	}
	if mtu <= 0 {
		mtu = 1450
	}
	if err := checkVNINetwork(underlay, local, vni, dstport, mtu, peers, gatewayCIDR); err != nil {
		return err
	}
	bridge, vx := VNINetworkNames(id)
	if !ifaceExists(bridge) {
		if err := run("ip", "link", "add", bridge, "type", "bridge"); err != nil {
			return err
		}
	}
	_ = run("ip", "link", "set", bridge, "mtu", strconv.Itoa(mtu))
	if err := run("ip", "link", "set", bridge, "up"); err != nil {
		return err
	}
	if !ifaceExists(vx) {
		args := []string{"ip", "link", "add", vx, "type", "vxlan",
			"id", strconv.Itoa(vni), "dev", underlay, "dstport", strconv.Itoa(dstport)}
		if local != "" {
			args = append(args, "local", local)
		}
		if err := run(args...); err != nil {
			return err
		}
		if err := run("ip", "link", "set", vx, "master", bridge); err != nil {
			return err
		}
	}
	_ = run("ip", "link", "set", vx, "mtu", strconv.Itoa(mtu))
	if err := run("ip", "link", "set", vx, "up"); err != nil {
		return err
	}
	for _, p := range peers {
		if p = strings.TrimSpace(p); p != "" {
			// append (not replace) the all-zero FDB entry per peer = head-end BUM.
			_ = run("bridge", "fdb", "append", "00:00:00:00:00:00", "dev", vx, "dst", p)
		}
	}
	if gatewayCIDR != "" {
		_ = run("ip", "addr", "add", gatewayCIDR, "dev", bridge) // idempotent-ignore
	}
	return nil
}

// TeardownVNINetwork removes a user VXLAN network's devices (best effort).
func TeardownVNINetwork(id int64) {
	bridge, vx := VNINetworkNames(id)
	_ = run("ip", "link", "del", vx)
	_ = run("ip", "link", "del", bridge)
}

// checkVNINetwork is the sink backstop for a VXLAN port group: every value is
// passed to ip(8) and written into its boot unit.
func checkVNINetwork(underlay, local string, vni, dstport, mtu int, peers []string, gatewayCIDR string) error {
	if err := (VXLANParams{VNI: vni, DstPort: dstport, MTU: mtu, Underlay: underlay, Local: local, Peers: peers}).Validate(); err != nil {
		return fmt.Errorf("vxlan network: %w", err)
	}
	if gatewayCIDR != "" {
		if err := validGatewayCIDR(gatewayCIDR); err != nil {
			return fmt.Errorf("vxlan network: %w", err)
		}
	}
	return nil
}

// RenderVNINetworkUnit returns a systemd oneshot unit that recreates the segment
// at boot (RemainAfterExit) so VXLAN VM networks survive a reboot. It loads the
// VXLAN ingress guard first so the device never comes up unfiltered. Every value
// is validated (a newline would smuggle in its own ExecStart=).
func RenderVNINetworkUnit(id int64, underlay, local string, vni, dstport, mtu int, peers []string, gatewayCIDR string) (string, error) {
	if err := checkVNINetwork(underlay, local, vni, dstport, mtu, peers, gatewayCIDR); err != nil {
		return "", err
	}
	bridge, vx := VNINetworkNames(id)
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=VXVisor VXLAN network %d (%s)\nAfter=network-online.target\nWants=network-online.target\n\n", id, bridge)
	b.WriteString("[Service]\nType=oneshot\nRemainAfterExit=yes\n")
	b.WriteString(VXLANGuardExecPre())
	ex := func(f string, a ...any) { fmt.Fprintf(&b, "ExecStart=-%s\n", fmt.Sprintf(f, a...)) }
	ex("/sbin/ip link add %s type bridge", bridge)
	ex("/sbin/ip link set %s mtu %d", bridge, mtu)
	ex("/sbin/ip link set %s up", bridge)
	local2 := ""
	if local != "" {
		local2 = " local " + local
	}
	ex("/sbin/ip link add %s type vxlan id %d dev %s dstport %d%s", vx, vni, underlay, dstport, local2)
	ex("/sbin/ip link set %s master %s", vx, bridge)
	ex("/sbin/ip link set %s mtu %d", vx, mtu)
	ex("/sbin/ip link set %s up", vx)
	for _, p := range peers {
		if p = strings.TrimSpace(p); p != "" {
			ex("/sbin/bridge fdb append 00:00:00:00:00:00 dev %s dst %s", vx, p)
		}
	}
	if gatewayCIDR != "" {
		ex("/sbin/ip addr add %s dev %s", gatewayCIDR, bridge)
	}
	b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return b.String(), nil
}
