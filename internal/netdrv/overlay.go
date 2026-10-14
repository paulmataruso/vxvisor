package netdrv

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
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
