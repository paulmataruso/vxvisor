package service

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"vdxclone/internal/netdrv"
)

// Networking entry points (M4). user-mode port forwards are safe and need no
// host changes; bridge/vlan networks are recorded here and realized by the
// session manager when a NIC attaches to them.

func (s *Service) ListNetworks(p *Principal) ([]netdrv.Network, error) {
	if p.OrgID == 0 {
		return nil, nil
	}
	return s.net.ListNetworks(p.OrgID)
}

func (s *Service) CreateNetwork(p *Principal, n netdrv.Network, ip string) (int64, error) {
	return s.createNetwork(p, n, false, ip)
}

// createNetwork records (and for VXLAN, builds) a port group. routed marks a
// VXLAN port group as routed through this host (networks.nat=1: host NAT on the
// next routing apply, and no host isolation); otherwise it is fenced off from
// the host like a tenant bridge.
func (s *Service) createNetwork(p *Principal, n netdrv.Network, routed bool, ip string) (int64, error) {
	if !p.atLeast("admin") {
		return 0, ErrUnauthorized
	}
	n.OrgID = p.OrgID
	if n.Mode == "" {
		n.Mode = "user"
	}
	// A raw VXLAN port group binds a host underlay NIC and takes a free-form VNI
	// — an instance-admin-only operation. Per-org admins build isolated segments
	// through the tenant-network path (server-chosen bridge, allocated identity),
	// never this free-text form. (Internal callers pass p as an instance admin.)
	if n.Mode == "vxlan" && !p.IsAdmin {
		return 0, ErrUnauthorized
	}
	// VLAN 1 is every vSwitch port's untagged default (PVID 1): a "VLAN 1" port
	// group would rewrite the uplink's native VLAN. 0 means untagged.
	if n.VLANID != 0 && (n.VLANID < 2 || n.VLANID > 4094) {
		return 0, fmt.Errorf("VLAN %d is out of range — use 0 for untagged or 2–4094 (VLAN 1 is the vSwitch's untagged default)", n.VLANID)
	}
	if n.Mode == "vxlan" {
		if err := s.validateVXLANNetwork(&n); err != nil {
			return 0, err
		}
	}
	// Cross-tenant collision guard: refuse a TAGGED port group (vlan_id>0) whose
	// bridge+VLAN is already claimed by a DIFFERENT org — that would merge two
	// tenants onto one 802.1q segment. Untagged (vlan_id=0) is intentionally left
	// alone so the historical shared-bridge default still works. Advisory: internal
	// inserts (default port group, vRouter legs, VXLAN realize) bypass this method.
	if n.VLANID > 0 && n.Bridge != "" {
		var other int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM networks WHERE bridge=? AND vlan_id=? AND org_id<>?`,
			n.Bridge, n.VLANID, p.OrgID).Scan(&other)
		if other > 0 {
			return 0, fmt.Errorf("VLAN %d on bridge %s is already in use by another organization", n.VLANID, n.Bridge)
		}
	}
	id, err := s.net.CreateNetwork(n)
	if err != nil {
		return 0, err
	}
	// A first-class VXLAN network gets its own L2 segment: a per-network bridge
	// (keyed on the row id, so no collision with the cluster overlay or other
	// VXLAN nets) that VMs attach to, persisted via a systemd unit for reboot.
	if n.Mode == "vxlan" {
		if routed {
			_, _ = s.db.Exec(`UPDATE networks SET nat=1 WHERE id=?`, id)
		}
		// The row exists now, so the ingress guard (only this VNI's peers) and
		// the host fence (by bridge name) are in place before the device is up.
		s.refreshVXLANHost()
		if err := s.realizeVXLANNetwork(id, n); err != nil {
			// Roll back cleanly: tear down any devices/unit the partial realize
			// created, then drop the row — never leak a half-built segment.
			netdrv.TeardownVNINetwork(id)
			_ = os.Remove(vxlanNetUnitPath(id))
			_ = s.net.DeleteNetwork(p.OrgID, id)
			s.refreshVXLANHost()
			return 0, err
		}
		// Again, now that the bridge exists: per-interface forwarding off.
		s.refreshVXLANHost()
	}
	// If this port group is on a vSwitch with a VLAN, carry that VLAN tagged on
	// the vSwitch's uplink trunk so the port group reaches the physical network,
	// with the bridge filtering VLANs so the port group is actually isolated.
	if n.Bridge != "" && n.VLANID > 0 {
		s.ensureVSwitchVlansFor(n.Bridge)
	}
	s.audit(p, p.OrgID, "network.create", "network", fmt.Sprint(id), ip, map[string]any{"name": n.Name, "mode": n.Mode, "vlan": n.VLANID, "vni": n.VNI})
	return id, nil
}

func vxlanNetUnitPath(id int64) string {
	return fmt.Sprintf("/etc/systemd/system/vdx-net-%d.service", id)
}

// realizeVXLANNetwork builds the segment now and persists it via systemd. The
// per-network bridge name is recorded back onto the row so VM taps enslave to it.
func (s *Service) realizeVXLANNetwork(id int64, n netdrv.Network) error {
	peers := splitCSV(n.VXLANPeers)
	gwCIDR := ""
	if n.Gateway != "" && n.CIDR != "" {
		if _, ipnet, err := net.ParseCIDR(n.CIDR); err == nil {
			ones, _ := ipnet.Mask.Size()
			gwCIDR = fmt.Sprintf("%s/%d", n.Gateway, ones)
		}
	}
	bridge, _ := netdrv.VNINetworkNames(id)
	// Render first: it validates every value that goes into the unit file.
	unit, err := netdrv.RenderVNINetworkUnit(id, n.Underlay, n.VXLANLocal, n.VNI, n.DstPort, n.MTU, peers, gwCIDR)
	if err != nil {
		return err
	}
	if err := netdrv.EnsureVNINetwork(id, n.Underlay, n.VXLANLocal, n.VNI, n.DstPort, n.MTU, peers, gwCIDR); err != nil {
		return err
	}
	if err := s.net.SetNetworkBridge(id, bridge); err != nil {
		return err
	}
	// Persist (best effort — the runtime segment already exists).
	if err := os.WriteFile(vxlanNetUnitPath(id), []byte(unit), 0o644); err == nil {
		_ = exec.Command("systemctl", "daemon-reload").Run()
		_ = exec.Command("systemctl", "enable", fmt.Sprintf("vdx-net-%d.service", id)).Run()
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DeleteNetwork deletes a port group nothing is bound to. One a tenant vSwitch
// owns, or with instances, a vRouter leg or containers on it, is refused with
// the reason (portGroupInUse).
func (s *Service) DeleteNetwork(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	n, err := s.net.GetNetwork(p.OrgID, id)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("port group %d not found", id)
	} else if err != nil {
		return err
	}
	if err := s.portGroupInUse(n); err != nil {
		return err
	}
	return s.deleteNetwork(p, id, ip)
}

// deleteNetwork removes a port group without the in-use checks — for an owner
// that has already released it (DeleteVRouter removing its own internal ones).
func (s *Service) deleteNetwork(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	// Tear down a VXLAN network's segment + its systemd unit before dropping the
	// row (best effort; order so a failure still removes the record).
	vx := false
	if n, err := s.net.GetNetwork(p.OrgID, id); err == nil && n.Mode == "vxlan" {
		vx = true
		netdrv.TeardownVNINetwork(id)
		_ = os.Remove(vxlanNetUnitPath(id))
		_ = exec.Command("systemctl", "disable", fmt.Sprintf("vdx-net-%d.service", id)).Run()
		_ = exec.Command("systemctl", "daemon-reload").Run()
	}
	if err := s.net.DeleteNetwork(p.OrgID, id); err != nil {
		return err
	}
	if vx {
		s.refreshVXLANHost() // drop its VNI from the ingress guard + its bridge from the fence
	}
	s.audit(p, p.OrgID, "network.delete", "network", fmt.Sprint(id), ip, nil)
	return nil
}

// ---- port forwards -------------------------------------------------------

func (s *Service) ListPortForwards(p *Principal, sessionID string) ([]netdrv.PortForward, error) {
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return nil, err
	}
	return s.net.ListPortForwards(sessionID)
}

// AddPortForward allocates a host port and records a user-mode forward. It takes
// effect the next time the instance starts.
func (s *Service) AddPortForward(p *Principal, sessionID string, guestPort int, proto, label, ip string) (int, error) {
	if !p.atLeast("member") {
		return 0, ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return 0, err
	}
	if guestPort <= 0 || guestPort > 65535 {
		return 0, fmt.Errorf("invalid guest port")
	}
	if proto != "udp" {
		proto = "tcp"
	}
	base := s.cfg.Network.ForwardPortBase
	if base == 0 {
		base = 20000
	}
	hostPort, err := s.net.AllocHostPort(base)
	if err != nil {
		return 0, err
	}
	hostIP := s.cfg.Network.ForwardHost
	if hostIP == "" {
		hostIP = "127.0.0.1"
	}
	if _, err := s.net.AddPortForward(netdrv.PortForward{
		SessionID: sessionID, Proto: proto, HostIP: hostIP, HostPort: hostPort, GuestPort: guestPort, Label: label,
	}); err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "portforward.add", "session", sessionID, ip, map[string]any{"host_port": hostPort, "guest_port": guestPort, "proto": proto})
	return hostPort, nil
}

func (s *Service) DeletePortForward(p *Principal, sessionID string, id int64, ip string) error {
	if !p.atLeast("member") {
		return ErrUnauthorized
	}
	if _, err := s.sessionInOrg(p, sessionID); err != nil {
		return err
	}
	if err := s.net.DeletePortForward(sessionID, id); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "portforward.delete", "session", sessionID, ip, nil)
	return nil
}

// ForwardHost reports the host address user-mode forwards bind to (for display).
func (s *Service) ForwardHost() string {
	if s.cfg.Network.ForwardHost == "" {
		return "127.0.0.1"
	}
	return s.cfg.Network.ForwardHost
}
