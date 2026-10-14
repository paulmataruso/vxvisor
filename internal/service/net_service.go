package service

import (
	"fmt"

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
	if !p.atLeast("admin") {
		return 0, ErrUnauthorized
	}
	n.OrgID = p.OrgID
	if n.Mode == "" {
		n.Mode = "user"
	}
	id, err := s.net.CreateNetwork(n)
	if err != nil {
		return 0, err
	}
	// If this port group is on a vSwitch with a VLAN, carry that VLAN tagged on
	// the vSwitch's uplink trunk so the port group reaches the physical network.
	if n.Bridge != "" && n.VLANID > 0 {
		if vs, err := s.net.VSwitchByBridge(n.Bridge); err == nil && vs.Uplink != "" {
			_ = netdrv.AddTrunkVlan(vs.Uplink, n.VLANID)
		}
	}
	s.audit(p, p.OrgID, "network.create", "network", fmt.Sprint(id), ip, map[string]any{"name": n.Name, "mode": n.Mode, "vlan": n.VLANID})
	return id, nil
}

func (s *Service) DeleteNetwork(p *Principal, id int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	if err := s.net.DeleteNetwork(p.OrgID, id); err != nil {
		return err
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
