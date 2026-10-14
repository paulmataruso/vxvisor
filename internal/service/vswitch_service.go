package service

import (
	"fmt"
	"net"
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// mgmtIface returns the host interface carrying the admin listener's IP, so we
// can refuse to bond/trunk it (doing so would cut the management path).
func (s *Service) mgmtIface() string {
	host, _, err := net.SplitHostPort(s.cfg.Server.Addr)
	if err != nil || host == "" || host == "0.0.0.0" {
		return ""
	}
	ifaces, err := hostinfo.Interfaces()
	if err != nil {
		return ""
	}
	for _, it := range ifaces {
		for _, a := range it.Addrs {
			if ip, _, _ := net.ParseCIDR(a); ip != nil && ip.String() == host {
				return it.Name
			}
		}
	}
	return ""
}

func (s *Service) guardMgmt(nics ...string) error {
	mgmt := s.mgmtIface()
	if mgmt == "" {
		return nil
	}
	for _, n := range nics {
		if n == mgmt {
			return fmt.Errorf("refusing to use the management interface %q (it carries the admin IP — using it here would cut host access)", mgmt)
		}
	}
	return nil
}

// ---- bonds ---------------------------------------------------------------

func (s *Service) ListBonds(p *Principal) ([]netdrv.Bond, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return s.net.Bonds()
}

// CreateBond builds a NIC bond (LACP / etherchannel / active-backup) and records
// it. Refuses to enslave the management NIC.
func (s *Service) CreateBond(p *Principal, name, mode string, members []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.guardMgmt(members...); err != nil {
		return err
	}
	if err := netdrv.EnsureBond(name, mode, members); err != nil {
		return err
	}
	if _, err := s.net.AddBond(name, mode, members); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "bond.create", "bond", name, ip, map[string]any{"mode": mode, "members": members})
	return nil
}

func (s *Service) DeleteBond(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	_ = netdrv.DeleteBond(name)
	if err := s.net.RemoveBond(name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "bond.delete", "bond", name, ip, nil)
	return nil
}

// ---- vSwitches -----------------------------------------------------------

func (s *Service) ListVSwitches(p *Principal) ([]netdrv.VSwitch, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return s.net.VSwitches()
}

// CreateVSwitch builds a VLAN-filtering bridge with the given uplink (a NIC or a
// bond) and records it. Refuses the management NIC as uplink. The bridge device
// name is derived from the vSwitch name.
func (s *Service) CreateVSwitch(p *Principal, name, uplink, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.guardMgmt(uplink); err != nil {
		return err
	}
	bridge := bridgeNameFor(name)
	if err := netdrv.EnsureVSwitch(bridge, uplink); err != nil {
		return err
	}
	if _, err := s.net.AddVSwitch(name, bridge, uplink); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vswitch.create", "vswitch", name, ip, map[string]any{"bridge": bridge, "uplink": uplink})
	return nil
}

func (s *Service) DeleteVSwitch(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if v, err := s.net.VSwitchByBridge(name); err == nil {
		_ = netdrv.DeleteVSwitch(v.Bridge)
	} else if v2, err2 := s.net.VSwitches(); err2 == nil {
		for _, vs := range v2 {
			if vs.Name == name {
				_ = netdrv.DeleteVSwitch(vs.Bridge)
			}
		}
	}
	if err := s.net.RemoveVSwitch(name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vswitch.delete", "vswitch", name, ip, nil)
	return nil
}

// bridgeNameFor derives a safe, short host bridge device name from a vSwitch
// name (IFNAMSIZ-safe): "vds" + sanitized name, truncated to 15 chars.
func bridgeNameFor(name string) string {
	var b strings.Builder
	b.WriteString("vds")
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 15 {
		s = s[:15]
	}
	return s
}
