package service

import (
	"fmt"

	"vdxclone/internal/netdrv"
)

// vSwitch MTU (jumbo frames). The MTU goes on the vSwitch's bridge, its physical
// adapter (a NIC team passes it on to its members) and the VM taps on it; taps
// attached later follow the bridge (netdrv.FollowBridgeMTU). Guests must set the
// same MTU on their NIC to send jumbo frames.

// mtuApply is the host hook (tests replace it so nothing touches a device).
var mtuApply = netdrv.SetVSwitchMTU

// VSwitchMTUs maps each vSwitch to its recorded MTU (0 = kernel default).
func (s *Service) VSwitchMTUs(p *Principal) map[string]int {
	if p == nil || !p.IsAdmin {
		return map[string]int{}
	}
	return s.net.VSwitchMTUs()
}

// SetVSwitchMTU sets a vSwitch's MTU (1280–9216). The management vSwitch is
// refused: host netplan owns it, so a live change would be undone at the next
// boot — and a wrong MTU there can cut the admin connection.
func (s *Service) SetVSwitchMTU(p *Principal, name string, mtu int, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if mtu < 1280 || mtu > 9216 {
		return fmt.Errorf("MTU %d is out of range — use 1500 for standard frames or up to 9000 (9216 max) for jumbo frames", mtu)
	}
	var bridge, uplink string
	if err := s.db.QueryRow(`SELECT bridge,uplink FROM net_vswitches WHERE name=?`, name).Scan(&bridge, &uplink); err != nil {
		return fmt.Errorf("unknown vSwitch %q", name)
	}
	f := netplanDefines("bridges", bridge)
	if mgmt := s.mgmtIface(); mgmt != "" && bridge == mgmt {
		if f == "" {
			f = mgmtNetplanDefault
		}
		return fmt.Errorf("vSwitch %q carries host management and its MTU is set by the host's netplan (%s) — change it there, from the host console, with `netplan try`", name, f)
	}
	if f != "" {
		return fmt.Errorf("vSwitch %q is defined by the host's netplan (%s) — set its MTU there and run `netplan apply`", name, f)
	}
	if err := mtuApply(bridge, uplink, mtu); err != nil {
		return err
	}
	if err := s.net.SetVSwitchMTUValue(name, mtu); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vswitch.mtu", "vswitch", name, ip, map[string]any{"mtu": mtu, "bridge": bridge, "uplink": uplink})
	return nil
}
