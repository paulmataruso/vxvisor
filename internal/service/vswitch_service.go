package service

import (
	"fmt"
	"net"
	"os"
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// ---- bonds ---------------------------------------------------------------

func (s *Service) ListBonds(p *Principal) ([]netdrv.Bond, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return s.net.Bonds()
}

// CreateBond builds a NIC team (bond) and records it. Supports ESXi-style teaming:
// LACP (802.3ad) and static etherchannel (balance-xor) with a selectable transmit
// hash (MAC / IP), plus the switch-config-free modes — balance-alb/tlb (both NICs
// active, adaptive load balancing, no LACP) and active-backup (failover). Refuses
// to enslave the management NIC. hashPolicy applies only to the hashing modes.
func (s *Service) CreateBond(p *Principal, name, mode, hashPolicy string, members []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.bondNameFree(name); err != nil {
		return err
	}
	if err := s.guardNICFree(members...); err != nil {
		return err
	}
	if err := netdrv.EnsureBond(name, mode, hashPolicy, members); err != nil {
		return err
	}
	// Persist a readable label so the list shows the teaming policy (e.g.
	// "balance-alb" or "lacp/layer3+4").
	label := mode
	if (mode == "lacp" || mode == "802.3ad" || mode == "etherchannel" || mode == "static" || mode == "balance-xor") && hashPolicy != "" {
		label = mode + "/" + hashPolicy
	}
	if _, err := s.net.AddBond(name, label, members); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "bond.create", "bond", name, ip, map[string]any{"mode": mode, "hash": hashPolicy, "members": members})
	return nil
}

// DeleteBond removes a bond that nothing uses. A bond in use is refused with the
// reason (guardBondInUse) — deleting the management uplink bond once cut the host
// off the network entirely.
func (s *Service) DeleteBond(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.guardBondInUse(name); err != nil {
		return err
	}
	if netdrv.IfaceExists(name) {
		if err := netdrv.DeleteBond(name); err != nil {
			return fmt.Errorf("delete bond %s: %w", name, err)
		}
	}
	if err := s.net.RemoveBond(name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "bond.delete", "bond", name, ip, nil)
	return nil
}

// BondsInUse maps each in-use bond to why it can't be deleted, so the Networks
// page can show that instead of a Delete button.
func (s *Service) BondsInUse(p *Principal) map[string]string {
	out := map[string]string{}
	bonds, err := s.ListBonds(p)
	if err != nil {
		return out
	}
	for _, b := range bonds {
		if err := s.guardBondInUse(b.Name); err != nil {
			out[b.Name] = err.Error()
		}
	}
	return out
}

// guardBondInUse refuses to delete a bond that carries anything (guardIfaceInUse).
func (s *Service) guardBondInUse(name string) error { return s.guardIfaceInUse(name, "bond") }

// guardNICFree refuses to claim (enslave into a bond or vSwitch) an interface
// that something already uses — the same checks as deleting a bond, so the
// management, storage, trunk and transit NICs can never be taken.
func (s *Service) guardNICFree(nics ...string) error {
	for _, n := range nics {
		if n = strings.TrimSpace(n); n == "" {
			continue
		}
		if err := s.guardIfaceInUse(n, "interface"); err != nil {
			return err
		}
	}
	return nil
}

// guardIfaceInUse reports why a NIC or bond can't be deleted or claimed: it
// carries the management path, is a vSwitch uplink, a tenant trunk / dedicated
// uplink, the storage or routing uplink, a vRouter transit link, holds an IP
// address, or has any device stacked on it (a bridge or bond it's enslaved to,
// VLAN subinterfaces). what ("bond" / "interface") is only for the message.
func (s *Service) guardIfaceInUse(name, what string) error {
	if s.isMgmtIface(name) || s.isMgmtBridgeUplink(name) {
		return fmt.Errorf("%s %q carries host management (the admin IP) — changing it would cut host access", what, name)
	}
	if s.mgmtIface() == "" {
		return errMgmtUnknown // can't tell whether it carries management: fail closed
	}
	var vs string
	if s.db.QueryRow(`SELECT name FROM net_vswitches WHERE uplink=?`, name).Scan(&vs) == nil {
		return fmt.Errorf("%s %q is the uplink of vSwitch %q — give the vSwitch another uplink or delete it first", what, name, vs)
	}
	var n int
	if _ = s.db.QueryRow(`SELECT COUNT(*) FROM ext_trunks WHERE iface=?`, name).Scan(&n); n > 0 {
		return fmt.Errorf("%s %q is a tenant egress trunk — remove the trunk on Tenant Egress first", what, name)
	}
	var upl string
	if s.db.QueryRow(`SELECT name FROM tenant_uplinks WHERE dedicated_iface=?`, name).Scan(&upl) == nil {
		return fmt.Errorf("%s %q is the dedicated interface of tenant uplink %q", what, name, upl)
	}
	var vr string
	if s.db.QueryRow(`SELECT r.name FROM vrouter_legs l JOIN vrouters r ON r.id=l.vrouter_id WHERE l.phys_iface=?`, name).Scan(&vr) == nil {
		return fmt.Errorf("%s %q is the transit link of vRouter %q", what, name, vr)
	}
	if st := s.StorageIface(); st != "" && st == name {
		return fmt.Errorf("%s %q is the storage interface", what, name)
	}
	if c, err := s.GetRoutingConfig(&Principal{IsAdmin: true}); err == nil && c.Uplink == name {
		return fmt.Errorf("%s %q is the L3 routing uplink", what, name)
	}
	if ifs, err := hostinfo.Interfaces(); err == nil {
		for _, it := range ifs {
			if it.Name != name {
				continue
			}
			var global []string
			for _, a := range it.Addrs {
				if ip, _, err := net.ParseCIDR(a); err == nil && !ip.IsLinkLocalUnicast() {
					global = append(global, a)
				}
			}
			if len(global) > 0 {
				return fmt.Errorf("%s %q has addresses (%s) — remove them first", what, name, strings.Join(global, ", "))
			}
		}
	}
	// Last, the kernel's view: anything stacked on it (e.g. enslaved to a bridge
	// vdxd doesn't track, or VLAN subinterfaces) — including the management bridge
	// when the admin listener binds 0.0.0.0 and mgmtIface can't be resolved.
	if up := ifaceUppers(name); len(up) > 0 {
		return fmt.Errorf("%s %q is in use by %s", what, name, strings.Join(up, ", "))
	}
	return nil
}

// validIfName: a Linux interface name we'll create (IFNAMSIZ 15, no spaces or
// slashes — those break the kernel and the name-keyed routes).
func validIfName(n string) bool {
	if n == "" || len(n) > 15 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// bondNameFree refuses a bond name that already exists (in the kernel or our
// records): EnsureBond would otherwise silently reuse it — adding NICs to, say,
// the management bond.
func (s *Service) bondNameFree(name string) error {
	if !validIfName(name) {
		return fmt.Errorf("invalid bond name %q (up to 15 letters, digits, - _ .)", name)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM net_bonds WHERE name=?`, name).Scan(&n)
	if n > 0 || netdrv.IfaceExists(name) {
		return fmt.Errorf("an interface named %q already exists — pick another bond name", name)
	}
	return nil
}

// ifaceUppers lists the devices stacked directly on iface: the bridge or bond it
// is enslaved to and any VLAN / macvlan subinterfaces (the kernel's upper_* links).
func ifaceUppers(iface string) []string {
	ents, err := os.ReadDir("/sys/class/net/" + iface)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutPrefix(e.Name(), "upper_"); ok {
			out = append(out, n)
		}
	}
	return out
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
	if name = strings.TrimSpace(name); name == "" || strings.ContainsAny(name, "/ ") {
		return fmt.Errorf("a vSwitch name is required (no spaces or slashes)")
	}
	if err := s.guardNICFree(uplink); err != nil {
		return err
	}
	// Two names can map to one bridge (non-alphanumerics are dropped, 15-char
	// limit); never let a second vSwitch land its uplink on an existing bridge.
	bridge := bridgeNameFor(name)
	var dup string
	if s.db.QueryRow(`SELECT name FROM net_vswitches WHERE name=? OR bridge=?`, name, bridge).Scan(&dup) == nil || netdrv.IfaceExists(bridge) {
		if dup == "" {
			dup = bridge
		}
		return fmt.Errorf("vSwitch name %q collides with existing %q — pick a different name", name, dup)
	}
	if err := netdrv.EnsureVSwitch(bridge, uplink); err != nil {
		return err
	}
	if _, err := s.net.AddVSwitch(name, bridge, uplink); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vswitch.create", "vswitch", name, ip, map[string]any{"bridge": bridge, "uplink": uplink})
	return nil
}

// UpgradeVSwitchToBond converts a vSwitch's single-NIC uplink into a NIC team
// (bond): it builds a bond from the CURRENT uplink plus the extra members, then
// repoints the vSwitch onto the bond — one safe operation. The management vSwitch
// is done via netplan with an auto-rollback (persistent + the admin IP can never
// be stranded); other vSwitches are applied live via netdrv.
func (s *Service) UpgradeVSwitchToBond(p *Principal, vswitch, bondName, mode, hashPolicy string, extraMembers []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var vs netdrv.VSwitch
	found := false
	if list, err := s.net.VSwitches(); err == nil {
		for _, v := range list {
			if v.Name == vswitch {
				vs = v
				found = true
				break
			}
		}
	}
	if !found {
		return fmt.Errorf("unknown vSwitch %q", vswitch)
	}
	kmode, err := netdrv.BondMode(mode)
	if err != nil {
		return err
	}
	hp, err := netdrv.BondHashPolicy(hashPolicy)
	if err != nil {
		return err
	}
	// Members = current uplink + the extras, de-duplicated.
	var members []string
	seen := map[string]bool{}
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n != "" && !seen[n] {
			seen[n] = true
			members = append(members, n)
		}
	}
	add(vs.Uplink)
	for _, m := range extraMembers {
		add(m)
	}
	if len(members) < 2 {
		if vs.Uplink != "" {
			return fmt.Errorf("a team needs at least two NICs — the current uplink (%s) plus one or more", vs.Uplink)
		}
		return fmt.Errorf("a team needs at least two NICs — pick two or more")
	}
	// Never team the IP-holding management interface itself (vs.Bridge may BE it —
	// that's fine, we team the uplink NICs feeding the bridge, not the bridge).
	if err := s.guardMgmt(members...); err != nil {
		return err
	}
	// The uplink is already a team: adding to it isn't this path (it would try to
	// enslave the bond into a new bond and leave the vSwitch without an uplink).
	var isBond int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM net_bonds WHERE name=?`, vs.Uplink).Scan(&isBond)
	if isBond > 0 || netdrv.IsBond(vs.Uplink) {
		return fmt.Errorf("vSwitch %q's uplink %s is already a NIC team — changing a team's members isn't supported yet", vswitch, vs.Uplink)
	}
	// The NICs being added must be free (the current uplink is this vSwitch's own).
	var extras []string
	for _, m := range members {
		if m != vs.Uplink {
			extras = append(extras, m)
		}
	}
	if err := s.guardNICFree(extras...); err != nil {
		return err
	}
	if bondName == "" {
		for i := 0; ; i++ {
			if s.bondNameFree(fmt.Sprintf("bond%d", i)) == nil {
				bondName = fmt.Sprintf("bond%d", i)
				break
			}
		}
	} else if err := s.bondNameFree(bondName); err != nil {
		return err
	}

	if s.isMgmtIface(vs.Bridge) {
		// Management vSwitch: netplan owns it. Its definition is edited in place
		// (every address / DHCP / route / DNS setting kept), verified, and applied
		// with auto-rollback (teamMgmtUplinkNetplan).
		if err := s.teamMgmtUplinkNetplan(vs.Bridge, vs.Uplink, bondName, kmode, hp, members); err != nil {
			return err
		}
	} else {
		// Non-management vSwitch: live via netdrv. EnsureBond enslaves all members
		// (freeing the old direct uplink from the bridge), then the bond becomes the
		// bridge's trunk uplink.
		netdrv.DetachUplink(vs.Uplink)
		if err := netdrv.EnsureBond(bondName, mode, hashPolicy, members); err != nil {
			return err
		}
		if err := netdrv.SetBridgeUplink(vs.Bridge, bondName); err != nil {
			return err
		}
	}

	label := mode
	if (kmode == "802.3ad" || kmode == "balance-xor") && hashPolicy != "" {
		label = mode + "/" + hp
	}
	_, _ = s.net.AddBond(bondName, label, members)
	if err := s.net.UpdateVSwitchUplink(vswitch, bondName); err != nil {
		return err
	}
	// The new uplink port starts on VID 1 only: re-add the port groups' VLANs
	// (and filtering, which a netplan apply may have reset).
	s.ensureVSwitchVlansFor(vs.Bridge)
	s.audit(p, p.OrgID, "vswitch.bond", "vswitch", vswitch, ip,
		map[string]any{"bond": bondName, "mode": mode, "hash": hashPolicy, "members": members})
	return nil
}

// DeleteVSwitch removes a vSwitch nothing uses. The management vSwitch, a
// netplan-defined one, and any with instances, containers, port groups, a
// tenant trunk / uplink or a vRouter link on it are refused with the reason
// (vswitchInUse) — the same class of guard as DeleteBond.
func (s *Service) DeleteVSwitch(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.vswitchByNameOrBridge(name)
	if err != nil {
		return err
	}
	if err := s.vswitchInUse(v); err != nil {
		return err
	}
	if ifaceExists(v.Bridge) {
		if err := netdrv.DeleteVSwitch(v.Bridge); err != nil {
			return fmt.Errorf("delete vSwitch %s: %w", v.Name, err)
		}
	}
	if err := s.net.RemoveVSwitch(v.Name); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vswitch.delete", "vswitch", v.Name, ip, map[string]any{"bridge": v.Bridge, "uplink": v.Uplink})
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
