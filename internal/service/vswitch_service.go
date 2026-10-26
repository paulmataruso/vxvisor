package service

import (
	"fmt"
	"log"
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

// defaultPortGroupName is the ESXi-style default VM network on the default vSwitch.
const defaultPortGroupName = "VM Network"

// EnsureDefaultPortGroup makes sure that when the management interface is itself
// a vSwitch (a bridge — e.g. the default vSwitch0 created at install time or by
// the mgmt-NIC conversion), there is a real "VM Network" port group bound to it
// that users can attach VMs to, exactly like ESXi ships a default VM Network on
// vSwitch0. Attaching VM taps to the mgmt bridge never disturbs the mgmt IP (it
// just adds bridge ports). Idempotent and safe to call on boot; it will not
// recreate a port group the admin deleted as long as any port group remains on
// that bridge.
func (s *Service) EnsureDefaultPortGroup() error {
	br := s.mgmtIface()
	if br == "" {
		return nil
	}
	// Only when the mgmt interface is actually a bridge (a default vSwitch), not
	// a bare NIC — a bare mgmt NIC has no vSwitch to hang a port group on.
	ifaces, err := hostinfo.Interfaces()
	if err != nil {
		return err
	}
	isBridge := false
	for _, it := range ifaces {
		if it.Name == br && it.Type == "bridge" {
			isBridge = true
			break
		}
	}
	if !isBridge {
		return nil
	}
	// Register the mgmt bridge as a managed vSwitch so it appears in the vSwitches
	// list (not just the diagram). Its uplink is the physical NIC enslaved to it.
	var vsExists int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM net_vswitches WHERE bridge=?`, br).Scan(&vsExists)
	if vsExists == 0 {
		uplink := ""
		for _, it := range ifaces {
			if it.Master == br && it.Type != "tap" && it.Type != "vxlan" && it.Type != "bridge" {
				uplink = it.Name
				break
			}
		}
		if _, err := s.net.AddVSwitch(br, br, uplink); err != nil {
			return err
		}
		log.Printf("registered default vSwitch %q (uplink %q)", br, uplink)
	}
	var orgID int64
	_ = s.db.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&orgID)
	if orgID == 0 {
		return nil
	}
	// Already have a port group on this bridge? Leave it alone (respects an admin
	// who renamed or removed the default).
	var existing int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM networks WHERE org_id=? AND bridge=?`, orgID, br).Scan(&existing)
	if existing > 0 {
		return nil
	}
	if _, err := s.net.CreateNetwork(netdrv.Network{
		OrgID:  orgID,
		Name:   defaultPortGroupName,
		Mode:   "bridge",
		Bridge: br,
		VLANID: 0, // untagged — VMs share the mgmt L2 segment (ESXi default)
	}); err != nil {
		return err
	}
	log.Printf("created default port group %q on vSwitch %s", defaultPortGroupName, br)
	return nil
}

// MgmtInterface returns the name of the interface (NIC or vSwitch bridge) that
// carries the admin IP — used by the UI to mark the management vSwitch as
// protected (not deletable).
func (s *Service) MgmtInterface() string { return s.mgmtIface() }

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

// CreateBond builds a NIC team (bond) and records it. Supports ESXi-style teaming:
// LACP (802.3ad) and static etherchannel (balance-xor) with a selectable transmit
// hash (MAC / IP), plus the switch-config-free modes — balance-alb/tlb (both NICs
// active, adaptive load balancing, no LACP) and active-backup (failover). Refuses
// to enslave the management NIC. hashPolicy applies only to the hashing modes.
func (s *Service) CreateBond(p *Principal, name, mode, hashPolicy string, members []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	if err := s.guardMgmt(members...); err != nil {
		return err
	}
	if err := s.guardTrunk(members...); err != nil {
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
	if err := s.guardTrunk(uplink); err != nil {
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
	if err := s.guardTrunk(members...); err != nil {
		return err
	}
	if bondName == "" {
		bondName = "bond0"
	}

	if vs.Bridge == s.mgmtIface() {
		// Management vSwitch: regenerate netplan with a bonded uplink, preserving the
		// bridge's static IPv4 + MAC, applied with auto-rollback.
		brMac, v4, gw, dns := bridgeIPv4Config(vs.Bridge)
		content := buildMgmtBondNetplan(vs.Bridge, brMac, bondName, kmode, hp, members, v4, dns, gw)
		want := ""
		if len(v4) > 0 {
			want = strings.SplitN(v4[0], "/", 2)[0]
		}
		verify := func() bool {
			return want == "" || strings.Contains(execOut("ip", "-o", "addr", "show", "dev", vs.Bridge), want)
		}
		if err := applyNetplanWithRollback(content, verify); err != nil {
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
	s.audit(p, p.OrgID, "vswitch.bond", "vswitch", vswitch, ip,
		map[string]any{"bond": bondName, "mode": mode, "hash": hashPolicy, "members": members})
	return nil
}

func (s *Service) DeleteVSwitch(p *Principal, name, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	// Never tear down the vSwitch that carries the management IP — deleting its
	// bridge would cut host access. Resolve this vSwitch's bridge and refuse if
	// it's the mgmt bridge (match by either the stored bridge or the name).
	mgmt := s.mgmtIface()
	if mgmt != "" {
		brdg := name
		if v, err := s.net.VSwitchByBridge(name); err == nil {
			brdg = v.Bridge
		} else if vs, err := s.net.VSwitches(); err == nil {
			for _, x := range vs {
				if x.Name == name {
					brdg = x.Bridge
					break
				}
			}
		}
		if brdg == mgmt || name == mgmt {
			return fmt.Errorf("refusing to delete the management vSwitch %q (it carries the admin IP — deleting it would cut host access)", mgmt)
		}
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
