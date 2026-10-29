package service

import (
	"fmt"
	"strings"
	"unicode"

	"vdxclone/internal/netdrv"
)

// CreatePortGroup is the instance-admin "Add port group" / "VXLAN network" form.
// Unlike the internal CreateNetwork callers (vRouter legs, defaults), every field
// here is free text from the browser, so it is checked before anything is
// recorded:
//
//   - user (NAT): no vSwitch, no VLAN.
//   - bridge (vSwitch VLAN): the bridge must be an existing vSwitch's bridge —
//     never a tenant bridge, a vRouter leg or an arbitrary host device — and the
//     VLAN is 0 (untagged) or 2–4094.
//   - overlay (cluster VXLAN): lands on the [cluster] bridge; needs the cluster
//     overlay turned on.
//   - vxlan: its own segment (validated by validateVXLANNetwork). routed marks
//     it as routed through this host instead of fenced off from it.
func (s *Service) CreatePortGroup(p *Principal, n netdrv.Network, routed bool, ip string) (int64, error) {
	if !p.IsAdmin {
		return 0, ErrUnauthorized
	}
	n.Name = strings.TrimSpace(n.Name)
	n.Bridge = strings.TrimSpace(n.Bridge)
	n.Gateway = strings.TrimSpace(n.Gateway)
	n.PoolStart, n.PoolEnd = strings.TrimSpace(n.PoolStart), strings.TrimSpace(n.PoolEnd)
	if err := validPortGroupName(n.Name); err != nil {
		return 0, err
	}
	if routed && n.Mode != "vxlan" {
		return 0, fmt.Errorf("only a VXLAN network can be routed through the host here — use the Routing page for other networks")
	}
	switch n.Mode {
	case "user":
		if n.Bridge != "" || n.VLANID != 0 {
			return 0, fmt.Errorf("a user (NAT) port group doesn't use a vSwitch or VLAN — clear those fields, or pick the vSwitch (VLAN) type")
		}
	case "bridge":
		if n.Bridge == "" {
			return 0, fmt.Errorf("pick the vSwitch this port group belongs to")
		}
		var vs string
		if s.db.QueryRow(`SELECT name FROM net_vswitches WHERE bridge=?`, n.Bridge).Scan(&vs) != nil {
			return 0, fmt.Errorf("%q is not a vSwitch on this host — pick one from the list", n.Bridge)
		}
		if n.VLANID != 0 && (n.VLANID < 2 || n.VLANID > 4094) {
			return 0, fmt.Errorf("VLAN %d is out of range — use 0 for untagged or 2–4094 (VLAN 1 is the vSwitch's untagged default)", n.VLANID)
		}
	case "overlay":
		if s.cfg == nil || !s.cfg.Cluster.Overlay || s.cfg.Cluster.Bridge == "" ||
			(s.cfg.Network.Mode != "bridge" && s.cfg.Network.Mode != "overlay") {
			return 0, fmt.Errorf("the cluster overlay is not turned on ([cluster] overlay = true in the config) — use a VXLAN network instead")
		}
		if (n.Bridge != "" && n.Bridge != s.cfg.Cluster.Bridge) || n.VLANID != 0 {
			return 0, fmt.Errorf("a cluster-overlay port group always uses the cluster bridge %s, untagged — clear the vSwitch and VLAN fields", s.cfg.Cluster.Bridge)
		}
		n.Bridge = s.cfg.Cluster.Bridge
	case "vxlan":
		if routed && (n.CIDR == "" || n.Gateway == "") {
			return 0, fmt.Errorf("a routed VXLAN network needs its subnet and the gateway address the host holds on it")
		}
	default:
		return 0, fmt.Errorf("unknown port group type %q", n.Mode)
	}
	if n.Mode != "vxlan" { // vxlan addressing is checked with the rest of its fields
		if err := checkPGAddressing(&n.CIDR, n.Gateway, n.PoolStart, n.PoolEnd); err != nil {
			return 0, err
		}
	}
	return s.createNetwork(p, n, routed, ip)
}

// validPortGroupName: a display name, 1–64 printable characters.
func validPortGroupName(n string) error {
	if n == "" || len(n) > 64 {
		return fmt.Errorf("a port group name of 1–64 characters is required")
	}
	for _, r := range n {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("the port group name can't contain control characters")
		}
	}
	return nil
}
