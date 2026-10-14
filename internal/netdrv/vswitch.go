package netdrv

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file implements the VMware-style data-plane: NIC bonds (link aggregation)
// → vSwitches (VLAN-filtering bridges) → port groups (per-VLAN) → VM access taps.
// All operations shell out to iproute2 and are idempotent where practical. The
// service layer gates them on admin and keeps the management NIC out of harm's way.

// BondMode maps a friendly mode to the kernel bonding mode string.
func BondMode(mode string) (string, error) {
	switch mode {
	case "lacp", "802.3ad":
		return "802.3ad", nil
	case "etherchannel", "static", "balance-xor":
		return "balance-xor", nil
	case "active-backup", "failover":
		return "active-backup", nil
	default:
		return "", fmt.Errorf("unknown bond mode %q (use lacp, etherchannel, or active-backup)", mode)
	}
}

// EnsureBond creates a bonding interface `name` in the given mode over `members`
// (link aggregation / NIC teaming). Members are brought down and enslaved, then
// the bond is brought up. Idempotent for an existing bond of the same name.
func EnsureBond(name, mode string, members []string) error {
	if name == "" {
		return errors.New("bond name required")
	}
	kmode, err := BondMode(mode)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return errors.New("a bond needs at least one member NIC")
	}
	if !ifaceExists(name) {
		args := []string{"ip", "link", "add", name, "type", "bond", "mode", kmode}
		if kmode == "802.3ad" {
			args = append(args, "lacp_rate", "fast", "miimon", "100", "xmit_hash_policy", "layer3+4")
		} else if kmode == "balance-xor" {
			args = append(args, "miimon", "100", "xmit_hash_policy", "layer3+4")
		} else {
			args = append(args, "miimon", "100")
		}
		if err := run(args...); err != nil {
			return err
		}
	}
	for _, m := range members {
		if m == "" {
			continue
		}
		// A member must be down and address-less before it can be enslaved.
		_ = run("ip", "addr", "flush", "dev", m)
		if err := run("ip", "link", "set", m, "down"); err != nil {
			return err
		}
		if err := run("ip", "link", "set", m, "master", name); err != nil {
			return err
		}
	}
	return run("ip", "link", "set", name, "up")
}

// DeleteBond frees the member NICs and removes the bond.
func DeleteBond(name string) error {
	return run("ip", "link", "del", name)
}

// EnsureVSwitch creates a VLAN-filtering bridge (a vSwitch) and, when uplink is
// set (a NIC or a bond), enslaves it as an 802.1q trunk carrying all VLANs.
// Idempotent. The caller must ensure the uplink is NOT the management NIC.
func EnsureVSwitch(bridge, uplink string) error {
	if bridge == "" {
		return errors.New("vSwitch (bridge) name required")
	}
	if !ifaceExists(bridge) {
		if err := run("ip", "link", "add", bridge, "type", "bridge"); err != nil {
			return err
		}
	}
	// VLAN filtering makes this a real vSwitch with per-port VLANs.
	if err := run("ip", "link", "set", bridge, "type", "bridge", "vlan_filtering", "1"); err != nil {
		return err
	}
	if err := run("ip", "link", "set", bridge, "up"); err != nil {
		return err
	}
	if uplink != "" {
		if err := run("ip", "link", "set", uplink, "master", bridge); err != nil {
			return err
		}
		if err := run("ip", "link", "set", uplink, "up"); err != nil {
			return err
		}
		// Trunk: carry the full tagged VLAN range on the uplink.
		_ = run("bridge", "vlan", "add", "dev", uplink, "vid", "2-4094", "tagged")
	}
	return nil
}

// DeleteVSwitch removes the bridge (ports are released automatically).
func DeleteVSwitch(bridge string) error {
	return run("ip", "link", "del", bridge)
}

// AddTrunkVlan ensures the given VLAN is carried tagged on the uplink trunk (so
// a new port group's traffic reaches the physical network).
func AddTrunkVlan(uplink string, vlan int) error {
	if uplink == "" || vlan <= 0 {
		return nil
	}
	return run("bridge", "vlan", "add", "dev", uplink, "vid", strconv.Itoa(vlan), "tagged")
}

// SetupTapAccess creates a VM tap as an ACCESS port on a VLAN-filtering vSwitch:
// untagged into exactly one VLAN (PVID). Owned by uid for a privdropped QEMU.
func SetupTapAccess(tap, bridge string, vlan, uid int) error {
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
	if err := run("ip", "link", "set", tap, "master", bridge); err != nil {
		return err
	}
	if vlan > 0 {
		// Replace the default VLAN 1 membership with an untagged PVID access port.
		_ = run("bridge", "vlan", "del", "dev", tap, "vid", "1")
		if err := run("bridge", "vlan", "add", "dev", tap, "vid", strconv.Itoa(vlan), "pvid", "untagged"); err != nil {
			return err
		}
	}
	return nil
}

// BondMembersCSV / parse helpers for the store.
func JoinMembers(m []string) string  { return strings.Join(m, ",") }
func SplitMembers(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
