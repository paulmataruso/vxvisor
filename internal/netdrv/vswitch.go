package netdrv

import (
	"errors"
	"fmt"
	"os"
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
	case "balance-tlb", "tlb":
		return "balance-tlb", nil
	case "balance-alb", "alb":
		return "balance-alb", nil
	default:
		return "", fmt.Errorf("unknown bond mode %q (use lacp, etherchannel, active-backup, balance-tlb, or balance-alb)", mode)
	}
}

// BondHashPolicy validates/normalizes a transmit-hash choice (exported wrapper).
func BondHashPolicy(h string) (string, error) { return bondHashPolicy(h) }

// bondHashPolicy maps a hash choice to a kernel xmit_hash_policy. Empty = the
// safe default (layer3+4). Only meaningful for 802.3ad / balance-xor.
func bondHashPolicy(h string) (string, error) {
	switch h {
	case "", "layer3+4", "ip", "iphash":
		return "layer3+4", nil
	case "layer2", "mac":
		return "layer2", nil
	case "layer2+3":
		return "layer2+3", nil
	case "encap2+3":
		return "encap2+3", nil
	case "encap3+4":
		return "encap3+4", nil
	default:
		return "", fmt.Errorf("unknown hash policy %q (use layer2, layer2+3, or layer3+4)", h)
	}
}

// EnsureBond creates a bonding interface `name` in the given mode over `members`
// (link aggregation / NIC teaming). hashPolicy selects the transmit hash for the
// hashing modes (802.3ad / balance-xor); it is ignored by the others. Members are
// brought down and enslaved, then the bond is brought up. Idempotent for an
// existing bond of the same name.
func EnsureBond(name, mode, hashPolicy string, members []string) error {
	if name == "" {
		return errors.New("bond name required")
	}
	kmode, err := BondMode(mode)
	if err != nil {
		return err
	}
	hp, err := bondHashPolicy(hashPolicy)
	if err != nil {
		return err
	}
	if len(members) == 0 {
		return errors.New("a bond needs at least one member NIC")
	}
	if !ifaceExists(name) {
		args := []string{"ip", "link", "add", name, "type", "bond", "mode", kmode, "miimon", "100"}
		switch kmode {
		case "802.3ad":
			args = append(args, "lacp_rate", "fast", "xmit_hash_policy", hp)
		case "balance-xor":
			args = append(args, "xmit_hash_policy", hp)
			// balance-tlb / balance-alb / active-backup: no xmit_hash_policy (they
			// load-balance adaptively / fail over — no switch-side config needed).
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

// SetBridgeUplink enslaves an uplink (a NIC or a bond) to an existing vSwitch
// bridge as an 802.1q trunk carrying all VLANs — the same wiring EnsureVSwitch
// does for a new vSwitch. Used when repointing a vSwitch's uplink (e.g. upgrading
// a single-NIC uplink to a bond). Idempotent.
func SetBridgeUplink(bridge, uplink string) error {
	if bridge == "" || uplink == "" {
		return errors.New("bridge and uplink are required")
	}
	if err := run("ip", "link", "set", uplink, "master", bridge); err != nil {
		return err
	}
	if err := run("ip", "link", "set", uplink, "up"); err != nil {
		return err
	}
	_ = run("bridge", "vlan", "add", "dev", uplink, "vid", "2-4094", "tagged")
	return nil
}

// DetachUplink removes an uplink (NIC or bond) from whatever bridge it is on.
func DetachUplink(uplink string) { _ = run("ip", "link", "set", uplink, "nomaster") }

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

// IfaceExists reports whether a network interface is present on the host.
func IfaceExists(name string) bool { return ifaceExists(name) }

// IsBond reports whether name is a kernel bond device.
func IsBond(name string) bool {
	if name == "" {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + name + "/bonding")
	return err == nil
}

// RebindTap live-moves an EXISTING VM tap to a different vSwitch (bridge) and
// VLAN without touching QEMU — the guest NIC stays up, only the host-side bridge
// membership changes (a brief L2 blip at most). Used to change a running VM's
// port group with no restart. `nomaster` first so leaving a VLAN-filtering bridge
// clears its old VLAN entries; then enslave to the new bridge and set the access
// PVID. vlan 0 = untagged (default PVID 1), the plain-bridge / native case.
func RebindTap(tap, bridge string, vlan int) error {
	if !ifaceExists(tap) {
		return errors.New("tap " + tap + " is not present (VM has no bridged NIC to move)")
	}
	if !ifaceExists(bridge) {
		return errors.New("target vSwitch " + bridge + " does not exist")
	}
	_ = run("ip", "link", "set", tap, "nomaster") // detach from current bridge
	if err := run("ip", "link", "set", tap, "up"); err != nil {
		return err
	}
	if err := run("ip", "link", "set", tap, "master", bridge); err != nil {
		return err
	}
	if vlan > 0 {
		_ = run("bridge", "vlan", "del", "dev", tap, "vid", "1")
		if err := run("bridge", "vlan", "add", "dev", tap, "vid", strconv.Itoa(vlan), "pvid", "untagged"); err != nil {
			return err
		}
	}
	return nil
}

// SetupTapAccess creates a VM tap as an ACCESS port on a VLAN-filtering vSwitch:
// untagged into exactly one VLAN (PVID). Owned by uid for a privdropped QEMU.
func SetupTapAccess(tap, bridge string, vlan, uid int) error {
	if !ifaceExists(tap) {
		// multi_queue: QEMU opens the tap once per virtio-net queue (one per vCPU)
		// for multiqueue networking. Without IFF_MULTI_QUEUE the kernel rejects the
		// second queue fd with EINVAL and QEMU fails to start.
		args := []string{"ip", "tuntap", "add", tap, "mode", "tap", "multi_queue"}
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
