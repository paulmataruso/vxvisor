package netdrv

import (
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
)

// VLAN filtering for admin vSwitches. A vSwitch bridge only isolates anything
// when the kernel filters VLANs: with vlan_filtering=0 the bridge ignores every
// port's VLAN membership, so a VM on any port group — even an untagged one — can
// send 802.1q-tagged frames straight out the uplink onto the physical network
// (VLAN hopping), and a "VLAN 20" port group's traffic actually leaves untagged.
// With filtering on, a VM's tap passes only its own port group's VLAN
// (SetupTapAccess makes it an untagged access port of that VID, or leaves it on
// the default VID 1 for an untagged port group) and guest-tagged frames are
// dropped — what a vSphere port group with VLAN 0 does.
//
// Untagged traffic is unchanged: the uplink and the bridge itself stay members
// of VID 1 as PVID + untagged (the kernel default), so the management IP on a
// management bridge never notices. Tagged port groups add their VIDs to the
// uplink. Nothing is removed (add-only, idempotent), so this is safe to re-run
// at boot, after a port-group change, or after netplan re-creates the uplink.
//
// Nothing here persists across reboot (netplan can't express vlan_filtering);
// the worker re-applies it at boot via the service's ReensureVSwitches.

// runCmd executes one command; swapped in tests so nothing touches the host.
var runCmd = run

// VSwitchVlanCmds returns the commands that make bridge a VLAN-filtering
// vSwitch, in the order they must run: memberships first and filtering last,
// so no frame is ever filtered against a half-built VLAN table. uplink may be
// empty (an internal-only vSwitch). tagged are the port groups' VIDs, carried
// tagged on the uplink; selfTagged are the VIDs of host VLAN interfaces stacked
// on the bridge itself (e.g. vSwitch0.30), which the bridge must keep receiving
// and the uplink must keep carrying. VID 1 is the untagged native VLAN, so a
// port group on VLAN 1 is the untagged one; VIDs outside 2-4094 are ignored.
func VSwitchVlanCmds(bridge, uplink string, tagged, selfTagged []int) [][]string {
	cmds := [][]string{{"bridge", "vlan", "add", "dev", bridge, "vid", "1", "pvid", "untagged", "self"}}
	for _, v := range normVIDs(selfTagged) {
		cmds = append(cmds, []string{"bridge", "vlan", "add", "dev", bridge, "vid", strconv.Itoa(v), "self"})
	}
	if uplink != "" {
		cmds = append(cmds, []string{"bridge", "vlan", "add", "dev", uplink, "vid", "1", "pvid", "untagged"})
		all := append(append([]int{}, tagged...), selfTagged...)
		for _, v := range normVIDs(all) {
			cmds = append(cmds, []string{"bridge", "vlan", "add", "dev", uplink, "vid", strconv.Itoa(v)})
		}
	}
	return append(cmds, []string{"ip", "link", "set", "dev", bridge, "type", "bridge", "vlan_filtering", "1"})
}

// EnsureVSwitchVlans applies VSwitchVlanCmds. It stops at the first failure,
// which is always before filtering is switched on — a membership that can't be
// added never leaves the bridge filtering against a partial VLAN table.
func EnsureVSwitchVlans(bridge, uplink string, tagged, selfTagged []int) error {
	if bridge == "" {
		return errors.New("vSwitch (bridge) name required")
	}
	for _, c := range VSwitchVlanCmds(bridge, uplink, tagged, selfTagged) {
		if err := runCmd(c...); err != nil {
			return err
		}
	}
	return nil
}

// normVIDs sorts and de-duplicates VIDs, keeping only taggable ones (2-4094).
func normVIDs(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range in {
		if v >= 2 && v <= 4094 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// VlanUpperVIDs returns the VIDs of the 802.1q devices stacked directly on
// parent (e.g. 30 for vSwitch0.30), read from /proc/net/vlan/config. The file
// is absent when the 8021q module isn't loaded, which means there are none.
func VlanUpperVIDs(parent string) []int {
	b, err := os.ReadFile("/proc/net/vlan/config")
	if err != nil {
		return nil
	}
	return parseVlanConfig(string(b), parent)
}

// parseVlanConfig reads /proc/net/vlan/config rows ("name | vid | parent"); the
// two header lines don't have three fields and are skipped.
func parseVlanConfig(content, parent string) []int {
	var out []int
	for _, ln := range strings.Split(content, "\n") {
		f := strings.Split(ln, "|")
		if len(f) != 3 || strings.TrimSpace(f[2]) != parent {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(f[1])); err == nil {
			out = append(out, v)
		}
	}
	return normVIDs(out)
}
