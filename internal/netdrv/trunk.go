package netdrv

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Host driver for tenant-networking v3 external trunks and per-tenant VLAN
// subinterfaces.
//
// An external trunk is a physical NIC/bond the admin dedicates to tenant egress.
// It is NOT enslaved to a bridge; instead each tenant uplink hangs a VLAN
// subinterface <trunk>.<vid> off it (proto 802.1q for a single-tag "access"
// uplink, proto 802.1ad for a QinQ uplink whose inner C-tags are preserved), and
// that subinterface is enslaved into the tenant network's PLAIN bridge. On a
// plain bridge the subinterface proto alone decides single-vs-double tag and the
// tenant's own inner 802.1q tags ride through untouched — avoiding the
// vlan_filtering-bridge C-tag-stripping hazard.
//
// Nothing here persists across reboot; the worker re-applies it idempotently.

// qinqOffloadFlags are the ethtool features that must be OFF for 802.1ad double
// tagging to survive a NIC: a NIC that only understands 802.1q acceleration can
// mis-strip/mis-insert the outer 0x88a8 tag. We record which were on before so
// teardown restores them exactly.
var qinqOffloadFlags = []string{
	"rx-vlan-offload",
	"tx-vlan-offload",
	"rx-vlan-stag-hw-parse",
	"tx-vlan-stag-hw-insert",
	"rx-vlan-stag-filter",
}

// SubName is the deterministic subinterface device name for (trunk, vid). It must
// fit the kernel IFNAMSIZ limit (15 chars); SubNameChecked enforces that.
func SubName(trunk string, vid int) string { return trunk + "." + strconv.Itoa(vid) }

// SubNameChecked returns the subinterface name or an error if it would exceed the
// 15-char interface-name limit (mirrors the veth-name guard).
func SubNameChecked(trunk string, vid int) (string, error) {
	n := SubName(trunk, vid)
	if len(n) > 15 {
		return "", fmt.Errorf("subinterface name %q exceeds the 15-char interface limit (trunk name too long)", n)
	}
	return n, nil
}

// EnsureVlanSub idempotently creates the VLAN subinterface <trunk>.<vid> with the
// given protocol ("802.1q" or "802.1ad") and brings it up. Returns the device name.
func EnsureVlanSub(trunk string, vid int, proto string) (string, error) {
	if proto != "802.1q" && proto != "802.1ad" {
		return "", fmt.Errorf("unsupported VLAN proto %q", proto)
	}
	name, err := SubNameChecked(trunk, vid)
	if err != nil {
		return "", err
	}
	if !ifaceExists(name) {
		if err := run("ip", "link", "add", "link", trunk, "name", name,
			"type", "vlan", "proto", proto, "id", strconv.Itoa(vid)); err != nil {
			return "", err
		}
	}
	if err := run("ip", "link", "set", name, "up"); err != nil {
		return "", err
	}
	return name, nil
}

// DelVlanSub removes a VLAN subinterface. Unlike the best-effort DeleteLink it
// RETURNS an error, so the caller can refuse to free the VID while the device
// still exists (the free-after-device-gone invariant).
func DelVlanSub(iface string) error {
	if !ifaceExists(iface) {
		return nil
	}
	if err := run("ip", "link", "del", iface); err != nil {
		return err
	}
	if ifaceExists(iface) {
		return fmt.Errorf("subinterface %s still present after delete", iface)
	}
	return nil
}

// linkMTU reads an interface's current MTU.
func linkMTU(iface string) int {
	out, err := exec.Command("cat", "/sys/class/net/"+iface+"/mtu").Output()
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// readOffloadOn returns the subset of qinqOffloadFlags currently reported "on" by
// ethtool for iface. Flags ethtool doesn't report (feature absent) are omitted.
func readOffloadOn(iface string) []string {
	out, err := exec.Command("ethtool", "-k", iface).CombinedOutput()
	if err != nil {
		return nil
	}
	on := map[string]bool{}
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		for _, f := range qinqOffloadFlags {
			if strings.HasPrefix(ln, f+":") && strings.Contains(ln, " on") {
				on[f] = true
			}
		}
	}
	var res []string
	for _, f := range qinqOffloadFlags {
		if on[f] {
			res = append(res, f)
		}
	}
	return res
}

// ReadTrunkState captures the CURRENT MTU and the set of QinQ-relevant offload
// flags that are ON, for an interface. The service stores this ONCE at first
// designation (never overwriting on re-apply) so RestoreTrunk can return the NIC
// to exactly its pre-designation state.
func ReadTrunkState(iface string) (mtu int, offloadOn string) {
	return linkMTU(iface), strings.Join(readOffloadOn(iface), ",")
}

// EnsureTrunk prepares a trunk (and all its bond slaves) for tenant egress: raise
// MTU so tagged/double-tagged frames aren't silently dropped, and — when the
// trunk is QinQ-capable — disable the VLAN offloads that corrupt 802.1ad. It is
// idempotent and is re-run on every boot and on any bond-membership change.
func EnsureTrunk(iface string, slaves []string, mtu int, disableOffload bool) error {
	targets := append([]string{iface}, slaves...)
	for _, t := range targets {
		if !ifaceExists(t) {
			continue
		}
		if mtu > 0 {
			if err := run("ip", "link", "set", t, "mtu", strconv.Itoa(mtu)); err != nil {
				return fmt.Errorf("set mtu on %s: %w", t, err)
			}
		}
		if disableOffload {
			// Toggle only the flags the NIC actually exposes; -K on an absent
			// feature errors, so apply them individually and tolerate per-flag
			// failure (feature not present) while surfacing nothing fatal.
			for _, f := range qinqOffloadFlags {
				_ = exec.Command("ethtool", "-K", t, f, "off").Run()
			}
		}
	}
	return nil
}

// RestoreTrunk returns a trunk (and its slaves) to the recorded pre-designation
// state: restore the original MTU and re-enable exactly the offload flags that
// were on before. Used by uplink teardown / feature disable.
func RestoreTrunk(iface string, slaves []string, origMTU int, origOffload string) error {
	wasOn := map[string]bool{}
	for _, f := range strings.Split(origOffload, ",") {
		if f = strings.TrimSpace(f); f != "" {
			wasOn[f] = true
		}
	}
	targets := append([]string{iface}, slaves...)
	for _, t := range targets {
		if !ifaceExists(t) {
			continue
		}
		if origMTU > 0 {
			_ = run("ip", "link", "set", t, "mtu", strconv.Itoa(origMTU))
		}
		for _, f := range qinqOffloadFlags {
			state := "off"
			if wasOn[f] {
				state = "on"
			}
			_ = exec.Command("ethtool", "-K", t, f, state).Run()
		}
	}
	return nil
}

// VerifyQinQ sanity-checks that a QinQ trunk is actually configured for double
// tagging on THIS host's NIC before the admin trusts it: offloads off and MTU
// high enough. It returns a plain-language result for the admin page; it does NOT
// prove wire behavior (only a tcpdump on the physical link can), so the message
// says so.
func VerifyQinQ(iface string, wantMTU int) (ok bool, detail string) {
	var problems []string
	if on := readOffloadOn(iface); len(on) > 0 {
		problems = append(problems, "VLAN offload still enabled ("+strings.Join(on, ",")+") — can corrupt 802.1ad")
	}
	if m := linkMTU(iface); m > 0 && m < wantMTU {
		problems = append(problems, fmt.Sprintf("MTU %d < required %d (big double-tagged frames will drop)", m, wantMTU))
	}
	if len(problems) == 0 {
		return true, "offloads off and MTU ok; confirm on the wire with: tcpdump -eni " + iface + " (expect outer 0x88a8 + inner 0x8100)"
	}
	return false, strings.Join(problems, "; ")
}

// BridgeVlanTagged adds a tagged VLAN membership to a bridge port (used when a
// subinterface is enslaved into a vlan_filtering tenant vSwitch rather than a
// plain bridge — the host-verified QinQ-over-filtering path).
func BridgeVlanTagged(port string, vid int) error {
	return run("bridge", "vlan", "add", "dev", port, "vid", strconv.Itoa(vid))
}
