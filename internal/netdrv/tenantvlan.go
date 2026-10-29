package netdrv

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Host driver for tenant vSwitches + port groups and their host isolation.
//
// A tenant vSwitch is its tenant network's bridge (vdxt<network_id>). It stays a
// PLAIN bridge until it gets its first tagged port group; then vlan_filtering is
// turned on and every port is an explicit VLAN member: VM taps are access ports
// (SetupTapAccess), router legs likewise, and the uplink port carries either one
// native port group untagged (access uplink) or every port group tagged (QinQ /
// dedicated). A port group with a host gateway gets a VLAN interface on the
// bridge (<bridge>.<vid>) carrying that IP and its DHCP.
//
// Nothing here persists across reboot; the worker re-applies it idempotently.

// SetBridgeVlanFiltering turns 802.1q filtering on or off for a bridge. Port
// VLAN memberships are kept either way (they are just not enforced when off).
func SetBridgeVlanFiltering(bridge string, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return run("ip", "link", "set", bridge, "type", "bridge", "vlan_filtering", v)
}

// bridgeVlanEntry is one element of `bridge -j vlan show dev X`.
type bridgeVlanEntry struct {
	Ifname string `json:"ifname"`
	Vlans  []struct {
		Vlan    int      `json:"vlan"`
		VlanEnd int      `json:"vlanEnd"`
		Flags   []string `json:"flags"`
	} `json:"vlans"`
}

// PortVlans reads a bridge port's (or, with self, the bridge device's own) VLAN
// memberships: its PVID (0 if none) and every member VID.
func PortVlans(port string, self bool) (pvid int, vids []int, err error) {
	args := []string{"-j", "vlan", "show", "dev", port}
	if self {
		args = append(args, "self")
	}
	out, err := exec.Command("bridge", args...).Output()
	if err != nil {
		return 0, nil, fmt.Errorf("bridge vlan show dev %s: %w", port, err)
	}
	var entries []bridgeVlanEntry
	if strings.TrimSpace(string(out)) != "" {
		if err := json.Unmarshal(out, &entries); err != nil {
			return 0, nil, fmt.Errorf("parse bridge vlan show: %w", err)
		}
	}
	for _, e := range entries {
		for _, v := range e.Vlans {
			end := v.VlanEnd
			if end < v.Vlan {
				end = v.Vlan
			}
			for id := v.Vlan; id <= end; id++ {
				vids = append(vids, id)
			}
			for _, f := range v.Flags {
				if f == "PVID" {
					pvid = v.Vlan
				}
			}
		}
	}
	return pvid, vids, nil
}

// SetPortVlans reconciles a bridge port to exactly: pvid as its untagged native
// VLAN (0 = no untagged VLAN) plus the tagged VIDs. Memberships not wanted are
// removed. Idempotent.
func SetPortVlans(port string, pvid int, tagged []int) error {
	_, have, err := PortVlans(port, false)
	if err != nil {
		return err
	}
	want := map[int]bool{}
	if pvid > 0 {
		want[pvid] = true
	}
	for _, v := range tagged {
		want[v] = true
	}
	for _, v := range have {
		if !want[v] {
			if err := run("bridge", "vlan", "del", "dev", port, "vid", strconv.Itoa(v)); err != nil {
				return err
			}
		}
	}
	if pvid > 0 {
		if err := run("bridge", "vlan", "add", "dev", port, "vid", strconv.Itoa(pvid), "pvid", "untagged"); err != nil {
			return err
		}
	}
	sort.Ints(tagged)
	for _, v := range tagged {
		if v == pvid {
			continue
		}
		// "add" on an existing membership replaces its flags, so a VID that used
		// to be the untagged PVID becomes plainly tagged.
		if err := run("bridge", "vlan", "add", "dev", port, "vid", strconv.Itoa(v)); err != nil {
			return err
		}
	}
	return nil
}

// SetAccessVlan makes a bridge port an untagged access port of vid only.
func SetAccessVlan(port string, vid int) error { return SetPortVlans(port, vid, nil) }

// BridgeVlanIfaceName is the host VLAN interface for a port group's host gateway.
func BridgeVlanIfaceName(bridge string, vid int) string { return bridge + "." + strconv.Itoa(vid) }

// EnsureBridgeVlanIface gives the bridge device itself a tagged membership of vid
// and creates the <bridge>.<vid> VLAN interface on it (up), so the host can hold
// a port group's gateway IP and serve its DHCP. Idempotent.
func EnsureBridgeVlanIface(bridge string, vid int) (string, error) {
	name := BridgeVlanIfaceName(bridge, vid)
	if len(name) > 15 {
		return "", fmt.Errorf("VLAN interface name %q exceeds 15 characters", name)
	}
	if err := run("bridge", "vlan", "add", "dev", bridge, "vid", strconv.Itoa(vid), "self"); err != nil {
		return "", err
	}
	if !ifaceExists(name) {
		if err := run("ip", "link", "add", "link", bridge, "name", name, "type", "vlan", "id", strconv.Itoa(vid)); err != nil {
			return "", err
		}
	}
	return name, run("ip", "link", "set", name, "up")
}

// DelBridgeVlanIface removes a port group's host VLAN interface and the bridge
// device's own membership of that VLAN. Best effort.
func DelBridgeVlanIface(bridge string, vid int) {
	_ = exec.Command("ip", "link", "del", BridgeVlanIfaceName(bridge, vid)).Run()
	_ = exec.Command("bridge", "vlan", "del", "dev", bridge, "vid", strconv.Itoa(vid), "self").Run()
}

// ---- tenant host isolation --------------------------------------------------

// TenantGuardTable is the host nftables table that keeps tenant bridges away
// from the host: from a tenant bridge only DHCP, a ping of that interface's own
// address, and replies to the host's own traffic reach the host. vdxd owns this
// table outright.
const TenantGuardTable = "vdxtenant"

// TenantL2GuardTable is the host nftables BRIDGE-family table that keeps a
// tenant's own VMs from impersonating the network's infrastructure on its
// segments (see RenderTenantL2Guard). vdxd owns it outright too.
const TenantL2GuardTable = "vdxtenantl2"

// IsolateTenantIface stops the host from ever routing traffic that arrives on a
// tenant bridge / port-group interface (IPv4 forwarding is decided per ingress
// interface), removes the host's IPv6 presence there, and keeps the host from
// answering ARP there for any address but that interface's own (arp_ignore=1)
// or announcing its other addresses into the segment (arp_announce=2). Bridged
// traffic between the tenant's own ports is L2 and unaffected. A tenant reaches
// other networks only through its own router (netns) or its uplink — never the
// host.
func IsolateTenantIface(dev string) error {
	if !strings.HasPrefix(dev, "vdxt") || !validIfName(dev) {
		return fmt.Errorf("refusing to isolate non-tenant interface %q", dev)
	}
	for _, kv := range [][2]string{
		{filepath.Join("/proc/sys/net/ipv4/conf", dev, "forwarding"), "0"},
		{filepath.Join("/proc/sys/net/ipv4/conf", dev, "arp_ignore"), "1"},
		{filepath.Join("/proc/sys/net/ipv4/conf", dev, "arp_announce"), "2"},
		{filepath.Join("/proc/sys/net/ipv6/conf", dev, "disable_ipv6"), "1"},
	} {
		if err := os.WriteFile(kv[0], []byte(kv[1]), 0o644); err != nil {
			return fmt.Errorf("isolate %s: %w", dev, err)
		}
	}
	return nil
}

// RenderTenantGuard builds the host guard for the given tenant interfaces.
//
//	input:   from a tenant interface only DHCP, a ping of the gateway address on
//	         that same interface, and replies to the host's own traffic reach
//	         the host — never SSH/the admin UI/DNS on any host IP.
//	forward: the host never routes into or out of a tenant interface. This is
//	         the durable layer: per-interface forwarding=0 is reset whenever the
//	         global ip_forward is rewritten (e.g. by host routing apply).
//
// The forward rules only let a packet through when it enters and leaves on the
// SAME tenant interface. That is what bridged traffic looks like when
// br_netfilter hands it to the inet hooks (in and out are both the bridge), and
// it is never true of a packet routed between two interfaces — so the guard is
// right whether or not br_netfilter is loaded, and stays right if something
// loads it later. (An earlier version picked its rules by the br_netfilter state
// at render time, and would have dropped a tenant's own bridged traffic had the
// module been loaded afterwards.)
func RenderTenantGuard(devs []string) string {
	var b strings.Builder
	// Declare-then-delete makes the load atomic and idempotent (no "table not
	// found" on first apply).
	b.WriteString("table inet " + TenantGuardTable + " {}\n")
	b.WriteString("delete table inet " + TenantGuardTable + "\n")
	b.WriteString("table inet " + TenantGuardTable + " {\n")
	if len(devs) > 0 {
		self := make([]string, len(devs))
		for i, d := range devs {
			self[i] = `"` + d + `" . "` + d + `"`
		}
		b.WriteString("  set tbr {\n    type ifname\n    elements = { " + quoteList(devs) + " }\n  }\n")
		b.WriteString("  set tself {\n    type ifname . ifname\n    elements = { " + strings.Join(self, ", ") + " }\n  }\n")
	}
	// A drop in any base chain is final, so other tables' accepts can't undo it.
	b.WriteString("  chain input {\n    type filter hook input priority filter - 10; policy accept;\n")
	if len(devs) > 0 {
		b.WriteString("    iifname @tbr ct state established,related accept\n")
		b.WriteString("    iifname @tbr udp dport 67 accept\n")
		// fib ... type local: the target is an address OF the ingress interface,
		// so a tenant can ping its gateway but not probe the host's other IPs.
		b.WriteString("    iifname @tbr icmp type echo-request fib daddr . iif type local accept\n")
		b.WriteString("    iifname @tbr drop\n")
	}
	b.WriteString("  }\n")
	b.WriteString("  chain forward {\n    type filter hook forward priority filter - 10; policy accept;\n")
	if len(devs) > 0 {
		b.WriteString("    iifname @tbr iifname . oifname != @tself drop\n")
		b.WriteString("    oifname @tbr iifname . oifname != @tself drop\n")
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// RenderTenantL2Guard builds the segment guard for the tenant bridges: a frame
// entering a tenant bridge on a port that isn't trusted (the vSwitch's uplink
// port, a tenant router's leg) is dropped when it is
//
//   - a DHCP server reply (IPv4 67→68, DHCPv6 547→546) — no rogue DHCP server;
//   - an IPv6 router advertisement — no rogue IPv6 router;
//   - an STP BPDU (IEEE 01:80:c2:00:00:00 or Cisco PVST+) — no VM claiming
//     root bridge, or reaching the provider's spanning tree through the uplink.
//
// So a tenant VM can't hijack its own segment's addressing or topology (the
// NSX segment-security defaults). It is a native bridge-family table, so it
// needs no br_netfilter. Frames the host sends itself (its gateway's DHCP)
// don't enter through a port and are never affected.
func RenderTenantL2Guard(bridges, trusted []string) string {
	var b strings.Builder
	b.WriteString("table bridge " + TenantL2GuardTable + " {}\n")
	b.WriteString("delete table bridge " + TenantL2GuardTable + "\n")
	b.WriteString("table bridge " + TenantL2GuardTable + " {\n")
	if len(bridges) > 0 {
		b.WriteString("  set tbr {\n    type ifname\n    elements = { " + quoteList(bridges) + " }\n  }\n")
		if len(trusted) > 0 {
			b.WriteString("  set trusted {\n    type ifname\n    elements = { " + quoteList(trusted) + " }\n  }\n")
		}
	}
	b.WriteString("  chain prerouting {\n    type filter hook prerouting priority filter - 10; policy accept;\n")
	if len(bridges) > 0 {
		b.WriteString("    meta ibrname != @tbr accept\n")
		if len(trusted) > 0 {
			b.WriteString("    iifname @trusted accept\n")
		}
		b.WriteString("    ether daddr { 01:80:c2:00:00:00, 01:00:0c:cc:cc:cd } drop\n")
		b.WriteString("    meta l4proto udp udp sport 67 udp dport 68 drop\n")
		b.WriteString("    meta l4proto udp udp sport 547 udp dport 546 drop\n")
		b.WriteString("    meta l4proto ipv6-icmp icmpv6 type nd-router-advert drop\n")
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return strings.Join(q, ", ")
}

// ApplyTenantGuard loads the host guard (devs: every tenant bridge and
// port-group interface) and the segment guard (bridges: the tenant bridges;
// trusted: their uplink ports and router legs) in one nft transaction,
// replacing any previous version of both. A name that isn't a plain interface
// name is refused rather than rendered.
func ApplyTenantGuard(devs, bridges, trusted []string) error {
	for _, l := range [][]string{devs, bridges, trusted} {
		for _, n := range l {
			if !validIfName(n) {
				return fmt.Errorf("tenant guard: %q is not an interface name", n)
			}
		}
	}
	return ApplyNFT(RenderTenantGuard(devs) + RenderTenantL2Guard(bridges, trusted))
}
