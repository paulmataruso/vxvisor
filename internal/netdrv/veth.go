package netdrv

import "os/exec"

// veth / network-namespace primitives for the vRouter feature. These are the
// building blocks the netns vRouter backend uses (create a namespace, wire veth
// pairs between host bridges and the namespace) and the transit-link path uses
// (plain-enslave a physical NIC to a bridge). None of this existed before the
// vRouter feature; all of it is idempotent where practical.

// FlushAddrs removes all IPv4/IPv6 addresses from an interface. Used before
// enslaving a transit NIC to a bridge so a stale host IP doesn't linger.
func FlushAddrs(iface string) error { return run("ip", "addr", "flush", "dev", iface) }

// EnslaveToBridge enslaves an interface to a bridge as a PLAIN access port (no
// 802.1q trunk — unlike EnsureVSwitch, which trunks VLAN 2-4094). This is the
// transit-link attach: a physical NIC bridged to a vRouter leg.
//
// It deliberately does NOT flush the interface's addresses. This function is
// re-run idempotently on every boot/restart by ReensureVRouters; flushing here
// would repeatedly wipe any IP on the NIC (e.g. the Ceph storage IP if a NIC
// were ever shared), wedging whatever depends on it. The attach-time guard
// already refuses a NIC that carries an address, so there is nothing to flush.
func EnslaveToBridge(iface, bridge string) error {
	if err := run("ip", "link", "set", iface, "master", bridge); err != nil {
		return err
	}
	return run("ip", "link", "set", iface, "up")
}

// DetachFromBridge returns an enslaved interface to a standalone state so it
// re-appears as a free transit candidate.
func DetachFromBridge(iface string) error { return run("ip", "link", "set", iface, "nomaster") }

// SetMaster live-moves an interface (e.g. a container's host-side veth) onto a
// bridge without a restart. Does NOT flush addresses (unlike EnslaveToBridge) —
// it's a plain re-master used when changing a container's network.
func SetMaster(iface, bridge string) error {
	if !ifaceExists(iface) {
		return nil // nothing to move live (e.g. container stopped); config change suffices
	}
	if err := run("ip", "link", "set", iface, "master", bridge); err != nil {
		return err
	}
	return run("ip", "link", "set", iface, "up")
}

// DeleteLink removes a link (bridge/veth); best-effort, ignores absence.
func DeleteLink(name string) { _ = exec.Command("ip", "link", "del", name).Run() }

// ---- network namespaces -------------------------------------------------

func netnsExists(ns string) bool { return exec.Command("ip", "netns", "pid", ns).Run() == nil }

// EnsureNetns creates a named network namespace (idempotent).
func EnsureNetns(ns string) error {
	if netnsExists(ns) {
		return nil
	}
	return run("ip", "netns", "add", ns)
}

// DeleteNetns removes a named network namespace (best-effort).
func DeleteNetns(ns string) { _ = exec.Command("ip", "netns", "del", ns).Run() }

// EnsureVethPair creates a veth pair host<->peer (idempotent). The caller then
// enslaves host to a bridge and moves peer into a namespace.
func EnsureVethPair(host, peer string) error {
	if ifaceExists(host) {
		return nil
	}
	return run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
}

// MoveToNetns moves an interface into a named namespace.
func MoveToNetns(iface, ns string) error { return run("ip", "link", "set", iface, "netns", ns) }

// MoveToNetnsPID moves an interface into the network namespace of a process
// (e.g. an LXC container's PID1), for hot-plugging a NIC into a running
// container without restarting it.
func MoveToNetnsPID(iface string, pid int) error {
	return run("ip", "link", "set", iface, "netns", itoa(pid))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// RenameInNetns renames an interface that already lives inside a namespace.
func RenameInNetns(ns, from, to string) error {
	if from == to {
		return nil
	}
	return run("ip", "netns", "exec", ns, "ip", "link", "set", from, "name", to)
}

// NetnsLinkUp brings an interface up inside a namespace.
func NetnsLinkUp(ns, iface string) error {
	return run("ip", "netns", "exec", ns, "ip", "link", "set", iface, "up")
}

// NetnsAddr assigns an address to an interface inside a namespace (idempotent-ish;
// a duplicate add is ignored by the caller). Normally zebra assigns leg IPs, so
// this is a fallback for the loopback / pre-FRR bring-up.
func NetnsAddr(ns, iface, cidr string) error {
	return run("ip", "netns", "exec", ns, "ip", "addr", "add", cidr, "dev", iface)
}
