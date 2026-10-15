package netdrv

import (
	"os/exec"
	"strings"
)

// Floating management VIP primitives. The leader owns the VIP; it lives on a
// macvlan CHILD of the mgmt NIC with a stable, cluster-derived MAC. Because the
// MAC is identical on every node, a DHCP server hands the same lease to whichever
// node currently holds it (lease affinity), so the IP "floats" to the leader.
//
// The macvlan child is strictly ADDITIVE: the parent mgmt NIC keeps its own IP
// and the admin listener, so this does not "reassign" the management NIC and is a
// sanctioned exception to the guardMgmt rule (critic M9).

// EnsureMacvlan creates (idempotently) a macvlan child `name` on `parent` with a
// fixed MAC, and brings it up.
func EnsureMacvlan(name, parent, mac string) error {
	if !ifaceExists(name) {
		if err := run("ip", "link", "add", name, "link", parent,
			"address", mac, "type", "macvlan", "mode", "bridge"); err != nil {
			return err
		}
	} else {
		// Ensure the MAC is the stable cluster MAC even if the link pre-existed.
		_ = run("ip", "link", "set", name, "address", mac)
	}
	return run("ip", "link", "set", name, "up")
}

// DelLink removes a link (best effort) — used to tear the VIP child down on demote.
func DelLink(name string) { _ = run("ip", "link", "del", name) }

// SetARPFlux hardens ARP behaviour so the VIP and the parent's own IP (same L2,
// same subnet) do not cross-answer, and asymmetric replies are not rp_filtered
// (critic M2). Best effort — failures are non-fatal.
func SetARPFlux(ifaces ...string) {
	for _, ifc := range ifaces {
		_ = run("sysctl", "-wq", "net.ipv4.conf."+ifc+".arp_ignore=1")
		_ = run("sysctl", "-wq", "net.ipv4.conf."+ifc+".arp_announce=2")
		_ = run("sysctl", "-wq", "net.ipv4.conf."+ifc+".rp_filter=2")
	}
}

// StartDHCP runs dhcpcd on `iface` with a PINNED client-id so both nodes present
// the same DHCP identity and get the same lease (critic M3). It never installs a
// default route (-G) or touches DNS/NTP (--nohook), so it cannot disturb the
// host's existing mgmt-NIC networking. clientID is a colon-hex string.
func StartDHCP(iface, clientID string) error {
	// Stop any stale instance for this iface first (idempotent re-claim).
	_ = exec.Command("dhcpcd", "-k", iface).Run()
	args := []string{"-4", "-b", "-G", "--nohook", "resolv.conf,ntp.conf"}
	if clientID != "" {
		args = append(args, "-I", clientID)
	}
	args = append(args, iface)
	return run2("dhcpcd", args...)
}

// StopDHCP releases the lease and stops dhcpcd for `iface` (best effort).
func StopDHCP(iface string) { _ = exec.Command("dhcpcd", "-k", iface).Run() }

// AddAddr/DelAddr manage a static VIP address on an interface (the non-DHCP path).
func AddAddr(iface, cidr string) error { return run("ip", "addr", "add", cidr, "dev", iface) }
func DelAddr(iface, cidr string)       { _ = run("ip", "addr", "del", cidr, "dev", iface) }

// IfaceIPv4 returns the first IPv4 address (bare, no prefix) on an interface, or
// "" if none is assigned yet.
func IfaceIPv4(iface string) string {
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", iface).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "inet" {
				return strings.SplitN(f[i+1], "/", 2)[0]
			}
		}
	}
	return ""
}

// GratuitousARP announces ip on iface so the switch relearns the MAC after a
// failover. dhcpcd already announces on the DHCP path; this covers the static
// path and is best effort (arping may be absent).
func GratuitousARP(iface, ip string) {
	if _, err := exec.LookPath("arping"); err == nil {
		_ = exec.Command("arping", "-A", "-c", "3", "-I", iface, ip).Run()
	}
}

// run2 is like run but returns the combined output in the error for diagnostics.
func run2(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return &cmdError{cmd: name + " " + strings.Join(args, " "), out: string(out), err: err}
	}
	return nil
}

type cmdError struct {
	cmd, out string
	err      error
}

func (e *cmdError) Error() string {
	if e.out != "" {
		return e.cmd + ": " + e.err.Error() + ": " + strings.TrimSpace(e.out)
	}
	return e.cmd + ": " + e.err.Error()
}
