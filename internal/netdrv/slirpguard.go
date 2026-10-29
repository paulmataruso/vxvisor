package netdrv

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// SLIRP loopback guard.
//
// QEMU user-mode networking (SLIRP) maps the guest-visible host alias (10.0.2.2,
// and the IPv6 alias) onto the HOST's loopback: a guest that connects to
// 10.0.2.2:5901 makes the QEMU process connect to 127.0.0.1:5901. Loopback is
// where vdxd keeps every VM's console (VNC/SPICE), the optional rustguac broker
// and its guacd — none of which are meant to be reachable from a guest. So a
// user-mode guest could open another VM's console.
//
// The guard is a vdxd-owned nftables table that drops NEW connections from QEMU
// processes to 127.0.0.0/8 and ::1, except DNS (port 53): SLIRP forwards guest
// DNS to the resolver in /etc/resolv.conf, which is often loopback
// (systemd-resolved's 127.0.0.53). It hooks OUTPUT and matches only ct state new,
// so replies on connections INTO QEMU (vdxd's console proxy dialing a VM's VNC
// listener, a hostfwd'd SSH session) are untouched.
//
// QEMU's sockets are told apart by owner: with [vm] run_as set QEMU runs as that
// user (meta skuid); without it QEMU runs as root with the dedicated system group
// SlirpGuardGroup as its primary gid (meta skgid). Both rules are rendered when
// both identities are known, so a config change between restarts never leaves an
// already-running VM unguarded.

// SlirpGuardTable is the nftables table (inet family) the guard owns.
const SlirpGuardTable = "vdxslirp"

// SlirpGuardGroup is the system group root-run QEMU uses as its primary gid.
const SlirpGuardGroup = "vdxqemu"

// RenderSlirpGuard renders the guard ruleset for QEMU running as uid and/or with
// primary group gid. A zero id is skipped (never matching root itself). The
// "table / delete table / table {...}" form makes `nft -f` replace it
// atomically and idempotently, whether or not it already exists.
func RenderSlirpGuard(uid, gid uint32) (string, error) {
	if uid == 0 && gid == 0 {
		return "", fmt.Errorf("slirp guard: no QEMU identity to match (set [vm] run_as, or let vdxd create the %s group)", SlirpGuardGroup)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", SlirpGuardTable)
	fmt.Fprintf(&b, "delete table inet %s\n", SlirpGuardTable)
	fmt.Fprintf(&b, "table inet %s {\n", SlirpGuardTable)
	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority filter; policy accept;\n")
	if uid != 0 {
		fmt.Fprintf(&b, "    meta skuid %d ct state new jump qemu_loopback\n", uid)
	}
	if gid != 0 {
		fmt.Fprintf(&b, "    meta skgid %d ct state new jump qemu_loopback\n", gid)
	}
	b.WriteString("  }\n")
	b.WriteString("  chain qemu_loopback {\n")
	b.WriteString("    ip daddr 127.0.0.0/8 udp dport 53 return\n")
	b.WriteString("    ip daddr 127.0.0.0/8 tcp dport 53 return\n")
	b.WriteString("    ip daddr 127.0.0.0/8 drop\n")
	b.WriteString("    ip6 daddr ::1 udp dport 53 return\n")
	b.WriteString("    ip6 daddr ::1 tcp dport 53 return\n")
	b.WriteString("    ip6 daddr ::1 drop\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// ApplySlirpGuard (re)loads the guard for the given QEMU identity via `nft -f -`.
func ApplySlirpGuard(uid, gid uint32) error {
	rs, err := RenderSlirpGuard(uid, gid)
	if err != nil {
		return err
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("slirp guard: nftables is not installed (install the nftables package)")
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("slirp guard: nft load: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SlirpGuardPresent reports whether the guard table is currently loaded (false
// after anything external flushed the ruleset, or when nft is missing).
func SlirpGuardPresent() bool {
	return exec.Command("nft", "list", "table", "inet", SlirpGuardTable).Run() == nil
}

// EnsureGuardGroup returns the gid of SlirpGuardGroup, creating it as a system
// group if it doesn't exist yet. Idempotent.
func EnsureGuardGroup() (uint32, error) {
	if gid, ok := lookupGroupID(SlirpGuardGroup); ok {
		return gid, nil
	}
	if out, err := exec.Command("groupadd", "--system", SlirpGuardGroup).CombinedOutput(); err != nil {
		// A concurrent creator may have won the race; look again before failing.
		if gid, ok := lookupGroupID(SlirpGuardGroup); ok {
			return gid, nil
		}
		return 0, fmt.Errorf("create group %s: %v: %s", SlirpGuardGroup, err, strings.TrimSpace(string(out)))
	}
	if gid, ok := lookupGroupID(SlirpGuardGroup); ok {
		return gid, nil
	}
	return 0, fmt.Errorf("group %s was created but can't be resolved", SlirpGuardGroup)
}

func lookupGroupID(name string) (uint32, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}
