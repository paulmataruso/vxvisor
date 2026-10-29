package vrouter

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/routing"
)

// netnsBackend runs a vRouter as a Linux network namespace with its own FRR
// instance (FRR pathspace -N) and, for internal legs, dnsmasq — both reached via
// `ip netns exec`. The host FRR binaries are reused (install.sh installs them);
// per-instance config lives in /etc/frr/<N>/ and sockets in /run/frr/<N>/.
//
// v1 starts the per-namespace daemons directly (`-d`); reboot persistence is a
// generated systemd oneshot that rebuilds the topology + restarts the daemons
// (see persist.go). Per-daemon crash supervision is a documented follow-up.
type netnsBackend struct{}

var _ EdgeApplier = netnsBackend{}

func (netnsBackend) Kind() string { return RuntimeNetns }
func (netnsBackend) available() bool {
	_, err := exec.LookPath("ip")
	return err == nil && frrBinsPresent()
}

func frrBinsPresent() bool {
	for _, d := range []string{"zebra", "staticd"} {
		if _, err := os.Stat("/usr/lib/frr/" + d); err != nil {
			return false
		}
	}
	return true
}

func nsPath(vr VRouter) string   { return strconv.FormatInt(vr.ID, 10) } // FRR -N pathspace
func nsFrrDir(vr VRouter) string { return "/etc/frr/" + nsPath(vr) }
func nsRunDir(vr VRouter) string { return "/run/frr/" + nsPath(vr) }
func nsStateDir(vr VRouter) string {
	return filepath.Join("/var/lib/vdxclone/vrouter", strconv.FormatInt(vr.ID, 10))
}

func nsrun(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Provision creates the namespace + FRR state dirs. FRR itself is the host's
// (already installed); no apt needed.
func (netnsBackend) Provision(vr VRouter, legs []Leg) error {
	if !frrBinsPresent() {
		return fmt.Errorf("host FRR is not installed (needed for the netns vRouter backend)")
	}
	if err := netdrv.EnsureNetns(vr.NetnsName); err != nil {
		return err
	}
	for _, d := range []string{nsFrrDir(vr), nsRunDir(vr), nsStateDir(vr)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	// FRR drops privileges to frr:frr and needs to own its runtime socket dir.
	_, _ = nsrun(10*time.Second, "chown", "-R", "frr:frr", nsRunDir(vr), nsFrrDir(vr))
	// Seed a daemons file in the pathspace (enables the routing daemons).
	daemons := "zebra=yes\nstaticd=yes\nospfd=yes\nbgpd=yes\neigrpd=yes\nvtysh_enable=yes\n"
	_ = os.WriteFile(filepath.Join(nsFrrDir(vr), "daemons"), []byte(daemons), 0o640)
	// Seed vtysh.conf in the pathspace: vtysh/frr-reload look for it there and
	// error ("Can't open .../vtysh.conf") without it. integrated-vtysh-config
	// makes the single frr.conf the source of truth for all daemons.
	_ = os.WriteFile(filepath.Join(nsFrrDir(vr), "vtysh.conf"), []byte("service integrated-vtysh-config\n"), 0o640)
	_, _ = nsrun(10*time.Second, "chown", "-R", "frr:frr", nsFrrDir(vr))
	// Bring up loopback inside the namespace.
	_, _ = nsrun(10*time.Second, "ip", "netns", "exec", vr.NetnsName, "ip", "link", "set", "lo", "up")
	return nil
}

func (b netnsBackend) Start(vr VRouter) error { return b.startDaemons(vr) }
func (b netnsBackend) Stop(vr VRouter) error  { b.killDaemons(vr); return nil }
func (b netnsBackend) Destroy(vr VRouter) error {
	b.killDaemons(vr)
	// Remove veths (host ends) then the namespace + state dirs.
	netdrv.DeleteNetns(vr.NetnsName)
	_ = os.RemoveAll(nsFrrDir(vr))
	_ = os.RemoveAll(nsRunDir(vr))
	_ = os.RemoveAll(nsStateDir(vr))
	return nil
}

// netnsIfacePresent reports whether an interface exists INSIDE the namespace.
func netnsIfacePresent(ns, iface string) bool {
	_, err := nsrun(5*time.Second, "ip", "netns", "exec", ns, "ip", "link", "show", iface)
	return err == nil
}

// ApplyLegs builds veth pairs for each leg: host end enslaved to the leg bridge,
// peer moved into the namespace and renamed ethN. veths can be added live.
//
// IDEMPOTENT: applyAndPush re-passes EVERY leg on every change (e.g. adding a
// second internal leg re-applies the first). A leg whose in-namespace iface is
// already present is fully wired, so we SKIP it — re-running MoveToNetns on a
// peer that has already been moved would fail ("Cannot find device") and take
// the whole apply (and every other leg/tenant on this router) down with it.
// A leg that is only half-applied (peer moved but not renamed, or a stale pair)
// is torn down and rebuilt clean: deleting the host end removes the veth pair
// wherever its peer landed, and we also clear any stale un-renamed peer in the ns.
//
// A wired leg is still reconciled: its host end must be a port of the leg's
// bridge before its VLAN is set. If that bridge was deleted and re-created the
// port fell off it; re-enslaving heals that, and a bridge that is gone yields a
// clear error instead of a VLAN failure on a non-port (which used to fail every
// later change on the router with an opaque RTNETLINK message).
func (netnsBackend) ApplyLegs(vr VRouter, legs []Leg) error {
	for _, l := range legs {
		host := legHostVeth(vr, l)
		peer := host + "p"
		if len(host) > 15 || len(peer) > 15 {
			return fmt.Errorf("veth name %q too long", host)
		}
		if netnsIfacePresent(vr.NetnsName, l.IfaceName) {
			if err := relinkLeg(host, l); err != nil {
				return err
			}
			if err := legAccessVlan(host, l); err != nil {
				return err
			}
			continue // already fully wired
		}
		// Clear any half-applied remnants so the rebuild starts from a clean slate.
		netdrv.DeleteLink(host)                                                                     // host-ns end (removes the pair wherever the peer is)
		_, _ = nsrun(5*time.Second, "ip", "netns", "exec", vr.NetnsName, "ip", "link", "del", peer) // stale un-renamed peer in the ns
		if err := netdrv.EnsureVethPair(host, peer); err != nil {
			return err
		}
		if err := netdrv.EnslaveToBridge(host, l.Bridge); err != nil {
			return err
		}
		if err := legAccessVlan(host, l); err != nil {
			return err
		}
		if err := netdrv.MoveToNetns(peer, vr.NetnsName); err != nil {
			return err
		}
		if err := netdrv.RenameInNetns(vr.NetnsName, peer, l.IfaceName); err != nil {
			return err
		}
		if err := netdrv.NetnsLinkUp(vr.NetnsName, l.IfaceName); err != nil {
			return err
		}
	}
	return nil
}

// legHostVeth is the host-side veth end of a netns leg.
func legHostVeth(vr VRouter, l Leg) string {
	return "vrh" + strconv.FormatInt(vr.ID, 10) + "e" + strconv.Itoa(l.Idx)
}

// linkMaster returns the bridge an interface is enslaved to ("" if none).
func linkMaster(iface string) string {
	t, err := os.Readlink("/sys/class/net/" + iface + "/master")
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// relinkLeg puts a wired leg's host end back on its bridge if it fell off.
func relinkLeg(host string, l Leg) error {
	if l.Bridge == "" || linkMaster(host) == l.Bridge {
		return nil
	}
	if !netdrv.IfaceExists(l.Bridge) {
		return fmt.Errorf("interface %s: its network's bridge %s no longer exists — detach this interface from the router", l.IfaceName, l.Bridge)
	}
	if err := netdrv.EnslaveToBridge(host, l.Bridge); err != nil {
		return fmt.Errorf("interface %s: re-attach to %s: %w", l.IfaceName, l.Bridge, err)
	}
	return nil
}

// RemoveLeg stops the leg's dnsmasq and deletes its veth pair: deleting the
// in-namespace end removes the host end too, so the bridge is untouched.
func (b netnsBackend) RemoveLeg(vr VRouter, l Leg) error {
	off := l
	off.DHCP = false
	_ = b.SetDHCP(vr, off)
	if vr.NetnsName != "" && l.IfaceName != "" {
		netdrv.NetnsDelLink(vr.NetnsName, l.IfaceName)
	}
	netdrv.DeleteLink(legHostVeth(vr, l)) // a half-applied pair whose ns end never got renamed
	return nil
}

// legAccessVlan makes a VLAN leg's host veth end an access port of its port
// group on the (VLAN-filtering) tenant vSwitch. Untagged legs keep the default.
func legAccessVlan(host string, l Leg) error {
	if l.VLAN <= 0 {
		return nil
	}
	if err := netdrv.SetAccessVlan(host, l.VLAN); err != nil {
		return fmt.Errorf("leg %s VLAN %d: %w", l.IfaceName, l.VLAN, err)
	}
	return nil
}

// ApplyEdge turns IPv4 forwarding on inside the namespace (a router must
// forward; never inherited-by-accident from the host) and loads the SNAT table.
func (netnsBackend) ApplyEdge(vr VRouter, legs []Leg) error {
	if _, err := nsrun(5*time.Second, "ip", "netns", "exec", vr.NetnsName, "sysctl", "-qw", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable forwarding in netns %s: %w", vr.NetnsName, err)
	}
	_ = os.MkdirAll(nsStateDir(vr), 0o755)
	confPath := filepath.Join(nsStateDir(vr), "nftables-vdxnat.conf")
	if err := os.WriteFile(confPath, []byte(RenderEdgeNAT(legs)), 0o640); err != nil {
		return err
	}
	if _, err := nsrun(15*time.Second, "ip", "netns", "exec", vr.NetnsName, "nft", "-f", confPath); err != nil {
		return fmt.Errorf("apply SNAT in netns %s: %w", vr.NetnsName, err)
	}
	return nil
}

// PushFRR writes the per-namespace frr.conf and reloads (or starts) FRR.
func (b netnsBackend) PushFRR(vr VRouter, frrConf string) error {
	if err := os.WriteFile(filepath.Join(nsFrrDir(vr), "frr.conf"), []byte(frrConf), 0o640); err != nil {
		return err
	}
	_, _ = nsrun(5*time.Second, "chown", "frr:frr", filepath.Join(nsFrrDir(vr), "frr.conf"))
	if !b.daemonsRunning(vr) {
		if err := b.startDaemons(vr); err != nil {
			return err
		}
		time.Sleep(500 * time.Millisecond) // let the daemons open their vty sockets
	}
	// Always load the config via a reload — on first bring-up too, so the leg
	// addresses/protocols actually take effect (starting the daemons alone leaves
	// them with an empty config).
	_, err := nsrun(30*time.Second, "ip", "netns", "exec", vr.NetnsName,
		"/usr/lib/frr/frr-reload.py", "-N", nsPath(vr), "--reload", filepath.Join(nsFrrDir(vr), "frr.conf"))
	return err
}

// PushFirewall applies the zone-firewall ruleset inside the namespace's own
// netfilter instance via `ip netns exec <ns> nft`. The ruleset is staged to a
// file under the vRouter's state dir. An empty ruleset removes the table.
func (b netnsBackend) PushFirewall(vr VRouter, ruleset string) error {
	if ruleset == "" {
		_, _ = nsrun(10*time.Second, "sh", "-c",
			"ip netns exec "+vr.NetnsName+" nft delete table inet "+FWTable+" 2>/dev/null; true")
		return nil
	}
	_ = os.MkdirAll(nsStateDir(vr), 0o755)
	confPath := filepath.Join(nsStateDir(vr), "nftables-vdxfw.conf")
	if err := os.WriteFile(confPath, []byte(ruleset), 0o640); err != nil {
		return err
	}
	// Flush our table first (ignore if absent), then load the fresh ruleset.
	if _, err := nsrun(15*time.Second, "sh", "-c",
		"ip netns exec "+vr.NetnsName+" nft delete table inet "+FWTable+" 2>/dev/null; "+
			"ip netns exec "+vr.NetnsName+" nft -f "+confPath); err != nil {
		return fmt.Errorf("apply zone firewall in netns %s: %w", vr.NetnsName, err)
	}
	return nil
}

func (netnsBackend) SetDHCP(vr VRouter, leg Leg) error {
	if routing.ValidIface(leg.IfaceName) != nil {
		return fmt.Errorf("DHCP: invalid interface name %q", leg.IfaceName)
	}
	pid := filepath.Join("/run", "vdx-vrouter-"+strconv.FormatInt(vr.ID, 10)+"-dnsmasq-"+leg.IfaceName+".pid")
	// Stop any existing instance for this leg.
	if b, err := os.ReadFile(pid); err == nil {
		_, _ = nsrun(5*time.Second, "sh", "-c", "kill "+strings.TrimSpace(string(b))+" 2>/dev/null; true")
		_ = os.Remove(pid)
	}
	if !leg.DHCP {
		return nil
	}
	frag, err := DnsmasqConf(leg)
	if err != nil {
		return err
	}
	lease := filepath.Join(nsStateDir(vr), "dnsmasq-"+leg.IfaceName+".leases")
	confPath := filepath.Join(nsStateDir(vr), "dnsmasq-"+leg.IfaceName+".conf")
	conf := frag + "dhcp-leasefile=" + lease + "\npid-file=" + pid + "\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		return err
	}
	_, err = nsrun(10*time.Second, "ip", "netns", "exec", vr.NetnsName, "dnsmasq", "-C", confPath)
	return err
}

func (b netnsBackend) Status(vr VRouter) (LiveStatus, error) {
	if !b.daemonsRunning(vr) {
		return LiveStatus{State: "stopped"}, nil
	}
	vt := func(cmd string) string {
		out, _ := nsrun(15*time.Second, "ip", "netns", "exec", vr.NetnsName, "vtysh", "-N", nsPath(vr), "-c", cmd)
		return out
	}
	return LiveStatus{
		State:         "running",
		RouteTable:    vt("show ip route"),
		BGPSummary:    vt("show ip bgp summary"),
		OSPFNeighbors: vt("show ip ospf neighbor"),
		Advertised:    vt("show ip bgp"),
	}, nil
}

// startDaemons launches the per-namespace FRR daemons (zebra first).
func (b netnsBackend) startDaemons(vr VRouter) error {
	for _, d := range []string{nsFrrDir(vr), nsRunDir(vr)} {
		_ = os.MkdirAll(d, 0o755)
	}
	_, _ = nsrun(10*time.Second, "chown", "-R", "frr:frr", nsRunDir(vr), nsFrrDir(vr))
	// mgmtd right after zebra: since FRR 9, static-route config is applied
	// through mgmtd (staticd is its backend), so without it frr-reload can't
	// install the leg routes. Absent on older FRR — skipped below.
	order := []string{"zebra", "mgmtd", "staticd", "ospfd", "bgpd", "eigrpd"}
	for _, d := range order {
		bin := "/usr/lib/frr/" + d
		if _, err := os.Stat(bin); err != nil {
			continue // e.g. eigrpd absent on some distros
		}
		// Redirect the daemon's stdio to /dev/null: with -d it double-forks and
		// daemonizes, but if it inherits our stdout/stderr pipe the exec never
		// sees EOF and blocks until the context deadline (every daemon then costs
		// ~15s and the whole apply hangs). Detaching stdio lets the start return
		// immediately.
		start := "exec ip netns exec " + vr.NetnsName + " " + bin + " -N " + nsPath(vr) + " -d </dev/null >/dev/null 2>&1"
		if _, err := nsrun(15*time.Second, "sh", "-c", start); err != nil {
			return fmt.Errorf("start %s: %w", d, err)
		}
		if d == "zebra" {
			time.Sleep(500 * time.Millisecond) // let zebra open its socket first
		}
	}
	return nil
}

func (b netnsBackend) killDaemons(vr VRouter) {
	// Pathspace -N <id> makes the daemon pidfiles live under /run/frr/<id>/.
	_, _ = nsrun(10*time.Second, "sh", "-c",
		"for p in "+nsRunDir(vr)+"/*.pid; do [ -f \"$p\" ] && kill $(cat \"$p\") 2>/dev/null; done; true")
	// Stop any dnsmasq instances for this vRouter.
	_, _ = nsrun(10*time.Second, "sh", "-c",
		"for p in /run/vdx-vrouter-"+strconv.FormatInt(vr.ID, 10)+"-dnsmasq-*.pid; do [ -f \"$p\" ] && kill $(cat \"$p\") 2>/dev/null; done; true")
}

func (netnsBackend) daemonsRunning(vr VRouter) bool {
	// zebra's pidfile under the pathspace runtime dir is the liveness signal.
	matches, _ := filepath.Glob(nsRunDir(vr) + "/zebra*.pid")
	return len(matches) > 0
}
