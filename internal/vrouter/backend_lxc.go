package vrouter

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/lxc"
	"vdxclone/internal/netdrv"
)

// lxcBackend runs a vRouter as a privileged LXC container with its own FRR.
// The container is dir-backed (so frr.conf can be written to its rootfs while
// stopped) and provisioned over a temporary lxcbr0 NIC to apt-install FRR, then
// re-wired to the real transit/internal legs.
type lxcBackend struct{}

func (lxcBackend) Kind() string     { return RuntimeLXC }
func (lxcBackend) available() bool  { return lxc.Available() }

// Provision creates the container on lxcbr0, installs FRR + dnsmasq from the
// distro, enables the FRR daemons, and leaves it stopped.
func (b lxcBackend) Provision(vr VRouter, legs []Leg) error {
	if err := lxc.Create(lxc.CreateOpts{
		Name: vr.ContainerName, Lxcpath: vr.LxcPath,
		Dist: vr.Dist, Release: vr.Release,
		Bridge: "lxcbr0", // temporary NAT NIC for apt; swapped to real legs by ApplyLegs
		CPUs:   vr.CPUs, MemMB: vr.MemMB,
	}); err != nil {
		return fmt.Errorf("lxc-create: %w", err)
	}
	if err := lxc.Start(vr.ContainerName, vr.LxcPath); err != nil {
		return fmt.Errorf("lxc-start (provision): %w", err)
	}
	// Wait for a default route (lxc-net DHCP), then install FRR + dnsmasq.
	_, _ = lxc.AttachRun(vr.ContainerName, vr.LxcPath, 60*time.Second,
		"sh", "-c", "for i in $(seq 1 30); do ip route 2>/dev/null | grep -q default && break; sleep 1; done")
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 300*time.Second,
		"sh", "-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y --no-install-recommends frr frr-pythontools dnsmasq nftables"); err != nil {
		return fmt.Errorf("install frr in container: %w", err)
	}
	// Enable the routing daemons (Debian ships them =no by default).
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 30*time.Second,
		"sh", "-c", "sed -i -E 's/^(zebra|staticd|ospfd|bgpd|eigrpd)=no/\\1=yes/' /etc/frr/daemons && systemctl enable frr || true"); err != nil {
		return fmt.Errorf("enable frr daemons: %w", err)
	}
	// dnsmasq must not run globally in the container (it would bind everything);
	// disable the default service — SetDHCP installs per-leg configs and starts it.
	_, _ = lxc.AttachRun(vr.ContainerName, vr.LxcPath, 30*time.Second,
		"sh", "-c", "systemctl disable --now dnsmasq 2>/dev/null; rm -f /etc/dnsmasq.d/*.conf 2>/dev/null; true")
	return lxc.Stop(vr.ContainerName, vr.LxcPath)
}

func (lxcBackend) Start(vr VRouter) error   { return lxc.Start(vr.ContainerName, vr.LxcPath) }
func (lxcBackend) Stop(vr VRouter) error    { return lxc.Stop(vr.ContainerName, vr.LxcPath) }
func (lxcBackend) Destroy(vr VRouter) error { return lxc.Destroy(vr.ContainerName, vr.LxcPath) }

// ApplyLegs makes the container's interfaces match the legs. A stopped container
// is configured and booted with all legs. A RUNNING container is NOT restarted
// (that would flap BGP/OSPF): the config is rewritten for persistence (read only
// at next start) and any missing interface is HOT-PLUGGED live — a veth whose
// host end joins the leg bridge and whose peer is moved into the container and
// renamed ethN. zebra then picks it up and PushFRR assigns its address.
func (b lxcBackend) ApplyLegs(vr VRouter, legs []Leg) error {
	nl := make([]lxc.NetLeg, 0, len(legs))
	for _, l := range legs {
		mac := l.MAC
		if mac == "" {
			mac = netdrv.GenMAC()
		}
		nl = append(nl, lxc.NetLeg{Bridge: l.Bridge, Name: l.IfaceName, MAC: mac})
	}
	c, err := lxc.Info(vr.ContainerName, vr.LxcPath)
	running := err == nil && strings.EqualFold(c.State, "RUNNING")
	if !running {
		if err := lxc.WriteLegs(vr.ContainerName, vr.LxcPath, nl, vr.CPUs, vr.MemMB); err != nil {
			return err
		}
		return lxc.Start(vr.ContainerName, vr.LxcPath)
	}
	// Persist config for the next boot (safe while running — only read at start),
	// then hot-plug any leg not yet present. No restart → no session flap.
	if err := lxc.WriteLegs(vr.ContainerName, vr.LxcPath, nl, vr.CPUs, vr.MemMB); err != nil {
		return err
	}
	for _, l := range legs {
		if b.ifacePresent(vr, l.IfaceName) {
			continue
		}
		if err := b.hotplugLeg(vr, c.PID, l); err != nil {
			return fmt.Errorf("hot-plug %s: %w", l.IfaceName, err)
		}
	}
	return nil
}

// ifacePresent reports whether an interface already exists inside the container.
func (b lxcBackend) ifacePresent(vr VRouter, iface string) bool {
	_, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second, "ip", "link", "show", iface)
	return err == nil
}

// hotplugLeg adds one interface to the running container without a restart.
func (b lxcBackend) hotplugLeg(vr VRouter, pid int, l Leg) error {
	host := lxc.LegVethName(vr.ContainerName, l.Idx)
	peer := host + "p"
	netdrv.DeleteLink(host) // clear any stale pair from a previous attempt
	if err := netdrv.EnsureVethPair(host, peer); err != nil {
		return err
	}
	if err := netdrv.EnslaveToBridge(host, l.Bridge); err != nil {
		return err
	}
	if err := netdrv.MoveToNetnsPID(peer, pid); err != nil {
		return err
	}
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second, "ip", "link", "set", peer, "name", l.IfaceName); err != nil {
		return err
	}
	_, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second, "ip", "link", "set", l.IfaceName, "up")
	return err
}

// PushFRR writes frr.conf into the (dir-backed) rootfs and reloads FRR if the
// container is running. It never touches the host FRR config.
//
// ApplyLegs restarts the container just before this runs, so the container's
// systemd + FRR may still be booting; we wait for FRR to answer vtysh before
// reloading (otherwise frr-reload can't reach the daemons and the dbus socket
// for a systemctl fallback isn't up yet). The fallback is FRR's own init script,
// which works without a ready systemd bus.
func (b lxcBackend) PushFRR(vr VRouter, frrConf string) error {
	if err := lxc.WriteRootfsFile(vr.ContainerName, vr.LxcPath, "/etc/frr/frr.conf", []byte(frrConf), 0o640); err != nil {
		return err
	}
	if st, _ := b.running(vr); !st {
		return nil // FRR reads it at next start
	}
	// Wait (up to ~40s) for FRR's vtysh to be answerable after the restart.
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 45*time.Second,
		"sh", "-c", "for i in $(seq 1 40); do vtysh -c 'show version' >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1"); err != nil {
		return fmt.Errorf("frr did not come up in container %s: %w", vr.ContainerName, err)
	}
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 30*time.Second,
		"sh", "-c", "/usr/lib/frr/frr-reload.py --reload /etc/frr/frr.conf 2>/dev/null || /usr/lib/frr/frrinit.sh restart"); err != nil {
		return fmt.Errorf("reload frr in container: %w", err)
	}
	return nil
}

// PushFirewall applies the zone-firewall nftables ruleset inside the container.
// The ruleset is written to the (dir-backed) rootfs for persistence and loaded
// via `nft -f` when the container is running. An empty ruleset removes the table.
func (b lxcBackend) PushFirewall(vr VRouter, ruleset string) error {
	const rel = "/etc/nftables-vdxfw.conf"
	if ruleset == "" {
		_ = lxc.WriteRootfsFile(vr.ContainerName, vr.LxcPath, rel, []byte("# zone firewall disabled\n"), 0o640)
		if st, _ := b.running(vr); st {
			_, _ = lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second,
				"sh", "-c", "nft delete table inet "+FWTable+" 2>/dev/null; true")
		}
		return nil
	}
	if err := lxc.WriteRootfsFile(vr.ContainerName, vr.LxcPath, rel, []byte(ruleset), 0o640); err != nil {
		return err
	}
	if st, _ := b.running(vr); !st {
		return nil // applied at next start by ReensureVRouters/applyAndPush
	}
	if err := b.ensureNft(vr); err != nil {
		return err
	}
	// Flush our table first (ignore if absent), then load the fresh ruleset.
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 15*time.Second,
		"sh", "-c", "nft delete table inet "+FWTable+" 2>/dev/null; nft -f "+rel); err != nil {
		return fmt.Errorf("apply zone firewall in container %s: %w", vr.ContainerName, err)
	}
	return nil
}

// ensureNft makes sure the nftables CLI is present in the container. Containers
// provisioned before nftables was added to the image won't have it; install it
// on demand (needs outbound connectivity via the vRouter's transit link).
func (b lxcBackend) ensureNft(vr VRouter) error {
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second,
		"sh", "-c", "command -v nft >/dev/null 2>&1"); err == nil {
		return nil
	}
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 180*time.Second,
		"sh", "-c", "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y --no-install-recommends nftables"); err != nil {
		return fmt.Errorf("nftables isn't installed in this vRouter and couldn't be installed automatically — it needs outbound internet via its transit link (or recreate the vRouter): %w", err)
	}
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second,
		"sh", "-c", "command -v nft >/dev/null 2>&1"); err != nil {
		return fmt.Errorf("nftables still unavailable after install in %s", vr.ContainerName)
	}
	return nil
}

// SetDHCP writes a per-leg dnsmasq config into the container and (re)starts
// dnsmasq. A leg with DHCP off removes its config.
func (b lxcBackend) SetDHCP(vr VRouter, leg Leg) error {
	rel := "/etc/dnsmasq.d/vdx-" + leg.IfaceName + ".conf"
	if !leg.DHCP {
		_ = lxc.WriteRootfsFile(vr.ContainerName, vr.LxcPath, rel, []byte("# disabled\n"), 0o644)
	} else {
		if err := lxc.WriteRootfsFile(vr.ContainerName, vr.LxcPath, rel, []byte(DnsmasqConf(leg)), 0o644); err != nil {
			return err
		}
	}
	if st, _ := b.running(vr); !st {
		return nil
	}
	// Any dnsmasq.d fragment left enabled? If none are active, keep dnsmasq off.
	anyOn := false
	legsConf, _ := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 10*time.Second,
		"sh", "-c", "grep -l dhcp-range /etc/dnsmasq.d/*.conf 2>/dev/null | head -1")
	anyOn = strings.TrimSpace(legsConf) != ""
	if !anyOn {
		_, _ = lxc.AttachRun(vr.ContainerName, vr.LxcPath, 20*time.Second, "sh", "-c", "systemctl disable --now dnsmasq 2>/dev/null; true")
		return nil
	}
	if _, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 30*time.Second,
		"sh", "-c", "systemctl enable --now dnsmasq 2>/dev/null; systemctl restart dnsmasq"); err != nil {
		return fmt.Errorf("start dnsmasq in container (check the DHCP range, e.g. 10.60.0.100,10.60.0.200): %w", err)
	}
	return nil
}

func (b lxcBackend) Status(vr VRouter) (LiveStatus, error) {
	running, _ := b.running(vr)
	if !running {
		return LiveStatus{State: "stopped"}, nil
	}
	vt := func(cmd string) string {
		out, err := lxc.AttachRun(vr.ContainerName, vr.LxcPath, 15*time.Second, "vtysh", "-c", cmd)
		if err != nil {
			return ""
		}
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

func (lxcBackend) running(vr VRouter) (bool, error) {
	c, err := lxc.Info(vr.ContainerName, vr.LxcPath)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(c.State, "RUNNING"), nil
}

// legIface returns the conventional in-container interface name for a leg index.
func legIface(idx int) string { return "eth" + strconv.Itoa(idx) }
