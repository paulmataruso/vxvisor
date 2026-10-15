package sharedstg

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// VXLAN storage overlay. When the cluster's storage server is not on the same L2
// segment as the hosts (common in nested/virtual labs, or when storage lives on
// an isolated fabric), a VXLAN overlay gives every node a shared L2 for storage
// traffic that rides OVER the existing (e.g. management) underlay as UDP. The
// overlay interface then becomes the dedicated storage interface; iSCSI/NFS/
// CIFS/Ceph targets live on the overlay subnet.
//
// This is not the management NIC (guardMgmt only refuses enslaving/assigning the
// mgmt NIC itself); using it merely as the UDP underlay transport is fine.

// VXLANSpec describes a storage overlay interface.
type VXLANSpec struct {
	Name        string   // overlay iface name, e.g. "vxlan-stor"
	Dev         string   // underlay device the UDP rides over, e.g. the mgmt NIC
	Local       string   // underlay local IP (source of the VXLAN UDP)
	OverlayCIDR string   // this node's overlay address, e.g. "10.10.4.11/24"
	VNI         int      // VXLAN network identifier
	DstPort     int      // UDP dest port (IANA VXLAN = 4789)
	MTU         int      // overlay MTU (underlay MTU minus ~50; commonly 1450)
	Peers       []string // peer underlay IPs for BUM flooding (unicast head-end)
}

func ipBin() string {
	for _, p := range []string{"/usr/sbin/ip", "/sbin/ip", "/bin/ip"} {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("ip"); err == nil {
		return p
	}
	return "/sbin/ip"
}

func bridgeBin() string {
	for _, p := range []string{"/usr/sbin/bridge", "/sbin/bridge"} {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("bridge"); err == nil {
		return p
	}
	return "/sbin/bridge"
}

// VXLANExists reports whether the named link is present.
func VXLANExists(name string) bool {
	_, err := run(5*time.Second, ipBin(), "link", "show", name)
	return err == nil
}

// VXLANUp (re)creates the overlay interface at runtime (idempotent: it deletes
// any existing link of the same name first). Persistence across reboot is the
// systemd unit the service layer installs; this is the immediate bring-up.
func VXLANUp(sp VXLANSpec) error {
	ip := ipBin()
	_, _ = run(5*time.Second, ip, "link", "del", sp.Name) // ignore if absent
	if _, err := run(10*time.Second, ip, "link", "add", sp.Name, "type", "vxlan",
		"id", fmt.Sprint(sp.VNI), "local", sp.Local, "dstport", fmt.Sprint(sp.DstPort), "dev", sp.Dev); err != nil {
		return fmt.Errorf("create vxlan: %w", err)
	}
	if sp.MTU > 0 {
		_, _ = run(5*time.Second, ip, "link", "set", sp.Name, "mtu", fmt.Sprint(sp.MTU))
	}
	if sp.OverlayCIDR != "" {
		if _, err := run(5*time.Second, ip, "addr", "add", sp.OverlayCIDR, "dev", sp.Name); err != nil {
			return fmt.Errorf("assign overlay address: %w", err)
		}
	}
	if _, err := run(5*time.Second, ip, "link", "set", sp.Name, "up"); err != nil {
		return fmt.Errorf("bring up overlay: %w", err)
	}
	br := bridgeBin()
	for _, peer := range sp.Peers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		// head-end replication: flood BUM traffic to each peer's underlay IP.
		if _, err := run(5*time.Second, br, "fdb", "append", "00:00:00:00:00:00", "dev", sp.Name, "dst", peer); err != nil {
			return fmt.Errorf("add fdb peer %s: %w", peer, err)
		}
	}
	return nil
}

// VXLANDown removes the overlay interface.
func VXLANDown(name string) error {
	_, err := run(5*time.Second, ipBin(), "link", "del", name)
	return err
}

// VXLANUnit renders a systemd oneshot unit that recreates the overlay on boot
// (and tears it down on stop), so the overlay survives a reboot. Multiple
// ExecStart lines run in order; a leading '-' tolerates the pre-clean failing.
func VXLANUnit(sp VXLANSpec) string {
	ip, br := ipBin(), bridgeBin()
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=VXVisor storage overlay %s\nAfter=network-online.target\nWants=network-online.target\n\n", sp.Name)
	b.WriteString("[Service]\nType=oneshot\nRemainAfterExit=yes\n")
	fmt.Fprintf(&b, "ExecStart=-%s link del %s\n", ip, sp.Name)
	fmt.Fprintf(&b, "ExecStart=%s link add %s type vxlan id %d local %s dstport %d dev %s\n", ip, sp.Name, sp.VNI, sp.Local, sp.DstPort, sp.Dev)
	if sp.MTU > 0 {
		fmt.Fprintf(&b, "ExecStart=%s link set %s mtu %d\n", ip, sp.Name, sp.MTU)
	}
	if sp.OverlayCIDR != "" {
		fmt.Fprintf(&b, "ExecStart=%s addr add %s dev %s\n", ip, sp.OverlayCIDR, sp.Name)
	}
	fmt.Fprintf(&b, "ExecStart=%s link set %s up\n", ip, sp.Name)
	for _, peer := range sp.Peers {
		if peer = strings.TrimSpace(peer); peer != "" {
			fmt.Fprintf(&b, "ExecStart=%s fdb append 00:00:00:00:00:00 dev %s dst %s\n", br, sp.Name, peer)
		}
	}
	fmt.Fprintf(&b, "ExecStop=-%s link del %s\n\n", ip, sp.Name)
	b.WriteString("[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}
