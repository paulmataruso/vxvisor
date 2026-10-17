package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// This file holds the netplan-based reconfiguration used ONLY for the management
// vSwitch, where restructuring has to be persistent (survive reboot) AND safe
// (never strand the admin IP). Non-management vSwitches are reconfigured live via
// netdrv (ip link), which is ephemeral — matching how they're created.

const mgmtNetplanFile = "/etc/netplan/90-vdx-vswitch0.yaml"

// execOut runs a command and returns trimmed stdout (empty on error).
func execOut(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// bridgeIPv4Config reads a live bridge's MAC, global IPv4 addresses (CIDR), the
// default-route gateway reachable through it, and the resolvers — enough to
// reproduce its static config in a regenerated netplan.
func bridgeIPv4Config(bridge string) (mac string, v4 []string, gw string, dns []string) {
	mac = strings.TrimSpace(readFileTrim("/sys/class/net/" + bridge + "/address"))
	for _, ln := range strings.Split(execOut("ip", "-o", "-4", "addr", "show", "dev", bridge), "\n") {
		f := strings.Fields(ln)
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "inet" {
				v4 = append(v4, f[i+1])
			}
		}
	}
	for _, ln := range strings.Split(execOut("ip", "-o", "-4", "route", "show", "default"), "\n") {
		f := strings.Fields(ln)
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "via" {
				gw = f[i+1]
				break
			}
		}
		if gw != "" {
			break
		}
	}
	if d := execOut("resolvectl", "dns", bridge); d != "" {
		// "Link N (br): 1.2.3.4 5.6.7.8"
		if i := strings.Index(d, ":"); i >= 0 {
			for _, s := range strings.Fields(d[i+1:]) {
				dns = append(dns, s)
			}
		}
	}
	if len(dns) == 0 {
		for _, ln := range strings.Split(readFileTrim("/etc/resolv.conf"), "\n") {
			if strings.HasPrefix(ln, "nameserver ") {
				dns = append(dns, strings.TrimSpace(strings.TrimPrefix(ln, "nameserver")))
			}
		}
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}
	return
}

func readFileTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// buildMgmtBondNetplan regenerates the management netplan so the bridge's uplink
// is a bond over `members` (teaming), preserving the bridge's exact static IPv4
// config + MAC so the admin IP never moves.
func buildMgmtBondNetplan(bridge, mac, bondName, kmode, hashPolicy string, members, v4, dns []string, gw string) string {
	var b strings.Builder
	b.WriteString("# Managed by VXVisor — management vSwitch with bonded uplink.\n")
	b.WriteString("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n")
	for _, m := range members {
		// A bond member carries no L3 config. Explicitly disable dhcp AND accept-ra
		// so this definition cleanly OVERRIDES the base installer config (which may
		// leave e.g. `accept-ra: true` on a NIC) when netplan merges the two files —
		// a leftover RA/dhcp on a bond member otherwise fails the apply.
		fmt.Fprintf(&b, "    %s:\n      dhcp4: no\n      dhcp6: no\n      accept-ra: no\n", m)
	}
	b.WriteString("  bonds:\n")
	fmt.Fprintf(&b, "    %s:\n      interfaces: [%s]\n", bondName, strings.Join(members, ", "))
	if mac != "" {
		fmt.Fprintf(&b, "      macaddress: \"%s\"\n", mac)
	}
	b.WriteString("      parameters:\n")
	fmt.Fprintf(&b, "        mode: %s\n", kmode)
	b.WriteString("        mii-monitor-interval: 100\n")
	if kmode == "802.3ad" || kmode == "balance-xor" {
		fmt.Fprintf(&b, "        transmit-hash-policy: %s\n", hashPolicy)
	}
	if kmode == "802.3ad" {
		b.WriteString("        lacp-rate: fast\n")
	}
	b.WriteString("  bridges:\n")
	fmt.Fprintf(&b, "    %s:\n      interfaces: [%s]\n", bridge, bondName)
	if mac != "" {
		fmt.Fprintf(&b, "      macaddress: \"%s\"\n", mac)
	}
	b.WriteString("      dhcp4: no\n      dhcp6: no\n      accept-ra: yes\n")
	if len(v4) > 0 {
		b.WriteString("      addresses:\n")
		for _, a := range v4 {
			fmt.Fprintf(&b, "        - %s\n", a)
		}
	}
	if gw != "" {
		b.WriteString("      routes:\n")
		fmt.Fprintf(&b, "        - {to: default, via: %s}\n", gw)
	}
	if len(dns) > 0 {
		b.WriteString("      nameservers:\n        addresses:\n")
		for _, d := range dns {
			fmt.Fprintf(&b, "          - %s\n", d)
		}
	}
	b.WriteString("      parameters:\n        stp: false\n        forward-delay: 0\n")
	return b.String()
}

// applyNetplanWithRollback writes `content` to the mgmt netplan file and applies
// it with the SAME safety net as the install-time conversion: a detached watchdog
// restores the backup unless we confirm success within the window, and we verify
// synchronously and restore immediately on failure. So a bad apply can never
// strand the management IP, even if vdxd itself is killed mid-apply.
func applyNetplanWithRollback(content string, verify func() bool) error {
	backup := fmt.Sprintf("/var/lib/vdxclone/netplan-backup.%d", time.Now().Unix())
	if err := os.MkdirAll(backup, 0o750); err != nil {
		return err
	}
	// Back up every current netplan file.
	entries, _ := filepath.Glob("/etc/netplan/*.yaml")
	for _, f := range entries {
		if b, err := os.ReadFile(f); err == nil {
			_ = os.WriteFile(filepath.Join(backup, filepath.Base(f)), b, 0o600)
		}
	}
	restore := func() {
		_ = os.Remove(mgmtNetplanFile)
		if bs, _ := filepath.Glob(backup + "/*.yaml"); bs != nil {
			for _, f := range bs {
				if b, err := os.ReadFile(f); err == nil {
					_ = os.WriteFile(filepath.Join("/etc/netplan", filepath.Base(f)), b, 0o600)
				}
			}
		}
		_ = exec.Command("netplan", "apply").Run()
	}

	if err := os.WriteFile(mgmtNetplanFile, []byte(content), 0o600); err != nil {
		return err
	}
	if err := exec.Command("netplan", "generate").Run(); err != nil {
		restore()
		return fmt.Errorf("netplan generate failed; reverted: %w", err)
	}
	// Detached watchdog: reverts unless /run/vdx-netok appears within 180s. Survives
	// even if vdxd dies during the apply.
	_ = os.Remove("/run/vdx-netok")
	wd := exec.Command("setsid", "bash", "-c",
		fmt.Sprintf("sleep 180; [ -f /run/vdx-netok ] && exit 0; rm -f %s; cp %s/*.yaml /etc/netplan/ 2>/dev/null; netplan apply",
			mgmtNetplanFile, backup))
	_ = wd.Start()
	if wd.Process != nil {
		_ = wd.Process.Release()
	}

	_ = exec.Command("netplan", "apply").Run()

	ok := false
	for i := 0; i < 20; i++ {
		if verify() {
			ok = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !ok {
		restore()
		return fmt.Errorf("management IP did not come up on the bonded uplink; reverted")
	}
	// Confirm: disarm the watchdog.
	_ = os.WriteFile("/run/vdx-netok", []byte("1"), 0o644)
	return nil
}
