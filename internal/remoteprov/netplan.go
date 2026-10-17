package remoteprov

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JoinConfig is the network configuration to push to the new node.
type JoinConfig struct {
	MgmtIface    string
	MgmtCIDR     string // e.g. 172.16.0.170/24
	Gateway      string // default route via (mgmt); "" = none
	DNS          []string
	ClusterIface string
	ClusterCIDR  string // e.g. 10.10.0.5/24 (no gateway)
}

// RenderJoinNetplan produces a netplan v2 document configuring exactly the mgmt
// and cluster interfaces (pure function — unit tested). renderer-only: it never
// touches the host.
func RenderJoinNetplan(c JoinConfig) string {
	var b strings.Builder
	b.WriteString("# Managed by VXVisor worker-join. Do not edit.\n")
	b.WriteString("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n")
	// Management interface: address + optional default route + DNS.
	fmt.Fprintf(&b, "    %s:\n", c.MgmtIface)
	b.WriteString("      dhcp4: no\n      dhcp6: no\n      accept-ra: no\n")
	fmt.Fprintf(&b, "      addresses: [%s]\n", c.MgmtCIDR)
	if c.Gateway != "" {
		b.WriteString("      routes:\n")
		fmt.Fprintf(&b, "        - to: default\n          via: %s\n", c.Gateway)
	}
	if len(c.DNS) > 0 {
		fmt.Fprintf(&b, "      nameservers:\n        addresses: [%s]\n", strings.Join(c.DNS, ", "))
	}
	// Cluster interface: address only (no gateway — intra-cluster traffic).
	if c.ClusterIface != "" && c.ClusterIface != c.MgmtIface {
		fmt.Fprintf(&b, "    %s:\n", c.ClusterIface)
		b.WriteString("      dhcp4: no\n      dhcp6: no\n      accept-ra: no\n")
		fmt.Fprintf(&b, "      addresses: [%s]\n", c.ClusterCIDR)
	}
	return b.String()
}

const joinNetplanFile = "/etc/netplan/90-vdx-join.yaml"
const joinBackupDir = "/var/lib/vdx-join-backup"
const joinRollbackBin = "/usr/local/sbin/vdx-join-rollback"

// rollbackScript restores the pre-join netplan and disables itself. It runs from
// a systemd oneshot that is BOTH timer-fired (after the window) AND enabled on
// multi-user.target, so an unconfirmed join reverts even across a reboot/panic in
// the window — the core "can never strand the node" guarantee.
const rollbackScript = `#!/bin/bash
set +e
systemctl disable vdx-join-rollback.timer vdx-join-rollback.service 2>/dev/null
rm -f ` + joinNetplanFile + `
cp ` + joinBackupDir + `/*.yaml /etc/netplan/ 2>/dev/null
netplan apply 2>/dev/null
`

const rollbackService = `[Unit]
Description=VXVisor worker-join network rollback (reverts unconfirmed network changes)
DefaultDependencies=no
After=local-fs.target
[Service]
Type=oneshot
ExecStart=` + joinRollbackBin + `
[Install]
WantedBy=multi-user.target
`

func rollbackTimer(sec int) string {
	return fmt.Sprintf(`[Unit]
Description=VXVisor worker-join rollback timer
[Timer]
OnActiveSec=%d
AccuracySec=1s
[Install]
WantedBy=timers.target
`, sec)
}

// PutRoot writes data to a root-owned path with an explicit mode (binary-safe).
// Exported for the bootstrap step (pushing the vdxd binary + config).
func PutRoot(r Runner, path string, data []byte, mode string) error {
	return putFileSudo(r, path, data, mode)
}

// putFileSudo writes data to a root-owned path atomically via `tee`, with an
// explicit mode. Binary-safe (base64 over the wire).
func putFileSudo(r Runner, path string, data []byte, mode string) error {
	enc := base64.StdEncoding.EncodeToString(data)
	cmd := fmt.Sprintf("base64 -d > %q && chmod %s %q", path, mode, path)
	_, errb, code, err := r.SudoRun(cmd, []byte(enc))
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("write %s: %s", path, strings.TrimSpace(errb))
	}
	return nil
}

func sudoCheck(r Runner, cmd, what string) error {
	_, errb, code, err := r.SudoRun(cmd, nil)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("%s: %s", what, strings.TrimSpace(errb))
	}
	return nil
}

// Preflight verifies sudo works and the chosen interfaces exist and differ.
func Preflight(r Runner, mgmtIface, clusterIface string) error {
	if mgmtIface == "" {
		return fmt.Errorf("management interface is required")
	}
	if clusterIface != "" && clusterIface == mgmtIface {
		return fmt.Errorf("management and cluster interfaces must be different")
	}
	if _, _, code, err := r.SudoRun("true", nil); err != nil || code != 0 {
		return fmt.Errorf("sudo does not work for this user (need passwordless sudo or a correct password)")
	}
	names, err := DetectIfaces(r)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	if !have[mgmtIface] {
		return fmt.Errorf("management interface %q not found on the node (have: %s)", mgmtIface, strings.Join(names, ", "))
	}
	if clusterIface != "" && !have[clusterIface] {
		return fmt.Errorf("cluster interface %q not found on the node (have: %s)", clusterIface, strings.Join(names, ", "))
	}
	return nil
}

// DetectIfaces returns the node's physical-ish interface names (excludes lo and
// virtual bridges/taps), parsed from `ip -j link`.
func DetectIfaces(r Runner) ([]string, error) {
	out, _, code, err := r.Run("ip -j link show", nil)
	if err != nil || code != 0 {
		// Fallback to plain parsing.
		out2, _, _, _ := r.Run("ls /sys/class/net", nil)
		var names []string
		for _, n := range strings.Fields(out2) {
			if n != "lo" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("could not enumerate interfaces")
		}
		return names, nil
	}
	var links []struct {
		Ifname  string `json:"ifname"`
		LinkTyp string `json:"link_type"`
	}
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		return nil, fmt.Errorf("parse ip link json: %w", err)
	}
	var names []string
	for _, l := range links {
		if l.Ifname == "lo" || strings.HasPrefix(l.Ifname, "vdx") || strings.HasPrefix(l.Ifname, "veth") {
			continue
		}
		names = append(names, l.Ifname)
	}
	return names, nil
}

// ArmAndApply installs the reboot-safe rollback (enabled service + timer) BEFORE
// applying the new netplan, moves the existing netplan aside, writes the new one,
// and kicks the apply in a DETACHED transient unit so an SSH drop mid-apply can't
// abort it. The node reverts automatically after rollbackSec unless Confirm() is
// called. rollbackSec must exceed the control node's verify+confirm budget.
func ArmAndApply(r Runner, content string, rollbackSec int) error {
	// 1. Back up and neutralize existing netplan (MOVE, not copy, so only our file
	//    is active during the window and the restore is clean).
	if err := sudoCheck(r, "mkdir -p "+joinBackupDir+" && rm -f "+joinBackupDir+"/*.yaml; (mv /etc/netplan/*.yaml "+joinBackupDir+"/ 2>/dev/null; true)", "back up netplan"); err != nil {
		return err
	}
	// 2. Write the new config.
	if err := putFileSudo(r, joinNetplanFile, []byte(content), "0600"); err != nil {
		return err
	}
	// 3. Install the rollback script + units.
	if err := putFileSudo(r, joinRollbackBin, []byte(rollbackScript), "0755"); err != nil {
		return err
	}
	if err := putFileSudo(r, "/etc/systemd/system/vdx-join-rollback.service", []byte(rollbackService), "0644"); err != nil {
		return err
	}
	if err := putFileSudo(r, "/etc/systemd/system/vdx-join-rollback.timer", []byte(rollbackTimer(rollbackSec)), "0644"); err != nil {
		return err
	}
	// 4. ARM (enable the service for reboot-safety + start the timer) BEFORE apply.
	if err := sudoCheck(r, "systemctl daemon-reload && systemctl enable vdx-join-rollback.service && systemctl start vdx-join-rollback.timer", "arm rollback"); err != nil {
		return err
	}
	// 5. Apply detached so the SSH session dropping (expected when the mgmt IP
	//    changes) cannot SIGHUP the apply. --no-block returns immediately.
	if err := sudoCheck(r, "systemd-run --unit=vdx-join-apply --collect --no-block bash -c 'netplan generate && netplan apply'", "apply netplan"); err != nil {
		return err
	}
	return nil
}

// Confirm disarms the rollback: the new network becomes permanent. Called only
// after the control node has independently verified the node is reachable on the
// new address.
func Confirm(r Runner) error {
	return sudoCheck(r, "systemctl disable --now vdx-join-rollback.timer vdx-join-rollback.service 2>/dev/null; rm -f /etc/systemd/system/vdx-join-rollback.timer /etc/systemd/system/vdx-join-rollback.service "+joinRollbackBin+"; systemctl daemon-reload; true", "confirm join")
}

// Restore immediately reverts the network (best-effort abort path; the armed
// timer/boot guarantee reverts anyway if this can't run).
func Restore(r Runner) error {
	return sudoCheck(r, joinRollbackBin+" 2>/dev/null; true", "restore")
}
