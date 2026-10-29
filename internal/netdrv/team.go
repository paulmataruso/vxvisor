package netdrv

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Editing a NIC team (bond) in place, and vSwitch MTU (jumbo frames).

// BondState is a team's live configuration.
type BondState struct {
	Mode    string   // kernel mode: 802.3ad, balance-xor, active-backup, balance-tlb, balance-alb
	Hash    string   // xmit_hash_policy (layer2, layer2+3, layer3+4, ...)
	Members []string // enslaved NICs
}

// HashingMode reports whether a kernel bond mode uses xmit_hash_policy.
func HashingMode(kmode string) bool { return kmode == "802.3ad" || kmode == "balance-xor" }

// ReadBondState reads a bond's live mode, hash policy and members from sysfs.
func ReadBondState(name string) (BondState, error) {
	if !ValidIfName(name) || !IsBond(name) {
		return BondState{}, fmt.Errorf("NIC team %s isn't present on this host", name)
	}
	dir := filepath.Join("/sys/class/net", name, "bonding")
	field := func(f string) string { // "balance-alb 6" -> "balance-alb"
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if fs := strings.Fields(string(b)); len(fs) > 0 {
			return fs[0]
		}
		return ""
	}
	b, _ := os.ReadFile(filepath.Join(dir, "slaves"))
	return BondState{Mode: field("mode"), Hash: field("xmit_hash_policy"), Members: strings.Fields(string(b))}, nil
}

// enslavePlan: a NIC must be down and address-less before it can join a bond;
// the bond brings it up itself.
func enslavePlan(nic, bond string) [][]string {
	return [][]string{
		{"ip", "addr", "flush", "dev", nic},
		{"ip", "link", "set", nic, "down"},
		{"ip", "link", "set", nic, "master", bond},
	}
}

// RenderBondEditPlan returns the ip commands that take bond `name` from cur to
// want. The kernel only changes a bond's mode while it is down with no members,
// so a mode change releases every member, switches mode and re-enslaves (a short
// outage on that team). Members and the hash policy alone change live, adding
// new members before releasing old ones so the team never drops to zero links.
// Pure, so the plan is reviewable and unit-tested.
func RenderBondEditPlan(name string, cur, want BondState) [][]string {
	var plan [][]string
	if cur.Mode != want.Mode {
		plan = append(plan, []string{"ip", "link", "set", name, "down"})
		for _, m := range cur.Members {
			plan = append(plan, []string{"ip", "link", "set", m, "nomaster"})
		}
		args := []string{"ip", "link", "set", name, "type", "bond", "mode", want.Mode}
		switch want.Mode {
		case "802.3ad":
			args = append(args, "lacp_rate", "fast", "xmit_hash_policy", want.Hash)
		case "balance-xor":
			args = append(args, "xmit_hash_policy", want.Hash)
		}
		plan = append(plan, args)
		for _, m := range want.Members {
			plan = append(plan, enslavePlan(m, name)...)
		}
		return append(plan, []string{"ip", "link", "set", name, "up"})
	}
	if HashingMode(want.Mode) && want.Hash != "" && want.Hash != cur.Hash {
		plan = append(plan, []string{"ip", "link", "set", name, "type", "bond", "xmit_hash_policy", want.Hash})
	}
	have := map[string]bool{}
	for _, m := range cur.Members {
		have[m] = true
	}
	keep := map[string]bool{}
	for _, m := range want.Members {
		keep[m] = true
		if !have[m] {
			plan = append(plan, enslavePlan(m, name)...)
		}
	}
	for _, m := range cur.Members {
		if !keep[m] {
			plan = append(plan, []string{"ip", "link", "set", m, "nomaster"})
		}
	}
	return plan
}

// ApplyBondEdit runs the edit plan. If a step fails it puts the team back the
// way it was (best effort) and says whether that worked.
func ApplyBondEdit(name string, cur, want BondState) error {
	for _, c := range RenderBondEditPlan(name, cur, want) {
		if err := run(c...); err != nil {
			now, rerr := ReadBondState(name)
			if rerr == nil {
				for _, r := range RenderBondEditPlan(name, now, cur) {
					if e := run(r...); e != nil {
						rerr = e
						break
					}
				}
			}
			if rerr != nil {
				return fmt.Errorf("%v (restoring the previous team also failed: %v — check it on the host with: cat /proc/net/bonding/%s)", err, rerr, name)
			}
			return fmt.Errorf("%v (the team was put back as it was)", err)
		}
	}
	return nil
}

// UpdateBond records a team's new mode label and members.
func (s *Store) UpdateBond(name, mode string, members []string) error {
	_, err := s.db.Exec(`UPDATE net_bonds SET mode=?,members=? WHERE name=?`, mode, JoinMembers(members), name)
	return err
}

// ---- MTU -------------------------------------------------------------------

// IfaceMTU reads an interface's MTU (0 if unknown).
func IfaceMTU(name string) int {
	if !ValidIfName(name) {
		return 0
	}
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "mtu"))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// bridgePorts lists the devices enslaved to a bridge.
func bridgePorts(bridge string) []string {
	ents, err := os.ReadDir(filepath.Join("/sys/class/net", bridge, "brif"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// FollowBridgeMTU gives a newly attached VM tap its bridge's MTU, so a VM on a
// jumbo-frame vSwitch can receive full-size frames. Best effort.
func FollowBridgeMTU(tap, bridge string) {
	if m := IfaceMTU(bridge); m > 0 && m != IfaceMTU(tap) {
		_ = run("ip", "link", "set", tap, "mtu", strconv.Itoa(m))
	}
}

// RenderMTUPlan orders an MTU change on a vSwitch: when raising, the physical
// adapter (a team passes it on to its members) and the other ports go first so
// the bridge never forwards frames a port can't carry; when lowering, the
// bridge goes first. ports are the bridge's other ports (VM taps).
func RenderMTUPlan(bridge, uplink string, ports []string, from, to int) [][]string {
	m := strconv.Itoa(to)
	var lower [][]string
	if uplink != "" {
		lower = append(lower, []string{"ip", "link", "set", uplink, "mtu", m})
	}
	for _, p := range ports {
		if p != uplink {
			lower = append(lower, []string{"ip", "link", "set", p, "mtu", m})
		}
	}
	br := []string{"ip", "link", "set", bridge, "mtu", m}
	if to < from {
		return append([][]string{br}, lower...)
	}
	return append(lower, br)
}

// SetVSwitchMTU sets a vSwitch's MTU: its physical adapter, its bridge, and the
// VM taps on it. The physical adapter goes first when raising, so a NIC that
// can't do jumbo frames refuses before anything else changes.
func SetVSwitchMTU(bridge, uplink string, mtu int) error {
	if !ValidIfName(bridge) || (uplink != "" && !ValidIfName(uplink)) {
		return fmt.Errorf("invalid vSwitch device name")
	}
	if mtu < 1280 || mtu > 9216 {
		return fmt.Errorf("MTU %d is out of range — use 1280–9216", mtu)
	}
	if !ifaceExists(bridge) {
		return fmt.Errorf("the vSwitch's bridge %s isn't present on this host right now", bridge)
	}
	from := IfaceMTU(bridge)
	for i, c := range RenderMTUPlan(bridge, uplink, bridgePorts(bridge), from, mtu) {
		if err := run(c...); err != nil {
			if i == 0 {
				return err // nothing changed yet
			}
			return fmt.Errorf("%v (the MTU is now partly changed — set it again, or back to %d)", err, from)
		}
	}
	return nil
}

// SetVSwitchMTUValue records a vSwitch's MTU (0 = leave the kernel default).
func (s *Store) SetVSwitchMTUValue(name string, mtu int) error {
	_, err := s.db.Exec(`UPDATE net_vswitches SET mtu=? WHERE name=?`, mtu, name)
	return err
}

// VSwitchMTUs maps each vSwitch name to its recorded MTU (0 = kernel default),
// for the page and for re-applying after a reboot.
func (s *Store) VSwitchMTUs() map[string]int {
	out := map[string]int{}
	rows, err := s.db.Query(`SELECT name,mtu FROM net_vswitches`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var m int
		if rows.Scan(&n, &m) == nil {
			out[n] = m
		}
	}
	return out
}
