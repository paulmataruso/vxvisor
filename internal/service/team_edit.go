package service

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"vdxclone/internal/netdrv"
)

// Editing a NIC team (bond) in place: add / remove member NICs, change the
// teaming mode or the load-balancing hash. Teams that host netplan owns — the
// management team above all — are refused with a pointer to the netplan file:
// a live change there would be undone at the next `netplan apply` or reboot,
// and a mistake on the management team cuts the admin connection.

// Host hooks, replaced by tests so nothing touches a real bond.
var (
	teamState   = netdrv.ReadBondState
	teamApply   = netdrv.ApplyBondEdit
	netplanGlob = "/etc/netplan/*.yaml"
	// mgmtNetplanDefault names the netplan file for the management vSwitch in
	// messages when no file under netplanGlob defines it.
	mgmtNetplanDefault = "/etc/netplan/90-vdx-vswitch0.yaml"
)

// TeamDetail is what the Edit-team modal needs about one team.
type TeamDetail struct {
	Mode    string   // form value: lacp | etherchannel | active-backup | balance-tlb | balance-alb
	Hash    string   // layer2 | layer2+3 | layer3+4 ("" when the mode doesn't hash)
	Members []string // member NICs
	Locked  string   // why it can't be edited here ("" = editable)
}

// friendlyBondMode maps a kernel bond mode to the form's value.
func friendlyBondMode(kmode string) string {
	switch kmode {
	case "802.3ad":
		return "lacp"
	case "balance-xor":
		return "etherchannel"
	}
	return kmode
}

// netplanDefines returns the netplan file that defines name under section
// ("bonds", "bridges", "ethernets"), or "" if none does.
func netplanDefines(section, name string) string {
	files, _ := filepath.Glob(netplanGlob)
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		in, secIndent, childIndent := false, 0, -1
		sc := bufio.NewScanner(fh)
		found := false
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), " \t\r")
			trim := strings.TrimSpace(line)
			if trim == "" || strings.HasPrefix(trim, "#") {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if trim == section+":" {
				in, secIndent, childIndent = true, indent, -1
				continue
			}
			if !in {
				continue
			}
			if indent <= secIndent {
				in = false
				continue
			}
			if childIndent < 0 {
				childIndent = indent
			}
			// A child key: "bond0:" or inline "eno1: {}".
			if key, _, ok := strings.Cut(trim, ":"); ok && indent == childIndent && strings.Trim(key, `"'`) == name {
				found = true
				break
			}
		}
		fh.Close()
		if found {
			return f
		}
	}
	return ""
}

// teamLock says why a team can't be edited here ("" = it can).
func (s *Service) teamLock(name string) string {
	mgmt := s.mgmtIface()
	isMgmt := mgmt != "" && (name == mgmt || s.isMgmtBridgeUplink(name))
	if !isMgmt && mgmt != "" {
		var n int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM net_vswitches WHERE bridge=? AND uplink=?`, mgmt, name).Scan(&n)
		isMgmt = n > 0
	}
	file := netplanDefines("bonds", name)
	switch {
	case isMgmt:
		if file == "" {
			file = mgmtNetplanDefault
		}
		return fmt.Sprintf("NIC team %q carries host management and is defined by the host's netplan (%s) — change it there, from the host console, with `netplan try` so a mistake rolls back instead of cutting the admin connection", name, file)
	case file != "":
		return fmt.Sprintf("NIC team %q is defined by the host's netplan (%s) — change it there and run `netplan apply`; a change made here would be undone at the next boot", name, file)
	}
	return ""
}

// TeamDetails describes every team the Networks page shows — the recorded ones
// plus any vSwitch uplink that is a kernel bond (e.g. the netplan management
// team) — for the Edit-team modal, with the reason a team is locked.
func (s *Service) TeamDetails(p *Principal) map[string]TeamDetail {
	out := map[string]TeamDetail{}
	if p == nil || !p.IsAdmin {
		return out
	}
	names := map[string]string{} // name -> recorded label
	if bonds, err := s.net.Bonds(); err == nil {
		for _, b := range bonds {
			names[b.Name] = b.Mode
		}
	}
	if vss, err := s.net.VSwitches(); err == nil {
		for _, v := range vss {
			if _, ok := names[v.Uplink]; !ok && v.Uplink != "" && netdrv.IsBond(v.Uplink) {
				names[v.Uplink] = ""
			}
		}
	}
	for name, label := range names {
		d := TeamDetail{Locked: s.teamLock(name)}
		if st, err := teamState(name); err == nil {
			d.Mode, d.Members = friendlyBondMode(st.Mode), st.Members
			if netdrv.HashingMode(st.Mode) {
				d.Hash = st.Hash
			}
		} else { // not present right now: fall back to the record ("lacp/layer3+4")
			mode, hash, _ := strings.Cut(label, "/")
			d.Mode, d.Hash = mode, hash
			if b, err := s.net.BondByName(name); err == nil {
				d.Members = b.Members
			}
		}
		out[name] = d
	}
	return out
}

// EditBond changes a team in place: its member NICs, its teaming mode and its
// load-balancing hash. New members must be free (guardNICFree — never the
// management, storage, trunk or another vSwitch's NIC). A mode change briefly
// takes the team down (a kernel rule); member and hash changes are live.
func (s *Service) EditBond(p *Principal, name, mode, hashPolicy string, members []string, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	var rec int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM net_bonds WHERE name=?`, name).Scan(&rec)
	if lock := s.teamLock(name); lock != "" {
		return fmt.Errorf("%s", lock)
	}
	if rec == 0 {
		return fmt.Errorf("unknown NIC team %q", name)
	}
	kmode, err := netdrv.BondMode(mode)
	if err != nil {
		return err
	}
	hp, err := netdrv.BondHashPolicy(hashPolicy)
	if err != nil {
		return err
	}
	var want []string
	for _, m := range members {
		if m = strings.TrimSpace(m); m == "" || slices.Contains(want, m) {
			continue
		}
		if !netdrv.ValidIfName(m) || m == name {
			return fmt.Errorf("%q can't be a member of NIC team %s", m, name)
		}
		if netdrv.IsBond(m) {
			return fmt.Errorf("%s is itself a NIC team — a team's members must be physical NICs", m)
		}
		want = append(want, m)
	}
	if len(want) == 0 {
		return fmt.Errorf("a NIC team needs at least one NIC — to remove the team, delete it instead")
	}
	cur, err := teamState(name)
	if err != nil {
		return fmt.Errorf("%v — delete the team and create it again", err)
	}
	var added []string
	for _, m := range want {
		if !slices.Contains(cur.Members, m) {
			added = append(added, m)
		}
	}
	if err := s.guardNICFree(added...); err != nil {
		return err
	}
	next := netdrv.BondState{Mode: kmode, Hash: cur.Hash, Members: want}
	if netdrv.HashingMode(kmode) {
		next.Hash = hp
	}
	if next.Mode == cur.Mode && next.Hash == cur.Hash && slices.Equal(slices.Sorted(slices.Values(next.Members)), slices.Sorted(slices.Values(cur.Members))) {
		return nil // nothing to change
	}
	if err := teamApply(name, cur, next); err != nil {
		return err
	}
	label := mode
	if netdrv.HashingMode(kmode) {
		label = mode + "/" + hp
	}
	if err := s.net.UpdateBond(name, label, want); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "bond.edit", "bond", name, ip, map[string]any{
		"mode": mode, "hash": next.Hash, "members": want,
		"was": map[string]any{"mode": cur.Mode, "hash": cur.Hash, "members": cur.Members},
	})
	return nil
}
