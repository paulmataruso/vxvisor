package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// This file holds the netplan-based reconfiguration used ONLY for the management
// vSwitch, where restructuring has to be persistent (survive reboot) AND safe
// (never strand the admin IP). Non-management vSwitches are reconfigured live via
// netdrv (ip link), which is ephemeral — matching how they're created.
//
// The management bridge's netplan definition is EDITED IN PLACE, never
// regenerated from live state: only its uplink changes (the bridge's interfaces
// list, the new bond, its members' stanzas). Every other key the bridge has —
// static IPv4/IPv6 addresses, DHCP, routes, nameservers, accept-ra, MTU — is kept
// as written. Before anything is applied the result is checked three ways: the
// bridge stanza is unchanged apart from its uplink, every address the bridge
// holds now is still configured for it, and `netplan generate` on a staged copy
// of the config renders that address for the bridge. Only then is it applied,
// under a rollback watchdog that restores the previous files unless the
// addresses (and the default route, if it ran through the bridge) come back.

// Where netplan reads its config. netplanDir is the one vdxd edits; the others
// are only staged for the dry-run generate. Swapped in tests.
var (
	netplanDir      = "/etc/netplan"
	netplanReadDirs = []string{"/lib/netplan", "/etc/netplan", "/run/netplan"}
)

// Host hooks, swapped in tests.
var (
	liveBridgeAddrs = readLiveAddrs
	netplanGenerate = func(rootDir string) error {
		out, err := exec.Command("netplan", "generate", "--root-dir", rootDir).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
)

func readFileTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ---- yaml.Node helpers ----------------------------------------------------

func yamlRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

// yamlGet returns the value of key in mapping m (nil if absent / not a mapping).
func yamlGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// yamlSet sets key in mapping m to v, replacing an existing value in place.
func yamlSet(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

// yamlMap returns the mapping under key in m, creating it if absent.
func yamlMap(m *yaml.Node, key string) *yaml.Node {
	if v := yamlGet(m, key); v != nil {
		return v
	}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	yamlSet(m, key, v)
	return v
}

func yamlStr(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
func yamlBool(b bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(b)}
}
func yamlInt(n int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(n)}
}
func yamlQuoted(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s, Style: yaml.DoubleQuotedStyle}
}

func yamlFlowSeq(items []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, it := range items {
		n.Content = append(n.Content, yamlStr(it))
	}
	return n
}

// yamlTrue: netplan's (YAML 1.1) spellings of true.
func yamlTrue(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	switch strings.ToLower(n.Value) {
	case "true", "yes", "on", "y":
		return true
	}
	return false
}

// yamlEncode renders one node (for comparing stanzas key by key).
func yamlEncode(n *yaml.Node) string {
	b, err := yaml.Marshal(n)
	if err != nil {
		return "\x00unencodable"
	}
	return string(b)
}

// ---- locating the management bridge's definition ---------------------------

// netplanFiles lists dir's netplan files in netplan's (lexical) order.
func netplanFiles(dir string) []string {
	fs, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	slices.Sort(fs)
	return fs
}

// netplanNetwork parses a netplan file and returns its document and "network"
// mapping (nil when the file has none).
func netplanNetwork(src []byte) (*yaml.Node, *yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, nil, err
	}
	nw := yamlGet(yamlRoot(&doc), "network")
	if nw != nil && nw.Kind != yaml.MappingNode {
		nw = nil
	}
	return &doc, nw, nil
}

// findNetplanBridge returns the one file in dir that defines bridge, and its
// contents. No definition, several, or an unparseable file is an error: vdxd
// only edits a definition it can see whole.
func findNetplanBridge(dir, bridge string) (string, []byte, error) {
	var found []string
	var src []byte
	for _, f := range netplanFiles(dir) {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", nil, fmt.Errorf("read %s: %w", f, err)
		}
		_, nw, err := netplanNetwork(b)
		if err != nil {
			return "", nil, fmt.Errorf("can't parse %s (%v) — fix it before changing the management vSwitch", f, err)
		}
		if yamlGet(yamlGet(nw, "bridges"), bridge) != nil {
			found = append(found, f)
			src = b
		}
	}
	switch len(found) {
	case 0:
		return "", nil, fmt.Errorf("the management vSwitch %s isn't defined in %s — change its uplink by hand (vdxd only edits a netplan-defined management bridge)", bridge, dir)
	case 1:
		return found[0], src, nil
	default:
		return "", nil, fmt.Errorf("the management vSwitch %s is defined in several netplan files (%s) — merge them into one first", bridge, strings.Join(found, ", "))
	}
}

// netplanDefinedIfaces maps every device netplan defines (ethernets, bonds,
// bridges, vlans, …) to the file defining it. Those are netplan's: vdxd never
// re-creates, re-enslaves or deletes them.
func netplanDefinedIfaces() map[string]string {
	out := map[string]string{}
	for _, dir := range netplanReadDirs {
		for _, f := range netplanFiles(dir) {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			_, nw, err := netplanNetwork(b)
			if err != nil || nw == nil {
				continue
			}
			for i := 0; i+1 < len(nw.Content); i += 2 {
				if sec := nw.Content[i+1]; sec.Kind == yaml.MappingNode {
					for j := 0; j+1 < len(sec.Content); j += 2 {
						out[sec.Content[j].Value] = f
					}
				}
			}
		}
	}
	return out
}

// ---- editing --------------------------------------------------------------

// editNetplanBridge applies edit to a netplan file's "network" mapping and
// returns the new file. The bridge's stanza must come out with every key it had
// unchanged except its interfaces (its uplink); the only key edit may add is a
// macaddress it lacked.
func editNetplanBridge(src []byte, bridge string, edit func(network *yaml.Node) error) ([]byte, error) {
	doc, nw, err := netplanNetwork(src)
	if err != nil {
		return nil, err
	}
	br := yamlGet(yamlGet(nw, "bridges"), bridge)
	if br == nil || br.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("bridge %s isn't defined in this netplan file", bridge)
	}
	before := map[string]string{}
	for i := 0; i+1 < len(br.Content); i += 2 {
		before[br.Content[i].Value] = yamlEncode(br.Content[i+1])
	}
	if err := edit(nw); err != nil {
		return nil, err
	}
	br = yamlGet(yamlGet(nw, "bridges"), bridge)
	if br == nil {
		return nil, fmt.Errorf("the edit removed bridge %s — not applied", bridge)
	}
	after := map[string]string{}
	for i := 0; i+1 < len(br.Content); i += 2 {
		after[br.Content[i].Value] = yamlEncode(br.Content[i+1])
	}
	for k, v := range before {
		if k != "interfaces" && after[k] != v {
			return nil, fmt.Errorf("the edit would change %s's %q setting — not applied", bridge, k)
		}
	}
	for k := range after {
		if _, had := before[k]; !had && k != "interfaces" && k != "macaddress" {
			return nil, fmt.Errorf("the edit would add %q to %s — not applied", k, bridge)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

// netplanTeamUplink is the edit that moves bridge's uplink onto a new bond:
// bonds.<bond> over members (the old uplink + the extras), each member an L3-
// less ethernet, and the bond in place of the old uplink in the bridge's
// interfaces. The bond and the bridge keep the bridge's current MAC so a DHCP
// lease (and the admin IP) doesn't move.
func netplanTeamUplink(nw *yaml.Node, bridge, uplink, mac, bond, kmode, hashPolicy string, members []string) error {
	br := yamlGet(yamlGet(nw, "bridges"), bridge)
	if yamlGet(yamlGet(nw, "bonds"), bond) != nil {
		return fmt.Errorf("bond %s is already defined in netplan — pick another name", bond)
	}
	// Bridge interfaces: the bond takes the old uplink's place; any other port
	// stays. The recorded uplink must be one of them, or the file and vdxd's
	// record disagree and nothing is changed.
	var ifaces []string
	if seq := yamlGet(br, "interfaces"); seq != nil {
		if seq.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s's netplan interfaces isn't a list — fix the file first", bridge)
		}
		for _, it := range seq.Content {
			ifaces = append(ifaces, it.Value)
		}
	}
	if !slices.Contains(ifaces, uplink) {
		return fmt.Errorf("%s's netplan interfaces (%s) don't include its uplink %s — fix the netplan file first", bridge, strings.Join(ifaces, ", "), uplink)
	}
	var newIfaces []string
	for _, it := range ifaces {
		switch {
		case it == uplink:
			newIfaces = append(newIfaces, bond)
		case slices.Contains(members, it):
			// another member already on the bridge: it moves into the bond
		default:
			newIfaces = append(newIfaces, it)
		}
	}
	// Members carry no L3 config. dhcp/accept-ra are switched off explicitly so
	// this file overrides a base installer file (e.g. accept-ra: true on a NIC)
	// when netplan merges them; an address or route here can't be silently
	// dropped, so it's refused instead.
	eth := yamlMap(nw, "ethernets")
	for _, m := range members {
		e := yamlMap(eth, m)
		for _, k := range []string{"addresses", "routes", "gateway4", "gateway6", "nameservers"} {
			if yamlGet(e, k) != nil {
				return fmt.Errorf("%s has %s in netplan — a team member can't carry IP config; remove it first", m, k)
			}
		}
		yamlSet(e, "dhcp4", yamlBool(false))
		yamlSet(e, "dhcp6", yamlBool(false))
		yamlSet(e, "accept-ra", yamlBool(false))
	}
	b := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	yamlSet(b, "interfaces", yamlFlowSeq(members))
	if mac != "" {
		yamlSet(b, "macaddress", yamlQuoted(mac))
	}
	params := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	yamlSet(params, "mode", yamlStr(kmode))
	yamlSet(params, "mii-monitor-interval", yamlInt(100))
	if kmode == "802.3ad" || kmode == "balance-xor" {
		yamlSet(params, "transmit-hash-policy", yamlStr(hashPolicy))
	}
	if kmode == "802.3ad" {
		yamlSet(params, "lacp-rate", yamlStr("fast"))
	}
	yamlSet(b, "parameters", params)
	yamlSet(yamlMap(nw, "bonds"), bond, b)

	yamlSet(br, "interfaces", yamlFlowSeq(newIfaces))
	if mac != "" && yamlGet(br, "macaddress") == nil {
		yamlSet(br, "macaddress", yamlQuoted(mac))
	}
	return nil
}

// ---- address checks -------------------------------------------------------

// liveAddr is one global address an interface holds right now.
type liveAddr struct {
	IP      net.IP
	Prefix  int
	Dynamic bool // DHCP / SLAAC-learned (expires) rather than static
}

func (a liveAddr) String() string { return fmt.Sprintf("%s/%d", a.IP, a.Prefix) }

// readLiveAddrs reads an interface's global addresses (`ip -j addr show dev`).
func readLiveAddrs(dev string) ([]liveAddr, error) {
	out, err := exec.Command("ip", "-j", "addr", "show", "dev", dev).Output()
	if err != nil {
		return nil, fmt.Errorf("ip addr show dev %s: %w", dev, err)
	}
	return parseLiveAddrs(out)
}

func parseLiveAddrs(js []byte) ([]liveAddr, error) {
	var links []struct {
		AddrInfo []struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
			Dynamic   bool   `json:"dynamic"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(js, &links); err != nil {
		return nil, err
	}
	var out []liveAddr
	for _, l := range links {
		for _, a := range l.AddrInfo {
			ip := net.ParseIP(a.Local)
			if ip == nil || a.Scope != "global" {
				continue
			}
			out = append(out, liveAddr{IP: ip, Prefix: a.PrefixLen, Dynamic: a.Dynamic})
		}
	}
	return out, nil
}

// mustKeepAddrs are the live addresses a rewrite has to bring back: every
// static one, and DHCP-learned IPv4 (the admin IP is often a lease). SLAAC /
// DHCPv6 addresses come back on their own and aren't required.
func mustKeepAddrs(live []liveAddr) []liveAddr {
	var out []liveAddr
	for _, a := range live {
		if !a.Dynamic || a.IP.To4() != nil {
			out = append(out, a)
		}
	}
	return out
}

// netplanKeepsAddrs checks a netplan file still configures every address in
// keep for bridge: a static one in its addresses list, a DHCP-learned IPv4 by
// dhcp4 (or the same address listed statically).
func netplanKeepsAddrs(src []byte, bridge, file string, keep []liveAddr) error {
	_, nw, err := netplanNetwork(src)
	if err != nil {
		return err
	}
	br := yamlGet(yamlGet(nw, "bridges"), bridge)
	configured := map[string]bool{}
	if seq := yamlGet(br, "addresses"); seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			v := it.Value
			if it.Kind == yaml.MappingNode && len(it.Content) > 0 { // {"10.0.0.5/24": {lifetime: 0}}
				v = it.Content[0].Value
			}
			if ip, _, err := net.ParseCIDR(v); err == nil {
				configured[ip.String()] = true
			}
		}
	}
	dhcp4 := yamlTrue(yamlGet(br, "dhcp4"))
	for _, a := range keep {
		if configured[a.IP.String()] || (a.Dynamic && a.IP.To4() != nil && dhcp4) {
			continue
		}
		return fmt.Errorf("%s holds %s but %s doesn't configure it — the rewrite would drop it, not applied (add it to the file first)", bridge, a, file)
	}
	return nil
}

// networkdKeepsAddrs checks the networkd config netplan rendered for bridge
// (10-netplan-<bridge>.network) still assigns every address in keep.
func networkdKeepsAddrs(network, bridge string, keep []liveAddr) error {
	addrs := map[string]bool{}
	dhcp4 := false
	for _, ln := range strings.Split(network, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok {
			continue
		}
		switch k {
		case "Address":
			if ip, _, err := net.ParseCIDR(v); err == nil {
				addrs[ip.String()] = true
			}
		case "DHCP":
			dhcp4 = v == "yes" || v == "ipv4"
		}
	}
	for _, a := range keep {
		if !addrs[a.IP.String()] && !(a.Dynamic && a.IP.To4() != nil && dhcp4) {
			return fmt.Errorf("netplan generate renders %s without %s — not applied", bridge, a)
		}
	}
	return nil
}

// stagedNetplanCheck runs `netplan generate` on a staged copy of every netplan
// file (with path replaced by content) and checks the networkd config it
// renders for bridge still assigns the addresses in keep. Nothing live changes.
func stagedNetplanCheck(path string, content []byte, bridge string, keep []liveAddr) error {
	root, err := os.MkdirTemp("", "vdx-netplan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	for _, dir := range netplanReadDirs {
		dst := filepath.Join(root, dir)
		for _, f := range netplanFiles(dir) {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			if f == path {
				b = content
			}
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dst, filepath.Base(f)), b, 0o600); err != nil {
				return err
			}
		}
	}
	if err := netplanGenerate(root); err != nil {
		return fmt.Errorf("netplan generate rejected the new config (nothing applied): %w", err)
	}
	nw, err := os.ReadFile(filepath.Join(root, "run/systemd/network", "10-netplan-"+bridge+".network"))
	if err != nil {
		return fmt.Errorf("netplan generate rendered no networkd config for %s (is its renderer networkd?) — can't verify, not applied", bridge)
	}
	return networkdKeepsAddrs(string(nw), bridge, keep)
}

// ---- apply ----------------------------------------------------------------

// teamMgmtUplinkNetplan moves the management bridge's uplink onto a new bond of
// members (the current uplink + extras) through editMgmtNetplan.
func (s *Service) teamMgmtUplinkNetplan(bridge, uplink, bond, kmode, hashPolicy string, members []string) error {
	mac := readFileTrim("/sys/class/net/" + bridge + "/address")
	return s.editMgmtNetplan(bridge, func(nw *yaml.Node) error {
		return netplanTeamUplink(nw, bridge, uplink, mac, bond, kmode, hashPolicy, members)
	})
}

// editMgmtNetplan edits the netplan file that defines the management bridge
// with edit (which may change anything but the bridge's own addressing), checks
// the result keeps every address the bridge holds (in the file and in what
// `netplan generate` renders), and applies it under the rollback watchdog.
func (s *Service) editMgmtNetplan(bridge string, edit func(network *yaml.Node) error) error {
	path, src, err := findNetplanBridge(netplanDir, bridge)
	if err != nil {
		return err
	}
	out, err := editNetplanBridge(src, bridge, edit)
	if err != nil {
		return err
	}
	live, err := liveBridgeAddrs(bridge)
	if err != nil {
		return err
	}
	keep := mustKeepAddrs(live)
	if len(keep) == 0 {
		return fmt.Errorf("%s holds no address to verify the change against — not applied", bridge)
	}
	if err := netplanKeepsAddrs(out, bridge, path, keep); err != nil {
		return err
	}
	if err := stagedNetplanCheck(path, out, bridge, keep); err != nil {
		return err
	}
	hadDefault := slices.Contains(defaultRouteIfaces(), bridge)
	verify := func() error {
		now, err := liveBridgeAddrs(bridge)
		if err != nil {
			return err
		}
		for _, a := range keep {
			if !slices.ContainsFunc(now, func(n liveAddr) bool { return n.IP.Equal(a.IP) }) {
				return fmt.Errorf("%s is not back on %s", a, bridge)
			}
		}
		if hadDefault && !slices.Contains(defaultRouteIfaces(), bridge) {
			return fmt.Errorf("the default route via %s is gone", bridge)
		}
		return nil
	}
	return applyNetplanFile(path, out, verify)
}

// applyNetplanFile writes content to path and applies it with the SAME safety
// net as the install-time conversion: every netplan file is backed up first, a
// detached watchdog restores the backup unless success is confirmed within the
// window (so even a vdxd killed mid-apply can't strand the management IP), and
// verify is polled after the apply — on failure the backup is restored at once.
func applyNetplanFile(path string, content []byte, verify func() error) error {
	backup := fmt.Sprintf("/var/lib/vdxclone/netplan-backup.%d", time.Now().Unix())
	if err := os.MkdirAll(backup, 0o750); err != nil {
		return err
	}
	for _, f := range netplanFiles(netplanDir) {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("back up %s: %w", f, err)
		}
		if err := os.WriteFile(filepath.Join(backup, filepath.Base(f)), b, 0o600); err != nil {
			return fmt.Errorf("back up %s: %w", f, err)
		}
	}
	_, statErr := os.Stat(path)
	isNew := errors.Is(statErr, os.ErrNotExist)
	restore := func(apply bool) {
		if isNew {
			_ = os.Remove(path)
		}
		bs, _ := filepath.Glob(backup + "/*.yaml")
		for _, f := range bs {
			if b, err := os.ReadFile(f); err == nil {
				_ = os.WriteFile(filepath.Join(netplanDir, filepath.Base(f)), b, 0o600)
			}
		}
		if apply {
			_ = exec.Command("netplan", "apply").Run()
		} else {
			_ = exec.Command("netplan", "generate").Run()
		}
	}

	if err := os.WriteFile(path, content, 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("netplan", "generate").CombinedOutput(); err != nil {
		restore(false)
		return fmt.Errorf("netplan generate failed; reverted (nothing applied): %v: %s", err, strings.TrimSpace(string(out)))
	}
	// Detached watchdog: reverts unless /run/vdx-netok appears within 180s.
	// Survives even if vdxd dies during the apply.
	rm := ""
	if isNew {
		rm = fmt.Sprintf("rm -f '%s'; ", path)
	}
	_ = os.Remove("/run/vdx-netok")
	wd := exec.Command("setsid", "bash", "-c",
		fmt.Sprintf("sleep 180; [ -f /run/vdx-netok ] && exit 0; %scp '%s'/*.yaml '%s'/ 2>/dev/null; netplan apply", rm, backup, netplanDir))
	if wd.Start() == nil {
		go func() { _ = wd.Wait() }() // reap it when it exits (no zombie)
	}

	_ = exec.Command("netplan", "apply").Run()

	var verr error
	for i := 0; i < 20; i++ {
		if verr = verify(); verr == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if verr != nil {
		restore(true)
		return fmt.Errorf("management network did not come back after the change (%v); reverted to the previous netplan", verr)
	}
	// Confirm: disarm the watchdog.
	_ = os.WriteFile("/run/vdx-netok", []byte("1"), 0o644)
	return nil
}
