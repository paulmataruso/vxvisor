package service

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The installer's static management vSwitch, with everything a rewrite used to
// drop: IPv6, extra routes, DNS search domains, MTU.
const staticMgmtNetplan = `# Managed by VXVisor installer — default management vSwitch.
network:
  version: 2
  renderer: networkd
  ethernets:
    eno1:
      dhcp4: no
      dhcp6: no
  bridges:
    vSwitch0:
      interfaces: [eno1]
      macaddress: "aa:bb:cc:dd:ee:01"
      dhcp4: no
      dhcp6: no
      mtu: 9000
      addresses:
        - 192.168.10.163/24
        - "2001:db8::163/64"
      routes:
        - {to: default, via: 192.168.10.1}
        - {to: "::/0", via: "2001:db8::1"}
        - {to: 10.9.0.0/16, via: 192.168.10.254}
      nameservers:
        search: [lab.example]
        addresses:
          - 192.168.10.1
          - "2001:db8::53"
      parameters:
        stp: false
        forward-delay: 0
`

const dhcpMgmtNetplan = `network:
  version: 2
  ethernets:
    eno1: {dhcp4: false}
  bridges:
    vSwitch0:
      interfaces: [eno1]
      dhcp4: true
      accept-ra: true
`

func team(src, bridge, uplink, mac, bond, kmode, hp string, members ...string) ([]byte, error) {
	return editNetplanBridge([]byte(src), bridge, func(nw *yaml.Node) error {
		return netplanTeamUplink(nw, bridge, uplink, mac, bond, kmode, hp, members)
	})
}

func stanza(t *testing.T, src []byte, section, name string) map[string]any {
	t.Helper()
	var doc struct {
		Network map[string]map[string]map[string]any `yaml:"network"`
	}
	// version/renderer are scalars; decode only the device sections.
	var raw map[string]map[string]any
	if err := yaml.Unmarshal(src, &raw); err != nil {
		t.Fatalf("output doesn't parse: %v\n%s", err, src)
	}
	_ = doc
	sec, _ := raw["network"][section].(map[string]any)
	st, _ := sec[name].(map[string]any)
	if st == nil {
		t.Fatalf("no %s.%s in:\n%s", section, name, src)
	}
	return st
}

func asYAML(v any) string { b, _ := yaml.Marshal(v); return string(b) }

// TestTeamMgmtUplinkKeepsAddressing: teaming the management uplink changes only
// the uplink — every address, route, DNS, DHCP, MTU and bridge setting survives.
func TestTeamMgmtUplinkKeepsAddressing(t *testing.T) {
	out, err := team(staticMgmtNetplan, "vSwitch0", "eno1", "aa:bb:cc:dd:ee:01", "bond0", "balance-alb", "layer3+4", "eno1", "eno2")
	if err != nil {
		t.Fatal(err)
	}
	before, after := stanza(t, []byte(staticMgmtNetplan), "bridges", "vSwitch0"), stanza(t, out, "bridges", "vSwitch0")
	for _, k := range []string{"macaddress", "dhcp4", "dhcp6", "mtu", "addresses", "routes", "nameservers", "parameters"} {
		if asYAML(before[k]) != asYAML(after[k]) {
			t.Fatalf("%s changed:\n%v\n->\n%v", k, before[k], after[k])
		}
	}
	if asYAML(after["interfaces"]) != asYAML([]any{"bond0"}) {
		t.Fatalf("the bridge's uplink must be the bond: %v", after["interfaces"])
	}
	bond := stanza(t, out, "bonds", "bond0")
	if asYAML(bond["interfaces"]) != asYAML([]any{"eno1", "eno2"}) || bond["macaddress"] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("bond stanza: %v", bond)
	}
	params := bond["parameters"].(map[string]any)
	if params["mode"] != "balance-alb" || params["transmit-hash-policy"] != nil || params["lacp-rate"] != nil {
		t.Fatalf("balance-alb takes no hash policy / LACP rate: %v", params)
	}
	for _, m := range []string{"eno1", "eno2"} {
		e := stanza(t, out, "ethernets", m)
		if e["dhcp4"] != false || e["dhcp6"] != false || e["accept-ra"] != false {
			t.Fatalf("member %s must carry no L3: %v", m, e)
		}
	}
	if !strings.HasPrefix(string(out), "# Managed by VXVisor installer") {
		t.Fatalf("the file's comments must survive:\n%s", out)
	}
	keep := []liveAddr{{IP: net.ParseIP("192.168.10.163"), Prefix: 24}, {IP: net.ParseIP("2001:db8::163"), Prefix: 64}}
	if err := netplanKeepsAddrs(out, "vSwitch0", "90.yaml", keep); err != nil {
		t.Fatalf("every static address is still configured: %v", err)
	}

	// LACP gets its hash policy and fast LACP rate.
	out, err = team(staticMgmtNetplan, "vSwitch0", "eno1", "", "bond0", "802.3ad", "layer2", "eno1", "eno2")
	if err != nil {
		t.Fatal(err)
	}
	params = stanza(t, out, "bonds", "bond0")["parameters"].(map[string]any)
	if params["transmit-hash-policy"] != "layer2" || params["lacp-rate"] != "fast" {
		t.Fatalf("LACP parameters: %v", params)
	}
}

// TestTeamMgmtUplinkDHCP: a DHCP management bridge stays DHCP and gains its
// current MAC (so the lease, and the admin IP, don't move with the new port).
func TestTeamMgmtUplinkDHCP(t *testing.T) {
	out, err := team(dhcpMgmtNetplan, "vSwitch0", "eno1", "aa:bb:cc:dd:ee:01", "bond0", "active-backup", "", "eno1", "eno2")
	if err != nil {
		t.Fatal(err)
	}
	br := stanza(t, out, "bridges", "vSwitch0")
	if br["dhcp4"] != true || br["accept-ra"] != true || br["macaddress"] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("DHCP bridge: %v", br)
	}
	lease := []liveAddr{{IP: net.ParseIP("192.168.10.45"), Prefix: 24, Dynamic: true}}
	if err := netplanKeepsAddrs(out, "vSwitch0", "f", lease); err != nil {
		t.Fatalf("a DHCP lease is kept by dhcp4: %v", err)
	}
	// A static address on the bridge that the file doesn't have would be lost.
	static := []liveAddr{{IP: net.ParseIP("192.168.10.200"), Prefix: 24}}
	if err := netplanKeepsAddrs(out, "vSwitch0", "f", static); err == nil || !strings.Contains(err.Error(), "192.168.10.200/24") {
		t.Fatalf("an address the file doesn't configure must block the apply, got %v", err)
	}
}

// TestTeamMgmtUplinkRefusals: anything that can't be done without guessing or
// dropping config is refused before a file is produced.
func TestTeamMgmtUplinkRefusals(t *testing.T) {
	for _, c := range []struct{ name, src, uplink, bond, want string }{
		{"uplink not in the file", staticMgmtNetplan, "eno9", "bond0", "don't include its uplink eno9"},
		{"bond already defined", strings.Replace(staticMgmtNetplan, "  bridges:", "  bonds:\n    bond0: {interfaces: [eno7]}\n  bridges:", 1), "eno1", "bond0", "already defined"},
		{"member with an address", strings.Replace(staticMgmtNetplan, "  bridges:", "    eno2: {addresses: [10.0.0.9/24]}\n  bridges:", 1), "eno1", "bond0", "eno2 has addresses"},
	} {
		if _, err := team(c.src, "vSwitch0", c.uplink, "", c.bond, "balance-alb", "", "eno1", "eno2"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// An edit touching the bridge's addressing is caught by editNetplanBridge.
	for _, c := range []struct {
		name string
		edit func(br *yaml.Node)
		want string
	}{
		{"drops addresses", func(br *yaml.Node) {
			for i := 0; i+1 < len(br.Content); i += 2 {
				if br.Content[i].Value == "addresses" {
					br.Content = append(br.Content[:i], br.Content[i+2:]...)
					return
				}
			}
		}, `change vSwitch0's "addresses"`},
		{"turns DHCP on", func(br *yaml.Node) { yamlSet(br, "dhcp4", yamlBool(true)) }, `"dhcp4"`},
		{"adds a key", func(br *yaml.Node) { yamlSet(br, "link-local", yamlFlowSeq(nil)) }, `add "link-local"`},
	} {
		_, err := editNetplanBridge([]byte(staticMgmtNetplan), "vSwitch0", func(nw *yaml.Node) error {
			c.edit(yamlGet(yamlGet(nw, "bridges"), "vSwitch0"))
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

func TestFindNetplanBridge(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("50-cloud-init.yaml", "network:\n  version: 2\n  ethernets:\n    eno1: {dhcp4: true}\n")
	if _, _, err := findNetplanBridge(dir, "vSwitch0"); err == nil || !strings.Contains(err.Error(), "isn't defined") {
		t.Fatalf("no definition: %v", err)
	}
	write("90-vdx-vswitch0.yaml", staticMgmtNetplan)
	if p, src, err := findNetplanBridge(dir, "vSwitch0"); err != nil || filepath.Base(p) != "90-vdx-vswitch0.yaml" || string(src) != staticMgmtNetplan {
		t.Fatalf("one definition: %s %v", p, err)
	}
	write("99-extra.yaml", "network:\n  bridges:\n    vSwitch0: {mtu: 1500}\n")
	if _, _, err := findNetplanBridge(dir, "vSwitch0"); err == nil || !strings.Contains(err.Error(), "several netplan files") {
		t.Fatalf("two definitions: %v", err)
	}
	write("99-extra.yaml", "network: [unclosed")
	if _, _, err := findNetplanBridge(dir, "vSwitch0"); err == nil || !strings.Contains(err.Error(), "can't parse") {
		t.Fatalf("an unparseable file: %v", err)
	}
}

func TestParseLiveAddrs(t *testing.T) {
	js := `[{"ifindex":5,"ifname":"vSwitch0","addr_info":[
		{"family":"inet","local":"192.168.10.163","prefixlen":24,"scope":"global","dynamic":true},
		{"family":"inet","local":"192.168.10.200","prefixlen":24,"scope":"global"},
		{"family":"inet6","local":"2001:db8::5","prefixlen":64,"scope":"global","dynamic":true},
		{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]}]`
	got, err := parseLiveAddrs([]byte(js))
	if err != nil || len(got) != 3 {
		t.Fatalf("global addresses: %v %v", got, err)
	}
	keep := mustKeepAddrs(got)
	if len(keep) != 2 || keep[0].String() != "192.168.10.163/24" || keep[1].String() != "192.168.10.200/24" {
		t.Fatalf("must keep static + DHCP IPv4 (not SLAAC): %v", keep)
	}
}

func TestNetworkdKeepsAddrs(t *testing.T) {
	const rendered = "[Match]\nName=vSwitch0\n\n[Network]\nLinkLocalAddressing=ipv6\nAddress=192.168.10.163/24\nAddress=2001:db8::163/64\n"
	keep := []liveAddr{{IP: net.ParseIP("192.168.10.163"), Prefix: 24}, {IP: net.ParseIP("2001:db8::163"), Prefix: 64}}
	if err := networkdKeepsAddrs(rendered, "vSwitch0", keep); err != nil {
		t.Fatal(err)
	}
	if err := networkdKeepsAddrs(strings.Replace(rendered, "Address=2001:db8::163/64\n", "", 1), "vSwitch0", keep); err == nil {
		t.Fatalf("a dropped IPv6 address must be caught")
	}
	lease := []liveAddr{{IP: net.ParseIP("192.168.10.45"), Prefix: 24, Dynamic: true}}
	if err := networkdKeepsAddrs("[Network]\nDHCP=ipv4\n", "vSwitch0", lease); err != nil {
		t.Fatalf("DHCP keeps a lease: %v", err)
	}
	if err := networkdKeepsAddrs("[Network]\nDHCP=ipv6\n", "vSwitch0", lease); err == nil {
		t.Fatalf("DHCPv6 doesn't keep an IPv4 lease")
	}
}

// TestStagedNetplanCheck: the dry-run generate sees every netplan file with the
// edited one swapped in, and its rendered addresses decide; nothing live moves.
func TestStagedNetplanCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "90-vdx-vswitch0.yaml")
	os.WriteFile(filepath.Join(dir, "50-cloud-init.yaml"), []byte("network: {version: 2}\n"), 0o600)
	os.WriteFile(path, []byte(staticMgmtNetplan), 0o600)
	oldDirs, oldGen := netplanReadDirs, netplanGenerate
	t.Cleanup(func() { netplanReadDirs, netplanGenerate = oldDirs, oldGen })
	netplanReadDirs = []string{dir}
	render := "Address=192.168.10.163/24\n"
	netplanGenerate = func(root string) error {
		staged, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(staged) != "NEW" {
			t.Fatalf("the edited file must be staged in place of the live one: %q %v", staged, err)
		}
		if _, err := os.Stat(filepath.Join(root, dir, "50-cloud-init.yaml")); err != nil {
			t.Fatalf("every other netplan file must be staged too: %v", err)
		}
		out := filepath.Join(root, "run/systemd/network")
		os.MkdirAll(out, 0o755)
		return os.WriteFile(filepath.Join(out, "10-netplan-vSwitch0.network"), []byte("[Network]\n"+render), 0o644)
	}
	keep := []liveAddr{{IP: net.ParseIP("192.168.10.163"), Prefix: 24}}
	if err := stagedNetplanCheck(path, []byte("NEW"), "vSwitch0", keep); err != nil {
		t.Fatal(err)
	}
	render = "Address=192.168.10.99/24\n"
	if err := stagedNetplanCheck(path, []byte("NEW"), "vSwitch0", keep); err == nil {
		t.Fatalf("a render without the admin IP must block the apply")
	}
	if b, _ := os.ReadFile(path); string(b) != staticMgmtNetplan {
		t.Fatalf("the live file must be untouched by the check")
	}
}

// TestEditMgmtNetplanRefusesDroppingAdminIP: an address the bridge holds that
// netplan doesn't configure stops the change before anything is written.
func TestEditMgmtNetplanRefusesDroppingAdminIP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "90-vdx-vswitch0.yaml")
	os.WriteFile(path, []byte(staticMgmtNetplan), 0o600)
	oldDir, oldDirs, oldLive := netplanDir, netplanReadDirs, liveBridgeAddrs
	t.Cleanup(func() { netplanDir, netplanReadDirs, liveBridgeAddrs = oldDir, oldDirs, oldLive })
	netplanDir, netplanReadDirs = dir, []string{dir}
	liveBridgeAddrs = func(string) ([]liveAddr, error) {
		return []liveAddr{{IP: net.ParseIP("192.168.10.163"), Prefix: 24}, {IP: net.ParseIP("192.168.10.77"), Prefix: 24}}, nil
	}
	s := &Service{}
	err := s.teamMgmtUplinkNetplan("vSwitch0", "eno1", "bond0", "balance-alb", "", []string{"eno1", "eno2"})
	if err == nil || !strings.Contains(err.Error(), "192.168.10.77/24") {
		t.Fatalf("want a refusal naming the unconfigured address, got %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != staticMgmtNetplan {
		t.Fatalf("a refused change must not touch the file")
	}
}
