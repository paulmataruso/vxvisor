package lxc

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Input validation for everything vdxd writes into an LXC config or passes to
// the lxc-* tools. The config is a line-oriented key = value file that liblxc
// (running as root) reads at start; a value carrying a newline would add
// arbitrary keys — lxc.hook.* runs commands on the host — so every value is
// checked here, at the sink, whatever the caller already validated.

// ValidName checks a container name. It becomes a path component under the
// lxcpath (config, rootfs) and an lxc-* argument, so: a letter or digit first,
// then letters, digits, '.', '_' or '-', at most 64 characters.
func ValidName(s string) error {
	if len(s) == 0 || len(s) > 64 || !isAlnum(s[0]) || !charsOK(s, "._-") {
		return fmt.Errorf("invalid container name %q — use letters, digits, '.', '_' or '-' (starting with a letter or digit, at most 64 characters)", s)
	}
	return nil
}

// ValidTemplateArg checks a download-template distribution / release / arch
// (e.g. "ubuntu", "noble", "3.24", "9-Stream", "amd64"). They become path
// components of the template cache and image URL, so no separators or "..".
func ValidTemplateArg(what, s string) error {
	if len(s) == 0 || len(s) > 32 || !isAlnum(s[0]) || !charsOK(s, "._-") || strings.Contains(s, "..") {
		return fmt.Errorf("invalid %s %q", what, s)
	}
	return nil
}

// validIfName checks a host bridge / in-container interface name: 1-15 chars
// of letters, digits, '.', '_' or '-' (never "." or "..").
func validIfName(s string) bool {
	return len(s) > 0 && len(s) <= 15 && s != "." && s != ".." && charsOK(s, "._-")
}

// cfgLine renders one "key = value" config line. It refuses a value that is
// empty after trimming or that could break out of its line (CR, LF, NUL).
func cfgLine(key, val string) (string, error) {
	if strings.ContainsAny(val, "\r\n\x00") || strings.TrimSpace(val) == "" {
		return "", fmt.Errorf("refusing unsafe LXC config value for %s", key)
	}
	return key + " = " + val + "\n", nil
}

// nicLines renders the managed NIC keys for interface index i: a veth into
// bridge (validated), its pinned host-side name, an optional MAC, an optional
// in-container name, the port group VLAN as the veth's untagged PVID on a
// vlan_filtering vSwitch (lxc.net.N.veth.vlan.id; 0 = untagged / none) and an
// optional MTU (a VXLAN-backed bridge runs at 1450).
func nicLines(i int, bridge, pair, ifname, mac string, vlan, mtu int) (string, error) {
	if !validIfName(bridge) {
		return "", fmt.Errorf("invalid bridge name %q", bridge)
	}
	if !validIfName(pair) || (ifname != "" && !validIfName(ifname)) {
		return "", fmt.Errorf("invalid interface name for %s", bridge)
	}
	if mac != "" {
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) != 6 {
			return "", fmt.Errorf("invalid MAC %q", mac)
		}
		mac = hw.String() // canonical aa:bb:cc:dd:ee:ff — nothing else reaches the file
	}
	if vlan < 0 || vlan > 4094 {
		return "", fmt.Errorf("invalid VLAN %d", vlan)
	}
	if mtu != 0 && (mtu < 576 || mtu > 65535) {
		return "", fmt.Errorf("invalid MTU %d", mtu)
	}
	p := "lxc.net." + strconv.Itoa(i)
	kv := [][2]string{{p + ".type", "veth"}, {p + ".link", bridge}, {p + ".veth.pair", pair}}
	if ifname != "" {
		kv = append(kv, [2]string{p + ".name", ifname})
	}
	kv = append(kv, [2]string{p + ".flags", "up"})
	if mac != "" {
		kv = append(kv, [2]string{p + ".hwaddr", mac})
	}
	if vlan > 0 {
		kv = append(kv, [2]string{p + ".veth.vlan.id", strconv.Itoa(vlan)})
	}
	if mtu > 0 {
		kv = append(kv, [2]string{p + ".mtu", strconv.Itoa(mtu)})
	}
	var b strings.Builder
	for _, x := range kv {
		l, err := cfgLine(x[0], x[1])
		if err != nil {
			return "", err
		}
		b.WriteString(l)
	}
	return b.String(), nil
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// charsOK reports whether every byte of s is alphanumeric or in extra.
func charsOK(s, extra string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) && !strings.ContainsRune(extra, rune(s[i])) {
			return false
		}
	}
	return true
}
