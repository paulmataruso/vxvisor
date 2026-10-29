package netdrv

import (
	"os"
	"strconv"
	"strings"
)

// LinkMTU reads an interface's current MTU from sysfs (0 when it doesn't exist
// or can't be read). Used to size a VM tap / container veth to its bridge, e.g.
// a VXLAN-backed port group whose bridge runs at 1450.
func LinkMTU(iface string) int {
	if !sysfsIfaceOK(iface) {
		return 0
	}
	b, err := os.ReadFile("/sys/class/net/" + iface + "/mtu")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// SetLinkMTU sets an interface's MTU.
func SetLinkMTU(iface string, mtu int) error {
	return run("ip", "link", "set", iface, "mtu", strconv.Itoa(mtu))
}

// sysfsIfaceOK reports whether s is a plausible Linux interface name (1-15
// chars, no path separators or whitespace) so it is safe in a sysfs path.
func sysfsIfaceOK(s string) bool {
	if s == "" || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
