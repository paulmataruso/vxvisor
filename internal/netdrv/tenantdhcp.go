package netdrv

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Host-side DHCP for an isolated tenant-network bridge. A single dnsmasq is bound
// STRICTLY to the one bridge (interface=<bridge> + bind-interfaces), so it can
// never answer on the management NIC or any other interface — the lockout-safe
// property we require. Instances are tracked by pidfile under /run/vdx-tnet.

const tenantDHCPDir = "/run/vdx-tnet"

// StartTenantDHCP (re)starts a dnsmasq serving DHCP on one bridge. It is
// idempotent: any prior instance for the bridge is stopped first. An empty
// dhcpRange means "no DHCP" and only stops any running instance.
//
//	gatewayIP — handed out as the default gateway (option 3); "" omits it.
//	dhcpRange — "start,end" (already normalized); "" disables DHCP.
//	mask      — dotted netmask for the range; "" lets dnsmasq infer.
//	dns       — CSV of resolvers (option 6); "" omits it.
func StartTenantDHCP(bridge, gatewayIP, dhcpRange, mask, dns string) error {
	_ = StopTenantDHCP(bridge)
	if strings.TrimSpace(dhcpRange) == "" {
		return nil
	}
	pid := filepath.Join(tenantDHCPDir, bridge+".pid")
	lease := filepath.Join(tenantDHCPDir, bridge+".leases")
	conf := filepath.Join(tenantDHCPDir, bridge+".conf")
	body, err := RenderTenantDHCPConf(bridge, gatewayIP, dhcpRange, mask, dns, lease, pid)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(tenantDHCPDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		return err
	}
	return exec.Command("dnsmasq", "-C", conf).Run()
}

// RenderTenantDHCPConf builds a tenant dnsmasq config. It is the backstop for
// every caller: each value must parse as exactly what it claims to be (an
// interface name, IPv4 addresses, a netmask) or nothing is written — a newline
// smuggled into any of them would add arbitrary dnsmasq directives, and some
// (dhcp-script=) run commands as root.
func RenderTenantDHCPConf(bridge, gatewayIP, dhcpRange, mask, dns, leaseFile, pidFile string) (string, error) {
	refuse := func(what, v string) (string, error) {
		return "", fmt.Errorf("refusing to write a DHCP config for %q: %s %q is not valid", bridge, what, v)
	}
	if !validIfName(bridge) {
		return refuse("interface", bridge)
	}
	if gatewayIP != "" && parseIPv4(gatewayIP) == nil {
		return refuse("gateway", gatewayIP)
	}
	parts := strings.Split(dhcpRange, ",")
	if len(parts) != 2 {
		return refuse("range", dhcpRange)
	}
	start, end := parseIPv4(strings.TrimSpace(parts[0])), parseIPv4(strings.TrimSpace(parts[1]))
	if start == nil || end == nil || ipv4Uint(start) > ipv4Uint(end) {
		return refuse("range", dhcpRange)
	}
	if mask != "" {
		m := parseIPv4(mask)
		if m == nil {
			return refuse("netmask", mask)
		}
		if ones, bits := net.IPMask(m).Size(); bits == 0 || ones == 0 {
			return refuse("netmask", mask)
		}
	}
	var resolvers []string
	for _, d := range strings.Split(dns, ",") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		if parseIPv4(d) == nil {
			return refuse("DNS server", d)
		}
		resolvers = append(resolvers, d)
	}
	for _, f := range []string{leaseFile, pidFile} {
		if !strings.HasPrefix(f, "/") || strings.ContainsAny(f, "\n\r") {
			return refuse("file", f)
		}
	}
	var b strings.Builder
	b.WriteString("interface=" + bridge + "\n")
	b.WriteString("bind-interfaces\n")
	b.WriteString("except-interface=lo\n")
	// DHCP only: no DNS listener, so a tenant can't use the host's resolver (and
	// its view of internal names). Clients get their resolvers via option 6.
	b.WriteString("port=0\n")
	rng := start.String() + "," + end.String()
	if mask != "" {
		b.WriteString("dhcp-range=" + rng + "," + parseIPv4(mask).String() + ",12h\n")
	} else {
		b.WriteString("dhcp-range=" + rng + ",12h\n")
	}
	if gatewayIP != "" {
		b.WriteString("dhcp-option=3," + parseIPv4(gatewayIP).String() + "\n")
	}
	if len(resolvers) > 0 {
		b.WriteString("dhcp-option=6," + strings.Join(resolvers, ",") + "\n")
	}
	b.WriteString("dhcp-leasefile=" + leaseFile + "\npid-file=" + pidFile + "\n")
	return b.String(), nil
}

// StopTenantDHCP stops the dnsmasq bound to the given bridge, if any.
func StopTenantDHCP(bridge string) error {
	if !validIfName(bridge) {
		return nil
	}
	pid := filepath.Join(tenantDHCPDir, bridge+".pid")
	if data, err := os.ReadFile(pid); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && n > 1 {
			_ = exec.Command("kill", strconv.Itoa(n)).Run()
		}
		_ = os.Remove(pid)
	}
	return nil
}

// TenantDHCPRunning reports whether the dnsmasq for this interface is alive.
func TenantDHCPRunning(bridge string) bool {
	if !validIfName(bridge) {
		return false
	}
	data, err := os.ReadFile(filepath.Join(tenantDHCPDir, bridge+".pid"))
	if err != nil {
		return false
	}
	pid := strings.TrimSpace(string(data))
	if n, err := strconv.Atoi(pid); err != nil || n <= 1 {
		return false
	}
	_, err = os.Stat("/proc/" + pid)
	return err == nil
}

// validIfName reports whether s is a kernel interface name vdxd would create:
// 1-15 characters of letters, digits, '.', '-' and '_' (and not "." / "..").
func validIfName(s string) bool {
	if s == "" || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// parseIPv4 parses a dotted-quad IPv4 address (nil for anything else, including
// IPv6 and IPv4-mapped IPv6 forms).
func parseIPv4(s string) net.IP {
	if strings.Contains(s, ":") {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func ipv4Uint(ip net.IP) uint32 {
	v := ip.To4()
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}
