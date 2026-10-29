package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"vdxclone/internal/hostinfo"
)

// Management-interface detection. Every guard that keeps the management path
// alive (guardMgmt, guardIfaceInUse, the vSwitch delete, the netplan rewrite)
// keys off this, so it never silently answers "unknown": when the interface
// can't be found it reports so and the guards refuse (fail closed).

var (
	hostIfaces         = hostinfo.Interfaces    // swapped in tests
	defaultRouteIfaces = readDefaultRouteIfaces // swapped in tests
)

// errMgmtUnknown is what management-sensitive operations return when the
// management interface can't be identified.
var errMgmtUnknown = errors.New("refusing: the management interface can't be identified " +
	"(the admin listener binds a wildcard or loopback address and the host has no default route) — " +
	"set [server] addr in the vdxd config to the management IP and restart vdxd")

// mgmtIfaces returns the interface(s) carrying host management: the one holding
// the admin listener's IP when it binds a specific address; otherwise (a
// wildcard 0.0.0.0 / :: / empty host, loopback, a hostname, or an IP no
// interface holds) every interface carrying a default route — the path an
// admin reaches the host over. Lowest-metric IPv4 default first. Empty means
// unknown: callers must fail closed.
func (s *Service) mgmtIfaces() []string {
	ifaces, err := hostIfaces()
	if err != nil {
		return nil
	}
	addr := ""
	if s.cfg != nil {
		addr = s.cfg.Server.Addr
	}
	if ip := listenIP(addr); ip != nil {
		for _, it := range ifaces {
			for _, a := range it.Addrs {
				if aip, _, err := net.ParseCIDR(a); err == nil && aip.Equal(ip) {
					return []string{it.Name}
				}
			}
		}
	}
	present := map[string]bool{}
	for _, it := range ifaces {
		present[it.Name] = true
	}
	var out []string
	for _, n := range defaultRouteIfaces() {
		if present[n] && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// listenIP is the specific, non-loopback IP a listen address binds, or nil for
// a wildcard / empty / loopback host or a hostname.
func listenIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return nil
	}
	return ip
}

// mgmtIface returns the primary management interface ("" when unknown). Use
// guardMgmt / isMgmtIface for checks — they see every management interface and
// fail closed.
func (s *Service) mgmtIface() string {
	if m := s.mgmtIfaces(); len(m) > 0 {
		return m[0]
	}
	return ""
}

// isMgmtIface reports whether name is (one of) the management interface(s).
func (s *Service) isMgmtIface(name string) bool {
	return name != "" && slices.Contains(s.mgmtIfaces(), name)
}

// MgmtInterface returns the name of the interface (NIC or vSwitch bridge) that
// carries the admin IP — used by the UI to mark the management vSwitch as
// protected (not deletable).
func (s *Service) MgmtInterface() string { return s.mgmtIface() }

// guardMgmt refuses any of nics that carries host management, and refuses
// outright (errMgmtUnknown) when the management interface can't be identified.
// Empty names are ignored, so an empty optional uplink never trips it.
func (s *Service) guardMgmt(nics ...string) error {
	var named []string
	for _, n := range nics {
		if n = strings.TrimSpace(n); n != "" {
			named = append(named, n)
		}
	}
	if len(named) == 0 {
		return nil
	}
	mgmt := s.mgmtIfaces()
	if len(mgmt) == 0 {
		return errMgmtUnknown
	}
	for _, n := range named {
		if slices.Contains(mgmt, n) {
			return fmt.Errorf("refusing to use the management interface %q (it carries the admin IP — using it here would cut host access)", n)
		}
	}
	return nil
}

// readDefaultRouteIfaces lists the interfaces carrying a default route: IPv4
// from /proc/net/route, then IPv6 from /proc/net/ipv6_route, each by metric.
func readDefaultRouteIfaces() []string {
	var out []string
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		out = append(out, parseDefaultRoutesV4(string(b))...)
	}
	if b, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		out = append(out, parseDefaultRoutesV6(string(b))...)
	}
	return out
}

const (
	rtfUp     = 0x0001
	rtfReject = 0x0200
)

type routeIf struct {
	iface  string
	metric uint64
}

func byMetric(rs []routeIf) []string {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].metric < rs[j].metric })
	var out []string
	for _, r := range rs {
		if !slices.Contains(out, r.iface) {
			out = append(out, r.iface)
		}
	}
	return out
}

// parseDefaultRoutesV4 reads /proc/net/route: "Iface Destination Gateway Flags
// RefCnt Use Metric Mask ..." in hex; a default route is destination and mask 0.
func parseDefaultRoutesV4(content string) []string {
	var rs []routeIf
	for _, ln := range strings.Split(content, "\n") {
		f := strings.Fields(ln)
		if len(f) < 8 || f[0] == "Iface" || f[0] == "lo" || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		metric, _ := strconv.ParseUint(f[6], 10, 64)
		rs = append(rs, routeIf{f[0], metric})
	}
	return byMetric(rs)
}

// parseDefaultRoutesV6 reads /proc/net/ipv6_route: "dest plen src plen nexthop
// metric refcnt use flags iface" in hex. The kernel's unreachable default on lo
// is skipped.
func parseDefaultRoutesV6(content string) []string {
	var rs []routeIf
	for _, ln := range strings.Split(content, "\n") {
		f := strings.Fields(ln)
		if len(f) < 10 || f[9] == "lo" || f[1] != "00" || strings.Trim(f[0], "0") != "" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfReject != 0 {
			continue
		}
		metric, _ := strconv.ParseUint(f[5], 16, 64)
		rs = append(rs, routeIf{f[9], metric})
	}
	return byMetric(rs)
}
