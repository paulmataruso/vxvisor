package netdrv

import (
	"os"
	"os/exec"
	"path/filepath"
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
//   gatewayIP — handed out as the default gateway (option 3); "" omits it.
//   dhcpRange — "start,end" (already normalized); "" disables DHCP.
//   mask      — dotted netmask for the range; "" lets dnsmasq infer.
//   dns       — CSV of resolvers (option 6); "" omits it.
func StartTenantDHCP(bridge, gatewayIP, dhcpRange, mask, dns string) error {
	_ = StopTenantDHCP(bridge)
	if strings.TrimSpace(dhcpRange) == "" {
		return nil
	}
	if err := os.MkdirAll(tenantDHCPDir, 0o755); err != nil {
		return err
	}
	pid := filepath.Join(tenantDHCPDir, bridge+".pid")
	lease := filepath.Join(tenantDHCPDir, bridge+".leases")
	conf := filepath.Join(tenantDHCPDir, bridge+".conf")
	var b strings.Builder
	b.WriteString("interface=" + bridge + "\n")
	b.WriteString("bind-interfaces\n")
	b.WriteString("except-interface=lo\n")
	if mask != "" {
		b.WriteString("dhcp-range=" + dhcpRange + "," + mask + ",12h\n")
	} else {
		b.WriteString("dhcp-range=" + dhcpRange + ",12h\n")
	}
	if gatewayIP != "" {
		b.WriteString("dhcp-option=3," + gatewayIP + "\n")
	}
	if dns != "" {
		b.WriteString("dhcp-option=6," + dns + "\n")
	}
	b.WriteString("dhcp-leasefile=" + lease + "\npid-file=" + pid + "\n")
	if err := os.WriteFile(conf, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return exec.Command("dnsmasq", "-C", conf).Run()
}

// StopTenantDHCP stops the dnsmasq bound to the given bridge, if any.
func StopTenantDHCP(bridge string) error {
	pid := filepath.Join(tenantDHCPDir, bridge+".pid")
	if data, err := os.ReadFile(pid); err == nil {
		_ = exec.Command("sh", "-c", "kill "+strings.TrimSpace(string(data))+" 2>/dev/null; true").Run()
		_ = os.Remove(pid)
	}
	return nil
}
