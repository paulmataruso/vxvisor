// Package lldp reads link-layer neighbor discovery from lldpd (which receives
// BOTH LLDP and Cisco CDP) so the topology diagram can show what upstream switch
// each uplink port is actually connected to. It shells out to `lldpctl -f
// keyvalue` — a flat, version-stable format that is far easier to parse reliably
// than lldpd's nested JSON — and groups the result by local interface.
package lldp

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Neighbor is what one local port learned about the device on the other end.
type Neighbor struct {
	Local       string `json:"local"`        // our interface (eno1, bond0, enp5s0f1…)
	Via         string `json:"via"`          // LLDP | CDPv2 | CDPv1 …
	SwitchName  string `json:"switch_name"`  // neighbor chassis name (the switch's hostname)
	SwitchDescr string `json:"switch_descr"` // chassis description (model/OS)
	MgmtIP      string `json:"mgmt_ip"`      // neighbor management IP
	PortID      string `json:"port_id"`      // neighbor's port (e.g. Gi0/1)
	PortDescr   string `json:"port_descr"`   // neighbor's port description
	VLAN        string `json:"vlan"`         // VLAN advertised on the port, if any
}

// Available reports whether the lldpctl CLI is present.
func Available() bool { _, err := exec.LookPath("lldpctl"); return err == nil }

// Neighbors returns the current neighbor per local interface. Best effort: if
// lldpd isn't installed or running, or no neighbor has been heard yet, the map is
// empty. Only interfaces with at least a chassis name or port id are included.
func Neighbors() map[string]Neighbor {
	out := map[string]Neighbor{}
	if !Available() {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "lldpctl", "-f", "keyvalue").Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "lldp.") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key, val := line[:eq], strings.TrimSpace(line[eq+1:])
		if val == "" {
			continue
		}
		// key = lldp.<iface>.<subkey...>
		rest := key[len("lldp."):]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		iface, sub := rest[:dot], rest[dot+1:]
		n := out[iface]
		n.Local = iface
		switch {
		case sub == "via":
			n.Via = val
		case sub == "chassis.name":
			n.SwitchName = val
		case sub == "chassis.descr":
			n.SwitchDescr = val
		case sub == "chassis.mgmt-ip":
			if n.MgmtIP == "" {
				n.MgmtIP = val
			}
		case sub == "port.ifname", sub == "port.local", sub == "port.id":
			if n.PortID == "" {
				n.PortID = val
			}
		case sub == "port.descr":
			n.PortDescr = val
		case sub == "vlan.vlan-id", sub == "vlan":
			if n.VLAN == "" {
				n.VLAN = val
			}
		}
		out[iface] = n
	}
	// Drop entries that carry nothing useful (e.g. only a via/rid with no peer).
	for k, n := range out {
		if n.SwitchName == "" && n.PortID == "" && n.MgmtIP == "" && n.SwitchDescr == "" {
			delete(out, k)
		}
	}
	return out
}
