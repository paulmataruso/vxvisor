package service

import (
	"os"
	"strconv"
	"strings"

	"vdxclone/internal/lxc"
	"vdxclone/internal/session"
	"vdxclone/internal/vrouter"
)

// topoLeg is one vRouter leg as the topology diagram needs it.
type topoLeg struct {
	vrID                   int64
	vr, kind, bridge, cidr string
	iface, phys            string
	netID                  int64 // internal / uplink: the networks row it serves
	vlan                   int   // > 0: a VLAN port group on a tenant vSwitch
}

// topoLegs loads every vRouter leg (orgID 0) or one org's, in diagram order.
func (s *Service) topoLegs(orgID int64) []topoLeg {
	q := `SELECT v.id, v.name, l.kind, l.bridge, COALESCE(l.cidr,''), COALESCE(l.iface_name,''),
		COALESCE(l.phys_iface,''), l.network_id, l.vlan_id
		FROM vrouter_legs l JOIN vrouters v ON v.id=l.vrouter_id`
	var args []any
	if orgID > 0 {
		q += ` WHERE v.org_id=?`
		args = append(args, orgID)
	}
	rows, err := s.db.Query(q+` ORDER BY v.name, v.id, l.idx`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []topoLeg
	for rows.Next() {
		var l topoLeg
		if rows.Scan(&l.vrID, &l.vr, &l.kind, &l.bridge, &l.cidr, &l.iface, &l.phys, &l.netID, &l.vlan) == nil && l.bridge != "" {
			out = append(out, l)
		}
	}
	return out
}

type topoVRMeta struct {
	routing  []string
	health   string
	runtime  string
	firewall bool
}

// topoVRouterMeta is each of the org's vRouters' routing protocols + health (the
// box's routing tag + status light), runtime and firewall state, by router id.
func (s *Service) topoVRouterMeta(orgID int64) map[int64]topoVRMeta {
	out := map[int64]topoVRMeta{}
	var vrows []vrouter.VRouter
	if rs, err := s.db.Query(`SELECT `+vrouterCols+` FROM vrouters WHERE org_id=?`, orgID); err == nil {
		for rs.Next() { // read all rows before any backend call (single-conn pool)
			if v, e := scanVRouter(rs); e == nil {
				vrows = append(vrows, v)
			}
		}
		rs.Close()
	}
	for _, v := range vrows {
		cfg := parseFRRJSON(v.FRRJSON)
		var protos []string
		if cfg.BGP.Enabled {
			protos = append(protos, "BGP")
		}
		if cfg.OSPF.Enabled {
			protos = append(protos, "OSPF")
		}
		if cfg.EIGRP.Enabled {
			protos = append(protos, "EIGRP")
		}
		if len(cfg.Static) > 0 {
			protos = append(protos, "Static")
		}
		health := ""
		if len(protos) > 0 {
			health = "up"
			if v.Status == "creating" || v.Status == "error" {
				health = "down"
			} else if b, err := vrouter.For(v.Runtime); err == nil {
				if ls, e := b.Status(v); e != nil || (ls.State != "" && ls.State != "running") {
					health = "down"
				} else if cfg.BGP.Enabled && bgpAnyDown(ls.BGPSummary) {
					health = "down"
				}
			}
		}
		out[v.ID] = topoVRMeta{routing: protos, health: health, runtime: v.Runtime, firewall: parseFW(v.FWJSON).Enabled}
	}
	return out
}

// topoZones maps each of the org's networks to the firewall VM Group it belongs
// to (the port-group badge). The compiler's internal per-leg zone keys (leg1…)
// never surface on the diagram.
func (s *Service) topoZones(orgID int64) map[int64]string {
	namesByNet := map[int64][]string{}
	for _, g := range s.loadOrgFW(orgID).Groups {
		for _, nid := range g.Networks {
			namesByNet[nid] = append(namesByNet[nid], g.Name)
		}
	}
	out := map[int64]string{}
	for nid, names := range namesByNet {
		if len(names) == 1 {
			out[nid] = names[0]
		} else {
			out[nid] = itoa(len(names)) + " groups"
		}
	}
	return out
}

// mergeVRouters draws each vRouter as ONE chain: port groups → vRouter → external
// port. An internal leg moves the port group it serves (by network id, else every
// port group with the leg's VLAN on that bridge) off its switch and onto the
// router; a transit leg takes its dedicated bridge's uplink as the external port;
// an uplink leg's external port is the vSwitch uplink carrying it. Transit bridges,
// and switches the internal legs left empty, are dropped. tenant hides the
// provider's transit bridge / NIC / LLDP neighbor.
func (s *Service) mergeVRouters(topo *Topology, legs []topoLeg, orgID int64, vmMAC map[string]string, tenant bool) {
	if len(legs) == 0 {
		return
	}
	meta := s.topoVRouterMeta(orgID)
	zones := s.topoZones(orgID)
	swAt := map[string]int{}
	for i, sw := range topo.Switches {
		if sw.bridge != "" {
			swAt[sw.bridge] = i
		}
	}
	vrs := map[int64]*TopoVRouter{}
	leases := map[int64]map[string]string{}
	var order []int64
	drop, routed := map[int]bool{}, map[int]bool{}
	for _, l := range legs {
		v := vrs[l.vrID]
		if v == nil {
			m := meta[l.vrID]
			v = &TopoVRouter{Name: l.vr, Transit: &TopoVRTransit{}, Routing: m.routing, Health: m.health,
				Runtime: m.runtime, Firewall: m.firewall}
			vrs[l.vrID] = v
			leases[l.vrID] = s.vrouterLeases(l.vrID)
			order = append(order, l.vrID)
		}
		i, onMap := swAt[l.bridge]
		switch l.kind {
		case vrouter.LegInternal:
			if !onMap {
				continue
			}
			sw := &topo.Switches[i]
			routed[i] = true
			byNet := false
			for _, pg := range sw.PortGroups {
				byNet = byNet || (l.netID != 0 && pg.netID == l.netID)
			}
			var keep []TopoPortGroup
			for _, pg := range sw.PortGroups {
				if (byNet && pg.netID != l.netID) || (!byNet && pg.VLAN != l.vlan) {
					keep = append(keep, pg)
					continue
				}
				vms := make([]TopoVM, len(pg.VMs))
				copy(vms, pg.VMs)
				for j := range vms {
					vms[j].IP = s.topoVMIP(leases[l.vrID], vms[j], vmMAC[vms[j].ID])
				}
				v.Internal = append(v.Internal, TopoVRInternal{Name: pg.Name, GW: l.cidr, Subnet: pg.CIDR,
					Bridge: legBridgeLabel(sw.Name, l.vlan), Iface: l.iface, Zone: zones[pg.netID], VMs: vms})
			}
			sw.PortGroups = keep
		case vrouter.LegTransit:
			v.Transit.CIDR = netAddr(l.cidr) // the subnet, not the vRouter's leg IP
			if tenant {
				v.Transit.Phys = "provider transit"
				continue
			}
			if !onMap {
				continue
			}
			drop[i] = true
			v.Transit.Bridge, v.Transit.Iface = l.bridge, l.iface
			for _, up := range topo.Switches[i].Uplinks {
				setTransitPhys(v.Transit, up)
			}
		case vrouter.LegUplink:
			v.Transit.CIDR, v.Transit.Iface = netAddr(l.cidr), l.iface
			if onMap {
				sw := topo.Switches[i]
				v.Transit.Bridge = legBridgeLabel(sw.Name, l.vlan)
				for _, up := range sw.Uplinks {
					setTransitPhys(v.Transit, up)
				}
			}
		}
	}
	var kept []TopoSwitch
	for i, sw := range topo.Switches {
		if drop[i] || (routed[i] && len(sw.PortGroups) == 0 && len(sw.Uplinks) == 0) {
			continue
		}
		kept = append(kept, sw)
	}
	topo.Switches = kept
	for _, id := range order {
		v := vrs[id]
		if v.Transit.CIDR == "" && v.Transit.Phys == "" {
			v.Transit = nil
		}
		topo.VRouters = append(topo.VRouters, *v)
	}
}

// legBridgeLabel names where a leg lands: the switch, plus the VLAN for a port
// group on a tenant vSwitch (its host end is an access port, not a device).
func legBridgeLabel(sw string, vlan int) string {
	if vlan > 0 {
		return sw + " · VLAN " + strconv.Itoa(vlan)
	}
	return sw
}

func setTransitPhys(t *TopoVRTransit, up TopoUplink) {
	t.Phys = up.Name
	if len(up.Neighbors) > 0 {
		n := up.Neighbors[0]
		t.Switch, t.Port, t.Mgmt, t.Descr = n.SwitchName, n.PortID, n.MgmtIP, n.SwitchDescr
	}
}

// topoVMIP resolves a drawn VM's address: the vRouter's DHCP lease first, else
// the guest agent / ARP. A stopped VM has none (the agent only answers while it
// runs; a lease or ARP entry would be stale).
func (s *Service) topoVMIP(leases map[string]string, vm TopoVM, mac string) string {
	if vm.ID == "" || vm.State == "stopped" {
		return ""
	}
	if mac != "" {
		if ip := leases[strings.ToLower(mac)]; ip != "" {
			return ip
		}
	}
	return s.guestPrimaryIP(&session.Session{ID: vm.ID, MAC: mac})
}

func (s *Service) topoFillVMIPs(topo *Topology, vmMAC map[string]string) {
	for si := range topo.Switches {
		for pi := range topo.Switches[si].PortGroups {
			vms := topo.Switches[si].PortGroups[pi].VMs
			for j := range vms {
				if vms[j].IP == "" {
					vms[j].IP = s.topoVMIP(nil, vms[j], vmMAC[vms[j].ID])
				}
			}
		}
	}
}

// tenantTopology is the Networks/vRouters diagram for one org: its vSwitches
// (each with its port groups + VMs and its uplink, by the tenant-facing uplink
// name), its routers, and any other network it was given. Nothing about the
// host — NICs, other orgs' bridges, management IPs, LLDP — is in it.
func (s *Service) tenantTopology(p *Principal) (*Topology, error) {
	topo := &Topology{Switches: []TopoSwitch{}}
	tnets, err := s.ListTenantNetworks(p)
	if err != nil {
		return nil, err
	}
	netToVMs := map[int64][]TopoVM{}
	vmNet := map[string]int64{}
	vmMAC := map[string]string{}
	var orgVMs []TopoVM
	rows, err := s.db.Query(`SELECT id, name, state, COALESCE(network_id,0), COALESCE(mac,'') FROM sessions
		WHERE deleted_at IS NULL AND org_id=? ORDER BY name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var vm TopoVM
		var netID int64
		var mac string
		if rows.Scan(&vm.ID, &vm.Name, &vm.State, &netID, &mac) != nil {
			continue
		}
		orgVMs = append(orgVMs, vm) // no Tap: a host device name the tenant has no use for
		vmNet[vm.ID], vmMAC[vm.ID] = netID, mac
		netToVMs[netID] = append(netToVMs[netID], vm)
	}
	rows.Close()
	vmsOf := func(netID int64) []TopoVM { return append([]TopoVM(nil), netToVMs[netID]...) }

	type ctRow struct{ name, bridge, lxcpath, status string }
	var cts []ctRow
	if rows, err := s.db.Query(`SELECT name, COALESCE(bridge,''), COALESCE(lxcpath,''), status FROM containers WHERE org_id=?`, p.OrgID); err == nil {
		for rows.Next() {
			var c ctRow
			if rows.Scan(&c.name, &c.bridge, &c.lxcpath, &c.status) == nil {
				cts = append(cts, c)
			}
		}
		rows.Close()
	}
	bridgeCts := map[string][]TopoVM{}
	for _, c := range cts {
		st := "stopped"
		if c.status != "creating" && c.status != "error" {
			if info, _ := lxc.Info(c.name, c.lxcpath); info.State == "RUNNING" {
				st = "running"
			}
		}
		bridgeCts[c.bridge] = append(bridgeCts[c.bridge], TopoVM{Name: c.name, Kind: "container", State: st, Veth: lxc.VethName(c.name)})
	}

	placed := map[int64]bool{} // networks drawn on a switch
	for _, t := range tnets {
		sw := TopoSwitch{Name: t.Name, Kind: "standard", bridge: t.Bridge}
		def := TopoPortGroup{Name: t.NetName, CIDR: t.CIDR, VMs: vmsOf(t.NetworkID), netID: t.NetworkID}
		def.VMs = append(def.VMs, bridgeCts[t.Bridge]...)
		delete(bridgeCts, t.Bridge)
		sw.PortGroups = append(sw.PortGroups, def)
		placed[t.NetworkID] = true
		for _, pg := range t.PortGroups {
			sw.PortGroups = append(sw.PortGroups, TopoPortGroup{Name: pg.Name, VLAN: pg.VLAN, CIDR: pg.CIDR,
				VMs: vmsOf(pg.NetworkID), netID: pg.NetworkID})
			placed[pg.NetworkID] = true
		}
		if t.UplinkID != 0 {
			sw.Uplinks = append(sw.Uplinks, TopoUplink{Name: t.UplinkName + " · " + t.UplinkMode, Kind: "nic",
				State: s.uplinkLinkState(t.UplinkID)})
		}
		topo.Switches = append(topo.Switches, sw)
	}

	// The org's VXVisor Fabric port groups: one fabric switch (no host devices).
	if ft, ok := s.fabricTopo(); ok {
		sw := TopoSwitch{Name: "VXVisor Fabric · " + ft.name, Kind: "overlay", VXLAN: true,
			Uplinks: []TopoUplink{{Name: "VXVisor Fabric", Kind: "nic", State: "up"}}}
		if rows, err := s.db.Query(`SELECT id, name, COALESCE(bridge,''), COALESCE(cidr,'') FROM networks
			WHERE org_id=? AND mode='fabric' ORDER BY name`, p.OrgID); err == nil {
			for rows.Next() {
				var id int64
				var name, bridge, cidr string
				if rows.Scan(&id, &name, &bridge, &cidr) != nil {
					continue
				}
				placed[id] = true
				pg := TopoPortGroup{Name: name, CIDR: cidr, VMs: vmsOf(id), netID: id}
				pg.VMs = append(pg.VMs, bridgeCts[bridge]...)
				delete(bridgeCts, bridge)
				sw.PortGroups = append(sw.PortGroups, pg)
			}
			rows.Close()
		}
		if len(sw.PortGroups) > 0 {
			topo.Switches = append(topo.Switches, sw)
		}
	}

	// Networks the org was given that aren't its vSwitches: provider port groups
	// (named only — their host bridge stays hidden) and user-mode NAT ones.
	var provPGs, natPGs []TopoPortGroup
	if rows, err := s.db.Query(`SELECT id, name, COALESCE(bridge,''), COALESCE(cidr,''), COALESCE(vlan_id,0)
		FROM networks WHERE org_id=? ORDER BY name`, p.OrgID); err == nil {
		for rows.Next() {
			var id int64
			var name, bridge, cidr string
			var vlan int
			if rows.Scan(&id, &name, &bridge, &cidr, &vlan) != nil || placed[id] {
				continue
			}
			placed[id] = true
			pg := TopoPortGroup{Name: name, VLAN: vlan, CIDR: cidr, VMs: vmsOf(id), netID: id}
			if bridge == "" {
				natPGs = append(natPGs, pg)
			} else {
				provPGs = append(provPGs, pg)
			}
		}
		rows.Close()
	}
	if len(provPGs) > 0 {
		topo.Switches = append(topo.Switches, TopoSwitch{Name: "Provider networks", Kind: "standard", PortGroups: provPGs})
	}
	// VMs on no port group use user-mode NAT; containers on a bridge that isn't
	// one of this org's vSwitches go there too, so nothing is hidden.
	var loose []TopoVM
	for _, vm := range orgVMs {
		if !placed[vmNet[vm.ID]] {
			loose = append(loose, vm)
		}
	}
	for _, c := range bridgeCts {
		loose = append(loose, c...)
	}
	if len(natPGs) > 0 || len(loose) > 0 {
		if len(natPGs) == 0 {
			natPGs = []TopoPortGroup{{Name: "VM Network (NAT)"}}
		}
		natPGs[0].VMs = append(natPGs[0].VMs, loose...)
		topo.Switches = append(topo.Switches, TopoSwitch{Name: "VM Network (NAT)", Kind: "user-mode", PortGroups: natPGs})
	}

	s.mergeVRouters(topo, s.topoLegs(p.OrgID), p.OrgID, vmMAC, true)
	s.topoFillVMIPs(topo, vmMAC)
	return topo, nil
}

// uplinkLinkState is a tenant uplink's link as the tenant sees it: "up" when it's
// bound and its port (subinterface or dedicated NIC) is up — a trunk with no
// carrier shows as down without naming the provider's NIC.
func (s *Service) uplinkLinkState(uplinkID int64) string {
	port, _ := s.uplinkPort(uplinkID)
	if port == "" {
		return "down"
	}
	b, err := os.ReadFile("/sys/class/net/" + port + "/operstate")
	if st := strings.TrimSpace(string(b)); err == nil && (st == "up" || st == "unknown") {
		return "up"
	}
	return "down"
}
