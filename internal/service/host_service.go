package service

import (
	"vdxclone/internal/hostinfo"
	"vdxclone/internal/lxc"
	"vdxclone/internal/netdrv"
)

// HostInterfaces returns the host's network interfaces (admin only). Backs the
// create-network interface picker and the topology diagram.
func (s *Service) HostInterfaces(p *Principal) ([]hostinfo.Iface, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return hostinfo.Interfaces()
}

// HostBlockDevices returns whole disks + partitions (admin only). Backs the
// ZFS/LVM pool-creation disk picker.
func (s *Service) HostBlockDevices(p *Principal) ([]hostinfo.BlockDev, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	return hostinfo.BlockDevices()
}

// HostBrowseDir lists subdirectories of a host path (admin only). Backs the
// storage mount-point autocomplete.
func (s *Service) HostBrowseDir(p *Principal, path string) (string, []hostinfo.DirEntry, error) {
	if !p.IsAdmin {
		return "", nil, ErrUnauthorized
	}
	return hostinfo.BrowseDir(path)
}

// deviceInUse reports whether any of the given /dev paths is a block device
// that host introspection considers in use (mounted, has a filesystem, is a PV,
// or has active partition/holder children). It is the server-side safety net so
// a wipe-and-create operation can never target the OS/boot disk or a live pool
// member, even if the request bypasses the UI's free-disk picker.
func deviceInUse(paths []string) (path, note string, used bool) {
	devs, err := hostinfo.BlockDevices()
	if err != nil {
		return "", "", false
	}
	byPath := map[string]hostinfo.BlockDev{}
	var index func(hostinfo.BlockDev)
	index = func(bd hostinfo.BlockDev) {
		byPath[bd.Path] = bd
		for _, c := range bd.Children {
			index(c)
		}
	}
	for _, d := range devs {
		index(d)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if bd, ok := byPath[p]; ok && bd.InUse {
			return p, bd.UseNote, true
		}
	}
	return "", "", false
}

// DiskStatusRow is one whole physical disk with its SMART health (admin view).
type DiskStatusRow struct {
	Path    string `json:"path"`
	Model   string `json:"model"`
	Size    string `json:"size"`
	FSType  string `json:"fstype"`
	InUse   bool   `json:"in_use"`
	UseNote string `json:"use_note"`
	Health  string `json:"health"` // PASSED | FAILED | unknown | n/a
}

// DiskStatus lists whole disks with SMART health (admin only). Backs the storage
// page "Disk status" card and the ZFS replace/cache/log device pickers.
func (s *Service) DiskStatus(p *Principal) []DiskStatusRow {
	if !p.IsAdmin {
		return nil
	}
	devs, err := hostinfo.BlockDevices()
	if err != nil {
		return nil
	}
	smart := hostinfo.SmartAvailable()
	var out []DiskStatusRow
	for _, d := range devs {
		if d.Type != "disk" {
			continue
		}
		h := "n/a"
		if smart {
			h = hostinfo.SmartHealth(d.Path)
		}
		out = append(out, DiskStatusRow{
			Path: d.Path, Model: d.Model, Size: d.Size, FSType: d.FSType,
			InUse: d.InUse, UseNote: d.UseNote, Health: h,
		})
	}
	return out
}

// ---- topology ------------------------------------------------------------

// TopoVM is a VM (or LXC container) attached to a port group.
type TopoVM struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Tap   string `json:"tap"`
	State string `json:"state"` // running | stopped | ""
	Kind  string `json:"kind"`  // "" = VM, "container" = LXC container
}

// TopoPortGroup is a VMware-style port group (a network/VLAN) on a vSwitch.
type TopoPortGroup struct {
	Name string   `json:"name"`
	VLAN int      `json:"vlan"`
	CIDR string   `json:"cidr"`
	VMs  []TopoVM `json:"vms"`
}

// TopoUplink is a physical adapter attached to a vSwitch. When it is a bond it
// carries its link-aggregation members so the diagram can draw it as a LAG.
type TopoUplink struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`    // nic | bond
	Mode    string   `json:"mode"`    // bond mode (lacp/etherchannel/active-backup) when kind=bond
	Members []string `json:"members"` // bond member NICs
	State   string   `json:"state"`   // up | down
	Speed   int      `json:"speed"`   // Mbps (0 = unknown)
}

// TopoSwitch is a vSwitch: a host bridge (standard switch) or the synthetic
// user-mode switch, with its uplinks and port groups.
type TopoSwitch struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"` // standard | user-mode | overlay
	Uplinks    []TopoUplink    `json:"uplinks"`
	VXLAN      bool            `json:"vxlan"`
	Addrs      []string        `json:"addrs"`
	PortGroups []TopoPortGroup `json:"port_groups"`
}

// Topology is the whole host network picture for the VMware-style diagram.
type Topology struct {
	Switches []TopoSwitch     `json:"switches"`
	FreeNICs []hostinfo.Iface `json:"free_nics"` // physical NICs not on any vSwitch (free uplinks)
}

type netRow struct {
	id                       int64
	name, mode, bridge, cidr string
	vlan                     int
}

// NetworkTopology derives a VMware-style topology (vSwitch → port groups → VMs,
// plus uplinks). Real host bridges become standard vSwitches; when the host runs
// user-mode networking (no bridges), it synthesizes a single user-mode vSwitch so
// the diagram is never empty.
func (s *Service) NetworkTopology(p *Principal) (*Topology, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	ifaces, err := hostinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	// Map each session's deterministic tap name back to the VM, and collect all
	// (running/known) VMs for the user-mode case.
	tapToVM := map[string]TopoVM{}
	var allVMs []TopoVM
	netToVMs := map[int64][]TopoVM{} // port group id -> bound VMs
	if rows, err := s.db.Query(`SELECT id, name, state, COALESCE(network_id,0) FROM sessions WHERE deleted_at IS NULL`); err == nil {
		for rows.Next() {
			var id, name, state string
			var netID int64
			if rows.Scan(&id, &name, &state, &netID) == nil {
				vm := TopoVM{ID: id, Name: name, Tap: netdrv.TapName(id), State: state}
				tapToVM[vm.Tap] = vm
				allVMs = append(allVMs, vm)
				if netID > 0 {
					netToVMs[netID] = append(netToVMs[netID], vm)
				}
			}
		}
		rows.Close()
	}

	// LXC containers attach to a host bridge by name (containers.bridge), via a
	// randomly-named veth we can't match back — so group them by configured bridge
	// and render them under that vSwitch like VMs. Leftovers (no/unknown bridge)
	// fall through to the user-mode switch.
	bridgeToCts := map[string][]TopoVM{}
	if rows, err := s.db.Query(`SELECT name, COALESCE(bridge,''), COALESCE(lxcpath,''), status FROM containers`); err == nil {
		for rows.Next() {
			var name, brdg, lxcpath, status string
			if rows.Scan(&name, &brdg, &lxcpath, &status) != nil {
				continue
			}
			st := "stopped"
			if status != "creating" && status != "error" {
				if info, _ := lxc.Info(name, lxcpath); info.State == "RUNNING" {
					st = "running"
				}
			}
			bridgeToCts[brdg] = append(bridgeToCts[brdg], TopoVM{Name: name, Kind: "container", State: st})
		}
		rows.Close()
	}
	renderedBridges := map[string]bool{}

	// Index interfaces by name and build the bond → (mode, members) map so an
	// uplink that is a bond renders as a link-aggregation group.
	ifByName := map[string]hostinfo.Iface{}
	for _, it := range ifaces {
		ifByName[it.Name] = it
	}
	type bondRec struct {
		mode    string
		members []string
	}
	bonds := map[string]bondRec{}
	if bl, err := s.net.Bonds(); err == nil {
		for _, b := range bl {
			bonds[b.Name] = bondRec{mode: b.Mode, members: b.Members}
		}
	}
	mkUplink := func(name string) TopoUplink {
		u := TopoUplink{Name: name, Kind: "nic"}
		if it, ok := ifByName[name]; ok {
			u.State = it.State
			u.Speed = it.SpeedMbps
		}
		if b, ok := bonds[name]; ok {
			u.Kind = "bond"
			u.Mode = b.mode
			u.Members = b.members
		}
		return u
	}
	// Networks (port groups), across orgs.
	var nets []netRow
	if rows, err := s.db.Query(`SELECT id, name, mode, COALESCE(bridge,''), COALESCE(cidr,''), COALESCE(vlan_id,0) FROM networks`); err == nil {
		for rows.Next() {
			var n netRow
			if rows.Scan(&n.id, &n.name, &n.mode, &n.bridge, &n.cidr, &n.vlan) == nil {
				nets = append(nets, n)
			}
		}
		rows.Close()
	}

	// placed tracks VMs (by id) already shown on some vSwitch, so the user-mode
	// NAT block only picks up VMs that aren't on a standard vSwitch.
	topo := &Topology{}
	placed := map[string]bool{}
	for _, br := range ifaces {
		if br.Type != "bridge" {
			continue
		}
		sw := TopoSwitch{Name: br.Name, Kind: "standard", Addrs: br.Addrs}
		var looseVMs []TopoVM // taps on the bridge not bound to a specific port group
		for _, m := range ifaces {
			if m.Master != br.Name {
				continue
			}
			switch m.Type {
			case "tap":
				if vm, ok := tapToVM[m.Name]; ok {
					looseVMs = append(looseVMs, vm)
				} else {
					looseVMs = append(looseVMs, TopoVM{Name: m.Name, Tap: m.Name})
				}
			case "vxlan":
				sw.Uplinks = append(sw.Uplinks, mkUplink(m.Name))
				sw.VXLAN = true
				sw.Kind = "overlay"
			default:
				sw.Uplinks = append(sw.Uplinks, mkUplink(m.Name))
			}
		}
		// Port groups = networks bound to this bridge. Each port group lists the
		// VMs bound to it (sessions.network_id). VMs whose tap is on the bridge
		// but which aren't bound to any port group land on the first one.
		boundTaps := map[string]bool{}
		for _, n := range nets {
			if n.bridge != br.Name {
				continue
			}
			pg := TopoPortGroup{Name: n.name, VLAN: n.vlan, CIDR: n.cidr, VMs: netToVMs[n.id]}
			for _, vm := range pg.VMs {
				boundTaps[vm.Tap] = true
				placed[vm.ID] = true
			}
			sw.PortGroups = append(sw.PortGroups, pg)
		}
		if len(sw.PortGroups) == 0 {
			sw.PortGroups = []TopoPortGroup{{Name: "VM Network"}}
		}
		var unbound []TopoVM
		for _, vm := range looseVMs {
			if !boundTaps[vm.Tap] {
				unbound = append(unbound, vm)
				if vm.ID != "" {
					placed[vm.ID] = true
				}
			}
		}
		sw.PortGroups[0].VMs = append(sw.PortGroups[0].VMs, unbound...)
		// LXC containers configured on this bridge.
		if cts := bridgeToCts[br.Name]; len(cts) > 0 {
			sw.PortGroups[0].VMs = append(sw.PortGroups[0].VMs, cts...)
			renderedBridges[br.Name] = true
		}
		topo.Switches = append(topo.Switches, sw)
	}

	// Containers whose configured bridge isn't a live host bridge (or is empty)
	// go on the user-mode switch so they're never hidden.
	var looseCts []TopoVM
	for brdg, cts := range bridgeToCts {
		if !renderedBridges[brdg] {
			looseCts = append(looseCts, cts...)
		}
	}

	// User-mode / NAT vSwitch. Always included so the view is unified: it carries
	// every network that isn't bound to a host bridge (user/NAT, and overlay
	// networks before their bridge exists) plus any VM not already placed on a
	// standard vSwitch. Shown even when standard vSwitches exist.
	var natPGs []TopoPortGroup
	for _, n := range nets {
		if n.bridge != "" {
			continue // already shown under its standard vSwitch
		}
		vms := netToVMs[n.id]
		for _, vm := range vms {
			placed[vm.ID] = true
		}
		natPGs = append(natPGs, TopoPortGroup{Name: n.name, VLAN: n.vlan, CIDR: n.cidr, VMs: vms})
	}
	var natDefault []TopoVM
	for _, vm := range allVMs {
		if !placed[vm.ID] {
			natDefault = append(natDefault, vm)
		}
	}
	if len(natPGs) > 0 || len(natDefault) > 0 || len(looseCts) > 0 || len(topo.Switches) == 0 {
		uplink := ""
		for _, it := range ifaces { // the up physical NIC carrying the host IP
			if it.Type == "physical" && it.State == "up" && len(it.Addrs) > 0 {
				uplink = it.Name
				break
			}
		}
		sw := TopoSwitch{Name: "vSwitch0", Kind: "user-mode"}
		if uplink != "" {
			sw.Uplinks = []TopoUplink{mkUplink(uplink)}
		}
		if len(natPGs) == 0 {
			natPGs = []TopoPortGroup{{Name: "VM Network (NAT)"}}
		}
		natPGs[0].VMs = append(natPGs[0].VMs, natDefault...)
		natPGs[0].VMs = append(natPGs[0].VMs, looseCts...)
		sw.PortGroups = natPGs
		topo.Switches = append(topo.Switches, sw)
	}

	for _, it := range ifaces {
		if it.Type == "physical" && it.Master == "" {
			topo.FreeNICs = append(topo.FreeNICs, it)
		}
	}
	return topo, nil
}
