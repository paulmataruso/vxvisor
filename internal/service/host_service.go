package service

import (
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/lldp"
	"vdxclone/internal/lxc"
	"vdxclone/internal/netdrv"
)

// HostInterfaces returns the host's network interfaces (admin only). Backs the
// create-network / storage-NIC interface pickers. Per-VM tap devices are filtered
// out — they're an internal implementation detail (one per running VM NIC) that
// only clutters the admin UI; the topology diagram uses hostinfo.Interfaces()
// directly and still renders taps as the VMs they belong to.
func (s *Service) HostInterfaces(p *Principal) ([]hostinfo.Iface, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	all, err := hostinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, i := range all {
		if i.Type == "tap" {
			continue // per-VM tap — hidden from the admin interface lists
		}
		out = append(out, i)
	}
	return out, nil
}

// EnsurePhysicalLinksUp administratively brings every physical NIC up, even ones
// carrying no configured network. A NIC left admin-down keeps its PHY powered off
// and never reports carrier, so the UI can't tell a plugged port from an empty
// one. Bringing them all up at boot makes "is a cable in this port?" visible in
// the GUI (the interface then shows carrier/link once a live cable is present).
// Idempotent and safe: bond/bridge members are already up, and an empty port just
// sits up with NO-CARRIER. One-shot at boot — it does NOT fight an admin who later
// downs a port by hand (there's no re-up loop).
func (s *Service) EnsurePhysicalLinksUp() {
	ifaces, err := hostinfo.Interfaces()
	if err != nil {
		return
	}
	for _, it := range ifaces {
		if it.Type != "physical" || it.State == "up" {
			continue
		}
		if err := netdrv.LinkUp(it.Name); err != nil {
			// Best effort: a NIC that refuses to come up is logged by the caller's
			// context, not fatal to boot.
			continue
		}
	}
}

// TransitIface is a candidate interface for a directly-addressed routed link
// (e.g. a point-to-point transit to another router), as the L3 page lists them.
type TransitIface struct {
	Name      string   `json:"name"`
	State     string   `json:"state"`     // up | down | unknown
	Carrier   bool     `json:"carrier"`   // a live cable is present
	SpeedMbps int      `json:"speed_mbps"`
	Addrs     []string `json:"addrs"`     // IPs already on it (e.g. a transit IP already assigned)
	Neighbor  string   `json:"neighbor"`  // LLDP/CDP: "<switch> <port>" on the other end, if heard
}

// TransitCandidates returns the "free" interfaces usable for a routed/transit
// link: physical NICs (or bonds) that are NOT the management interface and are
// NOT enslaved to a bridge/bond. Enriched with link state, carrier, speed, any IPs
// already assigned, and the LLDP/CDP neighbor so the admin can see which ports are
// up, unused, and what they're wired to before assigning an IP.
func (s *Service) TransitCandidates(p *Principal) ([]TransitIface, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	ifaces, err := hostinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	mgmt := s.mgmtIface()
	nbrs := lldp.Neighbors()
	var out []TransitIface
	for _, it := range ifaces {
		if it.Type != "physical" && it.Type != "bond" {
			continue
		}
		if it.Name == mgmt || it.Master != "" {
			continue // mgmt NIC or already enslaved to a vSwitch/bond — not free
		}
		ti := TransitIface{Name: it.Name, State: it.State, Carrier: it.Carrier, SpeedMbps: it.SpeedMbps, Addrs: it.Addrs}
		if n, ok := nbrs[it.Name]; ok {
			ti.Neighbor = strings.TrimSpace(n.SwitchName + " " + n.PortID)
		}
		out = append(out, ti)
	}
	return out, nil
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
	Veth  string `json:"veth"`  // container only: its host-side veth (drawn as an inline node)
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
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`      // nic | bond
	Mode      string          `json:"mode"`      // bond mode (lacp/etherchannel/active-backup) when kind=bond
	Members   []string        `json:"members"`   // bond member NICs
	State     string          `json:"state"`     // up | down
	Speed     int             `json:"speed"`     // Mbps (0 = unknown)
	Neighbors []lldp.Neighbor `json:"neighbors"` // upstream switch(es) learned via LLDP/CDP on this port (or its members)
}

// TopoVMK is a host IP endpoint on a vSwitch — a host-adapter box (e.g. the
// management interface), drawn as its own box on the left like an ESXi host adapter
// port so it's clear how the host's own IPs are wired to the switches.
type TopoVMK struct {
	Label string   `json:"label"` // "Management" or an interface name
	IPs   []string `json:"ips"`   // CIDRs on this one adapter (IPv4 + IPv6 together)
	Iface string   `json:"iface"` // the interface carrying it
}

// TopoSwitch is a vSwitch: a host bridge (standard switch), the synthetic
// user-mode switch, or a management switch for a NIC that carries a host IP.
type TopoSwitch struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"` // standard | user-mode | overlay | management
	Uplinks    []TopoUplink    `json:"uplinks"`
	VXLAN      bool            `json:"vxlan"`
	Addrs      []string        `json:"addrs"`
	VMKs       []TopoVMK       `json:"vmks"` // host IP adapters (host-adapter boxes)
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
	mgmtIf := s.mgmtIface() // the NIC carrying the admin IP, labelled "Management"
	// A host adapter is a HOST management endpoint. Only the interface that
	// carries the admin IP gets one — the SLAAC/link-local IPv6 that VM data
	// bridges pick up off the wire are not management endpoints and must not be
	// drawn as host adapters (that was the "7 copies on 3 switches" clutter).
	mkVMKs := func(iface string, addrs []string) []TopoVMK {
		if iface != mgmtIf || mgmtIf == "" {
			return nil
		}
		// One host adapter, carrying all of its real IPs (IPv4 + IPv6) — a
		// single box, exactly like one vmk in VMware, not one box per address.
		var ips []string
		for _, a := range addrs {
			if strings.HasPrefix(strings.ToLower(a), "fe80:") {
				continue // skip IPv6 link-local — it's noise, not a wired endpoint
			}
			ips = append(ips, a)
		}
		if len(ips) == 0 {
			return nil
		}
		return []TopoVMK{{Label: "Management", IPs: ips, Iface: iface}}
	}
	// Map each session's deterministic tap name back to the VM, and collect all
	// (running/known) VMs for the user-mode case.
	tapToVM := map[string]TopoVM{}
	var allVMs []TopoVM
	netToVMs := map[int64][]TopoVM{} // port group id -> bound VMs
	vmNetID := map[string]int64{}    // vm id -> its bound port group (0 = default/NAT)
	if rows, err := s.db.Query(`SELECT id, name, state, COALESCE(network_id,0) FROM sessions WHERE deleted_at IS NULL`); err == nil {
		for rows.Next() {
			var id, name, state string
			var netID int64
			if rows.Scan(&id, &name, &state, &netID) == nil {
				vm := TopoVM{ID: id, Name: name, Tap: netdrv.TapName(id), State: state}
				tapToVM[vm.Tap] = vm
				allVMs = append(allVMs, vm)
				vmNetID[vm.ID] = netID
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
			bridgeToCts[brdg] = append(bridgeToCts[brdg], TopoVM{Name: name, Kind: "container", State: st, Veth: lxc.VethName(name)})
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
	// LLDP/CDP neighbors per local port — so each uplink can show the upstream
	// switch it's wired to. Best effort (empty if lldpd absent / nothing heard).
	nbrs := lldp.Neighbors()
	addNbr := func(u *TopoUplink, port string) {
		if n, ok := nbrs[port]; ok {
			u.Neighbors = append(u.Neighbors, n)
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
			for _, m := range b.members { // a LAG's neighbors live on its member ports
				addNbr(&u, m)
			}
		} else {
			addNbr(&u, name)
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
	// A VM bound (network_id) to a port group whose bridge is a REAL host bridge is
	// rendered under that port group. Its live tap may still sit on its previous
	// bridge until the next start ("applies on next start"), which would otherwise
	// draw the VM a second time as a loose tap there — so suppress that loose copy.
	// (Only when the bound bridge actually exists, so a VM is never hidden.)
	realBridge := map[string]bool{}
	for _, it := range ifaces {
		if it.Type == "bridge" {
			realBridge[it.Name] = true
		}
	}
	netBridge := map[int64]string{}
	for _, n := range nets {
		netBridge[n.id] = n.bridge
	}
	boundElsewhere := map[string]bool{} // vm id -> shown under its bound port group
	for id, netID := range vmNetID {
		if netID > 0 && realBridge[netBridge[netID]] {
			boundElsewhere[id] = true
		}
	}

	// placed tracks VMs (by id) already shown on some vSwitch, so the user-mode
	// NAT block only picks up VMs that aren't on a standard vSwitch.
	topo := &Topology{}
	placed := map[string]bool{}
	for _, br := range ifaces {
		if br.Type != "bridge" {
			continue
		}
		sw := TopoSwitch{Name: br.Name, Kind: "standard", Addrs: br.Addrs, VMKs: mkVMKs(br.Name, br.Addrs)}
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
			case "veth":
				// A veth enslaved to the bridge is the host end of a container's
				// NIC (its peer is eth0 inside the container netns) — an ENDPOINT,
				// not an uplink. The container itself is drawn under this bridge via
				// bridgeToCts; the veth is recorded against it below, not here. Never
				// render it as an uplink (that mislabels a container cable as a NIC).
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
			// Skip a tap whose VM is bound to a port group on a real bridge — it's
			// drawn there, not as a loose tap on the bridge it hasn't left yet.
			if boundTaps[vm.Tap] || boundElsewhere[vm.ID] {
				if vm.ID != "" {
					placed[vm.ID] = true
				}
				continue
			}
			unbound = append(unbound, vm)
			if vm.ID != "" {
				placed[vm.ID] = true
			}
		}
		sw.PortGroups[0].VMs = append(sw.PortGroups[0].VMs, unbound...)
		// LXC containers configured on this bridge.
		if cts := bridgeToCts[br.Name]; len(cts) > 0 {
			sw.PortGroups[0].VMs = append(sw.PortGroups[0].VMs, cts...)
			renderedBridges[br.Name] = true
		}
		// Only draw a bridge that is actually in use: it has an uplink assigned OR
		// it has VMs/containers attached. An idle default bridge like lxcbr0 — no
		// uplink, no guests, just its auto NAT gateway IP — is noise and is hidden.
		// The management bridge is ALWAYS shown (it carries the admin IP and is the
		// anchor of the whole diagram), even with nothing attached.
		hasVMs := false
		for _, pg := range sw.PortGroups {
			if len(pg.VMs) > 0 {
				hasVMs = true
				break
			}
		}
		isMgmt := br.Name == mgmtIf
		if !isMgmt && len(sw.Uplinks) == 0 && !hasVMs {
			continue
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
		// User-mode/NAT networking does NOT bridge to a physical NIC — QEMU SLIRP
		// NATs out through the host's own routing. Showing a physical uplink here
		// (previously the management NIC) wrongly implied VM traffic rides that NIC,
		// so this switch is drawn with no uplink.
		sw := TopoSwitch{Name: "VM Network (NAT)", Kind: "user-mode"}
		if len(natPGs) == 0 {
			natPGs = []TopoPortGroup{{Name: "VM Network (NAT)"}}
		}
		natPGs[0].VMs = append(natPGs[0].VMs, natDefault...)
		natPGs[0].VMs = append(natPGs[0].VMs, looseCts...)
		sw.PortGroups = natPGs
		topo.Switches = append(topo.Switches, sw)
	}

	// Physical NICs not on any vSwitch. One that carries a host IP (the management
	// NIC, or a storage/other host IP) is drawn as its own management vSwitch with
	// a host-adapter box box showing the IP — so the diagram makes clear how
	// the host's own IPs are wired, VMware-style. An address-less NIC is a free
	// uplink available for a new vSwitch.
	for _, it := range ifaces {
		if it.Type != "physical" || it.Master != "" {
			continue
		}
		if len(it.Addrs) > 0 {
			name := "Management Network"
			if it.Name != mgmtIf {
				name = it.Name + " (host)"
			}
			topo.Switches = append(topo.Switches, TopoSwitch{
				Name:    name,
				Kind:    "management",
				Addrs:   it.Addrs,
				VMKs:    mkVMKs(it.Name, it.Addrs),
				Uplinks: []TopoUplink{mkUplink(it.Name)},
			})
		} else {
			topo.FreeNICs = append(topo.FreeNICs, it)
		}
	}
	return topo, nil
}
