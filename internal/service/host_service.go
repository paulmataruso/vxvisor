package service

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/lldp"
	"vdxclone/internal/lxc"
	"vdxclone/internal/netdrv"
	"vdxclone/internal/raidctl"
)

// bgpDownStates are the FRR "State/PfxRcd" values that mean a BGP peer is NOT
// established (an established peer shows a numeric prefix count there instead).
var bgpDownStates = map[string]bool{
	"Idle": true, "Connect": true, "Active": true, "OpenSent": true,
	"OpenConfirm": true, "Clearing": true, "Deleted": true,
}

// bgpAnyDown reports whether any BGP peer in an FRR "show ip bgp summary" output
// is NOT established. The summary's trailing "Desc" column can be free text
// (e.g. "N/A"), so we look for a known down-state token on a neighbour row rather
// than inspecting a fixed column.
func bgpAnyDown(summary string) bool {
	for _, ln := range strings.Split(summary, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 || net.ParseIP(f[0]) == nil {
			continue // not a neighbour row
		}
		for _, tok := range f[1:] {
			if bgpDownStates[tok] {
				return true
			}
		}
	}
	return false
}

// netAddr returns the network address for an "ip/prefix" CIDR (e.g.
// 10.111.100.2/30 → 10.111.100.0/30); returns the input unchanged if unparseable.
func netAddr(cidr string) string {
	if _, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil {
		return ipnet.String()
	}
	return cidr
}

// vrouterLeases returns the MAC→IP map from a vRouter's dnsmasq lease file(s).
// By id: names are only unique per org.
func (s *Service) vrouterLeases(id int64) map[string]string {
	out := map[string]string{}
	var runtime, container, lxcpath string
	if s.db.QueryRow(`SELECT runtime,container_name,lxcpath FROM vrouters WHERE id=?`, id).Scan(&runtime, &container, &lxcpath) != nil {
		return out
	}
	var files []string
	if runtime == "netns" {
		files, _ = filepath.Glob("/var/lib/vdxclone/vrouter/" + strconv.FormatInt(id, 10) + "/dnsmasq-*.leases")
	} else {
		files = []string{filepath.Join(lxc.RootfsPath(container, lxcpath), "var/lib/misc/dnsmasq.leases")}
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			// dnsmasq lease: "<expiry> <mac> <ip> <hostname> <clientid>"
			if fields := strings.Fields(line); len(fields) >= 3 {
				out[strings.ToLower(fields[1])] = fields[2]
			}
		}
	}
	return out
}

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
	// Classify bridges: a plain host bridge can be a vSwitch, a vRouter leg, a
	// storage/VM overlay bridge, or something external we didn't create. Only the
	// DB knows which, so the grouping label is assigned here (hostinfo can't).
	vswBridge := map[string]bool{} // bridge device -> is a vSwitch
	if rows, err := s.db.Query(`SELECT bridge FROM net_vswitches WHERE bridge<>''`); err == nil {
		for rows.Next() {
			var b string
			if rows.Scan(&b) == nil {
				vswBridge[b] = true
			}
		}
		rows.Close()
	}
	vrBridge := map[string]bool{} // bridge device -> is a vRouter leg (transit or internal)
	if rows, err := s.db.Query(`SELECT bridge FROM vrouter_legs WHERE bridge<>''`); err == nil {
		for rows.Next() {
			var b string
			if rows.Scan(&b) == nil {
				vrBridge[b] = true
			}
		}
		rows.Close()
	}
	out := all[:0]
	for _, i := range all {
		if i.Type == "tap" {
			continue // per-VM tap — hidden from the admin interface lists
		}
		i.Group = ifaceGroup(i, vswBridge, vrBridge)
		if (i.Type == "physical" || i.Type == "bond") && i.Master == "" {
			if err := s.guardIfaceInUse(i.Name, "interface"); err != nil {
				i.InUse = err.Error() // the bond / vSwitch pickers leave it out
			}
		}
		out = append(out, i)
	}
	return out, nil
}

// ifaceGroup returns the UI section label for an interface. Bridges are
// disambiguated with the DB (vSwitch vs vRouter leg); everything else maps
// straight off the link type.
func ifaceGroup(i hostinfo.Iface, vsw, vr map[string]bool) string {
	switch i.Type {
	case "physical":
		return "Physical interfaces"
	case "bond":
		return "Bonds / LAGs"
	case "vlan":
		return "VLAN interfaces"
	case "vxlan":
		return "VXLAN overlays"
	case "veth":
		return "Container veth (LXC)"
	case "loopback":
		return "Loopback"
	case "bridge":
		switch {
		case vsw[i.Name]:
			return "vSwitch bridges"
		case vr[i.Name]:
			return "vRouter bridges"
		default:
			return "Other bridges"
		}
	default:
		return "Other"
	}
}

// EnsurePhysicalLinksUp administratively brings every admin-down physical NIC
// up at boot, so the UI can show which ports have a live cable (carrier) even
// when they carry no configured network. Ports netplan defines are left to
// netplan. A port vdxd doesn't manage (managedNICs) first gets IPv6
// autoconfiguration turned off: an unconfigured port must never pick up an
// address from router advertisements on whatever it's cabled to (that would put
// a wildcard-bound admin UI on that network). Idempotent; one-shot at boot — it
// does NOT fight an admin who later downs a port by hand (there's no re-up loop).
func (s *Service) EnsurePhysicalLinksUp() {
	ifaces, err := hostIfaces()
	if err != nil {
		return
	}
	managed := s.managedNICs()
	planned := netplanDefinedIfaces()
	for _, it := range ifaces {
		if it.Type != "physical" || it.State == "up" {
			continue
		}
		if _, ok := planned[it.Name]; ok {
			continue
		}
		if !managed[it.Name] {
			if err := noIPv6Autoconf(it.Name); err != nil {
				log.Printf("leave %s down: can't turn off IPv6 autoconfiguration: %v", it.Name, err)
				continue
			}
		}
		if err := linkUp(it.Name); err != nil {
			log.Printf("bring up %s: %v", it.Name, err)
		}
	}
}

// linkUp and noIPv6Autoconf are swapped in tests.
var (
	linkUp         = netdrv.LinkUp
	noIPv6Autoconf = netdrv.NoIPv6Autoconf
)

// managedNICs is the set of devices vdxd configures itself: NIC-team members,
// vSwitch uplinks, dedicated tenant trunks (and their slaves) and dedicated
// uplinks, vRouter transit links — minus anything netplan defines (netplan
// brings those up and owns them).
func (s *Service) managedNICs() map[string]bool {
	out := map[string]bool{}
	if bonds, err := s.net.Bonds(); err == nil {
		for _, b := range bonds {
			for _, m := range b.Members {
				out[m] = true
			}
		}
	}
	for _, q := range []string{
		`SELECT uplink FROM net_vswitches WHERE uplink<>''`,
		`SELECT phys_iface FROM vrouter_legs WHERE phys_iface<>''`,
		`SELECT dedicated_iface FROM tenant_uplinks WHERE dedicated_iface<>''`,
	} {
		for _, n := range s.queryNames(q) {
			out[n] = true
		}
	}
	for n := range s.extTrunkIfaces() {
		out[n] = true
	}
	for n := range netplanDefinedIfaces() {
		delete(out, n)
	}
	return out
}

// TransitIface is a candidate interface for a directly-addressed routed link
// (e.g. a point-to-point transit to another router), as the L3 page lists them.
type TransitIface struct {
	Name      string   `json:"name"`
	State     string   `json:"state"`   // up | down | unknown
	Carrier   bool     `json:"carrier"` // a live cable is present
	SpeedMbps int      `json:"speed_mbps"`
	Addrs     []string `json:"addrs"`    // IPs already on it (e.g. a transit IP already assigned)
	Neighbor  string   `json:"neighbor"` // LLDP/CDP: "<switch> <port>" on the other end, if heard
}

// TransitCandidates returns the "free" interfaces usable for a routed/transit
// link: physical NICs (or bonds) that are NOT the management interface and are
// NOT enslaved to a bridge/bond. Enriched with link state, carrier, speed, any IPs
// already assigned, and the LLDP/CDP neighbor so the admin can see which ports are
// up, unused, and what they're wired to before assigning an IP.
// LLDPDetail returns the full LLDP/CDP neighbor fields for one interface.
func (s *Service) LLDPDetail(iface string) (sw, port, mgmt, descr string) {
	if n, ok := lldp.Neighbors()[iface]; ok {
		return n.SwitchName, n.PortID, n.MgmtIP, n.SwitchDescr
	}
	return "", "", "", ""
}

// LLDPNeighbors returns a simple iface → "switch port" label map for the UI.
func (s *Service) LLDPNeighbors() map[string]string {
	out := map[string]string{}
	for ifc, n := range lldp.Neighbors() {
		if lbl := strings.TrimSpace(n.SwitchName + " " + n.PortID); lbl != "" {
			out[ifc] = lbl
		}
	}
	return out
}

func (s *Service) TransitCandidates(p *Principal) ([]TransitIface, error) {
	if !p.IsAdmin {
		return nil, ErrUnauthorized
	}
	ifaces, err := hostinfo.Interfaces()
	if err != nil {
		return nil, err
	}
	mgmt := s.mgmtIfaces()
	if len(mgmt) == 0 {
		return nil, errMgmtUnknown // can't tell which NIC is management: offer none
	}
	storage := s.StorageIface()
	trunks := s.extTrunkIfaces()
	nbrs := lldp.Neighbors()
	var out []TransitIface
	for _, it := range ifaces {
		if it.Type != "physical" && it.Type != "bond" {
			continue
		}
		if slices.Contains(mgmt, it.Name) || it.Master != "" {
			continue // mgmt NIC or already enslaved to a vSwitch/bond — not free
		}
		if storage != "" && it.Name == storage {
			continue // the dedicated storage NIC (carries the Ceph/storage IP) — never a transit
		}
		if trunks[it.Name] {
			continue // a designated external trunk (bare NIC, Master=="") — reserved for tenant egress
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

// diskMountNote returns a non-empty reason when the disk (or any child) is
// currently mounted — the condition that must always block a reclaim wipe.
func diskMountNote(disk string) string {
	devs, err := hostinfo.BlockDevices()
	if err != nil {
		return ""
	}
	var walk func(hostinfo.BlockDev) string
	walk = func(bd hostinfo.BlockDev) string {
		if bd.Mount != "" {
			return "mounted at " + bd.Mount
		}
		for _, c := range bd.Children {
			if n := walk(c); n != "" {
				return n
			}
		}
		return ""
	}
	for _, d := range devs {
		if d.Path == disk {
			return walk(d)
		}
	}
	return ""
}

// storageStackMember returns a human label if the disk (or any of its children)
// is part of an active storage stack — LVM, software RAID, or LUKS — which must
// be torn down properly rather than blind-wiped. Empty string = safe to wipe.
func storageStackMember(d hostinfo.BlockDev) string {
	stack := map[string]string{
		"LVM2_member":       "an LVM volume group",
		"linux_raid_member": "a software RAID array",
		"crypto_LUKS":       "a LUKS container",
	}
	var walk func(hostinfo.BlockDev) string
	walk = func(b hostinfo.BlockDev) string {
		if lbl, ok := stack[b.FSType]; ok {
			return lbl
		}
		for _, c := range b.Children {
			if n := walk(c); n != "" {
				return n
			}
		}
		return ""
	}
	return walk(d)
}

// validDiskPath reports whether disk is a real whole-disk /dev path on this host.
func validDiskPath(disk string) bool {
	devs, err := hostinfo.BlockDevices()
	if err != nil {
		return false
	}
	for _, d := range devs {
		if d.Path == disk {
			return true
		}
	}
	return false
}

// DiskStatusRow is one whole physical disk with its SMART health (admin view).
type DiskStatusRow struct {
	Path        string `json:"path"`
	Model       string `json:"model"`
	Size        string `json:"size"`
	FSType      string `json:"fstype"`
	InUse       bool   `json:"in_use"`
	UseNote     string `json:"use_note"`
	Health      string `json:"health"`  // PASSED | FAILED | unknown | n/a
	Reclaim     bool   `json:"reclaim"` // can be cleared for reuse (Ceph remnants, not mounted)
	ReclaimNote string `json:"reclaim_note"`
	Wipeable    bool   `json:"wipeable"`  // has only inert leftovers (foreign partition table/fs) and is NOT actively used → safe to initialize
	WipeNote    string `json:"wipe_note"` // what's on it (for the button tooltip)
	Failed      bool   `json:"failed"`    // the drive has failed / dropped off the bus
	FailNote    string `json:"fail_note"` // why (for the UI + toast)
	Behind      string `json:"behind"`    // RAID controller this drive sits behind ("" = direct/kernel disk)
	State       string `json:"state"`     // controller's own drive state (Online/Rebuild/…) when Behind != ""
	Degraded    bool   `json:"degraded"`  // rebuilding / predictive — warn, not a hard failure
}

// reNVMeCtrl extracts the controller (nvme0) from a namespace device (nvme0n1).
var reNVMeCtrl = regexp.MustCompile(`^(nvme\d+)n\d+`)

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
	kerr := hostinfo.KernelDiskErrors()
	var out []DiskStatusRow
	for _, d := range devs {
		if d.Type != "disk" {
			continue
		}
		// Don't probe SMART on a dead device (0 bytes) — it only wastes the
		// run() timeout and reports "unknown" anyway; the size check flags it.
		h := "n/a"
		if smart && d.Bytes > 0 {
			h = hostinfo.SmartHealth(d.Path)
		}
		row := DiskStatusRow{
			Path: d.Path, Model: d.Model, Size: d.Size, FSType: d.FSType,
			InUse: d.InUse, UseNote: d.UseNote, Health: h,
		}
		// Failure detection — three independent signals, so a drive that drops off
		// the bus is caught even when SMART can't be read:
		//   1) the device now reports 0 bytes (offline / disabled controller),
		//   2) SMART overall-health self-assessment is FAILED,
		//   3) the kernel logged I/O errors or disabled the NVMe controller.
		switch {
		case d.Bytes == 0:
			row.Failed, row.FailNote = true, "device is offline — it reports 0 bytes (it dropped off the bus)"
		case h == "FAILED":
			row.Failed, row.FailNote = true, "SMART overall-health self-assessment: FAILED"
		}
		if r, ok := kerr[d.Name]; ok {
			row.Failed = true
			if row.FailNote == "" {
				row.FailNote = r
			}
		} else if m := reNVMeCtrl.FindStringSubmatch(d.Name); m != nil {
			if r, ok := kerr[m[1]]; ok {
				row.Failed = true
				if row.FailNote == "" {
					row.FailNote = r
				}
			}
		}
		// Offer a reclaim (wipe) only for a disk stranded by a removed Ceph OSD.
		if d.InUse {
			row.Reclaim, row.ReclaimNote = s.CephDiskReclaimable(d.Path)
		}
		// Generic initialize/wipe: a disk that carries only inert leftovers (a used
		// disk swapped in — e.g. a foreign Windows/data partition table) and is NOT
		// actively in use (not mounted, not part of an LVM/RAID/LUKS stack, not a
		// failed/offline drive). Lets an admin reclaim it from the UI; the hard
		// guards live again in WipeDisk server-side.
		if d.InUse && !row.Failed && !row.Reclaim && diskMountNote(d.Path) == "" {
			if storageStackMember(d) == "" {
				row.Wipeable, row.WipeNote = true, d.UseNote
			}
		}
		out = append(out, row)
	}
	return out
}

// RAIDGroupView is one virtual disk (disk group) behind a controller: the
// /dev node it appears as, its RAID type, and its physical member drives. A
// controller whose backend doesn't expose VD grouping yields a single group
// titled "Physical drives".
type RAIDGroupView struct {
	Dev    string // /dev/sdX this group maps to ("" if unresolved)
	RAID   string // "RAID 5", "RAID 0", … ("" for a plain physical-drive list)
	Size   string
	State  string // VD state, e.g. "Optimal"
	Name   string // controller's VD label, e.g. "BOOT"
	Group  int
	Drives []DiskStatusRow
}

// RAIDControllerView is one hardware RAID controller and its virtual disks, for
// the dedicated "RAID controller drives" card (kept separate from the kernel
// /dev disks, which are the controller's VIRTUAL disks that pools bind to).
type RAIDControllerView struct {
	Name   string
	Vendor string
	Tool   string
	Groups []RAIDGroupView
}

// raidMemberRow projects a raidctl.Drive onto a DiskStatusRow for the UI.
func raidMemberRow(dr raidctl.Drive) DiskStatusRow {
	loc := dr.Location
	if loc == "" {
		loc = "?"
	}
	row := DiskStatusRow{
		Path: loc, Model: dr.Model, Size: dr.Size, Health: dr.Health,
		Behind: dr.Controller, State: dr.State,
	}
	switch {
	case dr.Failed:
		row.Failed, row.FailNote = true, dr.Note
	case dr.Degraded:
		row.Degraded, row.FailNote = true, dr.Note
	}
	return row
}

// RAIDControllers lists the physical member drives behind each hardware RAID
// controller, grouped by virtual disk (admin only). These disks never appear in
// lsblk — the controller exposes only a virtual disk — so this is the only place
// a member's health / failure / RAID membership shows.
func (s *Service) RAIDControllers(p *Principal) []RAIDControllerView {
	if !p.IsAdmin {
		return nil
	}
	var out []RAIDControllerView
	for _, c := range raidctl.Enumerate().Controllers {
		v := RAIDControllerView{Name: c.Name, Vendor: c.Vendor, Tool: c.Tool}
		if len(c.VDisks) > 0 {
			for _, vd := range c.VDisks {
				g := RAIDGroupView{Dev: vd.Dev, RAID: vd.RAID, Size: vd.Size, State: vd.State, Name: vd.Name, Group: vd.Group}
				for _, dr := range vd.Members {
					g.Drives = append(g.Drives, raidMemberRow(dr))
				}
				v.Groups = append(v.Groups, g)
			}
		} else {
			// Backend without VD grouping (storcli/HPE/Adaptec) — flat list.
			g := RAIDGroupView{}
			for _, dr := range c.Drives {
				g.Drives = append(g.Drives, raidMemberRow(dr))
			}
			v.Groups = append(v.Groups, g)
		}
		out = append(out, v)
	}
	return out
}

// HostRestart reboots the physical host (admin only). It audits the request and
// then triggers `systemctl reboot` after a short delay so the HTTP response can
// flush first; systemd stops vdxd in order, which runs the graceful-VM-shutdown
// unit before the kernel reboots.
func (s *Service) HostRestart(p *Principal, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	s.audit(p, p.OrgID, "host.restart", "host", "", ip, nil)
	hostPowerAfterDelay("reboot")
	return nil
}

// HostShutdown powers off the physical host (admin only). Same ordering as
// HostRestart — graceful VM shutdown runs as vdxd is stopped.
func (s *Service) HostShutdown(p *Principal, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	s.audit(p, p.OrgID, "host.shutdown", "host", "", ip, nil)
	hostPowerAfterDelay("poweroff")
	return nil
}

// hostPowerAfterDelay fires `systemctl <verb>` after a brief pause so the caller
// can return an HTTP response before the connection drops.
func hostPowerAfterDelay(verb string) {
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = systemctl(verb)
	}()
}

// ControllerHints returns one install hint per RAID controller detected on the
// PCI bus whose management CLI is NOT installed — so the admin knows the single
// package to add to unlock per-drive SMART. Admin only.
func (s *Service) ControllerHints(p *Principal) []string {
	if !p.IsAdmin {
		return nil
	}
	var out []string
	for _, m := range raidctl.Enumerate().Missing {
		out = append(out, m.Vendor+" detected ("+m.PCI+") — "+m.Hint)
	}
	return out
}

// DriveAlert is a surfaced drive-failure, for the global toast poller.
type DriveAlert struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Msg   string `json:"msg"`
}

// NICAlert is a surfaced physical-NIC link failure, for the global toast poller.
type NICAlert struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Msg   string `json:"msg"`
}

// NICAlerts returns one alert per CONFIGURED physical NIC whose link is down — a
// NIC that is enslaved to a vSwitch/bond or carries an IP but has lost carrier
// (unplugged / switch-port down) or is admin-down. An unused, unconfigured NIC
// (vdxd holds those admin-up with no cable) is NOT alerted. Admin only.
func (s *Service) NICAlerts(p *Principal) []NICAlert {
	if !p.IsAdmin {
		return nil
	}
	ifs, err := s.HostInterfaces(p)
	if err != nil {
		return nil
	}
	var out []NICAlert
	for _, it := range ifs {
		if it.Type != "physical" {
			continue
		}
		configured := it.Master != "" || len(it.Addrs) > 0
		if !configured {
			continue // a spare NIC with no role — not a failure
		}
		if it.State != "down" && it.Carrier {
			continue // up with link — healthy
		}
		where := it.Master
		if where == "" && len(it.Addrs) > 0 {
			where = it.Addrs[0]
		}
		msg := it.Name
		if where != "" {
			msg += " (on " + where + ")"
		}
		if it.State == "down" {
			msg += " — interface is down"
		} else {
			msg += " — link is down (cable unplugged or switch port down)"
		}
		out = append(out, NICAlert{ID: "nic:" + it.Name, Title: "Network adapter down", Msg: msg})
	}
	return out
}

// DriveAlerts returns one alert per failed physical disk (admin only). Backs the
// /api/drive-alerts poller so a failure toasts from any page, not just /storage.
func (s *Service) DriveAlerts(p *Principal) []DriveAlert {
	if !p.IsAdmin {
		return nil
	}
	var out []DriveAlert
	for _, d := range s.DiskStatus(p) {
		if !d.Failed {
			continue
		}
		what := d.Path
		if d.Model != "" {
			what += " (" + d.Model + ")"
		}
		out = append(out, DriveAlert{ID: "disk:" + d.Path, Title: "Drive failure", Msg: what + " — " + d.FailNote})
	}
	// RAID controller member drives (hidden from lsblk, so scanned directly).
	for _, c := range raidctl.Enumerate().Controllers {
		for _, dr := range c.Drives {
			if !dr.Failed {
				continue
			}
			what := dr.Controller + " · " + dr.Location
			if dr.Model != "" {
				what += " (" + dr.Model + ")"
			}
			out = append(out, DriveAlert{ID: "raid:" + dr.Controller + ":" + dr.Location, Title: "RAID drive failure", Msg: what + " — " + dr.Note})
		}
	}
	return out
}

// ---- topology ------------------------------------------------------------

// TopoVM is a VM (or LXC container) attached to a port group.
type TopoVM struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Tap   string `json:"tap"`
	State string `json:"state"`        // running | stopped | ""
	Kind  string `json:"kind"`         // "" = VM, "container" = LXC container
	Veth  string `json:"veth"`         // container only: its host-side veth (drawn as an inline node)
	IP    string `json:"ip,omitempty"` // DHCP-assigned address (vRouter internal port groups)
}

// TopoPortGroup is a VMware-style port group (a network/VLAN) on a vSwitch.
type TopoPortGroup struct {
	Name string   `json:"name"`
	VLAN int      `json:"vlan"`
	CIDR string   `json:"cidr"`
	VMs  []TopoVM `json:"vms"`

	netID int64 // the networks row (vRouter merge key; not sent to the browser)
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
	// When this bridge belongs to a vRouter, its name + role (internal|transit) so
	// the diagram labels it as a vRouter component rather than a plain vSwitch.
	VRouter     string `json:"vrouter,omitempty"`
	VRouterRole string `json:"vrouter_role,omitempty"`

	bridge string // host bridge device (vRouter merge key; not sent to the browser)
}

// TopoVRInternal is one internal port group served by a vRouter (diagram).
type TopoVRInternal struct {
	Name   string   `json:"name"`
	GW     string   `json:"gw"`             // vRouter gateway IP/CIDR on this segment (IPv4)
	Subnet string   `json:"subnet"`         // the port-group subnet (networks.cidr)
	Bridge string   `json:"bridge"`         // host bridge device for this leg (e.g. vr4-bgp-test)
	Iface  string   `json:"iface"`          // the vRouter's interface on this leg (e.g. eth1)
	Zone   string   `json:"zone,omitempty"` // firewall zone this port group belongs to, if any
	VMs    []TopoVM `json:"vms"`
}

// TopoVRTransit is a vRouter's transit link + what it connects to (LLDP/CDP).
type TopoVRTransit struct {
	CIDR   string `json:"cidr"`
	Phys   string `json:"phys"`
	Bridge string `json:"bridge"` // host bridge device for the transit leg (e.g. vr4-wan)
	Iface  string `json:"iface"`  // the vRouter's transit interface (e.g. eth0)
	Switch string `json:"switch"`
	Port   string `json:"port"`
	Mgmt   string `json:"mgmt"`
	Descr  string `json:"descr"`
}

// TopoVRouter is a vRouter drawn as a single-flow chain: port groups → vRouter →
// transit → external port.
type TopoVRouter struct {
	Name     string           `json:"name"`
	Internal []TopoVRInternal `json:"internal"`
	Transit  *TopoVRTransit   `json:"transit,omitempty"`
	// Routing is the set of dynamic-routing protocols configured on this vRouter
	// (e.g. ["BGP","OSPF"]), shown as a tag in the box.
	Routing []string `json:"routing,omitempty"`
	// Health drives the status light next to the routing tag: "up" (green) when
	// every configured BGP peer is established, "down" (red) when a peer is down,
	// "" when there's nothing dynamic to monitor / the runtime isn't running.
	Health string `json:"health,omitempty"`
	// Runtime is the vRouter backend (lxc|netns), shown in the hover detail view.
	Runtime string `json:"runtime,omitempty"`
	// Firewall is true when the zone firewall is armed on this vRouter (shows a
	// shield pill on the box).
	Firewall bool `json:"firewall,omitempty"`
}

// Topology is the whole host network picture for the VMware-style diagram.
type Topology struct {
	Switches []TopoSwitch     `json:"switches"`
	FreeNICs []hostinfo.Iface `json:"free_nics"` // physical NICs not on any vSwitch (free uplinks)
	VRouters []TopoVRouter    `json:"vrouters,omitempty"`
}

type netRow struct {
	id                       int64
	name, mode, bridge, cidr string
	vlan                     int
}

// NetworkTopology derives a VMware-style topology (vSwitch → port groups → VMs,
// plus uplinks). Real host bridges become standard vSwitches; when the host runs
// user-mode networking (no bridges), it synthesizes a single user-mode vSwitch so
// the diagram is never empty. Anyone but an instance admin (incl. an admin in
// tenant view) gets only their own org's networks — see tenantTopology.
func (s *Service) NetworkTopology(p *Principal) (*Topology, error) {
	if !p.IsAdmin {
		if p.OrgID == 0 || !p.atLeast("viewer") {
			return nil, ErrUnauthorized
		}
		return s.tenantTopology(p)
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
	vmMAC := map[string]string{}     // vm id -> MAC (for DHCP-lease / ARP IP lookup)
	if rows, err := s.db.Query(`SELECT id, name, state, COALESCE(network_id,0), COALESCE(mac,'') FROM sessions WHERE deleted_at IS NULL`); err == nil {
		for rows.Next() {
			var id, name, state, mac string
			var netID int64
			if rows.Scan(&id, &name, &state, &netID, &mac) == nil {
				vm := TopoVM{ID: id, Name: name, Tap: netdrv.TapName(id), State: state}
				tapToVM[vm.Tap] = vm
				allVMs = append(allVMs, vm)
				vmNetID[vm.ID] = netID
				vmMAC[vm.ID] = mac
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
		sw := TopoSwitch{Name: br.Name, Kind: "standard", Addrs: br.Addrs, VMKs: mkVMKs(br.Name, br.Addrs), bridge: br.Name}
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
			pg := TopoPortGroup{Name: n.name, VLAN: n.vlan, CIDR: n.cidr, VMs: netToVMs[n.id], netID: n.id}
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
		natPGs = append(natPGs, TopoPortGroup{Name: n.name, VLAN: n.vlan, CIDR: n.cidr, VMs: vms, netID: n.id})
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
	// One node per vRouter (its legs pull their port groups / uplinks off the
	// switches), then every drawn VM's IP so a port group shows the same per-VM
	// info wherever it's connected.
	s.mergeVRouters(topo, s.topoLegs(0), p.OrgID, vmMAC, false)
	s.topoFillVMIPs(topo, vmMAC)
	return topo, nil
}
