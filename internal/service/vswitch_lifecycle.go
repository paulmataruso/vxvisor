package service

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// Lifecycle of the admin host switching layer (NIC teams → vSwitches → port
// groups): the management vSwitch's default port group, VLAN filtering on every
// vSwitch, re-creating the ephemeral teams / vSwitches at boot, and the in-use
// checks that stop a vSwitch or port group being deleted out from under
// whatever rides it.
//
// Ownership rule: devices netplan defines (the management bridge and its bond)
// belong to netplan — vdxd never re-creates, re-enslaves or deletes them; it
// only turns VLAN filtering on (netplan can't express it). Teams and vSwitches
// vdxd created with `ip link` are vdxd's, and are rebuilt here after a reboot.

// Host hooks, swapped in tests so nothing touches the kernel.
var (
	ifaceExists        = netdrv.IfaceExists
	ensureBond         = netdrv.EnsureBond
	ensureVSwitch      = netdrv.EnsureVSwitch
	ensureVSwitchVlans = netdrv.EnsureVSwitchVlans
	vlanUpperVIDs      = netdrv.VlanUpperVIDs
	// mgmtWait bounds how long the boot re-ensure waits for the management
	// interface to become identifiable (e.g. a DHCP default route still coming up).
	mgmtWait = 20 * time.Second
)

// defaultPortGroupName is the ESXi-style default VM network on the default vSwitch.
const defaultPortGroupName = "VM Network"

// EnsureDefaultPortGroup registers the management bridge as a vSwitch when the
// management interface is one (e.g. the vSwitch0 install.sh creates), and on
// that first registration seeds an attachable "VM Network" port group on it,
// exactly like ESXi ships a default VM Network on vSwitch0. Attaching VM taps to
// the mgmt bridge never disturbs the mgmt IP (it just adds bridge ports).
//
// It only writes vdxd's own records — no device is touched. Once registered the
// default port group is never re-created, so an admin's deletion stays deleted;
// the recorded uplink is kept in step with the kernel (netplan owns the bridge,
// so its real uplink — e.g. a bond made outside vdxd — is the truth).
func (s *Service) EnsureDefaultPortGroup() error {
	br := s.mgmtIface()
	if br == "" {
		return nil
	}
	ifaces, err := hostIfaces()
	if err != nil {
		return err
	}
	isBridge := false
	for _, it := range ifaces {
		if it.Name == br && it.Type == "bridge" {
			isBridge = true
			break
		}
	}
	if !isBridge {
		return nil // a bare mgmt NIC has no vSwitch to hang a port group on
	}
	uplink := bridgeUplinkPort(ifaces, br)
	var vsName, vsUplink string
	switch err := s.db.QueryRow(`SELECT name,uplink FROM net_vswitches WHERE bridge=?`, br).Scan(&vsName, &vsUplink); {
	case err == sql.ErrNoRows:
		if _, err := s.net.AddVSwitch(br, br, uplink); err != nil {
			return err
		}
		log.Printf("registered default vSwitch %q (uplink %q)", br, uplink)
	case err != nil:
		return err
	default:
		if uplink != "" && uplink != vsUplink {
			if err := s.net.UpdateVSwitchUplink(vsName, uplink); err != nil {
				return err
			}
			log.Printf("management vSwitch %q: recorded uplink %q -> %q (netplan's)", vsName, vsUplink, uplink)
		}
		return nil
	}
	var orgID int64
	_ = s.db.QueryRow(`SELECT id FROM orgs WHERE slug='default'`).Scan(&orgID)
	if orgID == 0 {
		return nil
	}
	var existing int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM networks WHERE bridge=?`, br).Scan(&existing)
	if existing > 0 {
		return nil
	}
	if _, err := s.net.CreateNetwork(netdrv.Network{
		OrgID:  orgID,
		Name:   defaultPortGroupName,
		Mode:   "bridge",
		Bridge: br,
		VLANID: 0, // untagged — VMs share the mgmt L2 segment (ESXi default)
	}); err != nil {
		return err
	}
	log.Printf("created default port group %q on vSwitch %s", defaultPortGroupName, br)
	return nil
}

// bridgeUplinkPort returns a bridge's physical uplink: the one NIC, bond or VLAN
// device enslaved to it (VM taps, container veths, VXLAN ports and nested
// bridges are never uplinks). "" unless there is exactly one.
func bridgeUplinkPort(ifaces []hostinfo.Iface, bridge string) string {
	var found []string
	for _, it := range ifaces {
		if it.Master == bridge && (it.Type == "physical" || it.Type == "bond" || it.Type == "vlan") {
			found = append(found, it.Name)
		}
	}
	if len(found) == 1 {
		return found[0]
	}
	return ""
}

// masterOf returns the bridge/bond name is enslaved to ("" if none or unknown).
func masterOf(name string) string {
	ifs, err := hostIfaces()
	if err != nil {
		return ""
	}
	for _, it := range ifs {
		if it.Name == name {
			return it.Master
		}
	}
	return ""
}

// ---- VLAN filtering -------------------------------------------------------

// vswitchTaggedVIDs returns the VLANs a vSwitch bridge must carry tagged on its
// uplink: every port group (any org) and vRouter leg on it with a VID 2-4094.
func (s *Service) vswitchTaggedVIDs(bridge string) []int {
	rows, err := s.db.Query(`SELECT vlan_id FROM networks WHERE bridge=? AND vlan_id BETWEEN 2 AND 4094
		UNION SELECT vlan_id FROM vrouter_legs WHERE bridge=? AND vlan_id BETWEEN 2 AND 4094`, bridge, bridge)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if rows.Scan(&v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// ensureVSwitchVlans turns VLAN filtering on for one vSwitch (see
// netdrv.EnsureVSwitchVlans): VID 1 stays untagged on the bridge and uplink, the
// port groups' VIDs ride the uplink tagged, guest-tagged frames are dropped.
// The uplink is only touched when it really is a port of this bridge. A bridge
// that doesn't exist is skipped.
func (s *Service) ensureVSwitchVlans(v netdrv.VSwitch) error {
	if v.Bridge == "" || !ifaceExists(v.Bridge) {
		return nil
	}
	uplink := v.Uplink
	if uplink != "" && masterOf(uplink) != v.Bridge {
		log.Printf("vSwitch %s: uplink %s is not a port of %s — VLANs not trunked on it", v.Name, uplink, v.Bridge)
		uplink = ""
	}
	return ensureVSwitchVlans(v.Bridge, uplink, s.vswitchTaggedVIDs(v.Bridge), vlanUpperVIDs(v.Bridge))
}

// ensureVSwitchVlansFor re-applies VLAN filtering on the admin vSwitch whose
// bridge is given — after a tagged port group is added or the uplink changes. A
// bridge that isn't an admin vSwitch (tenant / vRouter bridges manage their own
// VLANs) is left alone. Logged, not fatal: the boot re-ensure retries.
func (s *Service) ensureVSwitchVlansFor(bridge string) {
	v, err := s.net.VSwitchByBridge(bridge)
	if err != nil {
		return
	}
	if err := s.ensureVSwitchVlans(v); err != nil {
		log.Printf("vSwitch %s: VLAN filtering: %v", v.Name, err)
	}
}

// ---- boot re-ensure -------------------------------------------------------

// ReensureVSwitches rebuilds the NIC teams and vSwitches vdxd made with ip link
// (ephemeral: a reboot loses them) and turns VLAN filtering on for every
// vSwitch, the management one included. Netplan-defined devices are never
// re-created or re-enslaved. A team whose NICs, or an uplink that, something
// else now uses (management, an address, another master, a trunk, the storage
// NIC, …) is not claimed: the team is skipped / the vSwitch comes back without
// its uplink, with a log line saying why. Idempotent; the worker calls it at
// boot before vRouters, trunks and tenant networks, which may sit on these.
func (s *Service) ReensureVSwitches() {
	// Every claim below needs the management interface known (guards fail
	// closed); give a DHCP default route a moment to appear.
	for deadline := time.Now().Add(mgmtWait); s.mgmtIface() == "" && time.Now().Before(deadline); {
		time.Sleep(time.Second)
	}
	if s.mgmtIface() == "" {
		log.Printf("vSwitch re-ensure: %v — NIC teams and vSwitch uplinks are not re-claimed", errMgmtUnknown)
	}
	owned := netplanDefinedIfaces()
	if bonds, err := s.net.Bonds(); err == nil {
		for _, b := range bonds {
			if err := s.reensureBond(b, owned); err != nil {
				log.Printf("re-ensure NIC team %s: %v", b.Name, err)
			}
		}
	}
	vss, err := s.net.VSwitches()
	if err != nil {
		log.Printf("re-ensure vSwitches: %v", err)
		return
	}
	for _, v := range vss {
		if err := s.reensureVSwitch(v, owned); err != nil {
			log.Printf("re-ensure vSwitch %s: %v", v.Name, err)
		}
	}
}

// reensureBond re-creates one recorded team if the kernel lost it, after
// checking its member NICs are still free (EnsureBond flushes their addresses).
func (s *Service) reensureBond(b netdrv.Bond, netplanOwned map[string]string) error {
	if netplanOwned[b.Name] != "" || ifaceExists(b.Name) {
		return nil // netplan's (e.g. the management bond), or still present
	}
	var vs string
	if s.db.QueryRow(`SELECT name FROM net_vswitches WHERE uplink=? AND bridge NOT LIKE 'vds%'`, b.Name).Scan(&vs) == nil {
		return fmt.Errorf("not re-created: it is the uplink of %s, which vdxd didn't create (netplan / the admin owns it)", vs)
	}
	if err := s.guardNICFree(b.Members...); err != nil {
		return fmt.Errorf("not re-created: %w", err)
	}
	mode, hash, _ := strings.Cut(b.Mode, "/") // stored label: "balance-alb", "lacp/layer3+4"
	if err := ensureBond(b.Name, mode, hash, b.Members); err != nil {
		return err
	}
	log.Printf("re-created NIC team %s (%s over %s)", b.Name, b.Mode, strings.Join(b.Members, ","))
	return nil
}

// reensureVSwitch re-creates one vSwitch's bridge if the kernel lost it (its
// uplink only if still free), then applies its VLAN filtering. Only bridges
// vdxd named itself (vds…, bridgeNameFor) are ever re-created — the management
// bridge is registered under its own name and is netplan's to bring up.
func (s *Service) reensureVSwitch(v netdrv.VSwitch, netplanOwned map[string]string) error {
	if v.Bridge == "" {
		return nil
	}
	if strings.HasPrefix(v.Bridge, "vds") && netplanOwned[v.Bridge] == "" && !ifaceExists(v.Bridge) {
		uplink := v.Uplink
		if uplink != "" {
			if err := s.uplinkFreeFor(uplink, v.Bridge); err != nil {
				log.Printf("vSwitch %s: re-creating it without its uplink: %v", v.Name, err)
				uplink = ""
			}
		}
		if err := ensureVSwitch(v.Bridge, uplink); err != nil {
			return err
		}
		log.Printf("re-created vSwitch %s (bridge %s, uplink %q)", v.Name, v.Bridge, uplink)
	}
	return s.ensureVSwitchVlans(v)
}

// uplinkFreeFor checks a vSwitch's recorded uplink is still safe to enslave to
// its bridge: present, not management, and not taken by anything else since —
// a trunk, the storage or routing uplink, a vRouter transit, a tenant dedicated
// uplink, another master, an address, or a device stacked on it.
func (s *Service) uplinkFreeFor(uplink, bridge string) error {
	if !ifaceExists(uplink) {
		return fmt.Errorf("uplink %s doesn't exist", uplink)
	}
	if err := s.guardMgmt(uplink); err != nil {
		return err
	}
	if s.isMgmtBridgeUplink(uplink) {
		return fmt.Errorf("uplink %s carries host management", uplink)
	}
	if s.extTrunkIfaces()[uplink] {
		return fmt.Errorf("uplink %s is a tenant egress trunk", uplink)
	}
	if st := s.StorageIface(); st != "" && st == uplink {
		return fmt.Errorf("uplink %s is the storage interface", uplink)
	}
	if c, err := s.GetRoutingConfig(&Principal{IsAdmin: true}); err == nil && c.Uplink == uplink {
		return fmt.Errorf("uplink %s is the L3 routing uplink", uplink)
	}
	var who string
	if s.db.QueryRow(`SELECT r.name FROM vrouter_legs l JOIN vrouters r ON r.id=l.vrouter_id WHERE l.phys_iface=?`, uplink).Scan(&who) == nil {
		return fmt.Errorf("uplink %s is the transit link of vRouter %q", uplink, who)
	}
	if s.db.QueryRow(`SELECT name FROM tenant_uplinks WHERE dedicated_iface=?`, uplink).Scan(&who) == nil {
		return fmt.Errorf("uplink %s is the dedicated interface of tenant uplink %q", uplink, who)
	}
	if ifs, err := hostIfaces(); err == nil {
		for _, it := range ifs {
			if it.Name != uplink {
				continue
			}
			if it.Master != "" && it.Master != bridge {
				return fmt.Errorf("uplink %s is enslaved to %s", uplink, it.Master)
			}
			if g := globalAddrs(it.Addrs); len(g) > 0 {
				return fmt.Errorf("uplink %s has addresses (%s)", uplink, strings.Join(g, ", "))
			}
		}
	}
	for _, u := range ifaceUppers(uplink) {
		if u != bridge {
			return fmt.Errorf("uplink %s is in use by %s", uplink, u)
		}
	}
	return nil
}

// globalAddrs filters CIDRs to non-link-local ones.
func globalAddrs(cidrs []string) []string {
	var out []string
	for _, a := range cidrs {
		if ip, _, err := net.ParseCIDR(a); err == nil && !ip.IsLinkLocalUnicast() {
			out = append(out, a)
		}
	}
	return out
}

// ---- in-use checks (delete) ----------------------------------------------

// queryNames runs a one-column query and returns the values (the cursor is
// closed before returning — the single DB connection can't nest queries).
func (s *Service) queryNames(q string, args ...any) []string {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out = append(out, n)
		}
	}
	return out
}

// nameList renders up to five names for a message ("a, b, c and 4 more").
func nameList(names []string) string {
	if len(names) <= 5 {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:5], ", "), len(names)-5)
}

// instancesOnNetwork selects the names of instances bound to port groups (Trash
// included: a restored VM would come back pointing at a deleted port group).
const instancesOnNetwork = `SELECT s.name || CASE WHEN s.deleted_at IS NOT NULL THEN ' (in Trash)' ELSE '' END
	FROM sessions s JOIN networks n ON n.id=s.network_id WHERE `

// vswitchInUse reports why a vSwitch can't be deleted: it carries management
// (or management can't be identified), netplan defines it, or something is
// still on it — instances, containers, VM/container NICs, port groups, a tenant
// trunk or uplink, or a vRouter link.
func (s *Service) vswitchInUse(v netdrv.VSwitch) error {
	if s.isMgmtIface(v.Bridge) || s.isMgmtIface(v.Name) {
		return fmt.Errorf("vSwitch %q carries host management (the admin IP) — deleting it would cut host access", v.Name)
	}
	if s.mgmtIface() == "" {
		return errMgmtUnknown
	}
	if f := netplanDefinedIfaces()[v.Bridge]; f != "" {
		return fmt.Errorf("vSwitch %q is defined in netplan (%s) — change it there, not here", v.Name, f)
	}
	if vms := s.queryNames(instancesOnNetwork+`n.bridge=? ORDER BY s.name`, v.Bridge); len(vms) > 0 {
		return fmt.Errorf("vSwitch %q has %d instance(s) on its port groups (%s) — move them to another port group first", v.Name, len(vms), nameList(vms))
	}
	if cts := s.queryNames(`SELECT name FROM containers WHERE bridge=? ORDER BY name`, v.Bridge); len(cts) > 0 {
		return fmt.Errorf("vSwitch %q has container(s) attached (%s) — move them to another network first", v.Name, nameList(cts))
	}
	if s.cfg != nil && s.cfg.Cluster.Bridge == v.Bridge && (s.cfg.Network.Mode == "bridge" || s.cfg.Network.Mode == "overlay") {
		return fmt.Errorf("vSwitch %q is the cluster bridge instances without a port group attach to ([cluster] bridge in the vdxd config)", v.Name)
	}
	if ifs, err := hostIfaces(); err == nil {
		var ports []string
		for _, it := range ifs {
			if it.Master == v.Bridge && (it.Type == "tap" || it.Type == "veth") {
				ports = append(ports, it.Name)
			}
		}
		if len(ports) > 0 {
			return fmt.Errorf("vSwitch %q still has VM/container NICs attached (%s) — stop or move them first", v.Name, nameList(ports))
		}
	}
	if pgs := s.queryNames(`SELECT name FROM networks WHERE bridge=? ORDER BY name`, v.Bridge); len(pgs) > 0 {
		return fmt.Errorf("vSwitch %q still has port groups (%s) — delete them first", v.Name, nameList(pgs))
	}
	if t := s.queryNames(`SELECT iface FROM ext_trunks WHERE iface<>'' AND iface IN (?,?)`, v.Bridge, v.Uplink); len(t) > 0 {
		return fmt.Errorf("vSwitch %q's uplink %s is a tenant egress trunk — remove the trunk on Tenant Egress first", v.Name, t[0])
	}
	if u := s.queryNames(`SELECT name FROM tenant_uplinks WHERE egress_bridge=? ORDER BY name`, v.Bridge); len(u) > 0 {
		return fmt.Errorf("tenant uplink %q egresses through vSwitch %q — disconnect it on Tenant Egress first", u[0], v.Name)
	}
	if r := s.queryNames(`SELECT r.name FROM vrouter_legs l JOIN vrouters r ON r.id=l.vrouter_id
		WHERE l.bridge=? OR (l.phys_iface<>'' AND l.phys_iface=?) ORDER BY r.name`, v.Bridge, v.Uplink); len(r) > 0 {
		return fmt.Errorf("vRouter %q has a link on vSwitch %q — detach it from the router first", r[0], v.Name)
	}
	return nil
}

// VSwitchesInUse maps each vSwitch that can't be deleted to why, so the
// Networks page shows that instead of a Delete button.
func (s *Service) VSwitchesInUse(p *Principal) map[string]string {
	out := map[string]string{}
	vss, err := s.ListVSwitches(p)
	if err != nil {
		return out
	}
	for _, v := range vss {
		if err := s.vswitchInUse(v); err != nil {
			out[v.Name] = err.Error()
		}
	}
	return out
}

// vswitchByNameOrBridge resolves a vSwitch by its name or its bridge device.
func (s *Service) vswitchByNameOrBridge(name string) (netdrv.VSwitch, error) {
	vss, err := s.net.VSwitches()
	if err != nil {
		return netdrv.VSwitch{}, err
	}
	for _, v := range vss {
		if v.Name == name {
			return v, nil
		}
	}
	for _, v := range vss {
		if v.Bridge == name {
			return v, nil
		}
	}
	return netdrv.VSwitch{}, fmt.Errorf("unknown vSwitch %q", name)
}

// portGroupInUse reports why a port group can't be deleted: a tenant vSwitch
// owns it, or instances, a vRouter leg or containers are bound to it.
func (s *Service) portGroupInUse(n netdrv.Network) error {
	var owner string
	if s.db.QueryRow(`SELECT name FROM tenant_networks WHERE network_id=?`, n.ID).Scan(&owner) == nil {
		return fmt.Errorf("port group %q is tenant vSwitch %q's own network — delete that vSwitch on the tenant's Networks page", n.Name, owner)
	}
	if s.db.QueryRow(`SELECT name FROM tenant_portgroups WHERE network_id=?`, n.ID).Scan(&owner) == nil {
		return fmt.Errorf("port group %q belongs to a tenant vSwitch — delete it on the tenant's Networks page", n.Name)
	}
	if vms := s.queryNames(instancesOnNetwork+`s.network_id=? ORDER BY s.name`, n.ID); len(vms) > 0 {
		return fmt.Errorf("%d instance(s) use port group %q (%s) — move them to another port group (or purge them from Trash) first", len(vms), n.Name, nameList(vms))
	}
	if r := s.queryNames(`SELECT r.name FROM vrouter_legs l JOIN vrouters r ON r.id=l.vrouter_id
		WHERE l.network_id=? OR (l.network_id=0 AND ?<>'' AND l.bridge=? AND l.vlan_id=?) ORDER BY r.name`,
		n.ID, n.Bridge, n.Bridge, n.VLANID); len(r) > 0 {
		return fmt.Errorf("vRouter %q has a leg on port group %q — detach it from the router first", r[0], n.Name)
	}
	// Containers attach to a bridge, not a port group: they ride its untagged
	// segment, so the last untagged port group on that bridge is theirs.
	if n.Bridge != "" && n.VLANID == 0 {
		var others int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM networks WHERE bridge=? AND vlan_id=0 AND id<>?`, n.Bridge, n.ID).Scan(&others)
		if cts := s.queryNames(`SELECT name FROM containers WHERE bridge=? ORDER BY name`, n.Bridge); others == 0 && len(cts) > 0 {
			return fmt.Errorf("container(s) %s are on port group %q (bridge %s) — move them to another network first", nameList(cts), n.Name, n.Bridge)
		}
	}
	return nil
}

// PortGroupsInUse maps each of the caller's port groups that can't be deleted
// to why, for the Networks page.
func (s *Service) PortGroupsInUse(p *Principal) map[int64]string {
	out := map[int64]string{}
	if !p.IsAdmin {
		return out
	}
	nets, err := s.ListNetworks(p)
	if err != nil {
		return out
	}
	for _, n := range nets {
		if err := s.portGroupInUse(n); err != nil {
			out[n.ID] = err.Error()
		}
	}
	return out
}
