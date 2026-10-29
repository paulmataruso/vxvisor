package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/routing"
	"vdxclone/internal/vrouter"
)

// vRouter (NSX-lite) orchestration: authz(admin)+audit over the pluggable
// vrouter.Backend (lxc|netns). A vRouter routes between a transit link (a free
// physical NIC) and internal-only port groups that VMs attach to. HOST-SAFE: the
// vRouter path renders FRR with vrouter.RenderForVRouter (→ routing.RenderFRR)
// and pushes it into the runtime; it NEVER calls the host routing.Apply* writers.

// VRouterView is a vRouter plus its legs and live status, for the UI.
type VRouterView struct {
	vrouter.VRouter
	Legs       []vrouter.Leg
	Cfg        routing.Config // parsed frr_json, for listing/deleting protocol entries
	LiveState  string
	RouteTable string
	// Tenant: a tenant org's gateway, whose routing runs under the tenant
	// policy (vrouter.ConstrainTenant).
	Tenant bool
	// Ignored lists stored routing entries the gateway doesn't run (outside
	// the tenant policy, or no longer valid).
	Ignored []string
	// Owned marks the downlinks (by network id) this gateway created itself;
	// removing one deletes its port group. Others are attached tenant segments
	// or port groups, which removing only detaches.
	Owned map[int64]bool
}

// Tier is the NSX-style gateway tier: "Tier-0" when it has a provider link
// (transit), else "Tier-1".
func (v VRouterView) Tier() string {
	for _, l := range v.Legs {
		if l.Kind == vrouter.LegTransit {
			return "Tier-0"
		}
	}
	return "Tier-1"
}

// parseFRRJSON decodes a router's stored routing config, cleaned of entries
// the renderer would refuse (routing.Sanitize). It is the view the page lists
// and the index-based CRUD edits, so an index always names the entry shown.
func parseFRRJSON(blob string) routing.Config {
	c, _ := decodeFRRJSON(blob)
	c, _ = routing.Sanitize(c)
	return c
}

func decodeFRRJSON(blob string) (routing.Config, error) {
	var c routing.Config
	if strings.TrimSpace(blob) != "" && blob != "{}" {
		if err := json.Unmarshal([]byte(blob), &c); err != nil {
			return c, fmt.Errorf("parse vrouter frr config: %w", err)
		}
	}
	return c, nil
}

// isTenantRouter reports whether a router belongs to a tenant org (any org but
// the provider's Default org), so its routing runs under the tenant policy. It
// fails closed: if the Default org can't be resolved, the router is a tenant's.
func (s *Service) isTenantRouter(v vrouter.VRouter) bool {
	def, err := s.store.DefaultOrgID()
	return err != nil || def == 0 || v.OrgID != def
}

// vrouterRouting returns the routing config a router actually runs: cfg cleaned
// of entries the renderer would refuse and, for a tenant router, limited by the
// tenant policy. ignored describes every stored entry left out.
func (s *Service) vrouterRouting(v vrouter.VRouter, legs []vrouter.Leg, cfg routing.Config) (routing.Config, []string) {
	eff, ignored := routing.Sanitize(cfg)
	if s.isTenantRouter(v) {
		var more []string
		eff, more = vrouter.ConstrainTenant(eff, legs)
		ignored = append(ignored, more...)
	}
	return eff, ignored
}

// fillView loads a router's legs and routing state into its view.
func (s *Service) fillView(view *VRouterView) {
	v := view.VRouter
	view.Legs, _ = s.loadLegs(v.ID)
	view.Cfg = parseFRRJSON(v.FRRJSON)
	view.Tenant = s.isTenantRouter(v)
	if stored, err := decodeFRRJSON(v.FRRJSON); err != nil {
		view.Ignored = []string{err.Error()}
	} else {
		_, view.Ignored = s.vrouterRouting(v, view.Legs, stored)
	}
	view.Owned = map[int64]bool{}
	for _, l := range view.Legs {
		if l.Kind == vrouter.LegInternal && l.NetworkID != 0 && !s.isTenantSegment(l.NetworkID) {
			view.Owned[l.NetworkID] = true
		}
	}
}

// VRouterInput is the create form.
type VRouterInput struct {
	Name    string
	Runtime string // lxc|netns
	CPUs    int
	MemMB   int
	Dist    string
	Release string
}

func (s *Service) vrouterRuntimeOK(rt string) bool {
	return rt == vrouter.RuntimeLXC || rt == vrouter.RuntimeNetns
}

// VRouterAvailable reports whether the caller (an org admin or instance admin)
// can use any vRouter runtime here. A per-org admin gets the netns runtime; an
// instance admin additionally gets lxc.
func (s *Service) VRouterAvailable(p *Principal) bool {
	if p == nil || !p.atLeast("admin") {
		return false
	}
	if p.IsAdmin {
		return vrouter.Available(vrouter.RuntimeLXC) || vrouter.Available(vrouter.RuntimeNetns)
	}
	return vrouter.Available(vrouter.RuntimeNetns)
}

// NetworkModeUser reports whether the daemon runs SLIRP (user-mode) networking,
// in which case internal-port-group VMs won't attach to a vRouter bridge (QEMU
// ignores the tap). The vRouter page shows a warning banner when true.
func (s *Service) NetworkModeUser() bool { return s.cfg.Network.Mode == "user" }

// VRouterRuntimes returns which runtimes are usable on this host (for the UI).
func (s *Service) VRouterRuntimes() map[string]bool {
	return map[string]bool{
		vrouter.RuntimeLXC:   vrouter.Available(vrouter.RuntimeLXC),
		vrouter.RuntimeNetns: vrouter.Available(vrouter.RuntimeNetns),
	}
}

const vrouterCols = `id,org_id,owner_id,name,runtime,container_name,netns_name,vm_session_id,image,
	lxcpath,dist,release,cpus,mem_mb,frr_json,fw_json,status,error`

func scanVRouter(row interface{ Scan(...any) error }) (vrouter.VRouter, error) {
	var v vrouter.VRouter
	err := row.Scan(&v.ID, &v.OrgID, &v.OwnerID, &v.Name, &v.Runtime, &v.ContainerName, &v.NetnsName,
		&v.VMSessionID, &v.Image, &v.LxcPath, &v.Dist, &v.Release, &v.CPUs, &v.MemMB, &v.FRRJSON,
		&v.FWJSON, &v.Status, &v.Error)
	return v, err
}

func parseFW(blob string) vrouter.VRFirewall {
	var f vrouter.VRFirewall
	if strings.TrimSpace(blob) != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &f)
	}
	return f
}

func (s *Service) getVRouter(p *Principal, id int64) (vrouter.VRouter, error) {
	row := s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=? AND org_id=?`, id, p.OrgID)
	v, err := scanVRouter(row)
	if err == sql.ErrNoRows {
		return v, ErrNotFound
	}
	return v, err
}

func (s *Service) loadLegs(vrID int64) ([]vrouter.Leg, error) {
	rows, err := s.db.Query(`SELECT l.id,l.vrouter_id,l.idx,l.kind,l.bridge,l.phys_iface,l.network_id,l.iface_name,l.cidr,l.mac,l.dhcp,l.dhcp_range,l.dhcp_dns,
		l.vlan_id,l.upstream_gw,l.snat,COALESCE(n.name,''),COALESCE(n.cidr,'')
		FROM vrouter_legs l LEFT JOIN networks n ON n.id=l.network_id WHERE l.vrouter_id=? ORDER BY l.idx`, vrID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vrouter.Leg
	for rows.Next() {
		var l vrouter.Leg
		var dhcp, snat int
		if err := rows.Scan(&l.ID, &l.VRouterID, &l.Idx, &l.Kind, &l.Bridge, &l.PhysIface, &l.NetworkID,
			&l.IfaceName, &l.CIDR, &l.MAC, &dhcp, &l.DHCPRange, &l.DHCPDNS, &l.VLAN, &l.UpstreamGW, &snat,
			&l.NetworkName, &l.NetworkCIDR); err != nil {
			return nil, err
		}
		l.DHCP = dhcp != 0
		l.SNAT = snat != 0
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListVRouters returns all vRouters for the org with live backend status.
func (s *Service) ListVRouters(p *Principal) ([]VRouterView, error) {
	if !p.atLeast("admin") {
		return nil, ErrUnauthorized
	}
	rows, err := s.db.Query(`SELECT `+vrouterCols+` FROM vrouters WHERE org_id=? ORDER BY name`, p.OrgID)
	if err != nil {
		return nil, err
	}
	// Read all rows FIRST and close the result set before any follow-up query:
	// the SQLite pool is capped at one connection, so calling loadLegs/Status
	// while these rows are still open would deadlock on the held connection.
	var vs []vrouter.VRouter
	for rows.Next() {
		v, err := scanVRouter(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		vs = append(vs, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]VRouterView, 0, len(vs))
	for _, v := range vs {
		view := VRouterView{VRouter: v}
		s.fillView(&view)
		if v.Status != "creating" && v.Status != "error" {
			if b, err := vrouterBackend(v.Runtime); err == nil {
				if ls, e := b.Status(v); e == nil {
					view.LiveState, view.RouteTable = ls.State, ls.RouteTable
				}
			}
		}
		out = append(out, view)
	}
	return out, nil
}

// GetVRouterView returns one vRouter with legs + live status.
func (s *Service) GetVRouterView(p *Principal, id int64) (VRouterView, error) {
	if !p.atLeast("admin") {
		return VRouterView{}, ErrUnauthorized
	}
	v, err := s.getVRouter(p, id)
	if err != nil {
		return VRouterView{}, err
	}
	view := VRouterView{VRouter: v}
	s.fillView(&view)
	if v.Status != "creating" && v.Status != "error" {
		if b, err := vrouterBackend(v.Runtime); err == nil {
			if ls, e := b.Status(v); e == nil {
				view.LiveState, view.RouteTable = ls.State, ls.RouteTable
			}
		}
	}
	return view, nil
}

// VRouterLive returns the vRouter's live routing state (route table, BGP/OSPF
// neighbors) for the status poller. Cheap-ish (a few vtysh calls in the runtime).
func (s *Service) VRouterLive(p *Principal, id int64) (vrouter.LiveStatus, error) {
	if !p.atLeast("admin") {
		return vrouter.LiveStatus{}, ErrUnauthorized
	}
	v, err := s.getVRouter(p, id)
	if err != nil {
		return vrouter.LiveStatus{}, err
	}
	if v.Status == "creating" || v.Status == "error" {
		return vrouter.LiveStatus{State: v.Status}, nil
	}
	b, err := vrouterBackend(v.Runtime)
	if err != nil {
		return vrouter.LiveStatus{}, err
	}
	return b.Status(v)
}

// CreateVRouter inserts a creating-status row and provisions the runtime async.
func (s *Service) CreateVRouter(p *Principal, in VRouterInput, ip string) (int64, error) {
	if !p.atLeast("admin") {
		return 0, ErrUnauthorized
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return 0, fmt.Errorf("a name is required")
	}
	// A per-org (non-instance) admin may only create the unprivileged netns
	// runtime — an lxc vRouter is a privileged container on the host, which a
	// tenant must never spawn. (Instance admins keep both.)
	if !p.IsAdmin && in.Runtime != vrouter.RuntimeNetns {
		return 0, fmt.Errorf("choose the netns runtime")
	}
	if !s.vrouterRuntimeOK(in.Runtime) {
		if in.Runtime == vrouter.RuntimeVM {
			return 0, fmt.Errorf("the VM-appliance vRouter runtime is coming in a later release")
		}
		return 0, fmt.Errorf("choose a runtime: lxc or netns")
	}
	if !vrouter.Available(in.Runtime) {
		return 0, fmt.Errorf("the %s runtime is not available on this host", in.Runtime)
	}
	// Router names are unique per ORG (migration 45). Check explicitly for a
	// friendly message instead of surfacing the UNIQUE(org_id,name) constraint.
	var dupe int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM vrouters WHERE org_id=? AND name=?`, p.OrgID, name).Scan(&dupe)
	if dupe > 0 {
		return 0, fmt.Errorf("a router named %q already exists in this organization", name)
	}
	cpus, mem := in.CPUs, in.MemMB
	if cpus < 1 {
		cpus = 1
	}
	if mem < 128 {
		mem = 512
	}
	dist, rel := in.Dist, in.Release
	if dist == "" {
		dist = "debian"
	}
	if rel == "" {
		rel = "trixie" // FRR 10.x, matches the frr.conf version banner
	}
	res, err := s.db.Exec(`INSERT INTO vrouters(org_id,owner_id,name,runtime,cpus,mem_mb,dist,release,status)
		VALUES(?,?,?,?,?,?,?,?,'creating')`, p.OrgID, p.User.ID, name, in.Runtime, cpus, mem, dist, rel)
	if err != nil {
		return 0, fmt.Errorf("create vrouter: %w", err)
	}
	id, _ := res.LastInsertId()
	nm := "vrtr-" + strconv.FormatInt(id, 10)
	if _, err := s.db.Exec(`UPDATE vrouters SET container_name=?, netns_name=? WHERE id=?`, nm, nm, id); err != nil {
		return 0, err
	}
	s.audit(p, p.OrgID, "vrouter.create", "vrouter", name, ip, map[string]any{"runtime": in.Runtime})

	go func() {
		v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, id))
		if err != nil {
			return
		}
		b, err := vrouterBackend(v.Runtime)
		if err != nil {
			s.vrouterFail(id, err)
			return
		}
		if err := b.Provision(v, nil); err != nil {
			s.vrouterFail(id, err)
			return
		}
		s.db.Exec(`UPDATE vrouters SET status='stopped', error='' WHERE id=?`, id)
	}()
	return id, nil
}

func (s *Service) vrouterFail(id int64, err error) {
	s.db.Exec(`UPDATE vrouters SET status='error', error=? WHERE id=?`, err.Error(), id)
}

// bridge names (≤15 chars, the IFNAMSIZ limit). Scheme 2 — "vr<id>-<purpose>":
// the transit leg is "vr<id>-wan"; an internal leg is "vr<id>-<port-group-slug>".
// The "vr<id>-" root keeps every name unique across vRouters, while the human
// suffix mirrors what the UI shows (the port-group name) so the device name is
// self-explanatory (e.g. vr3-wan, vr3-bgp-test).
func transitBridge(vrID int64) string { return "vr" + strconv.FormatInt(vrID, 10) + "-wan" }

// internalBridge builds an internal leg's device name from the port-group name.
// taken = device names already used by this vRouter's other legs, so two port
// groups that slug to the same token don't collide (the loser falls back to the
// guaranteed-unique "lan<idx>" form). The slug is truncated to fit 15 chars.
func internalBridge(vrID int64, idx int, pgName string, taken map[string]bool) string {
	root := "vr" + strconv.FormatInt(vrID, 10) + "-"
	budget := 15 - len(root)
	if budget < 1 {
		budget = 1
	}
	slug := bridgeSlug(pgName)
	if len(slug) > budget {
		slug = strings.TrimRight(slug[:budget], "-")
	}
	name := root + slug
	if slug == "" || taken[name] {
		name = root + "lan" + strconv.Itoa(idx) // generic, always unique per vRouter
		if len(name) > 15 {
			name = name[:15]
		}
	}
	return name
}

// bridgeSlug reduces a human name to a lowercase [a-z0-9-] token: runs of other
// characters collapse to one dash, leading/trailing dashes are trimmed.
func bridgeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// legBridges returns the set of device names already used by a vRouter's legs.
func (s *Service) legBridges(vrID int64) map[string]bool {
	m := map[string]bool{}
	rows, err := s.db.Query(`SELECT bridge FROM vrouter_legs WHERE vrouter_id=? AND bridge<>''`, vrID)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var b string
		if rows.Scan(&b) == nil {
			m[b] = true
		}
	}
	return m
}

// nextLegIdx returns the next free leg index (0 = transit).
func (s *Service) nextLegIdx(vrID int64) int {
	var mx sql.NullInt64
	s.db.QueryRow(`SELECT MAX(idx) FROM vrouter_legs WHERE vrouter_id=?`, vrID).Scan(&mx)
	if !mx.Valid {
		return 0
	}
	return int(mx.Int64) + 1
}

// AddTransitLink binds a free physical NIC to the vRouter's transit leg (eth0).
func (s *Service) AddTransitLink(p *Principal, vrID int64, physIface, cidr, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	physIface, cidr = strings.TrimSpace(physIface), strings.TrimSpace(cidr)
	if physIface == "" || cidr == "" {
		return fmt.Errorf("an interface and a provider-link IP/CIDR are required")
	}
	if err := routing.ValidIface(physIface); err != nil {
		return err
	}
	if err := validLegCIDR(cidr); err != nil {
		return err
	}
	// Guard: never the mgmt NIC; must be a free (non-enslaved) transit candidate.
	if err := s.guardMgmt(physIface); err != nil {
		return err
	}
	if err := s.guardTrunk(physIface); err != nil {
		return err
	}
	cands, _ := s.TransitCandidates(p)
	ok := false
	for _, c := range cands {
		if c.Name == physIface {
			ok = true
			// A NIC that already carries an IP is in use (storage/overlay/etc.);
			// the transit attach enslaves it to a bridge and FLUSHES its address,
			// which would break whatever depends on it. Refuse — the operator must
			// free it first. (This is the safety net that stops a vRouter from
			// stealing the Ceph storage NIC and wedging the cluster.)
			if len(c.Addrs) > 0 {
				return fmt.Errorf("%s already has an IP (%v) — it's in use; free it before using it as a transit link", physIface, c.Addrs)
			}
			break
		}
	}
	if !ok {
		return fmt.Errorf("%s is not a free transit interface (it may be the mgmt NIC, the storage NIC, enslaved, or missing)", physIface)
	}
	if n := s.legCount(vrID, vrouter.LegTransit); n > 0 {
		return fmt.Errorf("this gateway already has a provider link")
	}
	br := transitBridge(vrID)
	if err := netdrv.EnsureBridge(br); err != nil {
		return err
	}
	if err := netdrv.EnslaveToBridge(physIface, br); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,phys_iface,iface_name,cidr)
		VALUES(?,?,?,?,?,?,?)`, vrID, 0, vrouter.LegTransit, br, physIface, "eth0", cidr); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.transit.add", "vrouter", v.Name, ip, map[string]any{"iface": physIface, "cidr": cidr})
	return s.applyAndPush(vrID)
}

// DeleteTransitLink removes a router's provider link (Tier-0 uplink): it takes
// the leg out of the runtime, releases the physical NIC from the link's bridge
// and deletes that bridge. Instance admin only — it changes a host NIC.
func (s *Service) DeleteTransitLink(p *Principal, vrID int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	legs, err := s.loadLegs(vrID)
	if err != nil {
		return err
	}
	var tr *vrouter.Leg
	for i := range legs {
		if legs[i].Kind == vrouter.LegTransit {
			tr = &legs[i]
		}
	}
	if tr == nil {
		return fmt.Errorf("this gateway has no provider link")
	}
	if b, err := vrouterBackend(v.Runtime); err == nil {
		if err := b.RemoveLeg(v, *tr); err != nil {
			log.Printf("vrouter %s: remove provider link: %v", v.Name, err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM vrouter_legs WHERE vrouter_id=? AND kind=?`, vrID, vrouter.LegTransit); err != nil {
		return err
	}
	if tr.PhysIface != "" {
		if err := netdrv.DetachFromBridge(tr.PhysIface); err != nil {
			log.Printf("vrouter %s: release %s from %s: %v", v.Name, tr.PhysIface, tr.Bridge, err)
		}
	}
	if tr.Bridge != "" {
		netdrv.DeleteLink(tr.Bridge)
	}
	s.audit(p, p.OrgID, "vrouter.transit.delete", "vrouter", v.Name, ip, map[string]any{"iface": tr.PhysIface, "cidr": tr.CIDR})
	return s.applyAndPush(vrID)
}

// validLegCIDR checks a router interface address (IPv4 address with a prefix of
// at least vrouter.MinLegPrefix).
func validLegCIDR(cidr string) error {
	if err := routing.ValidIfaceAddr(cidr); err != nil {
		return err
	}
	_, n, _ := net.ParseCIDR(cidr)
	if ones, _ := n.Mask.Size(); ones < vrouter.MinLegPrefix {
		return fmt.Errorf("%s: an interface prefix must be /%d or longer", cidr, vrouter.MinLegPrefix)
	}
	return nil
}

// AttachInternalNetwork creates an isolated internal port group served by the
// vRouter (its leg IP is the gateway) and attaches a new leg. Optionally runs
// DHCP on the leg. Instance admin only: it creates a host bridge outside the
// tenant vSwitch model (a tenant's gateway attaches its own segments and port
// groups instead — AttachSegment / AttachPortGroup).
func (s *Service) AttachInternalNetwork(p *Principal, vrID int64, name, cidr, gatewayCIDR string, dhcp bool, dhcpRange, dns, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if v.Status == "creating" {
		return fmt.Errorf("the router is still being created — wait a moment, then attach")
	}
	name, cidr = strings.TrimSpace(name), strings.TrimSpace(cidr)
	if name == "" || strings.TrimSpace(gatewayCIDR) == "" {
		return fmt.Errorf("a name and the gateway's IP/CIDR on the downlink are required")
	}
	if cidr != "" {
		if cidr, err = routing.CanonPrefix(cidr); err != nil {
			return err
		}
	}
	gwIP, gatewayCIDR, err := legAddr(gatewayCIDR, cidr)
	if err != nil {
		return err
	}
	dhcpRange, dns, err = legDHCP(dhcp, dhcpRange, dns, gatewayCIDR)
	if err != nil {
		return err
	}
	idx := s.nextLegIdx(vrID)
	if idx == 0 {
		idx = 1 // internal legs start at eth1; eth0 is reserved for transit
	}
	br := internalBridge(vrID, idx, name, s.legBridges(vrID))
	if err := netdrv.EnsureBridge(br); err != nil {
		return err
	}
	// A networks row so VMs can bind to this port group via the normal tap path.
	// gateway = the vRouter leg IP (the VM's default gateway). vlan_id=0 avoids
	// the VLAN-stranding trap.
	nid, err := s.CreateNetwork(p, netdrv.Network{
		Name: name, Mode: "bridge", Bridge: br, VLANID: 0, CIDR: cidr, Gateway: gwIP,
	}, ip)
	if err != nil {
		netdrv.DeleteLink(br)
		return fmt.Errorf("create internal port group: %w", err)
	}
	if _, err := s.db.Exec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,dhcp,dhcp_range,dhcp_dns)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, vrID, idx, vrouter.LegInternal, br, nid, "eth"+strconv.Itoa(idx),
		gatewayCIDR, b2iDHCP(dhcp), dhcpRange, dns); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.internal.add", "vrouter", v.Name, ip,
		map[string]any{"network": name, "cidr": cidr, "gateway": gwIP, "dhcp": dhcp})
	if err := s.applyAndPush(vrID); err != nil {
		return err
	}
	if dhcp {
		return s.applyDHCP(vrID, idx)
	}
	return nil
}

// AttachSegment attaches an EXISTING, owned tenant segment (resolved by its
// tenant_networks id, scoped to the caller's org) as an internal leg of a
// vRouter. The leg lands on the SEGMENT's own bridge — derived from the row,
// never from client input (so a crafted request can't land a leg on a shared or
// foreign bridge). Only a GATEWAYLESS segment may be attached: the router leg
// becomes its sole gateway (no live gateway-ownership handoff). The leg's
// gateway IP (gatewayCIDR) must sit inside the segment's subnet.
func (s *Service) AttachSegment(p *Principal, vrID, tnetID int64, gatewayCIDR string, dhcp bool, dhcpRange, dns, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	// Don't attach while the router is still provisioning: applyAndPush would race
	// the background Provision goroutine (half-built FRR dir → zebra never loads
	// the leg config). Make the caller wait until it reaches stopped/running.
	if v.Status == "creating" {
		return fmt.Errorf("the router is still being created — wait a moment, then attach the segment")
	}
	if v.Status == "error" {
		return fmt.Errorf("the router is in an error state (%s) — fix or recreate it before attaching", v.Error)
	}
	// Resolve the segment, scoped to the caller's org. Anything not owned by the
	// org (or not a tenant segment) is rejected here.
	var netID, attachedTo int64
	var bridge, segCIDR, segGW, segName string
	err = s.db.QueryRow(`SELECT t.network_id,t.vrouter_id,t.name,COALESCE(n.bridge,''),COALESCE(n.cidr,''),COALESCE(n.gateway,'')
		FROM tenant_networks t JOIN networks n ON n.id=t.network_id WHERE t.id=? AND t.org_id=?`, tnetID, p.OrgID).
		Scan(&netID, &attachedTo, &segName, &bridge, &segCIDR, &segGW)
	if err == sql.ErrNoRows {
		return fmt.Errorf("segment not found in this organization")
	}
	if err != nil {
		return err
	}
	if bridge == "" || bridge == s.mgmtIface() {
		return fmt.Errorf("refusing to attach a router leg to %q", bridge)
	}
	if attachedTo != 0 {
		return fmt.Errorf("that segment is already attached to a router")
	}
	if strings.TrimSpace(segGW) != "" {
		return fmt.Errorf("that segment has its own gateway — detach its gateway, or create a routed (gatewayless) segment, before attaching it to a router")
	}
	if mode, native := s.vswitchEgress(tnetID); carriedOut(mode, native, 0) {
		return fmt.Errorf("that vSwitch's untagged port group is carried out its uplink (the upstream network owns its gateway) — connect the router to the uplink instead")
	}
	gwIP, gatewayCIDR, err := legAddr(gatewayCIDR, segCIDR)
	if err != nil {
		return err
	}
	dhcpRange, dns, err = legDHCP(dhcp, dhcpRange, dns, gatewayCIDR)
	if err != nil {
		return err
	}
	idx := s.nextLegIdx(vrID)
	if idx == 0 {
		idx = 1
	}
	// Record the gateway on the segment's networks row (display + default route
	// source for VMs); the router leg actually answers for it on the same L2.
	if _, err := s.db.Exec(`UPDATE networks SET gateway=? WHERE id=?`, gwIP, netID); err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,dhcp,dhcp_range,dhcp_dns)
		VALUES(?,?,?,?,?,?,?,?,?,?)`, vrID, idx, vrouter.LegInternal, bridge, netID, "eth"+strconv.Itoa(idx),
		gatewayCIDR, b2iDHCP(dhcp), dhcpRange, dns); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE tenant_networks SET vrouter_id=? WHERE id=?`, vrID, tnetID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.segment.attach", "vrouter", v.Name, ip,
		map[string]any{"segment": segName, "gateway": gwIP, "dhcp": dhcp})
	if err := s.applyAndPush(vrID); err != nil {
		return err
	}
	if dhcp {
		return s.applyDHCP(vrID, idx)
	}
	return nil
}

// DetachSegment removes a downlink from a vRouter. An attached tenant segment or
// port group is only detached (its bridge/networks row + any VMs survive; its
// gateway is cleared so it can be attached again). An internal port group the
// router created itself (AttachInternalNetwork) has no life of its own, so it is
// deleted with its bridge — refused while instances are still on it. Either way
// the leg is taken out of the runtime (its veth pair; the bridge it sat on is
// left alone), its row dropped, and FRR re-pushed.
func (s *Service) DetachSegment(p *Principal, vrID, netID int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	legs, err := s.loadLegs(vrID)
	if err != nil {
		return err
	}
	var leg *vrouter.Leg
	for i := range legs {
		if legs[i].Kind == vrouter.LegInternal && legs[i].NetworkID == netID && netID != 0 {
			leg = &legs[i]
		}
	}
	if leg == nil {
		return fmt.Errorf("that network is not a downlink of this gateway")
	}
	// Resolve the owner by the backing networks id, scoped to the org — a
	// tenant segment, a vSwitch port group, or (neither) the router's own.
	var tnetID, pgID int64
	var segName string
	err = s.db.QueryRow(`SELECT id,name FROM tenant_networks WHERE network_id=? AND org_id=?`, netID, p.OrgID).Scan(&tnetID, &segName)
	if err == sql.ErrNoRows {
		err = s.db.QueryRow(`SELECT id,name FROM tenant_portgroups WHERE network_id=? AND org_id=?`, netID, p.OrgID).Scan(&pgID, &segName)
	}
	owned := false
	if err == sql.ErrNoRows {
		if err = s.db.QueryRow(`SELECT name FROM networks WHERE id=? AND org_id=?`, netID, p.OrgID).Scan(&segName); err == sql.ErrNoRows {
			return fmt.Errorf("that network is not in this organization")
		}
		owned = true
	}
	if err != nil {
		return err
	}
	if owned {
		// The same instance / container rules as deleting the port group itself
		// (an instance in Trash still points at it), checked before the leg goes.
		if vms := s.queryNames(instancesOnNetwork+`s.network_id=? ORDER BY s.name`, netID); len(vms) > 0 {
			return fmt.Errorf("%d instance(s) are still on port group %s (%s) — removing it deletes the port group, so move them (or purge them from Trash) first", len(vms), segName, nameList(vms))
		}
		if cts := s.queryNames(`SELECT name FROM containers WHERE network_id=? ORDER BY name`, netID); len(cts) > 0 {
			return fmt.Errorf("container(s) %s are on port group %s — move them first", nameList(cts), segName)
		}
	}
	if b, err := vrouterBackend(v.Runtime); err == nil {
		if err := b.RemoveLeg(v, *leg); err != nil {
			log.Printf("vrouter %s: remove leg %s: %v", v.Name, leg.IfaceName, err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM vrouter_legs WHERE vrouter_id=? AND network_id=? AND kind='internal'`, vrID, netID); err != nil {
		return err
	}
	switch {
	case owned:
		if err := s.DeleteNetwork(p, netID, ip); err != nil {
			log.Printf("vrouter %s: delete port group %s: %v", v.Name, segName, err)
		}
		if strings.HasPrefix(leg.Bridge, "vr"+strconv.FormatInt(vrID, 10)+"-") { // only a bridge this router created
			netdrv.DeleteLink(leg.Bridge)
		}
	case pgID != 0:
		s.db.Exec(`UPDATE tenant_portgroups SET vrouter_id=0 WHERE id=?`, pgID)
	default:
		s.db.Exec(`UPDATE tenant_networks SET vrouter_id=0 WHERE id=?`, tnetID)
	}
	if !owned {
		s.db.Exec(`UPDATE networks SET gateway='' WHERE id=?`, netID)
	}
	action := "vrouter.segment.detach"
	if owned {
		action = "vrouter.internal.delete"
	}
	s.audit(p, p.OrgID, action, "vrouter", v.Name, ip, map[string]any{"segment": segName})
	return s.applyAndPush(vrID)
}

// UpdateInternalDHCP changes an internal port group's DHCP settings (enable,
// range, DNS) after creation and re-applies dnsmasq. idx identifies the leg.
func (s *Service) UpdateInternalDHCP(p *Principal, vrID int64, idx int, dhcp bool, dhcpRange, dns, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	var legCIDR string
	if err := s.db.QueryRow(`SELECT cidr FROM vrouter_legs WHERE vrouter_id=? AND idx=? AND kind='internal'`, vrID, idx).Scan(&legCIDR); err != nil {
		return fmt.Errorf("no downlink at index %d", idx)
	}
	dhcpRange, dns, err = legDHCP(dhcp, dhcpRange, dns, legCIDR)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE vrouter_legs SET dhcp=?, dhcp_range=?, dhcp_dns=? WHERE vrouter_id=? AND idx=? AND kind='internal'`,
		b2iDHCP(dhcp), dhcpRange, dns, vrID, idx); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.internal.dhcp", "vrouter", v.Name, ip,
		map[string]any{"idx": idx, "dhcp": dhcp, "range": dhcpRange, "dns": dns})
	return s.applyDHCP(vrID, idx)
}

// validDHCPRange checks a DHCP range resolves to "start,end" with two IPv4
// addresses, start ≤ end (accepting the friendly "A.B.C.X-Y" shorthand).
func validDHCPRange(r string) error {
	if strings.TrimSpace(r) == "" {
		return fmt.Errorf("a DHCP range is required when DHCP is enabled (e.g. 10.60.0.100,10.60.0.200)")
	}
	_, _, err := vrouter.ParseDHCPRange(r)
	return err
}

// legDHCP checks a router leg's DHCP settings against the leg address legCIDR
// (IP/prefix) and returns them normalized for storage. With DHCP on, the range
// must lie inside the leg's subnet and not cover the leg's own address; the DNS
// list (optional) must be IPv4 addresses. With DHCP off, a range or DNS list
// that is given is still checked (it is stored for later).
func legDHCP(dhcp bool, dhcpRange, dns, legCIDR string) (string, string, error) {
	dhcpRange = strings.TrimSpace(dhcpRange)
	dns, err := vrouter.NormalizeDNS(dns)
	if err != nil {
		return "", "", err
	}
	if dhcpRange == "" {
		if dhcp {
			return "", "", validDHCPRange("")
		}
		return "", dns, nil
	}
	start, end, err := vrouter.ParseDHCPRange(dhcpRange)
	if err != nil {
		return "", "", err
	}
	own, sn, err := net.ParseCIDR(strings.TrimSpace(legCIDR))
	if err != nil {
		return "", "", fmt.Errorf("the leg has no valid address (%q) — set its gateway first", legCIDR)
	}
	if !sn.Contains(start) || !sn.Contains(end) {
		return "", "", fmt.Errorf("DHCP range %s-%s must be inside the leg's subnet %s", start, end, sn)
	}
	if o := own.To4(); o != nil && bytesInRange(o, start, end) {
		return "", "", fmt.Errorf("DHCP range %s-%s includes the gateway's own address %s — start the range after it", start, end, o)
	}
	return start.String() + "," + end.String(), dns, nil
}

// bytesInRange reports whether ip lies in [lo, hi] (all IPv4, 4-byte form).
func bytesInRange(ip, lo, hi net.IP) bool {
	return bytesCmp(ip, lo) >= 0 && bytesCmp(ip, hi) <= 0
}

func bytesCmp(a, b net.IP) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func b2iDHCP(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Service) legCount(vrID int64, kind string) int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM vrouter_legs WHERE vrouter_id=? AND kind=?`, vrID, kind).Scan(&n)
	return n
}

// vrouterBackend resolves a runtime's backend (a seam for tests).
var vrouterBackend = vrouter.For

// applyAndPush rebuilds the runtime's legs and pushes the rendered FRR config.
func (s *Service) applyAndPush(vrID int64) error {
	v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, vrID))
	if err != nil {
		return err
	}
	b, err := vrouterBackend(v.Runtime)
	if err != nil {
		return err
	}
	legs, err := s.loadLegs(vrID)
	if err != nil {
		return err
	}
	if err := b.ApplyLegs(v, legs); err != nil {
		return err
	}
	conf, err := s.renderVRouterFRR(v, legs)
	if err != nil {
		return err
	}
	if err := b.PushFRR(v, conf); err != nil {
		return err
	}
	// (Re)apply the zone firewall last — a fresh runtime (restart/hot-plug) has an
	// empty netfilter instance, so the ruleset must be re-pushed after legs change.
	if err := pushVRouterFW(b, v, legs); err != nil {
		return err
	}
	if ea, ok := b.(vrouter.EdgeApplier); ok {
		if err := ea.ApplyEdge(v, legs); err != nil {
			return err
		}
	}
	s.db.Exec(`UPDATE vrouters SET status='running', error='' WHERE id=?`, vrID)
	return nil
}

// pushVRouterFW renders and pushes a router's gateway firewall. A config that
// can't be rendered pushes vrouter.DenyAllFirewall instead (the gateway fails
// closed, never open) and returns the render error.
func pushVRouterFW(b vrouter.Backend, v vrouter.VRouter, legs []vrouter.Leg) error {
	rs, rerr := vrouter.RenderFirewall(v, legs, parseFW(v.FWJSON))
	if rerr != nil {
		log.Printf("vrouter %s: %v — blocking forwarding until it is fixed", v.Name, rerr)
		rs = vrouter.DenyAllFirewall()
	}
	if err := b.PushFirewall(v, rs); err != nil {
		return err
	}
	if rerr != nil {
		return fmt.Errorf("%v — forwarding through %s is blocked until the rule is fixed or removed", rerr, v.Name)
	}
	return nil
}

// applyFW re-renders and pushes just the zone firewall (used by the firewall
// CRUD; leg/routing changes go through applyAndPush which also calls PushFirewall).
func (s *Service) applyFW(vrID int64) error {
	v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, vrID))
	if err != nil {
		return err
	}
	b, err := vrouterBackend(v.Runtime)
	if err != nil {
		return err
	}
	legs, err := s.loadLegs(vrID)
	if err != nil {
		return err
	}
	return pushVRouterFW(b, v, legs)
}

func (s *Service) applyDHCP(vrID int64, idx int) error {
	v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, vrID))
	if err != nil {
		return err
	}
	b, err := vrouterBackend(v.Runtime)
	if err != nil {
		return err
	}
	legs, _ := s.loadLegs(vrID)
	for _, l := range legs {
		if l.Idx == idx {
			return b.SetDHCP(v, l)
		}
	}
	return nil
}

// renderVRouterFRR renders a router's stored routing config.
func (s *Service) renderVRouterFRR(v vrouter.VRouter, legs []vrouter.Leg) (string, error) {
	cfg, err := decodeFRRJSON(v.FRRJSON)
	if err != nil {
		return "", err
	}
	return s.renderVRouterCfg(v, legs, cfg)
}

// renderVRouterCfg renders what the router actually runs of cfg (see
// vrouterRouting), logging any entry it leaves out.
func (s *Service) renderVRouterCfg(v vrouter.VRouter, legs []vrouter.Leg, cfg routing.Config) (string, error) {
	eff, ignored := s.vrouterRouting(v, legs, cfg)
	if len(ignored) > 0 {
		log.Printf("vrouter %s: not applying: %s", v.Name, strings.Join(ignored, "; "))
	}
	return vrouter.RenderForVRouter(v, legs, eff)
}

// vrouterMu serializes routing changes to vRouters: each one reads the stored
// config, pushes the changed one, and only then saves it.
var vrouterMu sync.Mutex

// vrEdit is what a routing change on one router is checked against.
type vrEdit struct {
	v      vrouter.VRouter
	legs   []vrouter.Leg
	tenant bool // a tenant org's gateway: the tenant routing policy applies
}

// connected / export are the networks the tenant policy measures against.
func (e vrEdit) connected() []*net.IPNet { return vrouter.ConnectedNets(e.legs) }
func (e vrEdit) export() []*net.IPNet    { return vrouter.ExportNets(e.legs) }

// netList formats networks for an error message.
func netList(nets []*net.IPNet) string {
	if len(nets) == 0 {
		return "none yet — attach a segment or port group first"
	}
	s := make([]string, len(nets))
	for i, n := range nets {
		s[i] = n.String()
	}
	return strings.Join(s, ", ")
}

// mutateVRouterFRR loads the router's routing config, applies fn, pushes the
// result into the runtime and only then saves and audits it. If the push
// fails, the previous config is pushed back and nothing is saved — so the
// stored config is always one the router took.
func (s *Service) mutateVRouterFRR(p *Principal, vrID int64, ip, action string, detail map[string]any, fn func(e vrEdit, c *routing.Config) error) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	vrouterMu.Lock()
	defer vrouterMu.Unlock()
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if v.Status == "creating" {
		return fmt.Errorf("the router is still being created — wait a moment, then try again")
	}
	stored, err := decodeFRRJSON(v.FRRJSON)
	if err != nil {
		return err
	}
	prev, _ := routing.Sanitize(stored)
	next, _ := routing.Sanitize(stored) // an independent copy: fn may edit slices in place
	legs, err := s.loadLegs(vrID)
	if err != nil {
		return err
	}
	if err := fn(vrEdit{v: v, legs: legs, tenant: s.isTenantRouter(v)}, &next); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	conf, err := s.renderVRouterCfg(v, legs, next)
	if err != nil {
		return err
	}
	b, err := vrouterBackend(v.Runtime)
	if err != nil {
		return err
	}
	if err := b.PushFRR(v, conf); err != nil {
		old, rerr := s.renderVRouterCfg(v, legs, prev)
		if rerr == nil {
			rerr = b.PushFRR(v, old)
		}
		if rerr != nil {
			return fmt.Errorf("apply routing on %s: %v — restoring the previous config also failed (%v); check the router's FRR", v.Name, err, rerr)
		}
		return fmt.Errorf("apply routing on %s: %v — the change was not saved and the previous config was restored", v.Name, err)
	}
	blob, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE vrouters SET frr_json=? WHERE id=?`, string(blob), vrID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, action, "vrouter", v.Name, ip, detail)
	return nil
}

// ---- dynamic-routing CRUD (scoped to a vRouter) --------------------------
//
// Every value is checked here (friendly error) and again by the renderer. On a
// tenant org's gateway the tenant routing policy is checked too: BGP only with
// directly connected neighbors, only the gateway's own downlink networks
// advertised, OSPF only on its own networks, no EIGRP. (The renderer applies
// the same policy to whatever is stored — vrouter.ConstrainTenant.)

func errNoVREntry(what string, i int) error {
	return fmt.Errorf("there is no %s #%d on this gateway — reload the page", what, i+1)
}

func (s *Service) VRAddStaticRoute(p *Principal, vrID int64, dest, nextHop, ip string) error {
	r, err := staticRoute(dest, nextHop)
	if err != nil {
		return err
	}
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.static.add", map[string]any{"dest": r.Dest, "next_hop": r.NextHop},
		func(_ vrEdit, c *routing.Config) error {
			c.Static = append(c.Static, r)
			return nil
		})
}
func (s *Service) VRDelStaticRoute(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.static.delete", map[string]any{"index": idx}, func(_ vrEdit, c *routing.Config) error {
		if idx < 0 || idx >= len(c.Static) {
			return errNoVREntry("static route", idx)
		}
		c.Static = delRoute(c.Static, idx)
		return nil
	})
}
func (s *Service) VRSetOSPF(p *Principal, vrID int64, enabled bool, routerID, ip string) error {
	routerID = strings.TrimSpace(routerID)
	if err := routing.ValidRouterID(routerID); err != nil {
		return err
	}
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.set", map[string]any{"enabled": enabled, "router_id": routerID},
		func(_ vrEdit, c *routing.Config) error {
			c.OSPF.Enabled = enabled
			c.OSPF.RouterID = routerID
			return nil
		})
}

// vrOSPFNet checks an OSPF network for a router (tenant: one of its networks).
func vrOSPFNet(e vrEdit, cidr, area string) (routing.OSPFNet, error) {
	n, err := routing.CanonPrefix(cidr)
	if err != nil {
		return routing.OSPFNet{}, err
	}
	if area = strings.TrimSpace(area); area == "" {
		area = "0"
	}
	if err := routing.ValidArea(area); err != nil {
		return routing.OSPFNet{}, err
	}
	if e.tenant {
		pn, _ := routing.ParsePrefix(n)
		own := append(e.connected(), e.export()...)
		if !vrouter.NetWithin(pn, own) {
			return routing.OSPFNet{}, fmt.Errorf("%s isn't one of this gateway's networks (%s) — on a tenant gateway OSPF runs only on its own interfaces' networks", n, netList(own))
		}
	}
	return routing.OSPFNet{CIDR: n, Area: area}, nil
}

func (s *Service) VRAddOSPFNet(p *Principal, vrID int64, cidr, area, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.net.add", map[string]any{"cidr": cidr, "area": area}, func(e vrEdit, c *routing.Config) error {
		on, err := vrOSPFNet(e, cidr, area)
		if err != nil {
			return err
		}
		c.OSPF.Networks = append(c.OSPF.Networks, on)
		return nil
	})
}
func (s *Service) VRDelOSPFNet(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.net.delete", map[string]any{"index": idx}, func(_ vrEdit, c *routing.Config) error {
		if idx < 0 || idx >= len(c.OSPF.Networks) {
			return errNoVREntry("OSPF network", idx)
		}
		c.OSPF.Networks = delOSPFNet(c.OSPF.Networks, idx)
		return nil
	})
}
func (s *Service) VRSetBGP(p *Principal, vrID int64, enabled bool, asn int, routerID, ip string) error {
	routerID = strings.TrimSpace(routerID)
	if enabled {
		if err := routing.ValidASN(asn); err != nil {
			return fmt.Errorf("local %w", err)
		}
	}
	if err := routing.ValidRouterID(routerID); err != nil {
		return err
	}
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.set", map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID},
		func(_ vrEdit, c *routing.Config) error {
			c.BGP.Enabled = enabled
			c.BGP.ASN = asn
			c.BGP.RouterID = routerID
			return nil
		})
}

// vrNeighbor checks a BGP neighbor for a router (tenant: directly connected).
func vrNeighbor(e vrEdit, addr string, remoteAS int) (string, error) {
	addr = strings.TrimSpace(addr)
	if err := routing.ValidPeer(addr); err != nil {
		return "", err
	}
	if err := routing.ValidASN(remoteAS); err != nil {
		return "", fmt.Errorf("remote %w", err)
	}
	if e.tenant && !vrouter.OnConnected(e.legs, net.ParseIP(addr)) {
		return "", fmt.Errorf("%s isn't on a network this gateway is connected to (%s) — a tenant gateway can only peer with a neighbor on one of its interfaces' subnets", addr, netList(e.connected()))
	}
	return addr, nil
}

func (s *Service) VRAddBGPNeighbor(p *Principal, vrID int64, addr string, remoteAS int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.neighbor.add", map[string]any{"addr": addr, "remote_as": remoteAS}, func(e vrEdit, c *routing.Config) error {
		a, err := vrNeighbor(e, addr, remoteAS)
		if err != nil {
			return err
		}
		c.BGP.Neighbors = append(c.BGP.Neighbors, routing.Neighbor{Addr: a, RemoteAS: remoteAS})
		return nil
	})
}
func (s *Service) VRDelBGPNeighbor(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.neighbor.delete", map[string]any{"index": idx}, func(_ vrEdit, c *routing.Config) error {
		if idx < 0 || idx >= len(c.BGP.Neighbors) {
			return errNoVREntry("BGP neighbor", idx)
		}
		c.BGP.Neighbors = delNeighbor(c.BGP.Neighbors, idx)
		return nil
	})
}

// vrBGPNetwork checks a BGP network for a router (tenant: one of its
// downlink networks).
func vrBGPNetwork(e vrEdit, cidr string) (string, error) {
	n, err := routing.CanonPrefix(cidr)
	if err != nil {
		return "", err
	}
	if e.tenant {
		pn, _ := routing.ParsePrefix(n)
		if !vrouter.NetWithin(pn, e.export()) {
			return "", fmt.Errorf("%s isn't one of this gateway's downlink networks (%s) — a tenant gateway can only advertise the networks attached to it", n, netList(e.export()))
		}
	}
	return n, nil
}

func (s *Service) VRAddBGPNetwork(p *Principal, vrID int64, cidr, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.network.add", map[string]any{"cidr": cidr}, func(e vrEdit, c *routing.Config) error {
		n, err := vrBGPNetwork(e, cidr)
		if err != nil {
			return err
		}
		c.BGP.Networks = append(c.BGP.Networks, n)
		return nil
	})
}
func (s *Service) VRDelBGPNetwork(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.network.delete", map[string]any{"index": idx}, func(_ vrEdit, c *routing.Config) error {
		if idx < 0 || idx >= len(c.BGP.Networks) {
			return errNoVREntry("BGP network", idx)
		}
		c.BGP.Networks = delStr(c.BGP.Networks, idx)
		return nil
	})
}

// errTenantEIGRP: FRR's eigrpd has no per-neighbor export filter here, so a
// tenant gateway can't run it.
var errTenantEIGRP = fmt.Errorf("EIGRP isn't available on a tenant gateway — use OSPF or BGP")

func (s *Service) VRSetEIGRP(p *Principal, vrID int64, enabled bool, asn int, routerID, ip string) error {
	routerID = strings.TrimSpace(routerID)
	if enabled && (asn < 1 || asn > 65535) {
		return fmt.Errorf("EIGRP AS number must be 1-65535")
	}
	if err := routing.ValidRouterID(routerID); err != nil {
		return err
	}
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.eigrp.set", map[string]any{"enabled": enabled, "asn": asn, "router_id": routerID},
		func(e vrEdit, c *routing.Config) error {
			if e.tenant && enabled {
				return errTenantEIGRP
			}
			c.EIGRP.Enabled = enabled
			c.EIGRP.ASN = asn
			c.EIGRP.RouterID = routerID
			return nil
		})
}
func (s *Service) VRAddEIGRPNet(p *Principal, vrID int64, cidr, ip string) error {
	n, err := routing.CanonPrefix(cidr)
	if err != nil {
		return err
	}
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.eigrp.net.add", map[string]any{"cidr": n}, func(e vrEdit, c *routing.Config) error {
		if e.tenant {
			return errTenantEIGRP
		}
		c.EIGRP.Networks = append(c.EIGRP.Networks, n)
		return nil
	})
}
func (s *Service) VRDelEIGRPNet(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.eigrp.net.delete", map[string]any{"index": idx}, func(_ vrEdit, c *routing.Config) error {
		if idx < 0 || idx >= len(c.EIGRP.Networks) {
			return errNoVREntry("EIGRP network", idx)
		}
		c.EIGRP.Networks = delStr(c.EIGRP.Networks, idx)
		return nil
	})
}

// ---- edit existing entries (replace at index) ----------------------------

func (s *Service) VRUpdateStaticRoute(p *Principal, vrID int64, idx int, dest, nextHop, ip string) error {
	r, err := staticRoute(dest, nextHop)
	if err != nil {
		return err
	}
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.static.update", map[string]any{"index": idx, "dest": r.Dest, "next_hop": r.NextHop},
		func(_ vrEdit, c *routing.Config) error {
			if idx < 0 || idx >= len(c.Static) {
				return errNoVREntry("static route", idx)
			}
			c.Static[idx] = r
			return nil
		})
}
func (s *Service) VRUpdateOSPFNet(p *Principal, vrID int64, idx int, cidr, area, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.net.update", map[string]any{"index": idx, "cidr": cidr, "area": area},
		func(e vrEdit, c *routing.Config) error {
			if idx < 0 || idx >= len(c.OSPF.Networks) {
				return errNoVREntry("OSPF network", idx)
			}
			on, err := vrOSPFNet(e, cidr, area)
			if err != nil {
				return err
			}
			c.OSPF.Networks[idx] = on
			return nil
		})
}
func (s *Service) VRUpdateBGPNeighbor(p *Principal, vrID int64, idx int, addr string, remoteAS int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.neighbor.update", map[string]any{"index": idx, "addr": addr, "remote_as": remoteAS},
		func(e vrEdit, c *routing.Config) error {
			if idx < 0 || idx >= len(c.BGP.Neighbors) {
				return errNoVREntry("BGP neighbor", idx)
			}
			a, err := vrNeighbor(e, addr, remoteAS)
			if err != nil {
				return err
			}
			c.BGP.Neighbors[idx].Addr = a
			c.BGP.Neighbors[idx].RemoteAS = remoteAS
			return nil
		})
}
func (s *Service) VRUpdateBGPNetwork(p *Principal, vrID int64, idx int, cidr, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.network.update", map[string]any{"index": idx, "cidr": cidr},
		func(e vrEdit, c *routing.Config) error {
			if idx < 0 || idx >= len(c.BGP.Networks) {
				return errNoVREntry("BGP network", idx)
			}
			n, err := vrBGPNetwork(e, cidr)
			if err != nil {
				return err
			}
			c.BGP.Networks[idx] = n
			return nil
		})
}

// UpdateTransitLink changes the provider link's IP/CIDR (eth0). The physical
// NIC is unchanged; to change that, remove the provider link and add a new one.
func (s *Service) UpdateTransitLink(p *Principal, vrID int64, cidr, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if cidr = strings.TrimSpace(cidr); cidr == "" {
		return fmt.Errorf("a provider-link IP/CIDR is required")
	}
	if err := validLegCIDR(cidr); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE vrouter_legs SET cidr=? WHERE vrouter_id=? AND kind='transit'`, cidr, vrID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("this gateway has no provider link yet")
	}
	s.audit(p, p.OrgID, "vrouter.transit.update", "vrouter", v.Name, ip, map[string]any{"cidr": cidr})
	return s.applyAndPush(vrID)
}

// UpdateInternalNetwork edits a downlink (idx = leg index): the gateway's
// address on it and — for an internal port group the router created — the port
// group's name and subnet. An attached tenant segment / port group keeps its
// name and subnet (they belong to its vSwitch; edit them on the Networks page).
// Re-renders FRR (zebra re-assigns the leg IP) and re-applies DHCP if enabled.
func (s *Service) UpdateInternalNetwork(p *Principal, vrID int64, idx int, name, cidr, gatewayCIDR, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	var netID int64
	var curName, curCIDR, dhcpRange, dns string
	var dhcp int
	if err := s.db.QueryRow(`SELECT l.network_id,COALESCE(n.name,''),COALESCE(n.cidr,''),l.dhcp,l.dhcp_range,l.dhcp_dns
		FROM vrouter_legs l LEFT JOIN networks n ON n.id=l.network_id WHERE l.vrouter_id=? AND l.idx=? AND l.kind='internal'`, vrID, idx).
		Scan(&netID, &curName, &curCIDR, &dhcp, &dhcpRange, &dns); err != nil {
		return fmt.Errorf("no downlink at index %d", idx)
	}
	name, cidr = strings.TrimSpace(name), strings.TrimSpace(cidr)
	attached := s.isTenantSegment(netID)
	if attached {
		name, cidr = curName, curCIDR
	}
	if name == "" || strings.TrimSpace(gatewayCIDR) == "" {
		return fmt.Errorf("a name and the gateway's IP/CIDR on the downlink are required")
	}
	if cidr != "" {
		if cidr, err = routing.CanonPrefix(cidr); err != nil {
			return err
		}
	}
	gwIP, gatewayCIDR, err := legAddr(gatewayCIDR, cidr)
	if err != nil {
		return err
	}
	if dhcp != 0 {
		if _, _, err := legDHCP(true, dhcpRange, dns, gatewayCIDR); err != nil {
			return fmt.Errorf("DHCP is on for this downlink: %v — change or turn off DHCP first", err)
		}
	}
	if attached {
		_, err = s.db.Exec(`UPDATE networks SET gateway=? WHERE id=? AND org_id=?`, gwIP, netID, p.OrgID)
	} else {
		_, err = s.db.Exec(`UPDATE networks SET name=?, cidr=?, gateway=? WHERE id=? AND org_id=?`, name, cidr, gwIP, netID, p.OrgID)
	}
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE vrouter_legs SET cidr=? WHERE vrouter_id=? AND idx=?`, gatewayCIDR, vrID, idx); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.internal.update", "vrouter", v.Name, ip, map[string]any{"idx": idx, "network": name, "cidr": cidr, "gateway": gwIP})
	if err := s.applyAndPush(vrID); err != nil {
		return err
	}
	return s.applyDHCP(vrID, idx) // re-apply DHCP (gateway/subnet may have changed)
}

// ---- lifecycle -----------------------------------------------------------

func (s *Service) StartVRouter(p *Principal, vrID int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.start", "vrouter", v.Name, ip, nil)
	return s.applyAndPush(vrID)
}

func (s *Service) StopVRouter(p *Principal, vrID int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	b, err := vrouterBackend(v.Runtime)
	if err != nil {
		return err
	}
	if err := b.Stop(v); err != nil {
		return err
	}
	s.db.Exec(`UPDATE vrouters SET status='stopped' WHERE id=?`, vrID)
	s.audit(p, p.OrgID, "vrouter.stop", "vrouter", v.Name, ip, nil)
	return nil
}

// isTenantSegment reports whether a networks row is an ATTACHED tenant segment
// or tenant port group (owned by the tenant-networks lifecycle), as opposed to
// an internal port group this vRouter created itself. Attached segments survive
// the router.
func (s *Service) isTenantSegment(netID int64) bool {
	if netID == 0 {
		return false
	}
	var n int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM tenant_networks WHERE network_id=?)+
		(SELECT COUNT(*) FROM tenant_portgroups WHERE network_id=?)`, netID, netID).Scan(&n)
	return n > 0
}

// DeleteVRouter tears everything down in a safe order. Legs that are ATTACHED
// tenant segments are only detached (their networks row + bridge are owned by
// the tenant-networks lifecycle and may still run VMs); only internal port
// groups this router created are torn down.
func (s *Service) DeleteVRouter(p *Principal, vrID int64, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	legs, _ := s.loadLegs(vrID)
	// A transit leg holds a physical NIC — only an INSTANCE admin may cause its
	// detach. Per-org admins build netns routers with no transit, so this never
	// blocks them; it stops a tenant from triggering a host-plane NIC change.
	if !p.IsAdmin {
		for _, l := range legs {
			if l.Kind == vrouter.LegTransit {
				return fmt.Errorf("this gateway has a provider link (Tier-0 uplink) — an instance administrator must remove it first")
			}
		}
	}
	// Refuse only if a VM is still bound to an OWNED internal port group (one
	// this router created). Attached tenant segments have their own lifecycle
	// and survive the router, so they do not block the delete.
	for _, l := range legs {
		if l.Kind == vrouter.LegInternal && l.NetworkID != 0 && !s.isTenantSegment(l.NetworkID) {
			var n int
			s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE network_id=? AND deleted_at IS NULL`, l.NetworkID).Scan(&n)
			if n > 0 {
				return fmt.Errorf("%d instance(s) are still attached to this vRouter's internal port groups — move or delete them first", n)
			}
		}
	}
	b, err := vrouterBackend(v.Runtime)
	if err == nil {
		_ = b.Stop(v)
		_ = b.Destroy(v)
	}
	// Release transit NIC, delete OWNED internal networks + bridges, detach
	// attached segments without destroying them.
	for _, l := range legs {
		if l.Kind == vrouter.LegTransit && l.PhysIface != "" {
			_ = netdrv.DetachFromBridge(l.PhysIface)
		}
		if l.Kind == vrouter.LegUplink {
			continue // sits on a tenant vSwitch: the veth died with the runtime, the bridge stays
		}
		if l.Kind == vrouter.LegInternal && s.isTenantSegment(l.NetworkID) {
			// Attached tenant segment / port group: release the attach link only.
			// Its networks row and bridge belong to the tenant vSwitch. Also clear
			// the gateway the router owned, so it returns to an attachable
			// (gatewayless) state.
			s.db.Exec(`UPDATE tenant_networks SET vrouter_id=0 WHERE network_id=?`, l.NetworkID)
			s.db.Exec(`UPDATE tenant_portgroups SET vrouter_id=0 WHERE network_id=?`, l.NetworkID)
			s.db.Exec(`UPDATE networks SET gateway='' WHERE id=?`, l.NetworkID)
			continue
		}
		if l.Kind == vrouter.LegInternal && l.NetworkID != 0 {
			_ = s.deleteNetwork(p, l.NetworkID, ip) // its own: the in-use check would see this leg
		}
		if l.Bridge != "" {
			netdrv.DeleteLink(l.Bridge)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM vrouters WHERE id=? AND org_id=?`, vrID, p.OrgID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, "vrouter.delete", "vrouter", v.Name, ip, nil)
	return nil
}

// ReensureVRouters rebuilds every vRouter's topology + runtime at boot. vdxd is
// the single orchestrator (containers are lxc.start.auto=0): it ensures the
// bridges/veths exist before starting each runtime, avoiding the autostart race.
// Called from the worker boot hook.
func (s *Service) ReensureVRouters() {
	rows, err := s.db.Query(`SELECT ` + vrouterCols + ` FROM vrouters WHERE status IN ('running','stopped')`)
	if err != nil {
		return
	}
	var vs []vrouter.VRouter
	for rows.Next() {
		if v, err := scanVRouter(rows); err == nil {
			vs = append(vs, v)
		}
	}
	rows.Close()
	for _, v := range vs {
		legs, _ := s.loadLegs(v.ID)
		// Re-ensure transit + internal bridges and re-enslave the transit NIC
		// (idempotent — safe on a running vRouter).
		for _, l := range legs {
			if l.Bridge != "" {
				_ = netdrv.EnsureBridge(l.Bridge)
			}
			if l.Kind == vrouter.LegTransit && l.PhysIface != "" {
				_ = netdrv.EnslaveToBridge(l.PhysIface, l.Bridge)
			}
		}
		if v.Status != "running" {
			continue
		}
		b, err := vrouterBackend(v.Runtime)
		if err != nil {
			continue
		}
		// Only (re)build the runtime if it is actually DOWN (a real host reboot).
		// On a plain vdxd restart the container/netns is still up — ApplyLegs would
		// restart it and needlessly flap routing sessions (BGP/OSPF), so skip it.
		if ls, e := b.Status(v); e == nil && ls.State == "running" {
			// A tenant gateway's FRR is still re-pushed (frr-reload applies only the
			// difference, so sessions don't flap): the stored config is rendered
			// under the CURRENT tenant routing policy, so a config pushed by an
			// older build is brought in line on upgrade.
			if v.Runtime == vrouter.RuntimeNetns && s.isTenantRouter(v) {
				if conf, err := s.renderVRouterFRR(v, legs); err != nil {
					log.Printf("vrouter %s: render: %v", v.Name, err)
				} else if err := b.PushFRR(v, conf); err != nil {
					log.Printf("vrouter %s: re-push routing: %v", v.Name, err)
				}
			}
			continue
		}
		if err := b.ApplyLegs(v, legs); err != nil {
			log.Printf("vrouter %s: legs: %v", v.Name, err)
			continue
		}
		if conf, err := s.renderVRouterFRR(v, legs); err != nil {
			log.Printf("vrouter %s: render: %v", v.Name, err)
		} else if err := b.PushFRR(v, conf); err != nil {
			log.Printf("vrouter %s: push routing: %v", v.Name, err)
		}
		// Re-apply the zone firewall (the rebuilt runtime has an empty netfilter
		// instance after a host reboot).
		if err := pushVRouterFW(b, v, legs); err != nil {
			log.Printf("vrouter %s: firewall: %v", v.Name, err)
		}
		if ea, ok := b.(vrouter.EdgeApplier); ok {
			if err := ea.ApplyEdge(v, legs); err != nil {
				log.Printf("vrouter %s: edge: %v", v.Name, err)
			}
		}
		for _, l := range legs {
			if l.Kind == vrouter.LegInternal && l.DHCP {
				_ = b.SetDHCP(v, l)
			}
		}
	}
}

// slice helpers (mirror routing_service delAt family)
func delRoute(s []routing.Route, i int) []routing.Route {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}
func delOSPFNet(s []routing.OSPFNet, i int) []routing.OSPFNet {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}
func delNeighbor(s []routing.Neighbor, i int) []routing.Neighbor {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}
func delStr(s []string, i int) []string {
	if i < 0 || i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

// VRDiagram is the data for the vRouter network diagram (port groups → vRouter →
// transit → external ports).
type VRDiagram struct {
	Name     string           `json:"name"`
	Internal []VRDiagInternal `json:"internal"`
	Transit  *VRDiagTransit   `json:"transit,omitempty"`
}
type VRDiagInternal struct {
	Name  string `json:"name"`  // port-group name
	GW    string `json:"gw"`    // vRouter gateway IP/CIDR on this segment
	Iface string `json:"iface"` // ethN
}
type VRDiagTransit struct {
	CIDR   string `json:"cidr"`
	Phys   string `json:"phys"`
	Switch string `json:"switch"`
	Port   string `json:"port"`
	Mgmt   string `json:"mgmt"`
	Descr  string `json:"descr"`
}

// VRouterDiagram builds the diagram data for one vRouter.
func (s *Service) VRouterDiagram(p *Principal, id int64) (*VRDiagram, error) {
	if !p.atLeast("admin") {
		return nil, ErrUnauthorized
	}
	v, err := s.getVRouter(p, id)
	if err != nil {
		return nil, err
	}
	legs, _ := s.loadLegs(id)
	d := &VRDiagram{Name: v.Name}
	for _, l := range legs {
		switch l.Kind {
		case vrouter.LegInternal:
			nm := l.NetworkName
			if nm == "" {
				nm = l.IfaceName
			}
			d.Internal = append(d.Internal, VRDiagInternal{Name: nm, GW: l.CIDR, Iface: l.IfaceName})
		case vrouter.LegTransit:
			sw, port, mgmt, descr := s.LLDPDetail(l.PhysIface)
			d.Transit = &VRDiagTransit{CIDR: l.CIDR, Phys: l.PhysIface, Switch: sw, Port: port, Mgmt: mgmt, Descr: descr}
		case vrouter.LegUplink:
			if d.Transit == nil {
				d.Transit = &VRDiagTransit{CIDR: l.CIDR, Phys: "external interface · " + l.NetworkName}
			}
		}
	}
	return d, nil
}
