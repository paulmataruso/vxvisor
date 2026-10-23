package service

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

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
}

func parseFRRJSON(blob string) routing.Config {
	var c routing.Config
	if strings.TrimSpace(blob) != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &c)
	}
	return c
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

// VRouterAvailable reports whether the admin can use any vRouter runtime here.
func (s *Service) VRouterAvailable(p *Principal) bool {
	if p == nil || !p.IsAdmin {
		return false
	}
	return vrouter.Available(vrouter.RuntimeLXC) || vrouter.Available(vrouter.RuntimeNetns)
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
	rows, err := s.db.Query(`SELECT l.id,l.vrouter_id,l.idx,l.kind,l.bridge,l.phys_iface,l.network_id,l.iface_name,l.cidr,l.mac,l.dhcp,l.dhcp_range,l.dhcp_dns,COALESCE(n.name,''),COALESCE(n.cidr,'')
		FROM vrouter_legs l LEFT JOIN networks n ON n.id=l.network_id WHERE l.vrouter_id=? ORDER BY l.idx`, vrID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vrouter.Leg
	for rows.Next() {
		var l vrouter.Leg
		var dhcp int
		if err := rows.Scan(&l.ID, &l.VRouterID, &l.Idx, &l.Kind, &l.Bridge, &l.PhysIface, &l.NetworkID,
			&l.IfaceName, &l.CIDR, &l.MAC, &dhcp, &l.DHCPRange, &l.DHCPDNS, &l.NetworkName, &l.NetworkCIDR); err != nil {
			return nil, err
		}
		l.DHCP = dhcp != 0
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListVRouters returns all vRouters for the org with live backend status.
func (s *Service) ListVRouters(p *Principal) ([]VRouterView, error) {
	if !p.IsAdmin {
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
		view.Legs, _ = s.loadLegs(v.ID)
		view.Cfg = parseFRRJSON(v.FRRJSON)
		if v.Status != "creating" && v.Status != "error" {
			if b, err := vrouter.For(v.Runtime); err == nil {
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
	if !p.IsAdmin {
		return VRouterView{}, ErrUnauthorized
	}
	v, err := s.getVRouter(p, id)
	if err != nil {
		return VRouterView{}, err
	}
	view := VRouterView{VRouter: v}
	view.Legs, _ = s.loadLegs(id)
	view.Cfg = parseFRRJSON(v.FRRJSON)
	if v.Status != "creating" && v.Status != "error" {
		if b, err := vrouter.For(v.Runtime); err == nil {
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
	if !p.IsAdmin {
		return vrouter.LiveStatus{}, ErrUnauthorized
	}
	v, err := s.getVRouter(p, id)
	if err != nil {
		return vrouter.LiveStatus{}, err
	}
	if v.Status == "creating" || v.Status == "error" {
		return vrouter.LiveStatus{State: v.Status}, nil
	}
	b, err := vrouter.For(v.Runtime)
	if err != nil {
		return vrouter.LiveStatus{}, err
	}
	return b.Status(v)
}

// CreateVRouter inserts a creating-status row and provisions the runtime async.
func (s *Service) CreateVRouter(p *Principal, in VRouterInput, ip string) (int64, error) {
	if !p.IsAdmin {
		return 0, ErrUnauthorized
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return 0, fmt.Errorf("a name is required")
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
		b, err := vrouter.For(v.Runtime)
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
	physIface = strings.TrimSpace(physIface)
	if physIface == "" || strings.TrimSpace(cidr) == "" {
		return fmt.Errorf("an interface and a transit CIDR are required")
	}
	// Guard: never the mgmt NIC; must be a free (non-enslaved) transit candidate.
	if err := s.guardMgmt(physIface); err != nil {
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
		return fmt.Errorf("this vRouter already has a transit link")
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

// AttachInternalNetwork creates an isolated internal port group served by the
// vRouter (its leg IP is the gateway) and attaches a new leg. Optionally runs
// DHCP on the leg.
func (s *Service) AttachInternalNetwork(p *Principal, vrID int64, name, cidr, gatewayCIDR string, dhcp bool, dhcpRange, dns, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(gatewayCIDR) == "" {
		return fmt.Errorf("a name and the vRouter's gateway IP/CIDR are required")
	}
	if dhcp {
		if err := validDHCPRange(dhcpRange); err != nil {
			return err
		}
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
	gwIP := gatewayCIDR
	if i := strings.IndexByte(gwIP, '/'); i >= 0 {
		gwIP = gwIP[:i]
	}
	nid, err := s.CreateNetwork(p, netdrv.Network{
		Name: name, Mode: "bridge", Bridge: br, VLANID: 0, CIDR: cidr, Gateway: gwIP,
	}, ip)
	if err != nil {
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

// UpdateInternalDHCP changes an internal port group's DHCP settings (enable,
// range, DNS) after creation and re-applies dnsmasq. idx identifies the leg.
func (s *Service) UpdateInternalDHCP(p *Principal, vrID int64, idx int, dhcp bool, dhcpRange, dns, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if dhcp {
		if err := validDHCPRange(dhcpRange); err != nil {
			return err
		}
	}
	res, err := s.db.Exec(`UPDATE vrouter_legs SET dhcp=?, dhcp_range=?, dhcp_dns=? WHERE vrouter_id=? AND idx=? AND kind='internal'`,
		b2iDHCP(dhcp), strings.TrimSpace(dhcpRange), strings.TrimSpace(dns), vrID, idx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no internal port group at index %d", idx)
	}
	s.audit(p, p.OrgID, "vrouter.internal.dhcp", "vrouter", v.Name, ip,
		map[string]any{"idx": idx, "dhcp": dhcp, "range": dhcpRange, "dns": dns})
	return s.applyDHCP(vrID, idx)
}

// validDHCPRange checks a DHCP range resolves to "start,end" with two IPs
// (accepting the friendly "A.B.C.X-Y" shorthand).
func validDHCPRange(r string) error {
	r = strings.TrimSpace(r)
	if r == "" {
		return fmt.Errorf("a DHCP range is required when DHCP is enabled (e.g. 10.60.0.100,10.60.0.200)")
	}
	norm := vrouter.NormalizeDHCPRange(r)
	parts := strings.SplitN(norm, ",", 2)
	if len(parts) != 2 || net.ParseIP(strings.TrimSpace(parts[0])) == nil || net.ParseIP(strings.TrimSpace(parts[1])) == nil {
		return fmt.Errorf("DHCP range must be start,end (e.g. 10.60.0.100,10.60.0.200) — got %q", r)
	}
	return nil
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

// applyAndPush rebuilds the runtime's legs and pushes the rendered FRR config.
func (s *Service) applyAndPush(vrID int64) error {
	v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, vrID))
	if err != nil {
		return err
	}
	b, err := vrouter.For(v.Runtime)
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
	if err := b.PushFirewall(v, vrouter.RenderFirewall(v, legs, parseFW(v.FWJSON))); err != nil {
		return err
	}
	s.db.Exec(`UPDATE vrouters SET status='running', error='' WHERE id=?`, vrID)
	return nil
}

// applyFW re-renders and pushes just the zone firewall (used by the firewall
// CRUD; leg/routing changes go through applyAndPush which also calls PushFirewall).
func (s *Service) applyFW(vrID int64) error {
	v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, vrID))
	if err != nil {
		return err
	}
	b, err := vrouter.For(v.Runtime)
	if err != nil {
		return err
	}
	legs, err := s.loadLegs(vrID)
	if err != nil {
		return err
	}
	return b.PushFirewall(v, vrouter.RenderFirewall(v, legs, parseFW(v.FWJSON)))
}

func (s *Service) applyDHCP(vrID int64, idx int) error {
	v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, vrID))
	if err != nil {
		return err
	}
	b, err := vrouter.For(v.Runtime)
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

func (s *Service) renderVRouterFRR(v vrouter.VRouter, legs []vrouter.Leg) (string, error) {
	var cfg routing.Config
	if strings.TrimSpace(v.FRRJSON) != "" && v.FRRJSON != "{}" {
		if err := json.Unmarshal([]byte(v.FRRJSON), &cfg); err != nil {
			return "", fmt.Errorf("parse vrouter frr config: %w", err)
		}
	}
	return vrouter.RenderForVRouter(v, legs, cfg)
}

// mutateVRouterFRR loads the stored routing.Config, applies fn, persists, audits,
// re-renders and pushes it into the runtime.
func (s *Service) mutateVRouterFRR(p *Principal, vrID int64, ip, action string, fn func(*routing.Config)) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	var cfg routing.Config
	if strings.TrimSpace(v.FRRJSON) != "" && v.FRRJSON != "{}" {
		if err := json.Unmarshal([]byte(v.FRRJSON), &cfg); err != nil {
			return err
		}
	}
	fn(&cfg)
	blob, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE vrouters SET frr_json=? WHERE id=?`, string(blob), vrID); err != nil {
		return err
	}
	s.audit(p, p.OrgID, action, "vrouter", v.Name, ip, nil)
	v.FRRJSON = string(blob)
	legs, _ := s.loadLegs(vrID)
	conf, err := vrouter.RenderForVRouter(v, legs, cfg)
	if err != nil {
		return err
	}
	b, err := vrouter.For(v.Runtime)
	if err != nil {
		return err
	}
	return b.PushFRR(v, conf)
}

// ---- dynamic-routing CRUD (scoped to a vRouter) --------------------------

func (s *Service) VRAddStaticRoute(p *Principal, vrID int64, dest, nextHop, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.static.add", func(c *routing.Config) {
		c.Static = append(c.Static, routing.Route{Dest: dest, NextHop: nextHop})
	})
}
func (s *Service) VRDelStaticRoute(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.static.delete", func(c *routing.Config) {
		c.Static = delRoute(c.Static, idx)
	})
}
func (s *Service) VRSetOSPF(p *Principal, vrID int64, enabled bool, routerID, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.set", func(c *routing.Config) {
		c.OSPF.Enabled = enabled
		c.OSPF.RouterID = routerID
	})
}
func (s *Service) VRAddOSPFNet(p *Principal, vrID int64, cidr, area, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.net.add", func(c *routing.Config) {
		if area == "" {
			area = "0"
		}
		c.OSPF.Networks = append(c.OSPF.Networks, routing.OSPFNet{CIDR: cidr, Area: area})
	})
}
func (s *Service) VRDelOSPFNet(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.net.delete", func(c *routing.Config) {
		c.OSPF.Networks = delOSPFNet(c.OSPF.Networks, idx)
	})
}
func (s *Service) VRSetBGP(p *Principal, vrID int64, enabled bool, asn int, routerID, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.set", func(c *routing.Config) {
		c.BGP.Enabled = enabled
		c.BGP.ASN = asn
		c.BGP.RouterID = routerID
	})
}
func (s *Service) VRAddBGPNeighbor(p *Principal, vrID int64, addr string, remoteAS int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.neighbor.add", func(c *routing.Config) {
		c.BGP.Neighbors = append(c.BGP.Neighbors, routing.Neighbor{Addr: addr, RemoteAS: remoteAS})
	})
}
func (s *Service) VRDelBGPNeighbor(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.neighbor.delete", func(c *routing.Config) {
		c.BGP.Neighbors = delNeighbor(c.BGP.Neighbors, idx)
	})
}
func (s *Service) VRAddBGPNetwork(p *Principal, vrID int64, cidr, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.network.add", func(c *routing.Config) {
		c.BGP.Networks = append(c.BGP.Networks, cidr)
	})
}
func (s *Service) VRDelBGPNetwork(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.network.delete", func(c *routing.Config) {
		c.BGP.Networks = delStr(c.BGP.Networks, idx)
	})
}
func (s *Service) VRSetEIGRP(p *Principal, vrID int64, enabled bool, asn int, routerID, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.eigrp.set", func(c *routing.Config) {
		c.EIGRP.Enabled = enabled
		c.EIGRP.ASN = asn
		c.EIGRP.RouterID = routerID
	})
}
func (s *Service) VRAddEIGRPNet(p *Principal, vrID int64, cidr, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.eigrp.net.add", func(c *routing.Config) {
		c.EIGRP.Networks = append(c.EIGRP.Networks, cidr)
	})
}
func (s *Service) VRDelEIGRPNet(p *Principal, vrID int64, idx int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.eigrp.net.delete", func(c *routing.Config) {
		c.EIGRP.Networks = delStr(c.EIGRP.Networks, idx)
	})
}

// ---- edit existing entries (replace at index) ----------------------------

func (s *Service) VRUpdateStaticRoute(p *Principal, vrID int64, idx int, dest, nextHop, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.static.update", func(c *routing.Config) {
		if idx >= 0 && idx < len(c.Static) {
			c.Static[idx] = routing.Route{Dest: dest, NextHop: nextHop}
		}
	})
}
func (s *Service) VRUpdateOSPFNet(p *Principal, vrID int64, idx int, cidr, area, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.ospf.net.update", func(c *routing.Config) {
		if area == "" {
			area = "0"
		}
		if idx >= 0 && idx < len(c.OSPF.Networks) {
			c.OSPF.Networks[idx] = routing.OSPFNet{CIDR: cidr, Area: area}
		}
	})
}
func (s *Service) VRUpdateBGPNeighbor(p *Principal, vrID int64, idx int, addr string, remoteAS int, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.neighbor.update", func(c *routing.Config) {
		if idx >= 0 && idx < len(c.BGP.Neighbors) {
			c.BGP.Neighbors[idx].Addr = addr
			c.BGP.Neighbors[idx].RemoteAS = remoteAS
		}
	})
}
func (s *Service) VRUpdateBGPNetwork(p *Principal, vrID int64, idx int, cidr, ip string) error {
	return s.mutateVRouterFRR(p, vrID, ip, "vrouter.bgp.network.update", func(c *routing.Config) {
		if idx >= 0 && idx < len(c.BGP.Networks) {
			c.BGP.Networks[idx] = cidr
		}
	})
}

// UpdateTransitLink changes the transit leg's IP/CIDR (eth0). The physical NIC
// is unchanged; to change that, delete and re-add the transit link.
func (s *Service) UpdateTransitLink(p *Principal, vrID int64, cidr, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(cidr) == "" {
		return fmt.Errorf("a transit IP/CIDR is required")
	}
	res, err := s.db.Exec(`UPDATE vrouter_legs SET cidr=? WHERE vrouter_id=? AND kind='transit'`, cidr, vrID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("this vRouter has no transit link yet")
	}
	s.audit(p, p.OrgID, "vrouter.transit.update", "vrouter", v.Name, ip, map[string]any{"cidr": cidr})
	return s.applyAndPush(vrID)
}

// UpdateInternalNetwork edits an internal port group's name, subnet and the
// vRouter's gateway IP on it (idx = leg index). Re-renders FRR (zebra re-assigns
// the leg IP) and re-applies DHCP if enabled.
func (s *Service) UpdateInternalNetwork(p *Principal, vrID int64, idx int, name, cidr, gatewayCIDR, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(name) == "" || strings.TrimSpace(gatewayCIDR) == "" {
		return fmt.Errorf("a name and the vRouter's gateway IP/CIDR are required")
	}
	var netID int64
	if err := s.db.QueryRow(`SELECT network_id FROM vrouter_legs WHERE vrouter_id=? AND idx=? AND kind='internal'`, vrID, idx).Scan(&netID); err != nil {
		return fmt.Errorf("no internal port group at index %d", idx)
	}
	gwIP := gatewayCIDR
	if i := strings.IndexByte(gwIP, '/'); i >= 0 {
		gwIP = gwIP[:i]
	}
	if _, err := s.db.Exec(`UPDATE networks SET name=?, cidr=?, gateway=? WHERE id=? AND org_id=?`, name, cidr, gwIP, netID, p.OrgID); err != nil {
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
	if !p.IsAdmin {
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
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	b, err := vrouter.For(v.Runtime)
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

// DeleteVRouter tears everything down in a safe order.
func (s *Service) DeleteVRouter(p *Principal, vrID int64, ip string) error {
	if !p.IsAdmin {
		return ErrUnauthorized
	}
	v, err := s.getVRouter(p, vrID)
	if err != nil {
		return err
	}
	legs, _ := s.loadLegs(vrID)
	// Refuse if any VM is still bound to an internal port group.
	for _, l := range legs {
		if l.Kind == vrouter.LegInternal && l.NetworkID != 0 {
			var n int
			s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE network_id=? AND deleted_at IS NULL`, l.NetworkID).Scan(&n)
			if n > 0 {
				return fmt.Errorf("%d instance(s) are still attached to this vRouter's internal port groups — move or delete them first", n)
			}
		}
	}
	b, err := vrouter.For(v.Runtime)
	if err == nil {
		_ = b.Stop(v)
		_ = b.Destroy(v)
	}
	// Release transit NIC, delete internal networks + bridges.
	for _, l := range legs {
		if l.Kind == vrouter.LegTransit && l.PhysIface != "" {
			_ = netdrv.DetachFromBridge(l.PhysIface)
		}
		if l.Kind == vrouter.LegInternal && l.NetworkID != 0 {
			_ = s.DeleteNetwork(p, l.NetworkID, ip)
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
		b, err := vrouter.For(v.Runtime)
		if err != nil {
			continue
		}
		// Only (re)build the runtime if it is actually DOWN (a real host reboot).
		// On a plain vdxd restart the container/netns is still up — ApplyLegs would
		// restart it and needlessly flap routing sessions (BGP/OSPF), so skip it.
		if ls, e := b.Status(v); e == nil && ls.State == "running" {
			continue
		}
		if err := b.ApplyLegs(v, legs); err != nil {
			continue
		}
		if conf, err := s.renderVRouterFRR(v, legs); err == nil {
			_ = b.PushFRR(v, conf)
		}
		// Re-apply the zone firewall (the rebuilt runtime has an empty netfilter
		// instance after a host reboot).
		_ = b.PushFirewall(v, vrouter.RenderFirewall(v, legs, parseFW(v.FWJSON)))
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
	Name     string             `json:"name"`
	Internal []VRDiagInternal   `json:"internal"`
	Transit  *VRDiagTransit     `json:"transit,omitempty"`
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
	if !p.IsAdmin {
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
		}
	}
	return d, nil
}
