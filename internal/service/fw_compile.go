package service

import (
	"encoding/json"
	"sort"
	"strings"

	"vdxclone/internal/vrouter"
)

// Firewall compiler: turns the org-level document (fw_service.go) into the two
// existing enforcement engines and applies them. Nothing here invents new nft
// output — it drives the proven renderers:
//
//   East-West  → per-network PGFirewall → net_firewall rows → applyAllNetFW
//                (host nftables `bridge vdxdfw`, default ACCEPT)
//   North-South→ per-vRouter VRFirewall → vrouters.fw_json → applyFW
//                (each runtime's `inet vdxfw`, default DROP once ≥1 rule applies)
//
// Because the derived configs are persisted, the existing boot reensure paths
// reproduce the exact enforced state after a reboot without needing the document.
//
// SAFETY: a vRouter's firewall is enabled ONLY when at least one compiled policy
// governs it. A default-drop chain with no allow rules would blackhole a router,
// so "no rules for this vRouter" compiles to an EMPTY ruleset (table removed =
// open), never to a silent deny-all.

// fwMaps holds the per-org VM topology the compiler resolves groups against.
type fwMaps struct {
	netToMACs map[int64][]string // network id → VM MACs on it (lowercased)
	macToNet  map[string]int64   // VM MAC → its network id
	macToIP   map[string]string  // VM MAC → leased IP (for destination narrowing)
}

func (s *Service) buildFWMaps(orgID int64) fwMaps {
	m := fwMaps{netToMACs: map[int64][]string{}, macToNet: map[string]int64{}, macToIP: map[string]string{}}
	vms, _ := s.orgVMs(orgID)
	for _, v := range vms {
		if v.NetID == 0 {
			continue
		}
		m.macToNet[v.MAC] = v.NetID
		m.netToMACs[v.NetID] = append(m.netToMACs[v.NetID], v.MAC)
	}
	// MAC → IP from DHCP/static leases, so a destination-VM rule can match ip daddr.
	if rows, err := s.db.Query(`SELECT COALESCE(mac,''), ip FROM ip_leases`); err == nil {
		for rows.Next() {
			var mac, ip string
			if rows.Scan(&mac, &ip) == nil {
				if mac = strings.ToLower(strings.TrimSpace(mac)); mac != "" && ip != "" {
					m.macToIP[mac] = ip
				}
			}
		}
		rows.Close()
	}
	return m
}

func containsInt64(xs []int64, x int64) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// groupMACsOnNet returns the MACs a group resolves to on one network: all VMs on
// the net if the net is a whole-PG member, plus any explicit MACs that live there.
func (m fwMaps) groupMACsOnNet(g *FWGroup, nid int64) []string {
	var out []string
	if containsInt64(g.Networks, nid) {
		out = append(out, m.netToMACs[nid]...)
	}
	for _, mac := range g.MACs {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if m.macToNet[mac] == nid {
			out = append(out, mac)
		}
	}
	return uniqSorted(out)
}

// endpointMACsOnNet resolves a rule endpoint (group id or Internal/External
// literal) to its MAC set on one L2 network. External has no L2 presence.
func (f *OrgFirewall) endpointMACsOnNet(m fwMaps, key string, nid int64) []string {
	switch key {
	case ZoneExternal:
		return nil
	case ZoneInternal:
		var out []string
		for i := range f.Groups {
			if f.Groups[i].Zone == ZoneExternal {
				continue
			}
			out = append(out, m.groupMACsOnNet(&f.Groups[i], nid)...)
		}
		return uniqSorted(out)
	}
	if g := f.groupByID(key); g != nil {
		return m.groupMACsOnNet(g, nid)
	}
	return nil
}

// ReensureFirewall seeds (on first upgrade) and recompiles the unified firewall
// for every org at boot. The derived configs the compiler writes are also what
// the legacy reensure paths apply, so this mainly performs the one-time import
// and refreshes whole-port-group membership that may have changed while down.
func (s *Service) ReensureFirewall() {
	rows, err := s.db.Query(`SELECT id FROM orgs`)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_ = s.recompileFirewall(id)
	}
}

// recompileFirewall rebuilds BOTH planes for an org from its document.
func (s *Service) recompileFirewall(orgID int64) error {
	s.ensureOrgFWSeeded(orgID)
	f := s.loadOrgFW(orgID)
	m := s.buildFWMaps(orgID)
	// East-West first (host bridge) — default-allow, never blackholes.
	if err := s.compileEastWest(orgID, f, m); err != nil {
		return err
	}
	// North-South (per vRouter).
	return s.compileNorthSouth(orgID, f, m)
}

// ---- East-West → host bridge vdxdfw --------------------------------------

func (s *Service) compileEastWest(orgID int64, f OrgFirewall, m fwMaps) error {
	// Collect every network in the org (bridged ones can carry east-west rules).
	nets, err := s.net.ListNetworks(orgID)
	if err != nil {
		return err
	}
	for _, n := range nets {
		pf := PGFirewall{Enabled: f.Enabled}
		if f.Enabled {
			pf.Zones, pf.Policies = compileNetEW(&f, m, n.ID)
			if len(pf.Policies) == 0 {
				pf.Enabled = false // nothing to enforce here
			}
		}
		blob, _ := json.Marshal(pf)
		if _, err := s.db.Exec(`INSERT INTO net_firewall(network_id,fw_json,updated_at) VALUES(?,?,datetime('now'))
			ON CONFLICT(network_id) DO UPDATE SET fw_json=excluded.fw_json, updated_at=datetime('now')`, n.ID, string(blob)); err != nil {
			return err
		}
	}
	return s.applyAllNetFW()
}

// compileNetEW builds the zones+policies for one L2 network: only rules whose
// BOTH endpoints have MACs on this network (same-segment) are emitted. Each rule
// gets its own pair of zones so per-VM narrowing never collides with another
// rule reusing the same group.
func compileNetEW(f *OrgFirewall, m fwMaps, nid int64) ([]PGZone, []PGPolicy) {
	var zones []PGZone
	var pols []PGPolicy
	// macsFor resolves an endpoint (optionally narrowed to one VM) to its MACs on
	// this network.
	macsFor := func(key, vm string) []string {
		if vm = strings.ToLower(strings.TrimSpace(vm)); vm != "" {
			if m.macToNet[vm] == nid {
				return []string{vm}
			}
			return nil
		}
		return f.endpointMACsOnNet(m, key, nid)
	}
	for i, r := range f.RulesEW {
		from := macsFor(r.From, r.FromVM)
		to := macsFor(r.To, r.ToVM)
		if len(from) == 0 || len(to) == 0 {
			continue
		}
		fz, tz := "ewf"+itoa(i), "ewt"+itoa(i)
		zones = append(zones, PGZone{Name: fz, MACs: from}, PGZone{Name: tz, MACs: to})
		pols = append(pols, PGPolicy{From: fz, To: tz, Action: r.Action, Proto: r.Proto, DPort: r.DPort, Desc: r.Desc})
	}
	return zones, pols
}

// ---- North-South → per-vRouter inet vdxfw --------------------------------

func (s *Service) compileNorthSouth(orgID int64, f OrgFirewall, m fwMaps) error {
	rows, err := s.db.Query(`SELECT `+vrouterCols+` FROM vrouters WHERE org_id=?`, orgID)
	if err != nil {
		return err
	}
	var vrs []vrouter.VRouter
	for rows.Next() {
		v, e := scanVRouter(rows)
		if e == nil {
			vrs = append(vrs, v)
		}
	}
	rows.Close()

	var firstErr error
	for _, v := range vrs {
		legs, _ := s.loadLegs(v.ID)
		fw := compileVRouterFW(&f, m, legs)
		blob, _ := json.Marshal(fw)
		if _, err := s.db.Exec(`UPDATE vrouters SET fw_json=? WHERE id=?`, string(blob), v.ID); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// Push only into a live runtime; a stopped/creating vRouter picks the
		// staged fw_json up via applyAndPush / ReensureVRouters.
		if v.Status == "running" {
			if err := s.applyFW(v.ID); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// compileVRouterFW builds a VRFirewall for one vRouter from the org document.
// Zones = External (builtin) + one per internal leg ("leg<idx>"). Policies come
// from the North-South rules, with the SOURCE narrowed per-MAC when a group is a
// subset of a port group; cross-segment destinations stay leg-granular.
func compileVRouterFW(f *OrgFirewall, m fwMaps, legs []vrouter.Leg) vrouter.VRFirewall {
	fw := vrouter.VRFirewall{}
	// Map internal legs by their network id, and prepare zones.
	legOfNet := map[int64]int{}
	var internalLegIdx []int
	hasExternal := false // a transit leg must exist for External to resolve to an iface
	for _, l := range legs {
		if l.Kind == vrouter.LegTransit && l.IfaceName != "" {
			hasExternal = true
		}
	}
	fw.Zones = append(fw.Zones, vrouter.VRZone{Name: vrouter.ExternalZone, Builtin: true})
	for _, l := range legs {
		if l.Kind == vrouter.LegInternal && l.NetworkID != 0 && l.IfaceName != "" {
			legOfNet[l.NetworkID] = l.Idx
			internalLegIdx = append(internalLegIdx, l.Idx)
			fw.Zones = append(fw.Zones, vrouter.VRZone{Name: legZoneKey(l.Idx), Legs: []int{l.Idx}})
		}
	}
	if len(internalLegIdx) == 0 {
		return fw // no internal legs → nothing to route/filter
	}

	// fromTarget: a source leg plus optional per-MAC narrowing ("" = whole leg).
	type fromTarget struct {
		zone string
		macs []string // empty → no src narrowing
	}
	// toTarget: a destination leg plus optional per-VM ip daddr narrowing.
	type toTarget struct {
		zone string
		dst  string // "" → whole leg
	}
	// resolveFrom returns the source legs for a rule endpoint, optionally narrowed
	// to a single VM (vm = MAC). A VM endpoint resolves to its own leg only.
	resolveFrom := func(key, vm string) []fromTarget {
		if vm = strings.ToLower(strings.TrimSpace(vm)); vm != "" {
			if idx, ok := legOfNet[m.macToNet[vm]]; ok {
				return []fromTarget{{zone: legZoneKey(idx), macs: []string{vm}}}
			}
			return nil
		}
		switch key {
		case vrouter.ExternalZone:
			return []fromTarget{{zone: vrouter.ExternalZone}}
		case ZoneInternal:
			var out []fromTarget
			for _, idx := range internalLegIdx {
				out = append(out, fromTarget{zone: legZoneKey(idx)})
			}
			return out
		}
		g := f.groupByID(key)
		if g == nil {
			return nil
		}
		var out []fromTarget
		for nid, idx := range legOfNet {
			whole := containsInt64(g.Networks, nid)
			macs := m.groupMACsOnNet(g, nid)
			if len(macs) == 0 {
				continue
			}
			if whole {
				out = append(out, fromTarget{zone: legZoneKey(idx)}) // whole leg, no narrowing
			} else {
				out = append(out, fromTarget{zone: legZoneKey(idx), macs: macs})
			}
		}
		return out
	}
	// resolveTo returns destination targets for a rule endpoint, optionally narrowed
	// to a single VM (by its leased IP — routed traffic matches ip daddr, not MAC).
	resolveTo := func(key, vm string) []toTarget {
		if vm = strings.ToLower(strings.TrimSpace(vm)); vm != "" {
			if idx, ok := legOfNet[m.macToNet[vm]]; ok {
				return []toTarget{{zone: legZoneKey(idx), dst: m.macToIP[vm]}}
			}
			return nil
		}
		switch key {
		case vrouter.ExternalZone:
			return []toTarget{{zone: vrouter.ExternalZone}}
		case ZoneInternal:
			var out []toTarget
			for _, idx := range internalLegIdx {
				out = append(out, toTarget{zone: legZoneKey(idx)})
			}
			return out
		}
		g := f.groupByID(key)
		if g == nil {
			return nil
		}
		var out []toTarget
		for nid, idx := range legOfNet {
			if len(m.groupMACsOnNet(g, nid)) > 0 {
				out = append(out, toTarget{zone: legZoneKey(idx)})
			}
		}
		return out
	}

	emit := func(fromZone, toZone, src, dst string, r FWRule) {
		if fromZone == toZone {
			return // intra-leg traffic is East-West, not routed
		}
		// Skip a rule that can't actually be enforced here — otherwise an
		// unrenderable policy would leave fw.Enabled true with a default-drop
		// chain and no allow rule, blackholing the vRouter.
		if (fromZone == vrouter.ExternalZone || toZone == vrouter.ExternalZone) && !hasExternal {
			return
		}
		fw.Policies = append(fw.Policies, vrouter.VRPolicy{
			From: fromZone, To: toZone, Action: r.Action, Proto: r.Proto, DPort: r.DPort,
			Src: src, Dst: dst, Desc: r.Desc,
		})
	}

	for _, r := range f.RulesNS {
		froms := resolveFrom(r.From, r.FromVM)
		tos := resolveTo(r.To, r.ToVM)
		for _, ft := range froms {
			for _, tt := range tos {
				if len(ft.macs) == 0 {
					emit(ft.zone, tt.zone, "", tt.dst, r)
					continue
				}
				for _, mac := range ft.macs {
					emit(ft.zone, tt.zone, mac, tt.dst, r)
				}
			}
		}
	}

	// Enable only when ≥1 policy governs this vRouter (else leave OFF = open; a
	// default-drop chain with no allow rule would blackhole the router).
	fw.Enabled = f.Enabled && len(fw.Policies) > 0
	return fw
}

func legZoneKey(idx int) string { return "leg" + itoa(idx) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---- one-time seed from the legacy per-scope configs ----------------------

// ensureOrgFWSeeded creates the org document on first use, importing any existing
// per-vRouter (vrouters.fw_json) and per-network (net_firewall) config so live
// enforcement (e.g. an already-armed vRouter) survives the switch to the unified
// model. Idempotent: once a row exists it is never re-seeded.
func (s *Service) ensureOrgFWSeeded(orgID int64) {
	var one int
	s.db.QueryRow(`SELECT 1 FROM org_firewall WHERE org_id=?`, orgID).Scan(&one)
	if one == 1 {
		return
	}
	doc := s.buildSeed(orgID)
	_ = s.saveOrgFW(orgID, doc)
}

func (s *Service) buildSeed(orgID int64) OrgFirewall {
	doc := OrgFirewall{}
	used := map[string]bool{}
	uniqName := func(name string) string {
		base := strings.TrimSpace(name)
		if base == "" {
			base = "Group"
		}
		n := base
		for i := 2; used[strings.ToLower(n)]; i++ {
			n = base + " (" + itoa(i) + ")"
		}
		used[strings.ToLower(n)] = true
		return n
	}

	// vRouter zone firewalls → groups (whole-PG per leg) + North-South rules.
	if rows, err := s.db.Query(`SELECT `+vrouterCols+` FROM vrouters WHERE org_id=?`, orgID); err == nil {
		var vrs []vrouter.VRouter
		for rows.Next() {
			if v, e := scanVRouter(rows); e == nil {
				vrs = append(vrs, v)
			}
		}
		rows.Close()
		for _, v := range vrs {
			fw := parseFW(v.FWJSON)
			if !fw.Enabled {
				continue
			}
			doc.Enabled = true
			legs, _ := s.loadLegs(v.ID)
			netOfLeg := map[int]int64{}
			for _, l := range legs {
				if l.Kind == vrouter.LegInternal && l.NetworkID != 0 {
					netOfLeg[l.Idx] = l.NetworkID
				}
			}
			zoneToGID := map[string]string{}
			for _, z := range fw.Zones {
				if z.Builtin {
					continue
				}
				var nets []int64
				for _, idx := range z.Legs {
					if nid := netOfLeg[idx]; nid != 0 {
						nets = append(nets, nid)
					}
				}
				gid := newGroupID()
				doc.Groups = append(doc.Groups, FWGroup{ID: gid, Name: uniqName(z.Name), Zone: ZoneInternal, Networks: nets})
				zoneToGID[strings.ToLower(z.Name)] = gid
			}
			mapZone := func(name string) string {
				if strings.EqualFold(name, vrouter.ExternalZone) {
					return ZoneExternal
				}
				return zoneToGID[strings.ToLower(name)]
			}
			for _, pol := range fw.Policies {
				from, to := mapZone(pol.From), mapZone(pol.To)
				if from == "" || to == "" {
					continue
				}
				doc.RulesNS = append(doc.RulesNS, FWRule{From: from, To: to, Action: pol.Action, Proto: pol.Proto, DPort: pol.DPort, Desc: pol.Desc})
			}
		}
	}

	// Port-group microseg firewalls → groups (by MAC) + East-West rules.
	if rows, err := s.db.Query(`SELECT nf.network_id, nf.fw_json FROM net_firewall nf
		JOIN networks n ON n.id=nf.network_id WHERE n.org_id=?`, orgID); err == nil {
		type nfRow struct {
			nid  int64
			blob string
		}
		var nfs []nfRow
		for rows.Next() {
			var r nfRow
			if rows.Scan(&r.nid, &r.blob) == nil {
				nfs = append(nfs, r)
			}
		}
		rows.Close()
		for _, r := range nfs {
			pf := parsePGFW(r.blob)
			if !pf.Enabled {
				continue
			}
			doc.Enabled = true
			zoneToGID := map[string]string{}
			for _, z := range pf.Zones {
				gid := newGroupID()
				doc.Groups = append(doc.Groups, FWGroup{ID: gid, Name: uniqName(z.Name), Zone: ZoneInternal, MACs: z.MACs})
				zoneToGID[strings.ToLower(z.Name)] = gid
			}
			for _, pol := range pf.Policies {
				from, to := zoneToGID[strings.ToLower(pol.From)], zoneToGID[strings.ToLower(pol.To)]
				if from == "" || to == "" {
					continue
				}
				doc.RulesEW = append(doc.RulesEW, FWRule{From: from, To: to, Action: pol.Action, Proto: pol.Proto, DPort: pol.DPort, Desc: pol.Desc})
			}
		}
	}
	return doc
}
