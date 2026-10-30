package service

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"vdxclone/internal/fabric"
	"vdxclone/internal/routing"
	"vdxclone/internal/vrouter"
)

// A fabric gateway is an org's netns tenant router with a leg on one of its
// routed fabric port groups: that leg's address is the org's egress (every
// host's VRF default route points at it), and the router reaches the org's
// other fabric subnets through the port group's anycast gateway. The leg is an
// ordinary internal leg on the port group's bridge; the fabric owns the bridge,
// its networks row, DHCP and the address plan.

// FabricGateway is an org's connected gateway on one fabric.
type FabricGateway struct {
	VRouterID int64
	VRouter   string
	PG        string // port group UUID
	Addr      string // the leg's address (= the org's egress)
}

// FabricRouterChoice is a router the org may connect as its fabric gateway.
type FabricRouterChoice struct {
	ID   int64
	Name string
}

// fabricLegPG returns the fabric port group a router leg sits on ("" = none).
func (s *Service) fabricLegPG(l vrouter.Leg) string {
	if l.Kind != vrouter.LegInternal || l.NetworkID == 0 {
		return ""
	}
	return s.fabricPGOf(l.NetworkID)
}

// FabricGateways returns the org's connected gateways, by fabric UUID.
func (s *Service) FabricGateways(org int64) map[string]FabricGateway {
	out := map[string]FabricGateway{}
	in, err := s.fabricIntent()
	if err != nil {
		return out
	}
	rows, err := s.db.Query(`SELECT r.id, r.name, l.network_id, l.cidr FROM vrouter_legs l JOIN vrouters r ON r.id=l.vrouter_id
		JOIN fabric_pg_networks f ON f.network_id=l.network_id WHERE r.org_id=? AND l.kind='internal'`, org)
	if err != nil {
		return out
	}
	type leg struct {
		id    int64
		name  string
		netID int64
		cidr  string
	}
	var legs []leg
	for rows.Next() {
		var l leg
		if rows.Scan(&l.id, &l.name, &l.netID, &l.cidr) == nil {
			legs = append(legs, l)
		}
	}
	rows.Close()
	for _, l := range legs {
		pg := in.PG(s.fabricPGOf(l.netID))
		if pg == nil {
			continue
		}
		out[pg.Fabric] = FabricGateway{VRouterID: l.id, VRouter: l.name, PG: pg.UUID, Addr: strings.SplitN(l.cidr, "/", 2)[0]}
	}
	return out
}

// FabricRouterChoices lists the org's netns routers that can be connected.
func (s *Service) FabricRouterChoices(p *Principal) []FabricRouterChoice {
	var out []FabricRouterChoice
	if !p.atLeast("admin") {
		return out
	}
	rows, err := s.db.Query(`SELECT id, name FROM vrouters WHERE org_id=? AND runtime=? AND status='running' ORDER BY name`, p.OrgID, vrouter.RuntimeNetns)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c FabricRouterChoice
		if rows.Scan(&c.ID, &c.Name) == nil {
			out = append(out, c)
		}
	}
	return out
}

// ConnectFabricGateway gives router vrID a leg at addr on fabric port group
// pgUUID and makes that address the org's egress on the fabric.
func (s *Service) ConnectFabricGateway(p *Principal, vrID int64, pgUUID, addr, ip string) error {
	v, err := s.vswitchRouter(p, vrID)
	if err != nil {
		return err
	}
	in, err := s.fabricIntent()
	if err != nil {
		return err
	}
	pg := in.PG(pgUUID)
	if pg == nil || pg.Org != p.OrgID || !pg.Routed() {
		return fmt.Errorf("pick one of your organization's routed fabric port groups")
	}
	if _, ok := s.FabricGateways(p.OrgID)[pg.Fabric]; ok {
		return fmt.Errorf("the organization already has a gateway on this fabric — disconnect it first")
	}
	if !in.Spans(*pg, s.selfNode()) {
		return fmt.Errorf("port group %s doesn't reach this host (%s), where the router runs — add the host to its span first", pg.Name, s.selfNode())
	}
	n, ok := s.fabricNetwork(pgUUID)
	if !ok {
		return fmt.Errorf("port group %s isn't set up on this host yet — try again in a minute", pg.Name)
	}
	gwIP, legCIDR, err := legAddr(addr, pg.CIDR)
	if err != nil {
		return err
	}
	_, sn, _ := net.ParseCIDR(pg.CIDR)
	if ones, _ := sn.Mask.Size(); !strings.HasSuffix(legCIDR, "/"+strconv.Itoa(ones)) {
		return fmt.Errorf("the router's address must use the port group's prefix (/%d)", ones)
	}
	// The egress commit checks the address: inside the port group, not its
	// gateway, not leased. Only then does the leg exist.
	prev := ""
	if vrf := in.VRFOf(pg.Fabric, p.OrgID); vrf != nil {
		prev = vrf.Egress
	}
	if err := s.setFabricEgress(p, pg.Fabric, gwIP); err != nil {
		return err
	}
	undo := func() {
		if err := s.setFabricEgress(p, pg.Fabric, prev); err != nil {
			log.Printf("fabric gateway: restore egress %q: %v", prev, err)
		}
	}
	idx := s.legIndex(vrID)
	if _, err := s.db.Exec(`INSERT INTO vrouter_legs(vrouter_id,idx,kind,bridge,network_id,iface_name,cidr,dhcp,dhcp_range,dhcp_dns,vlan_id)
		VALUES(?,?,?,?,?,?,?,0,'','',0)`, vrID, idx, vrouter.LegInternal, n.Bridge, n.ID, "eth"+strconv.Itoa(idx), legCIDR); err != nil {
		undo()
		return err
	}
	if err := s.applyAndPush(vrID); err != nil {
		if b, berr := vrouterBackend(v.Runtime); berr == nil {
			_ = b.RemoveLeg(v, vrouter.Leg{VRouterID: vrID, Idx: idx, Kind: vrouter.LegInternal, Bridge: n.Bridge, IfaceName: "eth" + strconv.Itoa(idx)})
		}
		s.db.Exec(`DELETE FROM vrouter_legs WHERE vrouter_id=? AND idx=?`, vrID, idx)
		_ = s.applyAndPush(vrID)
		undo()
		return fmt.Errorf("connect %s: %w", v.Name, err)
	}
	s.audit(p, p.OrgID, "fabric.gateway.connect", "vrouter", v.Name, ip, map[string]any{"fabric": pg.Fabric, "portgroup": pg.Name, "address": legCIDR})
	return nil
}

// DisconnectFabricGateway removes the org's gateway leg on a fabric and clears
// its egress (with the rules to and from External).
func (s *Service) DisconnectFabricGateway(p *Principal, fabricUUID, ip string) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	g, ok := s.FabricGateways(p.OrgID)[fabricUUID]
	if !ok {
		return fmt.Errorf("the organization has no gateway on this fabric")
	}
	v, err := s.getVRouter(p, g.VRouterID)
	if err != nil {
		return err
	}
	if err := s.setFabricEgress(p, fabricUUID, ""); err != nil {
		return err
	}
	legs, _ := s.loadLegs(v.ID)
	for _, l := range legs {
		if s.fabricLegPG(l) != g.PG {
			continue
		}
		if b, err := vrouterBackend(v.Runtime); err == nil {
			if err := b.RemoveLeg(v, l); err != nil {
				log.Printf("vrouter %s: remove fabric leg %s: %v", v.Name, l.IfaceName, err)
			}
		}
		if _, err := s.db.Exec(`DELETE FROM vrouter_legs WHERE id=?`, l.ID); err != nil {
			return err
		}
	}
	if err := s.applyAndPush(v.ID); err != nil {
		log.Printf("vrouter %s: re-apply after fabric disconnect: %v", v.Name, err)
	}
	s.audit(p, p.OrgID, "fabric.gateway.disconnect", "vrouter", v.Name, ip, map[string]any{"fabric": fabricUUID})
	return nil
}

// fabricLegRoutes are the static routes a router with fabric legs needs: every
// other routed port group of the org on that fabric, via the leg's anycast
// gateway (the fabric routes between port groups on the host).
func (s *Service) fabricLegRoutes(v vrouter.VRouter, legs []vrouter.Leg) []routing.Route {
	var on []*fabric.PortGroup
	in, err := s.fabricIntent()
	if err != nil {
		return nil
	}
	for _, l := range legs {
		if pg := in.PG(s.fabricLegPG(l)); pg != nil {
			on = append(on, pg)
		}
	}
	var out []routing.Route
	for _, leg := range on {
		for _, pg := range in.PGs {
			if pg.Fabric == leg.Fabric && pg.Org == v.OrgID && pg.Routed() && pg.UUID != leg.UUID {
				out = append(out, routing.Route{Dest: pg.CIDR, NextHop: leg.Gateway})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dest < out[j].Dest })
	return out
}

// refreshFabricGateways re-pushes every router with a fabric leg whose fabric
// routes changed (a port group of its org was added or removed).
func (s *Service) refreshFabricGateways() {
	rows, err := s.db.Query(`SELECT DISTINCT l.vrouter_id FROM vrouter_legs l JOIN fabric_pg_networks f ON f.network_id=l.network_id WHERE l.kind='internal'`)
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
	rt := s.fabricRT()
	seen := map[int64]bool{}
	for _, id := range ids {
		seen[id] = true
		v, err := scanVRouter(s.db.QueryRow(`SELECT `+vrouterCols+` FROM vrouters WHERE id=?`, id))
		if err != nil {
			continue
		}
		legs, err := s.loadLegs(id)
		if err != nil {
			continue
		}
		sig := fmt.Sprint(s.fabricLegRoutes(v, legs))
		if rt.gwRoutes[id] == sig {
			continue
		}
		vrouterMu.Lock()
		err = s.applyAndPush(id)
		vrouterMu.Unlock()
		if err != nil {
			log.Printf("fabric: gateway %s: %v", v.Name, err)
			continue
		}
		rt.gwRoutes[id] = sig
	}
	for id := range rt.gwRoutes {
		if !seen[id] {
			delete(rt.gwRoutes, id)
		}
	}
}

// fabricTopoInfo is this host's share of its fabric, for the topology map.
type fabricTopoInfo struct{ name, dev, iface, tep string }

func (s *Service) fabricTopo() (fabricTopoInfo, bool) {
	in, err := s.fabricIntent()
	if err != nil {
		return fabricTopoInfo{}, false
	}
	f, h := in.HostOf(s.selfNode())
	if f == nil {
		return fabricTopoInfo{}, false
	}
	return fabricTopoInfo{name: f.Name, dev: h.UnderlayDev(), iface: h.Iface, tep: h.TEP}, true
}
