package web

import (
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/fabric"
	"vdxclone/internal/service"
)

// The VXVisor Fabric pages (/fabric): the deploy wizard and hosts (instance
// admin), and port groups, the connectivity table, egress (org admins on a
// fabric opened to their org). docs/FABRIC.md §14.

type fabricPGRow struct {
	fabric.PortGroup
	OrgName  string
	SpanText string
	Leases   int
	NetID    int64
	Mine     bool // the caller's org (may edit/delete)
}

type fabricRuleRow struct {
	fabric.Rule
	SrcName, DstName, Service, OrgName string
	Mine                               bool
}

type fabricMatrixRow struct {
	Name  string
	Cells []string
}

type fabricMatrix struct {
	OrgName string
	Names   []string
	Rows    []fabricMatrixRow
}

type fabricCard struct {
	fabric.Spec
	GuestMTU int
	Build    bool
	OrgNames string
	PGs      []fabricPGRow
	Rules    []fabricRuleRow
	Matrices []fabricMatrix
	Routed   []fabric.PortGroup // the caller org's routed PGs (rule / egress pickers)
	Egress   string
	HasVRF   bool
	Health   map[string]service.FabricNodeStatus
	Gateway  *service.FabricGateway // the caller org's connected router, if any
	GwPGName string
}

// lastFabricChecks keeps a deploy's check list for the page shown right after
// it (keyed by session token, shown once).
var lastFabricChecks sync.Map

type fabricChecksEntry struct {
	At     time.Time
	OK     bool
	Checks []service.FabricCheck
}

func (s *Server) fabricPage(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	v, err := s.svc.GetFabricView(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	orgName := map[int64]string{}
	var orgs []service.OrgLite
	if p.IsAdmin {
		orgs, _ = s.svc.ListOrgsLite(p)
	}
	for _, o := range orgs {
		orgName[o.ID] = o.Name
	}
	for _, o := range p.Orgs {
		orgName[o.ID] = o.Name
	}
	health := map[string]service.FabricNodeStatus{}
	if p.IsAdmin {
		hs, _ := s.svc.FabricHealth(p)
		for _, h := range hs {
			health[h.Node] = h
		}
	}
	cards := fabricCards(p, v, orgName, health)
	nics := s.svc.FabricNICChoices(p)
	nicsJSON, _ := json.Marshal(nics)
	mgmtJSON, _ := json.Marshal(s.svc.FabricWGChoices(p))
	var checks *fabricChecksEntry
	if e, ok := lastFabricChecks.LoadAndDelete(p.Token()); ok {
		if ce := e.(fabricChecksEntry); time.Since(ce.At) < 10*time.Minute {
			checks = &ce
		}
	}
	s.render(w, p, "fabric.html", "fabric", map[string]any{
		"V":        v,
		"Cards":    cards,
		"Orgs":     orgs,
		"NICsJSON": template.JS(nicsJSON),
		"MgmtJSON": template.JS(mgmtJSON),
		"WGPort":   fabric.WGPort,
		"Checks":   checks,
		"Routers":  s.svc.FabricRouterChoices(p),
	})
}

// fabricCards turns the (already org-filtered) view into one card per fabric.
func fabricCards(p *service.Principal, v service.FabricView, orgName map[int64]string, health map[string]service.FabricNodeStatus) []fabricCard {
	in := v.Intent
	pgName := map[string]string{fabric.External: "External"}
	for _, pg := range in.PGs {
		pgName[pg.UUID] = pg.Name
	}
	var cards []fabricCard
	for _, f := range in.Fabrics {
		c := fabricCard{Spec: f, GuestMTU: f.GuestMTU(), Build: v.Build[f.UUID], Health: health, Egress: v.Egress[f.UUID]}
		if g, ok := v.Gateways[f.UUID]; ok {
			c.Gateway, c.GwPGName = &g, pgName[g.PG]
		}
		_, c.HasVRF = v.VRF[f.UUID]
		var on []string
		for _, o := range f.Orgs {
			on = append(on, orgLabel(orgName, o))
		}
		c.OrgNames = strings.Join(on, ", ")
		byOrg := map[int64][]fabric.PortGroup{}
		for _, pg := range in.PGs {
			if pg.Fabric != f.UUID {
				continue
			}
			row := fabricPGRow{PortGroup: pg, OrgName: orgLabel(orgName, pg.Org), Leases: v.Leases[pg.UUID],
				NetID: v.Networks[pg.UUID], Mine: pg.Org == p.OrgID}
			row.SpanText = "all hosts"
			if len(pg.Span) > 0 {
				row.SpanText = strings.Join(pg.Span, ", ")
			}
			c.PGs = append(c.PGs, row)
			if pg.Routed() {
				byOrg[pg.Org] = append(byOrg[pg.Org], pg)
				if pg.Org == p.OrgID {
					c.Routed = append(c.Routed, pg)
				}
			}
		}
		for _, r := range in.Rules {
			if r.Fabric != f.UUID {
				continue
			}
			svc := r.Proto
			if r.Ports != "" {
				svc += " " + r.Ports
			}
			c.Rules = append(c.Rules, fabricRuleRow{Rule: r, SrcName: pgName[r.Src], DstName: pgName[r.Dst], Service: svc,
				OrgName: orgLabel(orgName, r.Org), Mine: r.Org == p.OrgID})
		}
		var orgIDs []int64
		for o := range byOrg {
			orgIDs = append(orgIDs, o)
		}
		sort.Slice(orgIDs, func(i, j int) bool { return orgIDs[i] < orgIDs[j] })
		for _, o := range orgIDs {
			c.Matrices = append(c.Matrices, connectivityMatrix(&in, f.UUID, o, byOrg[o], orgLabel(orgName, o)))
		}
		cards = append(cards, c)
	}
	return cards
}

func orgLabel(names map[int64]string, id int64) string {
	if n := names[id]; n != "" {
		return n
	}
	return "org " + strconv.FormatInt(id, 10)
}

// connectivityMatrix is the read-only PG × PG view of one org's table.
func connectivityMatrix(in *fabric.Intent, fab string, org int64, pgs []fabric.PortGroup, orgName string) fabricMatrix {
	m := fabricMatrix{OrgName: orgName}
	ends := append([]fabric.PortGroup{}, pgs...)
	ends = append(ends, fabric.PortGroup{UUID: fabric.External, Name: "External"})
	for _, pg := range ends {
		m.Names = append(m.Names, pg.Name)
	}
	for _, src := range ends {
		row := fabricMatrixRow{Name: src.Name}
		for _, dst := range ends {
			if src.UUID == dst.UUID {
				row.Cells = append(row.Cells, "·")
				continue
			}
			var svcs []string
			for _, r := range in.Rules {
				if r.Fabric != fab || r.Org != org || r.Off {
					continue
				}
				if (r.Src == src.UUID && r.Dst == dst.UUID) || (r.Both && r.Src == dst.UUID && r.Dst == src.UUID) {
					svc := r.Proto
					if r.Ports != "" {
						svc += " " + r.Ports
					}
					svcs = append(svcs, svc)
				}
			}
			if len(svcs) == 0 {
				row.Cells = append(row.Cells, "✗")
			} else {
				row.Cells = append(row.Cells, "✓ "+strings.Join(svcs, ", "))
			}
		}
		m.Rows = append(m.Rows, row)
	}
	return m
}

// fabricForm reads the deploy wizard.
func fabricForm(r *http.Request) service.FabricInput {
	_ = r.ParseForm()
	fi := service.FabricInput{Name: r.FormValue("name"), ASN: int(atoi(r.FormValue("asn"))), MTU: int(atoi(r.FormValue("mtu")))}
	if r.FormValue("underlay") == fabric.UnderlayMgmt {
		fi.Underlay = fabric.UnderlayMgmt
	}
	for _, o := range r.Form["orgs"] {
		if id := atoi(o); id > 0 {
			fi.Orgs = append(fi.Orgs, id)
		}
	}
	for _, n := range r.Form["node"] {
		fi.Hosts = append(fi.Hosts, service.FabricHostInput{Node: n, Iface: r.FormValue("iface_" + n),
			VLAN: int(atoi(r.FormValue("vlan_" + n))), TEP: r.FormValue("tep_" + n)})
	}
	return fi
}

func (s *Server) fabricBack(w http.ResponseWriter, r *http.Request, err error, ok string) {
	if err != nil {
		setFlash(w, err.Error())
	} else if ok != "" {
		setFlashOK(w, ok)
	}
	http.Redirect(w, r, "/fabric", http.StatusSeeOther)
}

func (s *Server) fabricPreflight(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	checks, err := s.svc.PreflightFabric(p, fabricForm(r))
	out := map[string]any{"checks": checks, "failed": service.FabricChecksFailed(checks)}
	if err != nil {
		out["error"] = err.Error()
		out["failed"] = true
	}
	writeJSON(w, out)
}

func (s *Server) fabricDeploy(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_, checks, err := s.svc.CreateFabric(p, fabricForm(r), clientIP(r))
	if len(checks) > 0 {
		lastFabricChecks.Store(p.Token(), fabricChecksEntry{At: time.Now(), OK: err == nil, Checks: checks})
	}
	s.fabricBack(w, r, err, "Fabric deployed: every host realized it and their tunnel endpoints reach each other at full MTU.")
}

func (s *Server) fabricAddHost(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	checks, err := s.svc.AddFabricHost(p, r.PathValue("id"), service.FabricHostInput{Node: r.FormValue("node"),
		Iface: r.FormValue("iface"), VLAN: int(atoi(r.FormValue("vlan"))), TEP: r.FormValue("tep")}, clientIP(r))
	if len(checks) > 0 {
		lastFabricChecks.Store(p.Token(), fabricChecksEntry{At: time.Now(), OK: err == nil, Checks: checks})
	}
	s.fabricBack(w, r, err, "Host added to the fabric.")
}

func (s *Server) fabricRemoveHost(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	var err error
	if r.FormValue("evict") == "1" {
		err = s.svc.EvictFabricHost(p, r.PathValue("id"), r.FormValue("node"), clientIP(r))
	} else {
		err = s.svc.RemoveFabricHost(p, r.PathValue("id"), r.FormValue("node"), clientIP(r))
	}
	s.fabricBack(w, r, err, "Host removed from the fabric.")
}

func (s *Server) fabricOrgs(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_ = r.ParseForm()
	var orgs []int64
	for _, o := range r.Form["orgs"] {
		if id := atoi(o); id > 0 {
			orgs = append(orgs, id)
		}
	}
	s.fabricBack(w, r, s.svc.SetFabricOrgs(p, r.PathValue("id"), orgs, clientIP(r)), "Organizations updated.")
}

func (s *Server) fabricDelete(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	s.fabricBack(w, r, s.svc.DeleteFabric(p, r.PathValue("id"), clientIP(r)), "Fabric deleted.")
}

func (s *Server) fabricCreatePG(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_ = r.ParseForm()
	in := service.FabricPGInput{Fabric: r.FormValue("fabric"), Name: r.FormValue("name"), DNS: r.FormValue("dns"),
		PoolStart: r.FormValue("pool_start"), PoolEnd: r.FormValue("pool_end"), Span: r.Form["span"]}
	if r.FormValue("kind") != "l2" {
		in.CIDR, in.Gateway = r.FormValue("cidr"), r.FormValue("gateway")
	}
	_, err := s.svc.CreateFabricPG(p, in, clientIP(r))
	s.fabricBack(w, r, err, "Port group created on every host in its span.")
}

func (s *Server) fabricEditPG(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	_ = r.ParseForm()
	s.fabricBack(w, r, s.svc.UpdateFabricPG(p, r.PathValue("id"), r.Form["span"], r.FormValue("dns"), clientIP(r)), "Port group updated.")
}

func (s *Server) fabricDeletePG(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	s.fabricBack(w, r, s.svc.DeleteFabricPG(p, r.PathValue("id"), clientIP(r)), "Port group deleted.")
}

func (s *Server) fabricAddRule(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	err := s.svc.AddFabricRule(p, service.FabricRuleInput{Fabric: r.FormValue("fabric"), Src: r.FormValue("src"),
		Dst: r.FormValue("dst"), Both: r.FormValue("dir") == "both", Proto: r.FormValue("proto"),
		Ports: r.FormValue("ports"), Note: r.FormValue("note")}, clientIP(r))
	s.fabricBack(w, r, err, "Rule added — every host enforces it now.")
}

func (s *Server) fabricRuleAction(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	var err error
	switch r.PathValue("action") {
	case "on":
		err = s.svc.SetFabricRuleOff(p, id, false, clientIP(r))
	case "off":
		err = s.svc.SetFabricRuleOff(p, id, true, clientIP(r))
	case "delete":
		err = s.svc.DeleteFabricRule(p, id, clientIP(r))
	default:
		http.NotFound(w, r)
		return
	}
	s.fabricBack(w, r, err, "")
}

func (s *Server) fabricEgress(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	s.fabricBack(w, r, s.svc.SetFabricEgress(p, r.PathValue("id"), r.FormValue("egress"), clientIP(r)), "Egress updated.")
}

func (s *Server) fabricGatewayConnect(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	err := s.svc.ConnectFabricGateway(p, atoi(r.FormValue("router")), r.FormValue("pg"), r.FormValue("addr"), clientIP(r))
	s.fabricBack(w, r, err, "Gateway connected: every host now routes the organization's outbound traffic to it.")
}

func (s *Server) fabricGatewayDisconnect(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	s.fabricBack(w, r, s.svc.DisconnectFabricGateway(p, r.PathValue("id"), clientIP(r)), "Gateway disconnected.")
}
