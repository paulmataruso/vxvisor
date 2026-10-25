package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Unified NSX-style firewall — ONE document per org.
//
// This supersedes the two older, separate firewall models (per-vRouter
// vrouters.fw_json and per-network net_firewall), which are now the DERIVED
// OUTPUT of the compiler (fw_compile.go), not a source of truth. An admin
// authors three things here and the compiler decides where each is enforced:
//
//   - VM Group : a set of VMs (by MAC) and/or whole port groups. The single
//                grouping primitive; a VM may be in several groups.
//   - Zone     : just Internal / External. A group belongs to exactly one.
//   - Rule     : From → To (a group id, or the literal "Internal"/"External"),
//                split into North-South (routed; compiled to each vRouter's
//                inet vdxfw) and East-West (same-L2; compiled to the host
//                bridge vdxdfw). The direction IS the enforcement plane —
//                exactly how NSX separates its gateway firewall from its DFW.

// Zone names (the only two) and the literal rule endpoints.
const (
	ZoneInternal = "Internal"
	ZoneExternal = "External"
)

// FWZoneColors is the palette cycled through group cards / rule chips; the
// External side gets a fixed slate. (Shared by the view builders here and the
// port-group microseg view.)
var FWZoneColors = []string{"#3b82f6", "#22c55e", "#f59e0b", "#a855f7", "#ef4444", "#14b8a6", "#ec4899", "#84cc16"}

const FWExternalColor = "#64748b"

// FWGroup is a VM Group: explicit VM MACs plus whole-port-group memberships.
type FWGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Zone     string   `json:"zone"` // Internal | External (default Internal)
	MACs     []string `json:"macs"`
	Networks []int64  `json:"networks"`
}

// FWRule is one ordered rule. From/To are a group id, or "Internal"/"External".
// FromVM/ToVM optionally narrow an endpoint to a SINGLE VM within it (by MAC) —
// so different VMs in one group can carry different rules. "" = the whole endpoint.
type FWRule struct {
	From   string `json:"from"`
	FromVM string `json:"from_vm,omitempty"`
	To     string `json:"to"`
	ToVM   string `json:"to_vm,omitempty"`
	Action string `json:"action"` // allow | deny
	Proto  string `json:"proto"`  // any | tcp | udp | icmp
	DPort  string `json:"dport"`
	Desc   string `json:"desc"`
}

// OrgFirewall is the whole org-level document (stored in org_firewall.fw_json).
type OrgFirewall struct {
	Enabled bool      `json:"enabled"`
	Groups  []FWGroup `json:"groups"`
	RulesNS []FWRule  `json:"rules_ns"` // North-South  → vRouter inet vdxfw
	RulesEW []FWRule  `json:"rules_ew"` // East-West    → host bridge vdxdfw
}

func (f *OrgFirewall) groupByID(id string) *FWGroup {
	for i := range f.Groups {
		if f.Groups[i].ID == id {
			return &f.Groups[i]
		}
	}
	return nil
}

// endpointOK reports whether a rule endpoint key is a known group or a literal.
func (f *OrgFirewall) endpointOK(key string) bool {
	switch key {
	case ZoneInternal, ZoneExternal:
		return true
	}
	return f.groupByID(key) != nil
}

func (f *OrgFirewall) rules(dir string) *[]FWRule {
	if dir == "ew" {
		return &f.RulesEW
	}
	return &f.RulesNS
}

func parseOrgFW(blob string) OrgFirewall {
	var f OrgFirewall
	if strings.TrimSpace(blob) != "" && blob != "{}" {
		_ = json.Unmarshal([]byte(blob), &f)
	}
	return f
}

func newGroupID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "g" + hex.EncodeToString(b[:])
}

// ---- persistence ---------------------------------------------------------

func (s *Service) loadOrgFW(orgID int64) OrgFirewall {
	var blob string
	s.db.QueryRow(`SELECT fw_json FROM org_firewall WHERE org_id=?`, orgID).Scan(&blob)
	return parseOrgFW(blob)
}

func (s *Service) saveOrgFW(orgID int64, f OrgFirewall) error {
	blob, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO org_firewall(org_id,fw_json,updated_at) VALUES(?,?,datetime('now'))
		ON CONFLICT(org_id) DO UPDATE SET fw_json=excluded.fw_json, updated_at=datetime('now')`, orgID, string(blob))
	return err
}

// mutateOrgFW loads the org document (seeding it on first use from any legacy
// per-vRouter / per-network config), applies fn, persists, audits, then
// recompiles both enforcement planes.
func (s *Service) mutateOrgFW(p *Principal, ip, action string, fn func(*OrgFirewall) error) error {
	if !p.atLeast("admin") {
		return ErrUnauthorized
	}
	s.ensureOrgFWSeeded(p.OrgID)
	f := s.loadOrgFW(p.OrgID)
	if err := fn(&f); err != nil {
		return err
	}
	if err := s.saveOrgFW(p.OrgID, f); err != nil {
		return err
	}
	s.audit(p, p.OrgID, action, "org", strconv.FormatInt(p.OrgID, 10), ip, nil)
	return s.recompileFirewall(p.OrgID)
}

// ---- CRUD ----------------------------------------------------------------

func (s *Service) FWSetEnabled(p *Principal, enabled bool, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.set", func(f *OrgFirewall) error {
		f.Enabled = enabled
		return nil
	})
}

func (s *Service) FWAddGroup(p *Principal, name, ip string) (string, error) {
	var newID string
	err := s.mutateOrgFW(p, ip, "firewall.group.add", func(f *OrgFirewall) error {
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 32 {
			return fmt.Errorf("group name must be 1–32 characters")
		}
		for i := range f.Groups {
			if strings.EqualFold(f.Groups[i].Name, name) {
				return fmt.Errorf("a group named %q already exists", name)
			}
		}
		newID = newGroupID()
		f.Groups = append(f.Groups, FWGroup{ID: newID, Name: name, Zone: ZoneInternal})
		return nil
	})
	return newID, err
}

func (s *Service) FWRenameGroup(p *Principal, gid, name, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.group.rename", func(f *OrgFirewall) error {
		g := f.groupByID(gid)
		if g == nil {
			return fmt.Errorf("no such group")
		}
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 32 {
			return fmt.Errorf("group name must be 1–32 characters")
		}
		for i := range f.Groups {
			if f.Groups[i].ID != gid && strings.EqualFold(f.Groups[i].Name, name) {
				return fmt.Errorf("a group named %q already exists", name)
			}
		}
		g.Name = name
		return nil
	})
}

func (s *Service) FWDelGroup(p *Principal, gid, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.group.delete", func(f *OrgFirewall) error {
		idx := -1
		for i := range f.Groups {
			if f.Groups[i].ID == gid {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("no such group")
		}
		// Drop every rule that referenced the group (either direction).
		for _, rp := range []*[]FWRule{&f.RulesNS, &f.RulesEW} {
			kept := (*rp)[:0]
			for _, r := range *rp {
				if r.From == gid || r.To == gid {
					continue
				}
				kept = append(kept, r)
			}
			*rp = kept
		}
		f.Groups = append(f.Groups[:idx], f.Groups[idx+1:]...)
		return nil
	})
}

// FWSetGroupMembers replaces a group's full membership (the drag-and-drop drop
// handler always sends the complete post-drop set).
func (s *Service) FWSetGroupMembers(p *Principal, gid string, macs []string, nets []int64, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.group.members", func(f *OrgFirewall) error {
		g := f.groupByID(gid)
		if g == nil {
			return fmt.Errorf("no such group")
		}
		g.MACs = validMACs(macs)
		seen := map[int64]bool{}
		var cleanNets []int64
		for _, n := range nets {
			if n > 0 && !seen[n] {
				seen[n] = true
				cleanNets = append(cleanNets, n)
			}
		}
		g.Networks = cleanNets
		return nil
	})
}

func (s *Service) FWSetGroupZone(p *Principal, gid, zone, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.group.zone", func(f *OrgFirewall) error {
		g := f.groupByID(gid)
		if g == nil {
			return fmt.Errorf("no such group")
		}
		switch zone {
		case ZoneInternal, ZoneExternal:
			g.Zone = zone
		default:
			return fmt.Errorf("zone must be Internal or External")
		}
		return nil
	})
}

func validFWRule(f *OrgFirewall, r FWRule) error {
	if strings.TrimSpace(r.From) == "" || strings.TrimSpace(r.To) == "" {
		return fmt.Errorf("a rule needs both a source and a destination")
	}
	if !f.endpointOK(r.From) {
		return fmt.Errorf("unknown source %q", r.From)
	}
	if !f.endpointOK(r.To) {
		return fmt.Errorf("unknown destination %q", r.To)
	}
	if r.From == r.To && r.FromVM == r.ToVM {
		return fmt.Errorf("source and destination must differ")
	}
	for _, vm := range []string{r.FromVM, r.ToVM} {
		if vm = strings.TrimSpace(vm); vm != "" {
			if _, err := net.ParseMAC(vm); err != nil {
				return fmt.Errorf("%q is not a valid VM (MAC) address", vm)
			}
		}
	}
	switch r.Action {
	case "allow", "deny":
	default:
		return fmt.Errorf("action must be allow or deny")
	}
	switch r.Proto {
	case "", "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("protocol must be any, tcp, udp or icmp")
	}
	if dp := strings.TrimSpace(r.DPort); dp != "" {
		if r.Proto != "tcp" && r.Proto != "udp" {
			return fmt.Errorf("a destination port needs protocol tcp or udp")
		}
		if !reDPortSvc.MatchString(dp) {
			return fmt.Errorf("destination port must be a number or range (e.g. 80 or 8000-8100)")
		}
		for _, part := range strings.Split(dp, "-") {
			n, _ := strconv.Atoi(part)
			if n < 1 || n > 65535 {
				return fmt.Errorf("port %s is out of range (1–65535)", part)
			}
		}
	}
	return nil
}

func reverseFWRule(r FWRule) FWRule {
	rev := r
	rev.From, rev.To = r.To, r.From
	rev.FromVM, rev.ToVM = r.ToVM, r.FromVM
	if strings.TrimSpace(r.Desc) != "" {
		rev.Desc = "reverse: " + r.Desc
	} else {
		rev.Desc = "reverse of " + r.From + " → " + r.To
	}
	return rev
}

// ewRejectsExternal guards East-West rules: External is the routed uplink, which
// never appears on an L2 segment, so it can't be an east-west endpoint.
func ewRejectsExternal(dir string, r FWRule) error {
	if dir == "ew" && (r.From == ZoneExternal || r.To == ZoneExternal) {
		return fmt.Errorf("External can't be used in an East-West rule (it isn't on any L2 segment)")
	}
	return nil
}

func (s *Service) FWAddRule(p *Principal, dir string, r FWRule, reverse bool, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.rule.add", func(f *OrgFirewall) error {
		if err := validFWRule(f, r); err != nil {
			return err
		}
		if err := ewRejectsExternal(dir, r); err != nil {
			return err
		}
		rp := f.rules(dir)
		*rp = append(*rp, r)
		if reverse {
			rev := reverseFWRule(r)
			if err := validFWRule(f, rev); err != nil {
				return err
			}
			*rp = append(*rp, rev)
		}
		return nil
	})
}

func (s *Service) FWDelRule(p *Principal, dir string, idx int, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.rule.delete", func(f *OrgFirewall) error {
		rp := f.rules(dir)
		if idx < 0 || idx >= len(*rp) {
			return fmt.Errorf("no such rule")
		}
		*rp = append((*rp)[:idx], (*rp)[idx+1:]...)
		return nil
	})
}

func (s *Service) FWUpdateRule(p *Principal, dir string, idx int, r FWRule, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.rule.update", func(f *OrgFirewall) error {
		rp := f.rules(dir)
		if idx < 0 || idx >= len(*rp) {
			return fmt.Errorf("no such rule")
		}
		if err := validFWRule(f, r); err != nil {
			return err
		}
		if err := ewRejectsExternal(dir, r); err != nil {
			return err
		}
		(*rp)[idx] = r
		return nil
	})
}

// FWMoveRule reorders within the same From→To group (like the old move: one step).
func (s *Service) FWMoveRule(p *Principal, dir string, idx int, up string, ip string) error {
	return s.mutateOrgFW(p, ip, "firewall.rule.move", func(f *OrgFirewall) error {
		rp := f.rules(dir)
		if idx < 0 || idx >= len(*rp) {
			return nil
		}
		step := -1
		if up == "down" {
			step = 1
		}
		cur := (*rp)[idx]
		for j := idx + step; j >= 0 && j < len(*rp); j += step {
			if (*rp)[j].From == cur.From && (*rp)[j].To == cur.To &&
				(*rp)[j].FromVM == cur.FromVM && (*rp)[j].ToVM == cur.ToVM {
				(*rp)[idx], (*rp)[j] = (*rp)[j], (*rp)[idx]
				return nil
			}
		}
		return nil
	})
}

// ---- view ----------------------------------------------------------------

type FWVMChip struct {
	Name  string `json:"name"`
	MAC   string `json:"mac"`
	Net   string `json:"net"`
	NetID int64  `json:"net_id"`
}
type FWNetChip struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
type FWGroupView struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Zone  string      `json:"zone"`
	Color string      `json:"color"`
	VMs   []FWVMChip  `json:"vms"`
	Nets  []FWNetChip `json:"nets"`
	Count int         `json:"count"` // distinct VMs this group resolves to
}
type FWRuleRow struct {
	Idx        int    `json:"idx"`
	Rule       FWRule `json:"rule"`
	FromName   string `json:"from_name"`
	ToName     string `json:"to_name"`
	FromColor  string `json:"from_color"`
	ToColor    string `json:"to_color"`
	FromVMName string `json:"from_vm_name,omitempty"` // VM display name when the endpoint is narrowed
	ToVMName   string `json:"to_vm_name,omitempty"`
}
type FWRuleGroupView struct {
	From      string      `json:"from"`
	To        string      `json:"to"`
	FromName  string      `json:"from_name"`
	ToName    string      `json:"to_name"`
	FromColor string      `json:"from_color"`
	ToColor   string      `json:"to_color"`
	Items     []FWRuleRow `json:"items"`
}
type FWEndpointOption struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}
type OrgFirewallView struct {
	Enabled        bool               `json:"enabled"`
	Groups         []FWGroupView      `json:"groups"`
	Internal       []FWGroupView      `json:"internal"` // groups in the Internal zone
	External       []FWGroupView      `json:"external"` // groups in the External zone
	VMPalette      []FWVMChip         `json:"vm_palette"`
	NetPalette     []FWNetChip        `json:"net_palette"`
	RulesNS        []FWRuleGroupView  `json:"rules_ns"`
	RulesEW        []FWRuleGroupView  `json:"rules_ew"`
	Endpoints   []FWEndpointOption `json:"endpoints"`    // North-South From/To (groups + Internal/External)
	EWEndpoints []FWEndpointOption `json:"ew_endpoints"` // East-West From/To (groups + Internal; NO External — it has no L2 presence)
	ColorOf        map[string]string  `json:"color_of"`        // endpoint key → color
	NameOf         map[string]string  `json:"name_of"`         // endpoint key → display name
	HasVRouter     bool               `json:"has_vrouter"`
}

// orgVMs returns every VM in the org with a MAC, plus the maps the compiler and
// the view both need: mac→network, mac→name, network→name.
type orgVM struct {
	Name  string
	MAC   string // lowercased
	NetID int64
	Net   string
}

func (s *Service) orgVMs(orgID int64) (vms []orgVM, byMAC map[string]orgVM) {
	byMAC = map[string]orgVM{}
	rows, err := s.db.Query(`SELECT s.name, COALESCE(s.mac,''), COALESCE(s.network_id,0), COALESCE(n.name,'')
		FROM sessions s LEFT JOIN networks n ON n.id=s.network_id
		WHERE s.org_id=? AND s.deleted_at IS NULL AND COALESCE(s.mac,'')<>'' ORDER BY s.name`, orgID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var v orgVM
		if rows.Scan(&v.Name, &v.MAC, &v.NetID, &v.Net) == nil {
			v.MAC = strings.ToLower(strings.TrimSpace(v.MAC))
			if v.MAC == "" {
				continue
			}
			vms = append(vms, v)
			byMAC[v.MAC] = v
		}
	}
	return
}

// ListFirewallView returns the single unified firewall view for the org.
func (s *Service) ListFirewallView(p *Principal) (OrgFirewallView, error) {
	if !p.atLeast("admin") {
		return OrgFirewallView{}, ErrUnauthorized
	}
	s.ensureOrgFWSeeded(p.OrgID)
	f := s.loadOrgFW(p.OrgID)
	vms, byMAC := s.orgVMs(p.OrgID)

	view := OrgFirewallView{
		Enabled: f.Enabled,
		ColorOf: map[string]string{ZoneExternal: FWExternalColor, ZoneInternal: "#0ea5e9"},
		NameOf:  map[string]string{ZoneExternal: ZoneExternal, ZoneInternal: ZoneInternal + " (any)"},
	}
	// Palettes: all org VMs, and all bridged networks (droppable as whole-PG).
	netName := map[int64]string{}
	for _, v := range vms {
		view.VMPalette = append(view.VMPalette, FWVMChip{Name: v.Name, MAC: v.MAC, Net: v.Net, NetID: v.NetID})
		if v.NetID != 0 {
			netName[v.NetID] = v.Net
		}
	}
	if nets, err := s.net.ListNetworks(p.OrgID); err == nil {
		for _, n := range nets {
			if strings.TrimSpace(n.Bridge) == "" {
				continue
			}
			view.NetPalette = append(view.NetPalette, FWNetChip{ID: n.ID, Name: n.Name})
			netName[n.ID] = n.Name
		}
	}
	view.HasVRouter = s.orgHasVRouter(p.OrgID)

	// Groups + colors + zone buckets + rule-endpoint options. East-West excludes
	// External (the uplink has no L2 presence on any segment).
	view.Endpoints = []FWEndpointOption{{Key: ZoneInternal, Name: ZoneInternal + " (any)"}, {Key: ZoneExternal, Name: ZoneExternal}}
	view.EWEndpoints = []FWEndpointOption{{Key: ZoneInternal, Name: ZoneInternal + " (any)"}}
	for gi := range f.Groups {
		g := f.Groups[gi]
		color := FWZoneColors[gi%len(FWZoneColors)]
		view.ColorOf[g.ID] = color
		view.NameOf[g.ID] = g.Name
		gv := FWGroupView{ID: g.ID, Name: g.Name, Zone: g.Zone, Color: color}
		if gv.Zone == "" {
			gv.Zone = ZoneInternal
		}
		distinct := map[string]bool{}
		for _, m := range validMACs(g.MACs) {
			v := byMAC[m]
			gv.VMs = append(gv.VMs, FWVMChip{Name: v.Name, MAC: m, Net: v.Net, NetID: v.NetID})
			distinct[m] = true
		}
		for _, nid := range g.Networks {
			gv.Nets = append(gv.Nets, FWNetChip{ID: nid, Name: netName[nid]})
			for _, v := range vms {
				if v.NetID == nid {
					distinct[v.MAC] = true
				}
			}
		}
		gv.Count = len(distinct)
		view.Groups = append(view.Groups, gv)
		view.Endpoints = append(view.Endpoints, FWEndpointOption{Key: g.ID, Name: g.Name})
		view.EWEndpoints = append(view.EWEndpoints, FWEndpointOption{Key: g.ID, Name: g.Name})
		if gv.Zone == ZoneExternal {
			view.External = append(view.External, gv)
		} else {
			view.Internal = append(view.Internal, gv)
		}
	}

	macName := map[string]string{}
	for _, v := range vms {
		macName[v.MAC] = v.Name
	}
	view.RulesNS = s.groupRules(f.RulesNS, view.ColorOf, view.NameOf, macName)
	view.RulesEW = s.groupRules(f.RulesEW, view.ColorOf, view.NameOf, macName)
	return view, nil
}

// groupRules buckets an ordered rule list by From→To (FortiGate-style), keeping
// each rule's ORIGINAL index for the edit/delete/move routes.
func (s *Service) groupRules(rules []FWRule, colorOf, nameOf, macName map[string]string) []FWRuleGroupView {
	gm := map[string]*FWRuleGroupView{}
	var order []string
	nm := func(k string) string {
		if n, ok := nameOf[k]; ok {
			return n
		}
		return k
	}
	vmnm := func(mac string) string {
		if mac == "" {
			return ""
		}
		if n, ok := macName[strings.ToLower(mac)]; ok {
			return n
		}
		return mac
	}
	for i, r := range rules {
		// Group by direction AND any VM narrowing, so each distinct endpoint pair
		// is its own bucket (two VMs in one group show as separate rows).
		key := r.From + "/" + r.FromVM + "\x00" + r.To + "/" + r.ToVM
		g := gm[key]
		if g == nil {
			g = &FWRuleGroupView{From: r.From, To: r.To, FromName: nm(r.From), ToName: nm(r.To),
				FromColor: colorOf[r.From], ToColor: colorOf[r.To]}
			if v := vmnm(r.FromVM); v != "" {
				g.FromName += " · " + v
			}
			if v := vmnm(r.ToVM); v != "" {
				g.ToName += " · " + v
			}
			gm[key] = g
			order = append(order, key)
		}
		g.Items = append(g.Items, FWRuleRow{Idx: i, Rule: r, FromName: nm(r.From), ToName: nm(r.To),
			FromColor: colorOf[r.From], ToColor: colorOf[r.To], FromVMName: vmnm(r.FromVM), ToVMName: vmnm(r.ToVM)})
	}
	out := make([]FWRuleGroupView, 0, len(order))
	for _, k := range order {
		out = append(out, *gm[k])
	}
	return out
}

func (s *Service) orgHasVRouter(orgID int64) bool {
	var one int
	s.db.QueryRow(`SELECT 1 FROM vrouters WHERE org_id=? LIMIT 1`, orgID).Scan(&one)
	return one == 1
}
