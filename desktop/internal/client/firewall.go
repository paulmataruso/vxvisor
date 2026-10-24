package client

import "fmt"

// Unified NSX-style vFirewall client — mirrors service.OrgFirewallView and its
// nested view types, and the REST surface in internal/api/api_fw.go.
//
// GET /api/v1/firewall returns service.OrgFirewallView, whose structs carry
// EXPLICIT snake_case json tags on the server, so these match those tags.
// Mutations are granular POSTs; the server recompiles both enforcement planes
// (vRouter inet vdxfw for North-South, host bridge vdxdfw for East-West) on each.

// FWRule is one ordered rule (service.FWRule). From/To are a group id, or the
// literal "Internal"/"External"; FromVM/ToVM optionally narrow to one VM by MAC.
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

// FWVMChip is a VM endpoint chip (service.FWVMChip).
type FWVMChip struct {
	Name  string `json:"name"`
	MAC   string `json:"mac"`
	Net   string `json:"net"`
	NetID int64  `json:"net_id"`
}

// FWNetChip is a whole-port-group chip (service.FWNetChip).
type FWNetChip struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// FWGroupView is a VM Group as rendered (service.FWGroupView).
type FWGroupView struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Zone  string      `json:"zone"` // Internal | External
	Color string      `json:"color"`
	VMs   []FWVMChip  `json:"vms"`
	Nets  []FWNetChip `json:"nets"`
	Count int         `json:"count"` // distinct VMs resolved
}

// FWRuleRow is one rule plus its display metadata (service.FWRuleRow). Idx is the
// rule's ORIGINAL index in its direction list — pass it to the delete/update/move
// calls.
type FWRuleRow struct {
	Idx        int    `json:"idx"`
	Rule       FWRule `json:"rule"`
	FromName   string `json:"from_name"`
	ToName     string `json:"to_name"`
	FromColor  string `json:"from_color"`
	ToColor    string `json:"to_color"`
	FromVMName string `json:"from_vm_name,omitempty"`
	ToVMName   string `json:"to_vm_name,omitempty"`
}

// FWRuleGroupView buckets rules by From→To (service.FWRuleGroupView).
type FWRuleGroupView struct {
	From      string      `json:"from"`
	To        string      `json:"to"`
	FromName  string      `json:"from_name"`
	ToName    string      `json:"to_name"`
	FromColor string      `json:"from_color"`
	ToColor   string      `json:"to_color"`
	Items     []FWRuleRow `json:"items"`
}

// FWEndpointOption is a From/To picker option (service.FWEndpointOption).
type FWEndpointOption struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// OrgFirewallView is the single unified firewall view (service.OrgFirewallView).
type OrgFirewallView struct {
	Enabled     bool               `json:"enabled"`
	Groups      []FWGroupView      `json:"groups"`
	Internal    []FWGroupView      `json:"internal"` // groups in the Internal zone
	External    []FWGroupView      `json:"external"` // groups in the External zone
	VMPalette   []FWVMChip         `json:"vm_palette"`
	NetPalette  []FWNetChip        `json:"net_palette"`
	RulesNS     []FWRuleGroupView  `json:"rules_ns"`     // North-South (routed → vRouter)
	RulesEW     []FWRuleGroupView  `json:"rules_ew"`     // East-West (same-L2 → host bridge)
	Endpoints   []FWEndpointOption `json:"endpoints"`    // N-S From/To options
	EWEndpoints []FWEndpointOption `json:"ew_endpoints"` // E-W From/To options (no External)
	ColorOf     map[string]string  `json:"color_of"`     // endpoint key → color
	NameOf      map[string]string  `json:"name_of"`      // endpoint key → display name
	HasVRouter  bool               `json:"has_vrouter"`
}

// Firewall fetches the unified vFirewall view for the org (admin only on server).
func (c *Client) Firewall() (OrgFirewallView, error) {
	var view OrgFirewallView
	err := c.getJSON("/api/v1/firewall", &view)
	return view, err
}

// FWSetEnabled turns the whole org firewall on or off.
func (c *Client) FWSetEnabled(enabled bool) error {
	return c.apiPostJSON("/api/v1/firewall/enabled", map[string]any{"enabled": enabled})
}

// FWAddGroup creates a VM Group (starts in the Internal zone) and returns its id.
func (c *Client) FWAddGroup(name string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.apiPostDecode("/api/v1/firewall/group", map[string]any{"name": name}, &out)
	return out.ID, err
}

// FWRenameGroup renames a VM Group.
func (c *Client) FWRenameGroup(gid, name string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/group/%s/rename", gid), map[string]any{"name": name})
}

// FWDelGroup deletes a VM Group (and any rule that referenced it).
func (c *Client) FWDelGroup(gid string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/group/%s/delete", gid), nil)
}

// FWSetGroupMembers replaces the group's full membership (VM MACs + whole-PG
// network ids) — send the complete post-drop set.
func (c *Client) FWSetGroupMembers(gid string, macs []string, networks []int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/group/%s/members", gid),
		map[string]any{"macs": macs, "networks": networks})
}

// FWSetGroupZone moves a group to the Internal or External zone.
func (c *Client) FWSetGroupZone(gid, zone string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/group/%s/zone", gid), map[string]any{"zone": zone})
}

// FWAddRule adds a rule in direction dir ("ns" or "ew"); reverse also inserts the
// mirror rule.
func (c *Client) FWAddRule(dir string, rule FWRule, reverse bool) error {
	body := struct {
		Dir     string `json:"dir"`
		Reverse bool   `json:"reverse"`
		FWRule
	}{Dir: dir, Reverse: reverse, FWRule: rule}
	return c.apiPostJSON("/api/v1/firewall/rule", body)
}

// FWDelRule removes rule i in direction dir ("ns" or "ew").
func (c *Client) FWDelRule(dir string, i int) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/rule/%s/%d/delete", dir, i), nil)
}

// FWUpdateRule replaces rule i in direction dir with rule.
func (c *Client) FWUpdateRule(dir string, i int, rule FWRule) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/rule/%s/%d/update", dir, i), rule)
}

// FWMoveRule reorders rule i one step ("up" or "down") within its From→To group.
func (c *Client) FWMoveRule(dir string, i int, step string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/firewall/rule/%s/%d/move", dir, i), map[string]any{"step": step})
}
