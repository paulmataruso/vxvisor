package client

// Network topology (VMware-style vSwitch → port group → VM hierarchy, plus
// uplinks and vRouters) from GET /api/topology. These mirror service.Topology
// (snake_case json tags). Admin-only on the server.

type TopoVM struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Tap   string `json:"tap"`
	State string `json:"state"`
	Kind  string `json:"kind"`
	Veth  string `json:"veth"`
	IP    string `json:"ip,omitempty"`
}

type TopoVMK struct {
	Label string   `json:"label"`
	IPs   []string `json:"ips"`
	Iface string   `json:"iface"`
}

type TopoNeighbor struct {
	Local      string `json:"local"`
	Via        string `json:"via"`
	SwitchName string `json:"switch_name"`
	MgmtIP     string `json:"mgmt_ip"`
	PortID     string `json:"port_id"`
	VLAN       string `json:"vlan"`
}

type TopoUplink struct {
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	Mode      string         `json:"mode"`
	Members   []string       `json:"members"`
	State     string         `json:"state"`
	Speed     int            `json:"speed"`
	Neighbors []TopoNeighbor `json:"neighbors"`
}

type TopoPortGroup struct {
	Name string   `json:"name"`
	VLAN int      `json:"vlan"`
	CIDR string   `json:"cidr"`
	VMs  []TopoVM `json:"vms"`
}

type TopoSwitch struct {
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Uplinks     []TopoUplink    `json:"uplinks"`
	VXLAN       bool            `json:"vxlan"`
	Addrs       []string        `json:"addrs"`
	VMKs        []TopoVMK       `json:"vmks"`
	PortGroups  []TopoPortGroup `json:"port_groups"`
	VRouter     string          `json:"vrouter,omitempty"`
	VRouterRole string          `json:"vrouter_role,omitempty"`
}

type TopoNIC struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Type      string `json:"type"`
	SpeedMbps int    `json:"speed_mbps"`
}

type TopoVRInternal struct {
	Name   string   `json:"name"`
	GW     string   `json:"gw"`
	Subnet string   `json:"subnet"`
	Bridge string   `json:"bridge"`
	Iface  string   `json:"iface"`
	Zone   string   `json:"zone,omitempty"`
	VMs    []TopoVM `json:"vms"`
}

type TopoVRTransit struct {
	CIDR   string `json:"cidr"`
	Phys   string `json:"phys"`
	Bridge string `json:"bridge"`
	Iface  string `json:"iface"`
	Switch string `json:"switch"`
	Port   string `json:"port"`
}

type TopoVRouter struct {
	Name     string           `json:"name"`
	Internal []TopoVRInternal `json:"internal"`
	Transit  *TopoVRTransit   `json:"transit,omitempty"`
	Routing  []string         `json:"routing,omitempty"`
	Health   string           `json:"health,omitempty"`
	Runtime  string           `json:"runtime,omitempty"`
	Firewall bool             `json:"firewall,omitempty"`
}

type Topology struct {
	Switches []TopoSwitch  `json:"switches"`
	FreeNICs []TopoNIC     `json:"free_nics"`
	VRouters []TopoVRouter `json:"vrouters,omitempty"`
}

// Topology returns the host network topology (admin-only server-side).
func (c *Client) Topology() (*Topology, error) {
	var t Topology
	if err := c.getJSON("/api/topology", &t); err != nil {
		return nil, err
	}
	return &t, nil
}
