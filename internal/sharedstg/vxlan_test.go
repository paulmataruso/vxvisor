package sharedstg

import (
	"strings"
	"testing"
)

// TestVXLANUnit: the storage overlay's boot unit loads the VXLAN ingress guard
// first, and no field can smuggle in a unit line (or reach ip(8) unchecked).
func TestVXLANUnit(t *testing.T) {
	ok := VXLANSpec{Name: "vxlan-stor", Dev: "eth0", Local: "10.0.0.1", OverlayCIDR: "10.10.4.11/24",
		VNI: 4000, DstPort: 4789, MTU: 1450, Peers: []string{"10.0.0.2"}}
	unit, err := VXLANUnit(ok)
	if err != nil {
		t.Fatal(err)
	}
	if pre, first := strings.Index(unit, "ExecStartPre=-"), strings.Index(unit, "ExecStart="); pre < 0 || first < pre {
		t.Fatalf("the unit must load the VXLAN guard before the device comes up:\n%s", unit)
	}
	if !strings.Contains(unit, "type vxlan id 4000 local 10.0.0.1 dstport 4789 dev eth0") {
		t.Fatalf("unit missing the vxlan line:\n%s", unit)
	}
	for name, mut := range map[string]func(*VXLANSpec){
		"dev":     func(s *VXLANSpec) { s.Dev = "eth0\nExecStart=/bin/sh -c id" },
		"local":   func(s *VXLANSpec) { s.Local = "10.0.0.1\nExecStart=/bin/sh" },
		"cidr":    func(s *VXLANSpec) { s.OverlayCIDR = "10.10.4.11/24\nExecStart=/bin/sh" },
		"peer":    func(s *VXLANSpec) { s.Peers = []string{"10.0.0.2 \nExecStart=/bin/sh"} },
		"name":    func(s *VXLANSpec) { s.Name = "x y" },
		"netaddr": func(s *VXLANSpec) { s.OverlayCIDR = "10.10.4.0/24" },
		"nolocal": func(s *VXLANSpec) { s.Local = "" },
		"vni":     func(s *VXLANSpec) { s.VNI = 0 },
	} {
		sp := ok
		mut(&sp)
		if _, err := VXLANUnit(sp); err == nil {
			t.Errorf("%s: must be refused", name)
		}
		if err := VXLANUp(sp); err == nil {
			t.Errorf("%s: VXLANUp must refuse it before touching the host", name)
		}
	}
}
