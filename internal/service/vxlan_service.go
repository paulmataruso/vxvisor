package service

import (
	"fmt"
	"log"
	"net"
	"strings"

	"vdxclone/internal/hostinfo"
	"vdxclone/internal/netdrv"
)

// VXLAN port groups and storage overlays: input validation, the host's VXLAN
// ingress guard (nft table inet vdxvxlan: VXLAN UDP only from each VNI's
// configured peers), and host isolation for VXLAN port groups (the same
// vdxtenant guard tenant bridges get — see applyTenantIsolation).

// hostAddrs lists every address configured on this host (CIDR form). A var so
// tests can stand in for the kernel.
var hostAddrs = func() []string {
	ifs, err := hostinfo.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, it := range ifs {
		out = append(out, it.Addrs...)
	}
	return out
}

// hostHasIP reports whether ip is configured on one of this host's interfaces.
func hostHasIP(ip string) bool {
	want := net.ParseIP(ip)
	if want == nil {
		return false
	}
	for _, a := range hostAddrs() {
		if have, _, err := net.ParseCIDR(a); err == nil && have.Equal(want) {
			return true
		}
	}
	return false
}

// validateVXLANNetwork normalizes and checks a VXLAN port group before anything
// is recorded or built: defaults (UDP 4789, MTU 1450), canonical peers, a free
// VNI, an underlay that exists, and a local IP this host actually holds.
func (s *Service) validateVXLANNetwork(n *netdrv.Network) error {
	n.Underlay = strings.TrimSpace(n.Underlay)
	n.VXLANLocal = strings.TrimSpace(n.VXLANLocal)
	if n.DstPort == 0 {
		n.DstPort = 4789
	}
	if n.MTU == 0 {
		n.MTU = 1450
	}
	if n.VLANID != 0 {
		return fmt.Errorf("a VXLAN network has no VLAN — leave the VLAN at 0")
	}
	n.Bridge = "" // derived from the row id when the segment is built
	peers, err := netdrv.ParsePeerCSV(n.VXLANPeers)
	if err != nil {
		return err
	}
	n.VXLANPeers = strings.Join(peers, ",")
	if err := (netdrv.VXLANParams{VNI: n.VNI, DstPort: n.DstPort, MTU: n.MTU, Underlay: n.Underlay,
		Local: n.VXLANLocal, Peers: peers}).Validate(); err != nil {
		return err
	}
	if err := checkPGAddressing(&n.CIDR, n.Gateway, n.PoolStart, n.PoolEnd); err != nil {
		return err
	}
	if who := s.vniUser(n.VNI, ""); who != "" {
		return fmt.Errorf("VNI %d is already used by %s — pick another VNI", n.VNI, who)
	}
	if n.VXLANLocal != "" && !hostHasIP(n.VXLANLocal) {
		return fmt.Errorf("local IP %s is not an address of this host — use the underlay NIC's own IP, or leave it blank", n.VXLANLocal)
	}
	if !netdrv.IfaceExists(n.Underlay) {
		return fmt.Errorf("underlay NIC %q was not found on this host", n.Underlay)
	}
	return nil
}

// vniUser names whatever already uses vni on this host ("" if it's free).
// VNIs are kept unique host-wide across VXLAN port groups, storage overlays,
// tenant segment identities and the [cluster] overlay. exceptOverlay skips a
// storage overlay being re-applied under its own name.
func (s *Service) vniUser(vni int, exceptOverlay string) string {
	var name string
	if s.db.QueryRow(`SELECT name FROM networks WHERE vni=? LIMIT 1`, vni).Scan(&name) == nil {
		return fmt.Sprintf("port group %q", name)
	}
	if s.db.QueryRow(`SELECT name FROM storage_overlays WHERE vni=? AND name<>? LIMIT 1`, vni, exceptOverlay).Scan(&name) == nil {
		return fmt.Sprintf("storage overlay %q", name)
	}
	var n int
	if _ = s.db.QueryRow(`SELECT COUNT(*) FROM net_segments WHERE seg_type='vxlan' AND seg_id=?`, vni).Scan(&n); n > 0 {
		return "a tenant network"
	}
	if s.cfg != nil && s.cfg.Cluster.Overlay && s.cfg.Cluster.VNI == vni {
		return "the cluster overlay ([cluster].vni)"
	}
	return ""
}

// checkPGAddressing validates a port group's optional IPv4 subnet, gateway and
// address pool, and rewrites the subnet in network form (10.20.0.0/24).
func checkPGAddressing(cidr *string, gw, start, end string) error {
	*cidr = strings.TrimSpace(*cidr)
	if *cidr == "" {
		if gw != "" || start != "" || end != "" {
			return fmt.Errorf("set the subnet (CIDR) to use a gateway or an address pool")
		}
		return nil
	}
	_, ipnet, err := net.ParseCIDR(*cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return fmt.Errorf("subnet %q is not an IPv4 CIDR — use e.g. 10.20.0.0/24", *cidr)
	}
	*cidr = ipnet.String()
	if gw != "" {
		if err := gatewayInCIDR(gw, *cidr); err != nil {
			return err
		}
	}
	if (start == "") != (end == "") {
		return fmt.Errorf("set both ends of the address pool, or neither")
	}
	if start != "" {
		a, b := net.ParseIP(start).To4(), net.ParseIP(end).To4()
		if a == nil || b == nil || !ipnet.Contains(a) || !ipnet.Contains(b) {
			return fmt.Errorf("the address pool %s–%s must be IPv4 addresses inside %s", start, end, *cidr)
		}
		if ipLess(b, a) {
			return fmt.Errorf("the address pool starts after it ends (%s–%s)", start, end)
		}
	}
	return nil
}

func ipLess(a, b net.IP) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// vxlanListeners collects every VXLAN identity this host terminates, each with
// the peers allowed to send to it.
func (s *Service) vxlanListeners() []netdrv.VXLANListener {
	var out []netdrv.VXLANListener
	collect := func(q string) {
		rows, err := s.db.Query(q)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var vni, port int
			var peers string
			if rows.Scan(&vni, &port, &peers) == nil {
				out = append(out, netdrv.VXLANListener{Port: port, VNI: vni, Peers: splitCSV(peers)})
			}
		}
	}
	collect(`SELECT vni,COALESCE(vxlan_dstport,4789),COALESCE(vxlan_peers,'') FROM networks WHERE mode='vxlan' AND vni>0`)
	collect(`SELECT vni,dstport,peers FROM storage_overlays WHERE vni>0`)
	// The [cluster] overlay has no peer list (it learns its peers), so its VNI is
	// left open; every other VNI on its port is still filtered.
	if c := s.cfg; c != nil && c.Cluster.Overlay && (c.Network.Mode == "bridge" || c.Network.Mode == "overlay") && c.Cluster.VNI > 0 {
		out = append(out, netdrv.VXLANListener{Port: 4789, VNI: c.Cluster.VNI, Open: true})
	}
	return out
}

// applyVXLANGuard rebuilds the vdxvxlan ingress guard from the DB. extra adds
// listeners not recorded yet (one being brought up right now).
func (s *Service) applyVXLANGuard(extra ...netdrv.VXLANListener) error {
	return netdrv.ApplyVXLANGuard(append(s.vxlanListeners(), extra...))
}

// vxlanIsolatedBridges lists the bridges of VXLAN port groups that get the
// tenant host isolation (from the segment only DHCP and a ping of the bridge's
// own IP reach the host, and the host never routes for it) — every VXLAN port
// group the admin hasn't chosen to route through this host. Routed means it was
// created as routed (networks.nat=1) or its subnet is in the host routing
// config (NAT / OSPF / BGP / EIGRP networks).
func (s *Service) vxlanIsolatedBridges() []string {
	rows, err := s.db.Query(`SELECT id,COALESCE(cidr,''),COALESCE(nat,0) FROM networks WHERE mode='vxlan'`)
	if err != nil {
		return nil
	}
	type row struct {
		id   int64
		cidr string
		nat  int
	}
	var list []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.cidr, &r.nat) == nil {
			list = append(list, r)
		}
	}
	rows.Close()
	routed := s.hostRoutedNets()
	var out []string
	for _, r := range list {
		if r.nat == 1 || subnetRouted(r.cidr, routed) {
			continue
		}
		br, _ := netdrv.VNINetworkNames(r.id)
		out = append(out, br)
	}
	return out
}

// hostRoutedNets is every subnet the host routing config routes or NATs.
func (s *Service) hostRoutedNets() []*net.IPNet {
	c, err := s.GetRoutingConfig(&Principal{IsAdmin: true})
	if err != nil {
		return nil
	}
	cidrs := append([]string{}, c.InternalCIDRs...)
	for _, o := range c.OSPF.Networks {
		cidrs = append(cidrs, o.CIDR)
	}
	cidrs = append(cidrs, c.BGP.Networks...)
	cidrs = append(cidrs, c.EIGRP.Networks...)
	var out []*net.IPNet
	for _, x := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(x)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// subnetRouted reports whether cidr lies inside one of the routed subnets.
func subnetRouted(cidr string, routed []*net.IPNet) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := n.Mask.Size()
	for _, r := range routed {
		rOnes, _ := r.Mask.Size()
		if rOnes <= ones && r.Contains(n.IP) {
			return true
		}
	}
	return false
}

// refreshVXLANHost re-applies the VXLAN ingress guard and VXLAN port-group
// isolation (applyTenantIsolation rebuilds both), logging rather than failing:
// the caller's change has already happened.
func (s *Service) refreshVXLANHost() {
	if err := s.applyTenantIsolation(); err != nil {
		log.Printf("vxlan: host isolation: %v", err)
	}
}
