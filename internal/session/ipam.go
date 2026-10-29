package session

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// Guest IPAM for cloud-init static addressing. A VM's address comes from its
// OWN port group (its CIDR + pool), never from the cluster subnet unless the VM
// actually sits on the cluster bridge. Leases are recorded per port group in
// ip_leases (UNIQUE(network_id, ip)); uniqueness is enforced across every port
// group that shares the same L2 segment (bridge + VLAN), so two orgs' rows over
// one shared segment never hand out the same address, while two isolated
// segments with overlapping CIDRs (two tenants both on 10.5.0.0/24) stay
// independent.

// ipamMu serializes allocation so two concurrent creates can't pick the same
// address on two rows that share a segment (the per-row UNIQUE can't see that).
var ipamMu sync.Mutex

// guestAddressing decides how a new VM's cloud-init network-config addresses its
// NIC, allocating a static lease when one is due:
//   - a bridged port group with an address pool (CIDR + pool start/end): a static
//     lease from that pool, with the port group's gateway;
//   - any other bridged port group: DHCP from the segment itself (the tenant
//     network's dnsmasq, a gateway (vRouter), or the LAN);
//   - a bridgeless (user-mode NAT) port group: nothing — SLIRP's own DHCP;
//   - no port group, or a port group that IS the untagged cluster bridge, in
//     bridge/overlay mode: the historical cluster-subnet IPAM (DHCP with
//     [cluster] dhcp).
//
// Only a pool allocation failure is an error (the admin delegated that pool, so
// an exhausted or malformed one must be fixed, not silently ignored); the
// cluster-subnet path stays best-effort, as before.
func (m *Manager) guestAddressing(orgID, netID int64, sessionID, mac string) (staticIP, gw string, dhcp bool, err error) {
	clusterMode := m.cfg.Network.Mode == "bridge" || m.cfg.Network.Mode == "overlay"
	if netID > 0 {
		pg, err := m.portGroup(orgID, netID)
		if err != nil {
			return "", "", false, err
		}
		if pg.Bridge == "" {
			return "", "", false, nil
		}
		onClusterBridge := clusterMode && pg.Bridge == m.cfg.Cluster.Bridge && pg.VLAN == 0
		if !onClusterBridge {
			if pg.CIDR != "" && pg.PoolStart != "" && pg.PoolEnd != "" {
				ip, err := m.allocLease(pg.ID, sessionID, mac, pg.CIDR, pg.Gateway, pg.PoolStart, pg.PoolEnd, false)
				if err != nil {
					return "", "", false, fmt.Errorf("port group %q: %w", pg.Name, err)
				}
				return ip, pg.Gateway, false, nil
			}
			return "", "", true, nil
		}
	}
	if !clusterMode {
		return "", "", false, nil
	}
	if m.cfg.Cluster.DHCP {
		return "", "", true, nil
	}
	bucket, cidr, gateway, derr := m.ensureDefaultNetwork(orgID)
	if derr != nil {
		return "", "", false, nil
	}
	leased, lerr := m.allocLease(bucket, sessionID, mac, cidr, gateway, "", "", true)
	if lerr != nil {
		return "", "", false, nil
	}
	return leased, gateway, false, nil
}

// allocLease assigns the lowest free address of [start,end] (the whole CIDR
// when unset) to a session, skipping the network, gateway and broadcast
// addresses and every address already leased on the same L2 segment, and records
// it under port group netID. wide additionally treats every bridge/overlay
// port group's leases as taken — used for the shared cluster subnet, whose
// legacy leases may have been filed under an org's first bridged row. Idempotent:
// an existing lease for the session on netID is returned. Returns "ip/prefix".
func (m *Manager) allocLease(netID int64, sessionID, mac, cidr, gateway, start, end string, wide bool) (string, error) {
	ipamMu.Lock()
	defer ipamMu.Unlock()

	var existing string
	if err := m.db.QueryRow(`SELECT ip FROM ip_leases WHERE network_id=? AND session_id=?`, netID, sessionID).Scan(&existing); err == nil && existing != "" {
		return existing, nil
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return "", fmt.Errorf("CIDR %q is not an IPv4 network", cidr)
	}
	prefix, _ := ipnet.Mask.Size()
	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	broadcast := base | (uint32(0xFFFFFFFF) >> uint(prefix))
	lo, hi := base+1, broadcast-1
	if prefix >= 31 {
		return "", fmt.Errorf("CIDR %s has no usable host addresses", cidr)
	}
	if start != "" || end != "" {
		s, e := net.ParseIP(start).To4(), net.ParseIP(end).To4()
		if s == nil || e == nil || !ipnet.Contains(s) || !ipnet.Contains(e) {
			return "", fmt.Errorf("its address pool (%s–%s) must be IPv4 addresses inside %s — fix the port group's pool", start, end, cidr)
		}
		if v := binary.BigEndian.Uint32(s); v > lo {
			lo = v
		}
		if v := binary.BigEndian.Uint32(e); v < hi {
			hi = v
		}
		if lo > hi {
			return "", fmt.Errorf("its address pool (%s–%s) is empty — fix the port group's pool", start, end)
		}
	}

	// Everything already leased on this segment (this row, any row on the same
	// bridge + VLAN, and — wide — any bridged row) is taken.
	var bridge string
	var vlan int
	_ = m.db.QueryRow(`SELECT COALESCE(bridge,''),COALESCE(vlan_id,0) FROM networks WHERE id=?`, netID).Scan(&bridge, &vlan)
	q := `SELECT l.ip FROM ip_leases l LEFT JOIN networks n ON n.id=l.network_id
		WHERE l.network_id=? OR (n.bridge<>'' AND n.bridge=? AND COALESCE(n.vlan_id,0)=?)`
	if wide {
		q += ` OR n.mode IN ('bridge','overlay')`
	}
	used := map[string]bool{}
	rows, err := m.db.Query(q, netID, bridge, vlan)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			used[leaseHost(ip)] = true
		}
	}
	rows.Close()
	gw := net.ParseIP(gateway).To4()

	for cand := lo; cand <= hi && cand >= lo; cand++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], cand)
		ip := net.IP(b[:])
		if (gw != nil && ip.Equal(gw)) || used[ip.String()] {
			continue
		}
		leased := ip.String() + "/" + strconv.Itoa(prefix)
		if _, err := m.db.Exec(`INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,?,?,?)`,
			netID, sessionID, leased, mac); err != nil {
			return "", err
		}
		return leased, nil
	}
	return "", fmt.Errorf("its address pool is exhausted — widen the pool or free an address")
}

// releaseLeases frees every address a session holds (on a failed create or a
// purge), so a pool doesn't leak addresses to deleted VMs.
func (m *Manager) releaseLeases(sessionID string) {
	_, _ = m.db.Exec(`DELETE FROM ip_leases WHERE session_id=?`, sessionID)
}

// leaseHost strips the /prefix from a stored lease.
func leaseHost(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
