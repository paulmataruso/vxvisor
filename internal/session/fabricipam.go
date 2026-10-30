package session

import (
	"fmt"
	"strings"
)

// FabricIPAM allocates addresses on VXVisor Fabric port groups (networks rows
// in mode 'fabric'). A fabric lease is fabric-wide — it lives in the replicated
// intent, so every host's DHCP answers the VM with it and it survives a
// migration unchanged — and is mirrored into this node's ip_leases.
type FabricIPAM interface {
	// Lease returns the session's address on fabric port group netID as
	// "ip/prefix", allocating one if it has none.
	Lease(netID int64, sessionID, mac string) (string, error)
	// Release gives back the session's leases on every fabric port group;
	// ReleaseOn only its lease on netID.
	Release(sessionID string)
	ReleaseOn(sessionID string, netID int64)
}

// SetFabricIPAM installs the fabric allocator (the service owns the intent).
func (m *Manager) SetFabricIPAM(f FabricIPAM) { m.fabric = f }

// fabricLease allocates (or returns) a VM's fabric lease and mirrors it locally.
func (m *Manager) fabricLease(pg portGroup, sessionID, mac string) (string, error) {
	if m.fabric == nil {
		return "", fmt.Errorf("port group %q is on the VXVisor Fabric, which isn't running on this node", pg.Name)
	}
	if pg.CIDR == "" {
		return "", nil // L2-only: addressing is the guest's business
	}
	lease, err := m.fabric.Lease(pg.ID, sessionID, mac)
	if err != nil {
		return "", fmt.Errorf("port group %q: %w", pg.Name, err)
	}
	ipamMu.Lock()
	defer ipamMu.Unlock()
	_, _ = m.db.Exec(`DELETE FROM ip_leases WHERE network_id=? AND session_id=?`, pg.ID, sessionID)
	if _, err := m.db.Exec(`INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,?,?,?)`,
		pg.ID, sessionID, lease, strings.ToLower(mac)); err != nil {
		return "", fmt.Errorf("port group %q: record lease %s: %w", pg.Name, lease, err)
	}
	return lease, nil
}

// rebindFabricLease runs before a VM's NIC moves to networkID: off a fabric port
// group, its lease there goes back; onto one, it gets a lease (static-only DHCP
// answers nobody else).
func (m *Manager) rebindFabricLease(cur *Session, networkID int64) error {
	if networkID == cur.NetworkID {
		return nil
	}
	if networkID > 0 {
		pg, err := m.portGroup(cur.OrgID, networkID)
		if err != nil {
			return err
		}
		if pg.Mode == "fabric" {
			if _, err := m.fabricLease(pg, cur.ID, cur.MAC); err != nil {
				return err
			}
		}
	}
	if cur.NetworkID > 0 && m.fabric != nil {
		var mode string
		if m.db.QueryRow(`SELECT mode FROM networks WHERE id=?`, cur.NetworkID).Scan(&mode) == nil && mode == "fabric" {
			m.fabric.ReleaseOn(cur.ID, cur.NetworkID)
			_, _ = m.db.Exec(`DELETE FROM ip_leases WHERE network_id=? AND session_id=?`, cur.NetworkID, cur.ID)
		}
	}
	return nil
}
