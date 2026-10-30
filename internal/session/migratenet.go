package session

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/qemu"
)

// A migrating VM's network binding. A networks row id is local to each node's
// DB, so the port group travels by identity (qemu.PortGroupRef) and the
// destination binds the VM to its OWN matching row, never to whatever row
// happens to carry the source's id there (another org's, or nothing). A live
// receiver's tap goes on that port group's vSwitch before the stream starts,
// exactly as Start would attach it, so the guest resumes on the network it left.

// errOldMigrationPeer: the record came from a node that doesn't ship the port
// group, so binding it here would mean guessing.
var errOldMigrationPeer = errors.New("the source node runs an older VXVisor that doesn't send the instance's port group — update every node to the same version before migrating")

// receiverNet is how an inbound migration was attached on this node.
type receiverNet struct {
	NetID int64  // this node's networks.id (0 = no port group)
	Lease string // the guest's address, reserved here ("" = none)
	Tap   string // vdxd-made tap ("" = none)
}

// PortGroupRefFor describes a VM's port group, and its address on it, by an
// identity another node can resolve. A port group that no longer exists is
// shipped as none, matching what planNIC does with it.
func (m *Manager) PortGroupRefFor(s *Session) (*qemu.PortGroupRef, error) {
	ref := &qemu.PortGroupRef{OrgID: s.OrgID}
	if s.NetworkID == 0 {
		return ref, nil
	}
	var org int64
	err := m.db.QueryRow(`SELECT org_id,name,COALESCE(vlan_id,0),COALESCE(vni,0),COALESCE(cidr,'') FROM networks WHERE id=?`,
		s.NetworkID).Scan(&org, &ref.Name, &ref.VLAN, &ref.VNI, &ref.CIDR)
	if isNoRows(err) {
		return &qemu.PortGroupRef{OrgID: s.OrgID}, nil
	}
	if err != nil {
		return nil, err
	}
	if org != s.OrgID {
		return nil, fmt.Errorf("this instance's port group belongs to another organization — pick one of its own port groups in the Network setting")
	}
	_ = m.db.QueryRow(`SELECT ip FROM ip_leases WHERE network_id=? AND session_id=? ORDER BY id LIMIT 1`,
		s.NetworkID, s.ID).Scan(&ref.Lease)
	return ref, nil
}

// describePortGroupRef renders a ref's segment identity for an error message.
func describePortGroupRef(ref *qemu.PortGroupRef) string {
	parts := []string{"untagged"}
	if ref.VLAN > 0 {
		parts[0] = fmt.Sprintf("VLAN %d", ref.VLAN)
	}
	if ref.VNI > 0 {
		parts = append(parts, fmt.Sprintf("VNI %d", ref.VNI))
	}
	if ref.CIDR != "" {
		parts = append(parts, "subnet "+ref.CIDR)
	} else {
		parts = append(parts, "no subnet")
	}
	return strings.Join(parts, ", ")
}

// resolvePortGroupRef finds this node's port group matching ref: same org,
// name, VLAN, VNI and subnet. Exactly one must match; none or several is an
// error saying what to fix, so a VM is never bound to a look-alike.
func (m *Manager) resolvePortGroupRef(ref *qemu.PortGroupRef) (int64, error) {
	if ref.Name == "" {
		return 0, nil
	}
	rows, err := m.db.Query(`SELECT id FROM networks WHERE org_id=? AND name=? AND COALESCE(vlan_id,0)=?
		AND COALESCE(vni,0)=? AND COALESCE(cidr,'')=?`, ref.OrgID, ref.Name, ref.VLAN, ref.VNI, ref.CIDR)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return 0, fmt.Errorf("this node has no port group %q (%s) in the instance's organization — create a matching one on this node first",
			ref.Name, describePortGroupRef(ref))
	default:
		return 0, fmt.Errorf("this node has %d port groups named %q (%s) in the instance's organization — rename all but one",
			len(ids), ref.Name, describePortGroupRef(ref))
	}
}

// migratedNetwork resolves an inbound record's port group to this node's row.
// A record without a ref is accepted only when the VM had no port group.
func (m *Manager) migratedNetwork(s *Session) (int64, error) {
	if s.PortGroup == nil {
		if s.NetworkID != 0 {
			return 0, errOldMigrationPeer
		}
		return 0, nil
	}
	if s.PortGroup.OrgID != s.OrgID {
		return 0, fmt.Errorf("migration record: port group org doesn't match the instance's")
	}
	return m.resolvePortGroupRef(s.PortGroup)
}

// leaseTaken reports whether another instance holds lease's address on netID's
// segment here (its own leases, or any port group on the same bridge + VLAN).
// The guest keeps its address across the move, so it must be free here.
func (m *Manager) leaseTaken(netID int64, sessionID, lease string) (bool, error) {
	var bridge string
	var vlan int
	_ = m.db.QueryRow(`SELECT COALESCE(bridge,''),COALESCE(vlan_id,0) FROM networks WHERE id=?`, netID).Scan(&bridge, &vlan)
	rows, err := m.db.Query(`SELECT l.ip FROM ip_leases l LEFT JOIN networks n ON n.id=l.network_id
		WHERE l.session_id<>? AND (l.network_id=? OR (n.bridge<>'' AND n.bridge=? AND COALESCE(n.vlan_id,0)=?))`,
		sessionID, netID, bridge, vlan)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	host := leaseHost(lease)
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil && leaseHost(ip) == host {
			return true, nil
		}
	}
	return false, rows.Err()
}

// reserveMigratedLease records the guest's address on this node's port group,
// replacing any lease this instance left here before (a migrate-back). The
// check and the insert run under ipamMu so a concurrent create can't take it.
func (m *Manager) reserveMigratedLease(netID int64, sessionID, mac, lease string) error {
	ipamMu.Lock()
	defer ipamMu.Unlock()
	if netID == 0 || lease == "" {
		return nil
	}
	taken, err := m.leaseTaken(netID, sessionID, lease)
	if err != nil {
		return err
	}
	if taken {
		return fmt.Errorf("address %s is already in use on this node's port group — free it there first", leaseHost(lease))
	}
	if _, err := m.db.Exec(`DELETE FROM ip_leases WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	_, err = m.db.Exec(`INSERT INTO ip_leases(network_id,session_id,ip,mac) VALUES(?,?,?,?)`, netID, sessionID, lease, mac)
	return err
}

// CheckMigrationTarget is the destination's pre-flight for an inbound
// migration record, run before any disk copy or stream: the port group must
// resolve to one of this node's own, be usable by the org, and the guest's
// address must be free here. Changes nothing.
func (m *Manager) CheckMigrationTarget(s *Session) error {
	netID, err := m.migratedNetwork(s)
	if err != nil {
		return err
	}
	if err := m.CheckPortGroup(s.OrgID, netID); err != nil {
		return err
	}
	if netID != 0 && s.PortGroup != nil && s.PortGroup.Lease != "" {
		ipamMu.Lock()
		taken, err := m.leaseTaken(netID, s.ID, s.PortGroup.Lease)
		ipamMu.Unlock()
		if err != nil {
			return err
		}
		if taken {
			return fmt.Errorf("address %s is already in use on this node's port group — free it there first", leaseHost(s.PortGroup.Lease))
		}
	}
	return nil
}

// attachReceiverNIC binds an inbound live migration to this node's network
// before its QEMU launches: it resolves the shipped port group, reserves the
// guest's address, and puts the receiver's tap on the vSwitch with the port
// group's VLAN, as Start does. The NIC's device config (netdev type, host_mtu,
// queues) stays the source's, or the stream would be rejected. On error
// nothing is left behind. Call after prepareReceiverSpec (it sets RunAsUID).
func (m *Manager) attachReceiverNIC(spec *qemu.Spec) (receiverNet, error) {
	ref := spec.PortGroup
	if ref == nil {
		return receiverNet{}, errOldMigrationPeer
	}
	netID, err := m.resolvePortGroupRef(ref)
	if err != nil {
		return receiverNet{}, err
	}
	plan, err := m.planNIC(&Session{ID: spec.ID, OrgID: ref.OrgID, NetworkID: netID})
	if err != nil {
		return receiverNet{}, err
	}
	bridged := !spec.UserNet && plan.Bridge != ""
	if !spec.UserNet && plan.UserNet {
		return receiverNet{}, fmt.Errorf("the instance is bridged on the source, but this node would run it on user-mode NAT — give it a vSwitch-backed port group here")
	}
	if bridged {
		guestMTU := spec.HostMTU
		if guestMTU == 0 {
			guestMTU = 1500
		}
		if plan.MTU > 0 && plan.MTU < guestMTU {
			return receiverNet{}, fmt.Errorf("vSwitch %s here has MTU %d, below the instance's %d — raise it or pick another port group", plan.Bridge, plan.MTU, guestMTU)
		}
	}
	rn := receiverNet{NetID: netID}
	if err := m.reserveMigratedLease(netID, spec.ID, spec.MAC, ref.Lease); err != nil {
		return receiverNet{}, err
	}
	rn.Lease = ref.Lease
	if !bridged {
		// SLIRP, or a QEMU-managed tap with no bridge: the same as the source.
		return rn, nil
	}
	tap := netdrv.TapName(spec.ID)
	if err := netdrv.SetupTapAccess(tap, plan.Bridge, plan.VLAN, int(spec.RunAsUID)); err != nil {
		netdrv.TeardownTap(tap)
		m.detachReceiverNIC(spec.ID, rn)
		return receiverNet{}, fmt.Errorf("setup tap %s on %s: %w", tap, plan.Bridge, err)
	}
	if plan.MTU > 0 && netdrv.LinkMTU(tap) != plan.MTU {
		if err := netdrv.SetLinkMTU(tap, plan.MTU); err != nil {
			log.Printf("migration receiver %s: tap %s MTU %d (bridge %s): %v", spec.ID, tap, plan.MTU, plan.Bridge, err)
		}
	}
	spec.TapName = tap
	rn.Tap = tap
	return rn, nil
}

// detachReceiverNIC undoes attachReceiverNIC for a receiver that won't be
// adopted: its tap goes, and so does the address it reserved.
func (m *Manager) detachReceiverNIC(id string, rn receiverNet) {
	if rn.Tap != "" {
		netdrv.TeardownTap(rn.Tap)
	}
	if rn.Lease != "" {
		m.releaseLeases(id)
	}
}

// takeIncoming removes and returns an inbound migration's receiver process and
// network attachment (nil, false when there is none).
func (m *Manager) takeIncoming(id string) (*os.Process, receiverNet, bool) {
	m.incomingMu.Lock()
	defer m.incomingMu.Unlock()
	proc := m.incoming[id]
	rn, ok := m.incomingNet[id]
	delete(m.incoming, id)
	delete(m.incomingNet, id)
	return proc, rn, ok
}

// trackIncoming records a launched receiver for the adopt or abort to come.
func (m *Manager) trackIncoming(id string, proc *os.Process, rn receiverNet) {
	m.incomingMu.Lock()
	m.incoming[id] = proc
	m.incomingNet[id] = rn
	m.incomingMu.Unlock()
}

// ReleaseMigratedSource frees what a VM held on THIS node once another node has
// adopted it: the tap its QEMU used and its address leases. The source calls it
// after removing its row.
func (m *Manager) ReleaseMigratedSource(id string) {
	netdrv.TeardownTap(netdrv.TapName(id))
	m.releaseLeases(id)
}
