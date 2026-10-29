package service

import (
	"vdxclone/internal/netdrv"
	"vdxclone/internal/session"
)

// VM NIC attachment policy (service side). A tenant org — any org other than the
// provider's Default org (slug "default", the same org Principal treats as the
// provider: an instance admin switched into any other org is in TenantView) —
// must keep every VM on one of its OWN vSwitch-backed port groups: "no port
// group" would land it on the global cluster bridge every org shares (or SLIRP
// NAT out of the host), voiding tenant isolation. The Default org keeps the
// historical fallback. session.Manager re-checks the same rule at the sink
// (Create / SetNetwork / Start). The rule follows the VM's org, never the
// viewer's, so it holds for an admin in TenantView and in the provider view.

// TenantOrg reports whether orgID is a tenant (non-Default) org.
func (s *Service) TenantOrg(orgID int64) bool { return s.mgr.IsTenantOrg(orgID) }

// vmPortGroupCheck validates binding a VM of orgID to port group networkID. On
// create, 0 means "the org's default tenant network" (what session.Create binds),
// so a tenant org with a default network may leave it unset.
func (s *Service) vmPortGroupCheck(orgID, networkID int64, onCreate bool) error {
	if networkID == 0 && onCreate {
		networkID = s.defaultTenantNetworkFor(orgID)
	}
	return s.mgr.CheckPortGroup(orgID, networkID)
}

// vmPortGroups lists orgID's port groups a VM may attach to: all of them for the
// Default org, only vSwitch-backed ones (incl. tenant vSwitch VLAN port groups,
// which are ordinary bridged rows) for a tenant org.
func (s *Service) vmPortGroups(orgID int64) ([]netdrv.Network, error) {
	all, err := s.net.ListNetworks(orgID)
	if err != nil || !s.TenantOrg(orgID) {
		return all, err
	}
	out := all[:0]
	for _, n := range all {
		if n.Bridge != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

// SessionPortGroups lists the port groups an instance may be attached to: its
// OWN org's (not the viewer's — an instance admin may be looking at another
// org's VM).
func (s *Service) SessionPortGroups(p *Principal, sess *session.Session) ([]netdrv.Network, error) {
	if _, err := s.sessionInOrg(p, sess.ID); err != nil {
		return nil, err
	}
	return s.vmPortGroups(sess.OrgID)
}

// LaunchPortGroups lists the port groups a new instance of the caller's current
// org may be created on, plus the one preselected: the org's default tenant
// network (0 when it has none — the Default org's "default (NAT)").
func (s *Service) LaunchPortGroups(p *Principal) ([]netdrv.Network, int64, error) {
	if p.OrgID == 0 || !p.atLeast("viewer") {
		return nil, 0, nil
	}
	pgs, err := s.vmPortGroups(p.OrgID)
	return pgs, s.defaultTenantNetworkFor(p.OrgID), err
}
