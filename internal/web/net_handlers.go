package web

import (
	"net/http"
	"strconv"

	"vdxclone/internal/netdrv"
	"vdxclone/internal/service"
)

func (s *Server) networks(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	list, err := s.svc.ListNetworks(p)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	bonds, _ := s.svc.ListBonds(p)
	vswitches, _ := s.svc.ListVSwitches(p)
	tnets, _ := s.svc.ListTenantNetworks(p)
	uplinks, _ := s.svc.AttachableUplinks(p)
	// Tenant vSwitch / port-group rows are shown in the vSwitches card — keep the
	// raw Port Groups card to everything else.
	tenantNet := map[int64]bool{}
	for _, t := range tnets {
		tenantNet[t.NetworkID] = true
		for _, pg := range t.PortGroups {
			tenantNet[pg.NetworkID] = true
		}
	}
	var others []netdrv.Network
	for _, n := range list {
		if !tenantNet[n.ID] {
			others = append(others, n)
		}
	}
	list = others
	s.render(w, p, "networks.html", "networks", map[string]any{
		"Networks":       list,
		"TenantNetworks": tnets,
		"Uplinks":        uplinks,
		"Bonds":          bonds,
		"BondInUse":      s.svc.BondsInUse(p),
		"Teams":          s.svc.TeamDetails(p),
		"VSwitches":      vswitches,
		"VSwitchInUse":   s.svc.VSwitchesInUse(p),
		"PortGroupInUse": s.svc.PortGroupsInUse(p),
		"VSwitchMTU":     s.svc.VSwitchMTUs(p),
		"MgmtBridge":     s.svc.MgmtInterface(),
		"ClusterPeers":   s.svc.ClusterPeerUnderlayIPs(p),
	})
}

func (s *Server) createNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		// Raw port groups / VXLAN networks bind vSwitch uplinks and host underlay
		// NICs — physical infrastructure. Per-org admins create isolated segments
		// instead (the Segments card), which can't reach the physical network.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	vlan, _ := strconv.Atoi(r.FormValue("vlan_id"))
	vni, _ := strconv.Atoi(r.FormValue("vni"))
	dstport, _ := strconv.Atoi(r.FormValue("vxlan_dstport"))
	mtu, _ := strconv.Atoi(r.FormValue("vxlan_mtu"))
	n := netdrv.Network{
		Name: r.FormValue("name"), Mode: r.FormValue("mode"),
		Bridge: r.FormValue("bridge"), VLANID: vlan,
		CIDR: r.FormValue("cidr"), Gateway: r.FormValue("gateway"),
		PoolStart: r.FormValue("pool_start"), PoolEnd: r.FormValue("pool_end"),
		VNI: vni, Underlay: r.FormValue("underlay"), VXLANLocal: r.FormValue("vxlan_local"),
		VXLANPeers: r.FormValue("vxlan_peers"), DstPort: dstport, MTU: mtu,
	}
	// Auto-peer with the other cluster members (their cluster-net underlay IPs),
	// so a VXLAN segment spans the cluster without hand-typing every peer.
	if r.FormValue("vxlan_autopeer") == "1" {
		n.VXLANPeers = service.MergePeerCSV(n.VXLANPeers, s.svc.ClusterPeerUnderlayIPs(p))
	}
	routed := r.FormValue("host_routing") == "routed"
	switch _, err := s.svc.CreatePortGroup(p, n, routed, clientIP(r)); {
	case err != nil:
		setFlash(w, err.Error())
	case n.Mode == "vxlan":
		setFlashOK(w, "VXLAN network "+n.Name+" created.")
	default:
		setFlashOK(w, "Port group "+n.Name+" created.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !p.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteNetwork(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Port group deleted.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// editBond changes a NIC team in place (members, mode, hash). Teams owned by the
// host's netplan — the management team — are refused with where to change them.
func (s *Server) editBond(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	name := r.PathValue("name")
	mode, hash := r.FormValue("mode"), r.FormValue("hash_policy") // parses the form, so r.Form is set
	if err := s.svc.EditBond(p, name, mode, hash, r.Form["members"], clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "NIC team "+name+" updated.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// setVSwitchMTU sets a vSwitch's MTU (jumbo frames).
func (s *Server) setVSwitchMTU(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	name := r.PathValue("name")
	mtu, _ := strconv.Atoi(r.FormValue("mtu"))
	if err := s.svc.SetVSwitchMTU(p, name, mtu, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "vSwitch "+name+" MTU set to "+strconv.Itoa(mtu)+".")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// ---- tenant networks -----------------------------------------------------

func (s *Server) createTenantNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	dhcp := r.FormValue("dhcp") == "1"
	id, err := s.svc.CreateTenantNetwork(p, r.FormValue("name"), r.FormValue("cidr"), r.FormValue("gateway"),
		dhcp, r.FormValue("dhcp_range"), r.FormValue("dhcp_dns"), clientIP(r))
	switch {
	case err != nil:
		setFlash(w, err.Error())
	case atoi(r.FormValue("uplink_id")) > 0:
		if err := s.svc.ConnectNetworkUplink(p, id, atoi(r.FormValue("uplink_id")), clientIP(r)); err != nil {
			setFlash(w, "vSwitch created, but connecting the external network failed: "+err.Error())
		} else {
			setFlashOK(w, "vSwitch created and connected to its external network.")
		}
	default:
		setFlashOK(w, "vSwitch created.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteTenantNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteTenantNetwork(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// portGroupEdit reads the edit modal shared by vSwitches and port groups. The
// addressing fields only count when the form carried them (l3=1): a routed port
// group's form has none.
func portGroupEdit(r *http.Request) service.PortGroupEdit {
	return service.PortGroupEdit{
		Name: r.FormValue("name"), L3: r.FormValue("l3") == "1",
		CIDR: r.FormValue("cidr"), Gateway: r.FormValue("gateway"), DHCP: r.FormValue("dhcp") == "1",
		DHCPRange: r.FormValue("dhcp_range"), DNS: r.FormValue("dhcp_dns"),
	}
}

// editTenantNetwork edits a vSwitch: its name and its untagged port group.
func (s *Server) editTenantNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.UpdateTenantNetwork(p, atoi(r.PathValue("id")), portGroupEdit(r), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "vSwitch updated.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// setDefaultTenantNetwork makes a vSwitch the org's default.
func (s *Server) setDefaultTenantNetwork(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.SetDefaultTenantNetwork(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Default vSwitch changed — new instances attach to it.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// editTenantPortGroup edits a VLAN port group.
func (s *Server) editTenantPortGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.UpdateTenantPortGroup(p, atoi(r.PathValue("id")), portGroupEdit(r), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Port group updated.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// createTenantPortGroup adds a VLAN port group to one of the org's vSwitches.
func (s *Server) createTenantPortGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	vlan, _ := strconv.Atoi(r.FormValue("vlan_id"))
	tnetID := atoi(r.PathValue("id"))
	if tnetID == 0 { // the Port Groups card's modal picks the vSwitch
		tnetID = atoi(r.FormValue("tnet_id"))
	}
	if _, err := s.svc.CreateTenantPortGroup(p, tnetID, r.FormValue("name"), vlan,
		r.FormValue("cidr"), r.FormValue("gateway"), r.FormValue("dhcp") == "1", r.FormValue("dhcp_range"),
		r.FormValue("dhcp_dns"), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Port group added.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) deleteTenantPortGroup(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DeleteTenantPortGroup(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// setVSwitchNative picks the port group a vSwitch's uplink carries untagged.
func (s *Server) setVSwitchNative(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	vlan, _ := strconv.Atoi(r.FormValue("vlan"))
	if err := s.svc.SetVSwitchNative(p, atoi(r.PathValue("id")), vlan, clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "Native port group updated.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// connectUplink connects a tenant network to one of the org's admin-provisioned
// uplinks (org admin); the uplink device is realized into the network's bridge.
func (s *Server) connectUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.ConnectNetworkUplink(p, atoi(r.PathValue("id")), atoi(r.FormValue("uplink_id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "vSwitch connected to the external network.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

func (s *Server) disconnectUplink(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	if err := s.svc.DisconnectNetworkUplink(p, atoi(r.PathValue("id")), clientIP(r)); err != nil {
		setFlash(w, err.Error())
	} else {
		setFlashOK(w, "vSwitch disconnected from its external network.")
	}
	http.Redirect(w, r, "/networks", http.StatusSeeOther)
}

// ---- port forwards (on the instance detail page) -------------------------

func (s *Server) addPortForward(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	guest, _ := strconv.Atoi(r.FormValue("guest_port"))
	if _, err := s.svc.AddPortForward(p, id, guest, r.FormValue("proto"), r.FormValue("label"), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}

func (s *Server) deletePortForward(w http.ResponseWriter, r *http.Request, p *service.Principal) {
	if !s.checkCSRF(p, r) {
		s.badCSRF(w)
		return
	}
	id := r.PathValue("id")
	if err := s.svc.DeletePortForward(p, id, atoi(r.PathValue("pfid")), clientIP(r)); err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	http.Redirect(w, r, "/instances/"+id, http.StatusSeeOther)
}
