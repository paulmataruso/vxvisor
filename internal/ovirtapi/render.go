package ovirtapi

import (
	"strconv"
	"strings"
	"time"
)

// Renderers: VXVisor objects → oVirt model nodes. Field sets follow the
// oVirt 4.5 API model, trimmed to what clients read; the identities (one data
// center, one cluster, one host) are derived from the node name so they are
// stable across restarts.

func (s *Server) dcID() string      { return derive("dc", s.cfg.NodeName) }
func (s *Server) clusterID() string { return derive("cluster", s.cfg.NodeName) }
func (s *Server) hostID() string    { return derive("host", s.cfg.NodeName) }

func ver(major, minor int) *Node {
	return El("version", I("major", int64(major)), I("minor", int64(minor)))
}

func (s *Server) renderDC() *Node {
	id := s.dcID()
	return El("data_center",
		T("name", s.cfg.NodeName), T("description", "VXVisor host "+s.cfg.NodeName),
		B("local", false), T("quota_mode", "disabled"), T("status", "up"),
		T("storage_format", "v5"),
		ListOf("supported_versions", ver(4, 7)), ver(4, 7),
		Link(api("datacenters", id, "clusters"), "clusters"),
		Link(api("datacenters", id, "networks"), "networks"),
		Link(api("datacenters", id, "storagedomains"), "storagedomains"),
	).Obj(api("datacenters", id), id)
}

func (s *Server) renderCluster() *Node {
	id := s.clusterID()
	return El("cluster",
		T("name", s.cfg.NodeName), T("description", ""),
		El("cpu", T("architecture", "x86_64"), T("type", "Host CPU")),
		T("bios_type", "q35_ovmf"), B("ballooning_enabled", true),
		El("error_handling", T("on_error", "migrate")),
		B("firewall_type_iptables", false), T("firewall_type", "firewalld"),
		El("memory_policy", El("over_commit", I("percent", 100))),
		T("switch_type", "legacy"), B("virt_service", true), B("gluster_service", false),
		B("threads_as_cores", false), B("trusted_service", false),
		ver(4, 7),
		Ref("data_center", api("datacenters", s.dcID()), s.dcID()),
		Link(api("clusters", id, "networks"), "networks"),
	).Obj(api("clusters", id), id)
}

func (s *Server) renderHost(h Host) *Node {
	id := s.hostID()
	sockets := max(h.Sockets, 1)
	cores := max(h.CPUs/sockets, 1)
	return El("host",
		T("name", h.Name), T("address", h.Address), T("status", "up"),
		T("external_status", "ok"), T("type", "rhel"), T("protocol", "stomp"), I("port", 54321),
		El("cpu", T("name", h.CPUModel), T("type", "Host CPU"),
			El("topology", I("sockets", int64(sockets)), I("cores", int64(cores)), I("threads", 1))),
		I("memory", h.MemoryMB<<20), I("max_scheduling_memory", h.FreeMB<<20),
		El("summary", I("active", int64(h.VMsRunning)), I("migrating", 0), I("total", int64(h.VMsRunning))),
		El("os", T("type", "RHEL"), El("version", T("full_version", h.OSVersion))),
		El("version", I("build", 5), T("full_version", "vdsm-4.50.5.1"), I("major", 4), I("minor", 50), I("revision", 1)),
		El("libvirt_version", T("full_version", "libvirt-"+h.QEMUVer)),
		T("kdump_status", "unknown"), El("spm", T("status", "spm"), I("priority", 5)),
		Ref("cluster", api("clusters", s.clusterID()), s.clusterID()),
		Link(api("hosts", id, "statistics"), "statistics"),
	).Obj(api("hosts", id), id)
}

func storageType(kind string) string {
	switch kind {
	case "nfs", "cephfs", "cifs", "glusterfs":
		if kind == "cifs" {
			return "posixfs"
		}
		return kind
	case "rbd":
		return "managed_block_storage"
	case "lvm", "iscsi":
		return "iscsi"
	}
	return "localfs"
}

func (s *Server) renderSD(p StoragePool, attached bool) *Node {
	id := poolUUID(p.PoolID)
	n := El("storage_domain",
		T("name", p.Name), T("description", "VXVisor storage pool ("+p.Kind+")"),
		T("type", "data"), B("master", p.PoolID == 0), T("storage_format", "v5"),
		El("storage", T("type", storageType(p.Kind))),
		I("available", p.Available), I("used", p.Used), I("committed", p.Used),
		T("external_status", "ok"), B("backup", false), I("block_size", 512),
		B("discard_after_delete", false), B("supports_discard", true), B("wipe_after_delete", false),
		I("warning_low_space_indicator", 10), I("critical_space_action_blocker", 5),
		ListOf("data_centers", Ref("data_center", api("datacenters", s.dcID()), s.dcID())),
		Link(api("storagedomains", id, "disks"), "disks"),
	)
	// oVirt reports status only on a data center's attached-domain view;
	// clients written against the emulators expect it everywhere.
	n.Add(T("status", "active"))
	if attached {
		n.Obj(api("datacenters", s.dcID(), "storagedomains", id), id)
		n.Add(Ref("data_center", api("datacenters", s.dcID()), s.dcID()))
		return n
	}
	return n.Obj(api("storagedomains", id), id)
}

func (s *Server) renderNetwork(n Network) *Node {
	id := netUUID(n.NetID)
	out := El("network",
		T("name", n.Name), T("description", "VXVisor port group"),
		ListOf("usages", T("usage", "vm")), B("required", false), I("mtu", 0),
		B("stp", false), B("display", false),
		Ref("data_center", api("datacenters", s.dcID()), s.dcID()),
		Link(api("networks", id, "vnicprofiles"), "vnicprofiles"),
	).Obj(api("networks", id), id)
	if n.VLAN > 0 {
		out.Add(&Node{Name: "vlan", ID: strconv.Itoa(n.VLAN)})
	}
	return out
}

func (s *Server) renderProfile(n Network) *Node {
	id := netUUID(n.NetID)
	return El("vnic_profile",
		T("name", n.Name), T("description", ""), B("port_mirroring", false),
		T("pass_through", "disabled"), B("migratable", false),
		Ref("network", api("networks", id), id),
	).Obj(api("vnicprofiles", id), id)
}

// ---- VMs --------------------------------------------------------------------

func biosType(vm VM) string {
	switch {
	case vm.Firmware == "uefi" && vm.SecureBoot:
		return "q35_secure_boot"
	case vm.Firmware == "uefi":
		return "q35_ovmf"
	case vm.MachineType == "pc":
		return "i440fx_sea_bios"
	}
	return "q35_sea_bios"
}

func osName(vm VM) string {
	if vm.OSType == "windows" {
		return "windows_2019x64"
	}
	return "other_linux"
}

func diskIface(bus string) string {
	switch bus {
	case "virtio-scsi":
		return "virtio_scsi"
	case "sata":
		return "sata"
	}
	return "virtio"
}

func nicIface(model string) string {
	switch model {
	case "e1000e":
		return "e1000"
	case "rtl8139":
		return "rtl8139"
	}
	return "virtio"
}

func nicID(vmID string) string { return derive("nic", vmID) }

func (s *Server) renderVM(x *req, vm VM) *Node {
	id := vm.ID
	n := El("vm",
		El("actions",
			Link(api("vms", id, "shutdown"), "shutdown"), Link(api("vms", id, "start"), "start"),
			Link(api("vms", id, "stop"), "stop"), Link(api("vms", id, "poweroff"), "poweroff"),
			Link(api("vms", id, "backups"), "backups"),
		),
		T("name", vm.Name), T("description", ""), T("comment", ""),
		T("status", vm.Status), T("type", "server"), T("origin", "ovirt"),
		I("memory", int64(vm.MemoryMB)<<20),
		El("memory_policy", I("guaranteed", int64(vm.MemoryMB)<<20), I("max", int64(vm.MemoryMB)<<20), B("ballooning", true)),
		El("cpu", T("architecture", "x86_64"),
			El("topology", I("cores", 1), I("sockets", int64(max(vm.CPUs, 1))), I("threads", 1))),
		El("bios", T("type", biosType(vm)), El("boot_menu", B("enabled", false))),
		El("os", T("type", osName(vm)), El("boot", ListOf("devices", T("device", "hd")))),
		El("display", T("type", "vnc"), I("monitors", 1)),
		El("high_availability", B("enabled", false), I("priority", 0)),
		El("usb", B("enabled", false)), El("io", I("threads", 1)),
		B("stateless", false), B("start_paused", false), B("delete_protected", false),
		B("next_run_configuration_exists", false), B("tpm_enabled", vm.TPM),
		T("storage_error_resume_behaviour", "auto_resume"),
		El("placement_policy", T("affinity", "migratable")),
		D("creation_time", vm.Created),
		El("initialization", El("configuration", T("type", "ovf"), T("data", s.ovf(vm)))),
		Ref("cluster", api("clusters", s.clusterID()), s.clusterID()),
		Ref("template", api("templates", blankTemplate), blankTemplate),
		Ref("original_template", api("templates", blankTemplate), blankTemplate),
		Link(api("vms", id, "diskattachments"), "diskattachments"),
		Link(api("vms", id, "nics"), "nics"),
		Link(api("vms", id, "snapshots"), "snapshots"),
		Link(api("vms", id, "backups"), "backups"),
		Link(api("vms", id, "checkpoints"), "checkpoints"),
		Link(api("vms", id, "reporteddevices"), "reporteddevices"),
		Link(api("vms", id, "tags"), "tags"),
	).Obj(api("vms", id), id)
	if vm.Status == "up" {
		n.Add(Ref("host", api("hosts", s.hostID()), s.hostID()))
		n.Add(D("start_time", vm.Created))
	}
	if x != nil {
		if x.follow["disk_attachments"] {
			n.Add(s.renderAttachments(x, vm))
		}
		if x.follow["nics"] {
			n.Add(ListOf("nics", s.renderNIC(x, vm)))
		}
		if x.follow["tags"] {
			n.Add(ListOf("tags"))
		}
	}
	return n
}

func (s *Server) renderAttachments(x *req, vm VM) *Node {
	l := ListOf("disk_attachments")
	if vm.Disk != nil {
		l.Add(s.renderAttachment(x, vm))
	}
	return l
}

func (s *Server) renderAttachment(x *req, vm VM) *Node {
	d := vm.Disk
	n := El("disk_attachment",
		B("active", true), B("bootable", true), T("interface", diskIface(vm.DiskBus)),
		B("pass_discard", true), B("read_only", false), B("uses_scsi_reservation", false),
		Ref("vm", api("vms", vm.ID), vm.ID),
	).Obj(api("vms", vm.ID, "diskattachments", d.ID), d.ID)
	if x != nil && (x.follow["disk"] || x.follow["disk_attachments.disk"]) {
		n.Add(s.renderDisk(*d, ""))
	} else {
		n.Add(Ref("disk", api("disks", d.ID), d.ID))
	}
	return n
}

func (s *Server) renderNIC(x *req, vm VM) *Node {
	id := nicID(vm.ID)
	prof := netUUID(vm.NetID)
	n := El("nic",
		T("name", "nic1"), T("interface", nicIface(vm.NICModel)),
		El("mac", T("address", vm.MAC)),
		B("linked", true), B("plugged", true), B("synced", true),
		Ref("vnic_profile", api("vnicprofiles", prof), prof),
		Ref("vm", api("vms", vm.ID), vm.ID),
		Link(api("vms", vm.ID, "nics", id, "reporteddevices"), "reporteddevices"),
	).Obj(api("vms", vm.ID, "nics", id), id)
	if x != nil && (x.follow["reporteddevices"] || x.follow["nics.reporteddevices"]) {
		n.Add(ListOf("reported_devices", s.renderReported(x, vm)))
	}
	return n
}

func (s *Server) renderReported(x *req, vm VM) *Node {
	id := nicID(vm.ID)
	ips := ListOf("ips")
	if x != nil {
		for _, ip := range s.be.GuestIPs(x.c, vm.ID) {
			v := "v4"
			if strings.Contains(ip, ":") {
				v = "v6"
			}
			ips.Add(El("ip", T("address", ip), T("version", v)))
		}
	}
	return El("reported_device",
		T("name", "eth0"), T("description", "guest reported data"), T("type", "network"),
		El("mac", T("address", vm.MAC)), ips,
		Ref("vm", api("vms", vm.ID), vm.ID),
	).Obj(api("vms", vm.ID, "reporteddevices", id), id)
}

// renderDisk renders a disk; backupMode ("full"/"incremental") is set for a
// backup's disks.
func (s *Server) renderDisk(d Disk, backupMode string) *Node {
	format, backup := "raw", "none"
	if d.Format == "qcow2" {
		format = "cow"
	}
	if d.Incremental {
		backup = "incremental"
	}
	status := "ok"
	if d.Locked {
		status = "locked"
	}
	sd := poolUUID(d.PoolID)
	name := d.Name
	if name == "" {
		name = "disk-" + d.ID[:8]
	}
	n := El("disk",
		T("name", name), T("alias", name), T("description", ""),
		T("status", status), T("format", format), T("backup", backup),
		T("content_type", "data"), T("storage_type", "image"), T("qcow_version", "qcow2_v3"),
		I("provisioned_size", d.Provisioned), I("actual_size", d.Actual), I("total_size", d.Actual),
		B("sparse", true), B("shareable", false), B("propagate_errors", false), B("wipe_after_delete", false),
		T("image_id", derive("image", d.ID)),
		ListOf("storage_domains", Ref("storage_domain", api("storagedomains", sd), sd)),
	).Obj(api("disks", d.ID), d.ID)
	if backupMode != "" {
		n.Add(T("backup_mode", backupMode))
	}
	if d.VMID != "" {
		n.Add(ListOf("vms", Ref("vm", api("vms", d.VMID), d.VMID)))
	}
	return n
}

func dateOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}
