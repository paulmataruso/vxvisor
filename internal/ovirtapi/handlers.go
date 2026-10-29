package ovirtapi

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// route dispatches /ovirt-engine/api/... on the path segments.
func (s *Server) route(x *req) {
	sg, m := x.segs, x.r.Method
	n := len(sg)
	if n == 0 {
		if m == http.MethodGet || m == http.MethodHead {
			s.apiRoot(x)
			return
		}
		x.fault(http.StatusMethodNotAllowed, "Operation Failed", "method not allowed")
		return
	}
	get := m == http.MethodGet
	switch sg[0] {
	case "datacenters":
		s.datacenters(x, get)
	case "clusters":
		s.clusters(x, get)
	case "hosts":
		s.hosts(x, get)
	case "storagedomains":
		s.storageDomains(x)
	case "networks":
		s.networks(x, get)
	case "vnicprofiles":
		s.profiles(x, get)
	case "tags":
		if get && n == 1 {
			x.ok(ListOf("tags"))
			return
		}
		x.notFound()
	case "disks":
		s.disks(x)
	case "vms":
		s.vms(x)
	case "imagetransfers":
		s.imageTransfers(x)
	case "jobs":
		if get && n == 2 {
			x.ok(El("job", T("description", "job"), T("status", "finished"), B("auto_cleared", true),
				B("external", false), D("start_time", s.now()), D("end_time", s.now())).Obj(api("jobs", sg[1]), sg[1]))
			return
		}
		x.notFound()
	default:
		x.notFound()
	}
}

func (s *Server) apiRoot(x *req) {
	vms, _ := s.be.VMs(x.c)
	sds, _ := s.be.StoragePools(x.c)
	up := 0
	for _, v := range vms {
		if v.Status == "up" {
			up++
		}
	}
	root := El("api")
	for _, rel := range []string{"clusters", "datacenters", "disks", "hosts", "imagetransfers", "networks",
		"storagedomains", "tags", "vms", "vnicprofiles"} {
		root.Add(Link(api(rel), rel))
	}
	root.Add(Link(api("vms")+"?search={query}", "vms/search"),
		Link(api("disks")+"?search={query}", "disks/search"))
	root.Add(
		El("product_info",
			T("instance_id", s.cfg.InstanceID), T("name", s.cfg.ProductName), T("vendor", "VXVisor"),
			El("version", I("build", 0), T("full_version", "4.5.6-1.vxvisor"), I("major", 4), I("minor", 5), I("revision", 6))),
		El("special_objects",
			Ref("blank_template", api("templates", blankTemplate), blankTemplate),
			Ref("root_tag", api("tags", blankTemplate), blankTemplate)),
		El("summary",
			El("hosts", I("active", 1), I("total", 1)),
			El("storage_domains", I("active", int64(len(sds))), I("total", int64(len(sds)))),
			El("users", I("active", 1), I("total", 1)),
			El("vms", I("active", int64(up)), I("total", int64(len(vms))))),
		D("time", s.now()),
		Ref("authenticated_user", "", derive("user", x.user)),
		Ref("effective_user", "", derive("user", x.user)),
	)
	x.ok(root)
}

// ---- inventory -------------------------------------------------------------------

func (s *Server) datacenters(x *req, get bool) {
	sg := x.segs
	if !get {
		x.fault(http.StatusMethodNotAllowed, "Operation Failed", "the data center is read-only")
		return
	}
	if len(sg) >= 2 && sg[1] != s.dcID() {
		x.notFound()
		return
	}
	switch len(sg) {
	case 1:
		x.ok(ListOf("data_centers", s.renderDC()))
	case 2:
		x.ok(s.renderDC())
	case 3:
		switch sg[2] {
		case "clusters":
			x.ok(ListOf("clusters", s.renderCluster()))
		case "networks":
			s.listNetworks(x)
		case "storagedomains":
			pools, err := s.be.StoragePools(x.c)
			if err != nil {
				x.fail(err)
				return
			}
			l := ListOf("storage_domains")
			for _, p := range pools {
				l.Add(s.renderSD(p, true))
			}
			x.ok(l)
		default:
			x.notFound()
		}
	case 4:
		if sg[2] != "storagedomains" {
			x.notFound()
			return
		}
		p, ok := s.pool(x, sg[3])
		if ok {
			x.ok(s.renderSD(p, true))
		}
	default:
		x.notFound()
	}
}

func (s *Server) clusters(x *req, get bool) {
	sg := x.segs
	if !get {
		x.fault(http.StatusMethodNotAllowed, "Operation Failed", "the cluster is read-only")
		return
	}
	if len(sg) >= 2 && sg[1] != s.clusterID() {
		x.notFound()
		return
	}
	switch {
	case len(sg) == 1:
		x.ok(ListOf("clusters", s.renderCluster()))
	case len(sg) == 2:
		x.ok(s.renderCluster())
	case len(sg) == 3 && sg[2] == "networks":
		s.listNetworks(x)
	default:
		x.notFound()
	}
}

func (s *Server) hosts(x *req, get bool) {
	sg := x.segs
	if !get {
		x.fault(http.StatusMethodNotAllowed, "Operation Failed", "hosts are read-only")
		return
	}
	if len(sg) >= 2 && sg[1] != s.hostID() {
		x.notFound()
		return
	}
	h, err := s.be.Host(x.c)
	if err != nil {
		x.fail(err)
		return
	}
	switch {
	case len(sg) == 1:
		l := ListOf("hosts")
		if x.matcher().match("name", h.Name) {
			l.Add(s.renderHost(h))
		}
		x.ok(l)
	case len(sg) == 2:
		x.ok(s.renderHost(h))
	case len(sg) == 3 && sg[2] == "statistics":
		st := func(name, unit string, v int64) *Node {
			return El("statistic", T("name", name), T("kind", "gauge"), T("type", "integer"), T("unit", unit),
				ListOf("values", El("value", I("datum", v))))
		}
		x.ok(ListOf("statistics",
			st("memory.total", "bytes", h.MemoryMB<<20), st("memory.free", "bytes", h.FreeMB<<20),
			st("memory.used", "bytes", (h.MemoryMB-h.FreeMB)<<20)))
	default:
		x.notFound()
	}
}

func (s *Server) pool(x *req, id string) (StoragePool, bool) {
	pools, err := s.be.StoragePools(x.c)
	if err != nil {
		x.fail(err)
		return StoragePool{}, false
	}
	for _, p := range pools {
		if poolUUID(p.PoolID) == id {
			return p, true
		}
	}
	x.notFound()
	return StoragePool{}, false
}

func (s *Server) storageDomains(x *req) {
	sg, m := x.segs, x.r.Method
	switch {
	case len(sg) == 1 && m == http.MethodGet:
		pools, err := s.be.StoragePools(x.c)
		if err != nil {
			x.fail(err)
			return
		}
		mt := x.matcher()
		l := ListOf("storage_domains")
		for _, p := range pools {
			if mt.match("name", p.Name) && mt.match("id", poolUUID(p.PoolID)) {
				l.Add(s.renderSD(p, false))
			}
		}
		x.ok(l)
	case len(sg) == 2 && m == http.MethodGet:
		if p, ok := s.pool(x, sg[1]); ok {
			x.ok(s.renderSD(p, false))
		}
	case len(sg) == 3 && sg[2] == "disks" && m == http.MethodGet:
		disks, err := s.allDisks(x)
		if err != nil {
			x.fail(err)
			return
		}
		l := ListOf("disks")
		for _, d := range disks {
			if poolUUID(d.PoolID) == sg[1] {
				l.Add(s.renderDisk(d, ""))
			}
		}
		x.ok(l)
	case len(sg) == 3 && sg[2] == "disks" && m == http.MethodPost:
		s.addDisk(x, sg[1])
	default:
		x.notFound()
	}
}

func (s *Server) listNetworks(x *req) {
	nets, err := s.be.Networks(x.c)
	if err != nil {
		x.fail(err)
		return
	}
	mt := x.matcher()
	l := ListOf("networks")
	for _, n := range nets {
		if mt.match("name", n.Name) {
			l.Add(s.renderNetwork(n))
		}
	}
	x.ok(l)
}

func (s *Server) network(x *req, id string) (Network, bool) {
	nets, err := s.be.Networks(x.c)
	if err != nil {
		x.fail(err)
		return Network{}, false
	}
	for _, n := range nets {
		if netUUID(n.NetID) == id {
			return n, true
		}
	}
	x.notFound()
	return Network{}, false
}

func (s *Server) networks(x *req, get bool) {
	sg := x.segs
	if !get {
		x.fault(http.StatusMethodNotAllowed, "Operation Failed", "networks are managed in VXVisor")
		return
	}
	switch len(sg) {
	case 1:
		s.listNetworks(x)
	case 2:
		if n, ok := s.network(x, sg[1]); ok {
			x.ok(s.renderNetwork(n))
		}
	case 3:
		if sg[2] != "vnicprofiles" {
			x.notFound()
			return
		}
		if n, ok := s.network(x, sg[1]); ok {
			x.ok(ListOf("vnic_profiles", s.renderProfile(n)))
		}
	default:
		x.notFound()
	}
}

func (s *Server) profiles(x *req, get bool) {
	sg := x.segs
	if !get {
		x.fault(http.StatusMethodNotAllowed, "Operation Failed", "vNIC profiles are managed in VXVisor")
		return
	}
	switch len(sg) {
	case 1:
		nets, err := s.be.Networks(x.c)
		if err != nil {
			x.fail(err)
			return
		}
		mt := x.matcher()
		l := ListOf("vnic_profiles")
		for _, n := range nets {
			if mt.match("name", n.Name) {
				l.Add(s.renderProfile(n))
			}
		}
		x.ok(l)
	case 2:
		if n, ok := s.network(x, sg[1]); ok {
			x.ok(s.renderProfile(n))
		}
	default:
		x.notFound()
	}
}

// ---- disks ----------------------------------------------------------------------

// allDisks is every VM disk plus every staged disk.
func (s *Server) allDisks(x *req) ([]Disk, error) {
	vms, err := s.be.VMs(x.c)
	if err != nil {
		return nil, err
	}
	staged, err := s.be.Disks(x.c)
	if err != nil {
		return nil, err
	}
	out := staged
	for _, v := range vms {
		if v.Disk != nil {
			out = append(out, *v.Disk)
		}
	}
	return out, nil
}

func (s *Server) disk(x *req, id string) (Disk, bool) {
	disks, err := s.allDisks(x)
	if err != nil {
		x.fail(err)
		return Disk{}, false
	}
	for _, d := range disks {
		if d.ID == id {
			s.mu.Lock()
			d.Locked = d.Locked || s.diskBusyLocked(d.ID)
			s.mu.Unlock()
			return d, true
		}
	}
	x.notFound()
	return Disk{}, false
}

func (s *Server) diskBusyLocked(id string) bool {
	for _, t := range s.transfers {
		if t.diskID == id && t.phase == "transferring" && t.direction == "upload" {
			return true
		}
	}
	return false
}

func (s *Server) disks(x *req) {
	sg, m := x.segs, x.r.Method
	switch {
	case len(sg) == 1 && m == http.MethodGet:
		disks, err := s.allDisks(x)
		if err != nil {
			x.fail(err)
			return
		}
		mt := x.matcher()
		var keep []Disk
		for _, d := range disks {
			if mt.match("name", d.Name) && mt.match("alias", d.Name) && mt.match("id", d.ID) {
				keep = append(keep, d)
			}
		}
		from, to := mt.window(len(keep))
		l := ListOf("disks")
		s.mu.Lock()
		for _, d := range keep[from:to] {
			d.Locked = d.Locked || s.diskBusyLocked(d.ID)
			l.Add(s.renderDisk(d, ""))
		}
		s.mu.Unlock()
		x.ok(l)
	case len(sg) == 1 && m == http.MethodPost:
		s.addDisk(x, "")
	case len(sg) == 2 && (m == http.MethodGet || m == http.MethodPut):
		// PUT (rename etc.) is accepted and ignored, as known-working
		// emulators do; disks are reconfigured in VXVisor.
		if d, ok := s.disk(x, sg[1]); ok {
			x.ok(s.renderDisk(d, ""))
		}
	case len(sg) == 2 && m == http.MethodDelete:
		d, ok := s.disk(x, sg[1])
		if !ok {
			return
		}
		if d.VMID != "" {
			x.fault(http.StatusConflict, "Operation Failed", "disk "+d.ID+" is attached to a VM; detach it or delete the VM")
			return
		}
		if d.Locked {
			x.fault(http.StatusConflict, "Operation Failed", "disk "+d.ID+" is locked by a transfer")
			return
		}
		if err := s.be.DeleteDisk(x.c, d.ID); err != nil {
			x.fail(err)
			return
		}
		x.actionDone()
	default:
		x.notFound()
	}
}

// addDisk implements POST /disks and POST /storagedomains/{sd}/disks.
func (s *Server) addDisk(x *req, sdID string) {
	body, err := x.body("disk")
	if err != nil {
		x.fault(http.StatusBadRequest, "Operation Failed", "invalid request body: "+err.Error())
		return
	}
	if sdID == "" {
		if sd := body.Child("storage_domains"); sd != nil {
			if dom := sd.Child("storage_domain"); dom != nil {
				sdID = dom.ID
				if sdID == "" && dom.Str("name") != "" {
					if pools, err := s.be.StoragePools(x.c); err == nil {
						for _, p := range pools {
							if p.Name == dom.Str("name") {
								sdID = poolUUID(p.PoolID)
							}
						}
					}
				}
			}
		}
	}
	if sdID == "" {
		x.fault(http.StatusBadRequest, "Operation Failed", "storage_domains.storage_domain is required")
		return
	}
	p, ok := s.pool(x, sdID)
	if !ok {
		return
	}
	size := body.Int("provisioned_size")
	if size <= 0 {
		x.fault(http.StatusBadRequest, "Operation Failed", "provisioned_size is required")
		return
	}
	name := body.Str("name")
	if name == "" {
		name = body.Str("alias")
	}
	d, err := s.be.CreateDisk(x.c, DiskSpec{Name: name, Provisioned: size, PoolID: p.PoolID, Sparse: body.Bool("sparse", true)})
	if err != nil {
		x.fail(err)
		return
	}
	x.created(s.renderDisk(d, ""))
}

// ---- VMs ------------------------------------------------------------------------

func (s *Server) vm(x *req, id string) (VM, bool) {
	vm, err := s.be.VM(x.c, id)
	if err != nil {
		x.fail(err)
		return VM{}, false
	}
	return vm, true
}

func (s *Server) vms(x *req) {
	sg, m := x.segs, x.r.Method
	if len(sg) == 1 {
		switch m {
		case http.MethodGet:
			vms, err := s.be.VMs(x.c)
			if err != nil {
				x.fail(err)
				return
			}
			mt := x.matcher()
			var keep []VM
			for _, v := range vms {
				if mt.match("name", v.Name) && mt.match("id", v.ID) && mt.match("status", v.Status) {
					keep = append(keep, v)
				}
			}
			sort.SliceStable(keep, func(i, j int) bool { return keep[i].Name < keep[j].Name })
			from, to := mt.window(len(keep))
			l := ListOf("vms")
			for _, v := range keep[from:to] {
				l.Add(s.renderVM(x, v))
			}
			x.ok(l)
		case http.MethodPost:
			s.addVM(x)
		default:
			x.notFound()
		}
		return
	}
	id := sg[1]
	if len(sg) == 2 {
		switch m {
		case http.MethodGet, http.MethodPut:
			if vm, ok := s.vm(x, id); ok {
				x.ok(s.renderVM(x, vm))
			}
		case http.MethodDelete:
			s.mu.Lock()
			_, busy := s.busyVM[id]
			s.mu.Unlock()
			if busy {
				x.fault(http.StatusConflict, "Operation Failed", "the VM is being backed up")
				return
			}
			if err := s.be.DeleteVM(x.c, id, x.q.Get("detach_only") == "true"); err != nil {
				x.fail(err)
				return
			}
			s.mu.Lock()
			delete(s.snaps, id)
			s.mu.Unlock()
			x.actionDone()
		default:
			x.notFound()
		}
		return
	}
	switch sg[2] {
	case "start", "stop", "shutdown", "poweroff", "reboot":
		if m != http.MethodPost || len(sg) != 3 {
			x.notFound()
			return
		}
		s.vmAction(x, id, sg[2])
	case "diskattachments", "disks":
		s.diskAttachments(x, id)
	case "nics":
		s.nics(x, id)
	case "reporteddevices":
		vm, ok := s.vm(x, id)
		if !ok {
			return
		}
		if len(sg) == 3 {
			x.ok(ListOf("reported_devices", s.renderReported(x, vm)))
		} else if len(sg) == 4 && sg[3] == nicID(id) {
			x.ok(s.renderReported(x, vm))
		} else {
			x.notFound()
		}
	case "snapshots":
		s.snapshots(x, id)
	case "backups":
		s.backupsRoute(x, id)
	case "checkpoints":
		s.checkpoints(x, id)
	case "tags":
		if _, ok := s.vm(x, id); !ok {
			return
		}
		if m == http.MethodPost {
			body, _ := x.body("tag")
			name := ""
			if body != nil {
				name = body.Str("name")
			}
			tid := derive("tag", name)
			x.created(El("tag", T("name", name), Ref("vm", api("vms", id), id)).Obj(api("tags", tid), tid))
			return
		}
		x.ok(ListOf("tags"))
	default:
		x.notFound()
	}
}

func (s *Server) vmAction(x *req, id, act string) {
	if _, ok := s.vm(x, id); !ok {
		return
	}
	var err error
	switch act {
	case "start":
		err = s.be.StartVM(x.c, id)
	case "reboot":
		if err = s.be.StopVM(x.c, id); err == nil {
			err = s.be.StartVM(x.c, id)
		}
	default:
		err = s.be.StopVM(x.c, id)
	}
	if err != nil {
		x.fail(err)
		return
	}
	x.actionDone()
}

// addVM implements POST /vms: a restore (initialization.configuration holds
// the backed-up OVF) or a fresh VM (a backup worker: name, CPU, memory,
// bios type, OS type and a cloud-init custom_script). Either way the VM is
// created without a disk; disks are attached afterwards.
func (s *Server) addVM(x *req) {
	body, err := x.body("vm")
	if err != nil {
		x.fault(http.StatusBadRequest, "Operation Failed", "invalid request body: "+err.Error())
		return
	}
	if cid := body.RefID("cluster"); cid != "" && cid != s.clusterID() {
		x.fault(http.StatusBadRequest, "Operation Failed", "unknown cluster "+cid)
		return
	}
	spec := VMSpec{CPUs: 1, MemoryMB: 1024, Firmware: "uefi", MachineType: "q35", OSType: "linux",
		GuestAgent: true, Purpose: "worker"}
	if data := body.Str("initialization/configuration/data"); data != "" {
		o, err := parseOVF(data)
		if err != nil {
			x.fault(http.StatusBadRequest, "Operation Failed", err.Error())
			return
		}
		spec.Purpose = "restore"
		spec.Name = o.Name
		if o.CPUs > 0 {
			spec.CPUs = o.CPUs
		}
		if o.MemoryMB > 0 {
			spec.MemoryMB = o.MemoryMB
		}
		if t, ok := biosByNum[o.BiosType]; ok {
			applyBios(&spec, t)
		}
		if strings.Contains(strings.ToLower(o.OS), "windows") {
			spec.OSType = "windows"
		}
		if o.Native {
			spec.OrgID = o.OrgID
			spec.Firmware, spec.SecureBoot, spec.MachineType = o.Firmware, o.SecureBoot, o.Machine
			spec.OSType, spec.DiskBus, spec.NICModel, spec.VGA = o.OSType, o.DiskBus, o.NICModel, o.VGA
			spec.GuestAgent, spec.TPM = o.GuestAgent, o.TPM
		}
	}
	// Explicit fields override the OVF.
	if v := body.Str("name"); v != "" {
		spec.Name = v
	}
	if c := body.Child("cpu"); c != nil {
		n := max(body.Int("cpu/topology/sockets"), 1) * max(body.Int("cpu/topology/cores"), 1) * max(body.Int("cpu/topology/threads"), 1)
		spec.CPUs = int(n)
	}
	if v := body.Int("memory"); v > 0 {
		spec.MemoryMB = int(v >> 20)
	}
	if v := body.Str("bios/type"); v != "" {
		applyBios(&spec, v)
	}
	if v := body.Str("os/type"); v != "" {
		if strings.Contains(strings.ToLower(v), "windows") {
			spec.OSType = "windows"
		} else {
			spec.OSType = "linux"
		}
	}
	spec.UserData = body.Str("initialization/custom_script")
	if spec.Name == "" {
		x.fault(http.StatusBadRequest, "Operation Failed", "name is required")
		return
	}
	vm, err := s.be.CreateVM(x.c, spec)
	if err != nil {
		x.fail(err)
		return
	}
	x.created(s.renderVM(x, vm))
}

func (s *Server) diskAttachments(x *req, vmID string) {
	sg, m := x.segs, x.r.Method
	vm, ok := s.vm(x, vmID)
	if !ok {
		return
	}
	legacy := sg[2] == "disks" // GET /vms/{id}/disks (pre-4.0 shape)
	switch {
	case len(sg) == 3 && m == http.MethodGet:
		if legacy {
			l := ListOf("disks")
			if vm.Disk != nil {
				l.Add(s.renderDisk(*vm.Disk, ""))
			}
			x.ok(l)
			return
		}
		x.ok(s.renderAttachments(x, vm))
	case len(sg) == 3 && m == http.MethodPost && !legacy:
		body, err := x.body("disk_attachment")
		if err != nil {
			x.fault(http.StatusBadRequest, "Operation Failed", "invalid request body: "+err.Error())
			return
		}
		did := body.RefID("disk")
		if did == "" {
			x.fault(http.StatusBadRequest, "Operation Failed", "disk.id is required")
			return
		}
		s.mu.Lock()
		busy := s.diskBusyLocked(did)
		s.mu.Unlock()
		if busy {
			x.fault(http.StatusConflict, "Operation Failed", "disk "+did+" is locked by a transfer")
			return
		}
		if err := s.be.AttachDisk(x.c, vmID, did, body.Str("interface")); err != nil {
			x.fail(err)
			return
		}
		if vm, ok = s.vm(x, vmID); ok && vm.Disk != nil {
			x.created(s.renderAttachment(x, vm))
		}
	case len(sg) == 4:
		if vm.Disk == nil || vm.Disk.ID != sg[3] {
			x.notFound()
			return
		}
		switch m {
		case http.MethodGet, http.MethodPut:
			if legacy {
				x.ok(s.renderDisk(*vm.Disk, ""))
				return
			}
			x.ok(s.renderAttachment(x, vm))
		case http.MethodDelete:
			s.mu.Lock()
			_, busy := s.busyVM[vmID]
			s.mu.Unlock()
			if busy {
				x.fault(http.StatusConflict, "Operation Failed", "the VM is being backed up")
				return
			}
			if err := s.be.DetachDisk(x.c, vmID, sg[3]); err != nil {
				x.fail(err)
				return
			}
			x.actionDone()
		default:
			x.notFound()
		}
	default:
		x.notFound()
	}
}

// nics: a VXVisor instance has exactly one NIC. Adding one binds that NIC to
// the requested vNIC profile (port group); removing it is refused.
func (s *Server) nics(x *req, vmID string) {
	sg, m := x.segs, x.r.Method
	vm, ok := s.vm(x, vmID)
	if !ok {
		return
	}
	switch {
	case len(sg) == 3 && m == http.MethodGet:
		x.ok(ListOf("nics", s.renderNIC(x, vm)))
	case len(sg) == 3 && m == http.MethodPost, len(sg) == 4 && m == http.MethodPut:
		if len(sg) == 4 && sg[3] != nicID(vmID) {
			x.notFound()
			return
		}
		body, err := x.body("nic")
		if err != nil {
			x.fault(http.StatusBadRequest, "Operation Failed", "invalid request body: "+err.Error())
			return
		}
		prof := body.RefID("vnic_profile")
		if prof != "" || body.Str("interface") != "" {
			if err := s.be.SetNIC(x.c, vmID, prof, body.Str("interface")); err != nil {
				x.fail(err)
				return
			}
		}
		if vm, ok = s.vm(x, vmID); !ok {
			return
		}
		if m == http.MethodPost {
			x.created(s.renderNIC(x, vm))
		} else {
			x.ok(s.renderNIC(x, vm))
		}
	case len(sg) >= 4 && sg[3] == nicID(vmID):
		switch {
		case len(sg) == 4 && m == http.MethodGet:
			x.ok(s.renderNIC(x, vm))
		case len(sg) == 5 && sg[4] == "reporteddevices" && m == http.MethodGet:
			x.ok(ListOf("reported_devices", s.renderReported(x, vm)))
		case len(sg) == 4 && m == http.MethodDelete:
			x.fault(http.StatusConflict, "Operation Failed", "a VXVisor instance always has one NIC; bind it to another vNIC profile instead")
		default:
			x.notFound()
		}
	default:
		x.notFound()
	}
}

// snapshots: VXVisor takes the backup's point-in-time from the backup itself
// (fleecing), so a snapshot a backup client requests around a backup is only
// recorded — no disk state changes — and the "Active VM" snapshot is always
// listed.
func (s *Server) snapshots(x *req, vmID string) {
	sg, m := x.segs, x.r.Method
	vm, ok := s.vm(x, vmID)
	if !ok {
		return
	}
	render := func(sn *snapshot, typ string) *Node {
		return El("snapshot",
			T("description", sn.description), T("snapshot_type", typ), T("snapshot_status", "ok"),
			D("date", sn.created), B("persist_memorystate", false),
			Ref("vm", api("vms", vmID), vmID),
		).Obj(api("vms", vmID, "snapshots", sn.id), sn.id)
	}
	active := &snapshot{id: derive("active-snapshot", vmID), description: "Active VM", created: dateOrNow(vm.Created)}
	s.mu.Lock()
	list := append([]*snapshot(nil), s.snaps[vmID]...)
	s.mu.Unlock()
	switch {
	case len(sg) == 3 && m == http.MethodGet:
		l := ListOf("snapshots", render(active, "active"))
		for _, sn := range list {
			l.Add(render(sn, "regular"))
		}
		x.ok(l)
	case len(sg) == 3 && m == http.MethodPost:
		body, _ := x.body("snapshot")
		desc := ""
		if body != nil {
			desc = body.Str("description")
		}
		sn := &snapshot{id: uuid.NewString(), description: desc, created: s.now()}
		s.mu.Lock()
		s.snaps[vmID] = append(s.snaps[vmID], sn)
		s.mu.Unlock()
		x.audit("ovirt.snapshot.record", "session", vmID, map[string]any{"snapshot": sn.id})
		x.created(render(sn, "regular"))
	case len(sg) == 4:
		if sg[3] == active.id && m == http.MethodGet {
			x.ok(render(active, "active"))
			return
		}
		for i, sn := range list {
			if sn.id != sg[3] {
				continue
			}
			switch m {
			case http.MethodGet:
				x.ok(render(sn, "regular"))
			case http.MethodDelete:
				s.mu.Lock()
				cur := s.snaps[vmID]
				s.snaps[vmID] = append(cur[:i:i], cur[i+1:]...)
				s.mu.Unlock()
				x.audit("ovirt.snapshot.remove", "session", vmID, map[string]any{"snapshot": sn.id})
				x.actionDone()
			default:
				x.notFound()
			}
			return
		}
		x.notFound()
	default:
		x.notFound()
	}
}

// ---- backups & checkpoints ---------------------------------------------------------

func (s *Server) backupsRoute(x *req, vmID string) {
	sg, m := x.segs, x.r.Method
	switch {
	case len(sg) == 3 && m == http.MethodGet:
		if _, ok := s.vm(x, vmID); !ok {
			return
		}
		s.mu.Lock()
		var bs []*backup
		for _, b := range s.backups {
			if b.vmID == vmID {
				bs = append(bs, b)
			}
		}
		s.mu.Unlock()
		sort.Slice(bs, func(i, j int) bool { return bs[i].created.Before(bs[j].created) })
		l := ListOf("backups")
		for _, b := range bs {
			l.Add(s.renderBackup(b))
		}
		x.ok(l)
	case len(sg) == 3 && m == http.MethodPost:
		body, err := x.body("backup")
		if err != nil {
			x.fault(http.StatusBadRequest, "Operation Failed", "invalid request body: "+err.Error())
			return
		}
		var disks []string
		if dl := body.Child("disks"); dl != nil {
			for _, d := range dl.Children("disk") {
				if d.ID != "" {
					disks = append(disks, d.ID)
				}
			}
		}
		from := body.Str("from_checkpoint_id")
		b, err := s.startBackup(x.c, vmID, disks, from, body.Str("description"))
		if err != nil {
			x.audit("ovirt.backup.start_failed", "session", vmID, map[string]any{"from_checkpoint": from, "error": err.Error()})
			x.fail(err)
			return
		}
		x.audit("ovirt.backup.start", "session", vmID, map[string]any{"backup": b.id, "mode": b.mode(),
			"from_checkpoint": b.from, "to_checkpoint": b.to})
		x.created(s.renderBackup(b))
	case len(sg) >= 4:
		s.mu.Lock()
		b := s.backups[sg[3]]
		s.mu.Unlock()
		if b == nil || b.vmID != vmID {
			x.notFound()
			return
		}
		switch {
		case len(sg) == 4 && m == http.MethodGet:
			x.ok(s.renderBackup(b))
		case len(sg) == 5 && sg[4] == "disks" && m == http.MethodGet:
			d := b.disk
			x.ok(ListOf("disks", s.renderDisk(d, b.mode())))
		case len(sg) == 5 && sg[4] == "finalize" && m == http.MethodPost:
			err := s.endBackup(b, true)
			x.audit("ovirt.backup.finalize", "session", vmID, map[string]any{"backup": b.id, "phase": b.phase,
				"checkpoint": b.to, "ok": err == nil})
			if err != nil {
				x.fail(fmt.Errorf("finalizing backup %s: %w", b.id, err))
				return
			}
			x.actionDone(s.renderBackup(b))
		default:
			x.notFound()
		}
	default:
		x.notFound()
	}
}

func (s *Server) renderCheckpoint(cp Checkpoint) *Node {
	state := "created"
	if cp.Invalid {
		state = "invalid"
	}
	n := El("checkpoint",
		T("description", cp.Description), D("creation_date", cp.Created), T("state", state),
		Ref("vm", api("vms", cp.VMID), cp.VMID),
	).Obj(api("vms", cp.VMID, "checkpoints", cp.ID), cp.ID)
	if cp.ParentID != "" {
		n.Add(T("parent_id", cp.ParentID))
	}
	return n
}

func (s *Server) checkpoints(x *req, vmID string) {
	sg, m := x.segs, x.r.Method
	if _, ok := s.vm(x, vmID); !ok {
		return
	}
	cps, err := s.be.Checkpoints(x.c, vmID)
	if err != nil {
		x.fail(err)
		return
	}
	switch {
	case len(sg) == 3 && m == http.MethodGet:
		l := ListOf("checkpoints")
		for _, cp := range cps {
			l.Add(s.renderCheckpoint(cp))
		}
		x.ok(l)
	case len(sg) == 4:
		for _, cp := range cps {
			if cp.ID != sg[3] {
				continue
			}
			switch m {
			case http.MethodGet:
				x.ok(s.renderCheckpoint(cp))
			case http.MethodDelete:
				s.mu.Lock()
				_, busy := s.busyVM[vmID]
				s.mu.Unlock()
				if busy {
					x.fault(http.StatusConflict, "Operation Failed", "the VM is being backed up")
					return
				}
				if err := s.be.RemoveCheckpoint(x.c, vmID, cp.ID); err != nil {
					x.fail(err)
					return
				}
				x.actionDone()
			default:
				x.notFound()
			}
			return
		}
		x.notFound()
	default:
		x.notFound()
	}
}

// ---- image transfers -------------------------------------------------------------

func (s *Server) imageTransfers(x *req) {
	sg, m := x.segs, x.r.Method
	switch {
	case len(sg) == 1 && m == http.MethodGet:
		s.mu.Lock()
		var ts []*transfer
		for _, t := range s.transfers {
			ts = append(ts, t)
		}
		s.mu.Unlock()
		sort.Slice(ts, func(i, j int) bool { return ts[i].created.Before(ts[j].created) })
		l := ListOf("image_transfers")
		for _, t := range ts {
			l.Add(s.renderTransfer(t))
		}
		x.ok(l)
	case len(sg) == 1 && m == http.MethodPost:
		body, err := x.body("image_transfer")
		if err != nil {
			x.fault(http.StatusBadRequest, "Operation Failed", "invalid request body: "+err.Error())
			return
		}
		spec := transferSpec{diskID: body.RefID("disk"), backupID: body.RefID("backup"),
			direction: body.Str("direction"), format: body.Str("format"), policy: body.Str("timeout_policy"),
			inactivity: secondsParam(body.Str("inactivity_timeout"))}
		if spec.diskID == "" {
			spec.diskID = body.RefID("image") // legacy: image.id names the disk's image
		}
		t, err := s.startTransfer(x.c, spec)
		if err != nil {
			x.audit("ovirt.transfer.start_failed", "disk", spec.diskID, map[string]any{"direction": spec.direction, "error": err.Error()})
			x.fail(err)
			return
		}
		x.audit("ovirt.transfer.start", "disk", t.diskID, map[string]any{"transfer": t.id, "direction": t.direction,
			"backup": t.backupID})
		x.created(s.renderTransfer(t))
	case len(sg) >= 2:
		s.mu.Lock()
		t := s.transfers[sg[1]]
		s.mu.Unlock()
		if t == nil {
			x.notFound()
			return
		}
		if len(sg) == 2 && m == http.MethodGet {
			x.ok(s.renderTransfer(t))
			return
		}
		if len(sg) != 3 || m != http.MethodPost {
			x.notFound()
			return
		}
		switch sg[2] {
		case "finalize":
			s.endTransfer(t, true, "finished_success")
			x.audit("ovirt.transfer.finalize", "disk", t.diskID, map[string]any{"transfer": t.id, "bytes": t.transferred})
			x.actionDone()
		case "cancel":
			s.endTransfer(t, false, "finished_failure")
			x.audit("ovirt.transfer.cancel", "disk", t.diskID, map[string]any{"transfer": t.id})
			x.actionDone()
		case "extend", "pause", "resume":
			// The ticket stays alive on activity; nothing to do.
			x.actionDone()
		default:
			x.notFound()
		}
	default:
		x.notFound()
	}
}
