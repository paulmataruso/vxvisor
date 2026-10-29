package ovirtapi

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// OVF: an oVirt engine hands a VM's configuration out as an OVF document
// (vm.initialization.configuration, type "ovf") and accepts one back when a VM
// is created from a backup. Backup software stores it with the backup and
// replays it on restore, so it is the only VM metadata that survives the round
// trip. The document follows oVirt's OVF layout (Content/Name, BiosType, an
// OperatingSystemSection, a VirtualHardwareSection with CPU/memory/disk/NIC
// items) and adds a vxvisor:Instance element carrying the VXVisor-specific
// settings (org, firmware, buses, NIC model, ...), so a VXVisor → VXVisor
// restore is exact. OVFs from other platforms are parsed for the standard
// fields only.

const ovfNS = "urn:vxvisor:ovf:1"

// biosTypeNum follows the numbering the known-working oVirt emulators accept
// from Veeam (0 i440fx SeaBIOS, 1 q35 SeaBIOS, 2 q35 OVMF, 3 q35 Secure Boot).
func biosTypeNum(vm VM) int {
	switch biosType(vm) {
	case "i440fx_sea_bios":
		return 0
	case "q35_sea_bios":
		return 1
	case "q35_secure_boot":
		return 3
	}
	return 2
}

func xmlEsc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (s *Server) ovf(vm VM) string {
	var b strings.Builder
	cpus := max(vm.CPUs, 1)
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ovf:Envelope xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1/"` +
		` xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"` +
		` xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"` +
		` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vxvisor="` + ovfNS + `" ovf:version="4.4.0.0">`)
	if d := vm.Disk; d != nil {
		fmt.Fprintf(&b, `<References><File ovf:href="%s" ovf:id="%s" ovf:size="%d" ovf:description="%s"/></References>`,
			d.ID, d.ID, d.Provisioned, xmlEsc(d.Name))
		vf, vt := "RAW", "Preallocated"
		if d.Format == "qcow2" {
			vf, vt = "COW", "Sparse"
		}
		fmt.Fprintf(&b, `<Section xsi:type="ovf:DiskSection_Type"><Info>List of Virtual Disks</Info>`+
			`<Disk ovf:diskId="%s" ovf:size="%d" ovf:actual_size="%d" ovf:fileRef="%s" ovf:volume-format="%s" ovf:volume-type="%s" ovf:disk-interface="%s" ovf:boot="true" ovf:disk-alias="%s"/></Section>`,
			d.ID, (d.Provisioned+(1<<30)-1)>>30, (d.Actual+(1<<30)-1)>>30, d.ID, vf, vt, ovfDiskIface(vm.DiskBus), xmlEsc(d.Name))
	}
	fmt.Fprintf(&b, `<Content ovf:id="out" xsi:type="ovf:VirtualSystem_Type"><Name>%s</Name><Description></Description>`,
		xmlEsc(vm.Name))
	fmt.Fprintf(&b, `<CreationDate>%s</CreationDate><BiosType>%d</BiosType><ClusterCompatibilityVersion>4.7</ClusterCompatibilityVersion>`,
		dateOrNow(vm.Created).UTC().Format("2006/01/02 15:04:05"), biosTypeNum(vm))
	fmt.Fprintf(&b, `<vxvisor:Instance vxvisor:id="%s" vxvisor:org_id="%d" vxvisor:firmware="%s" vxvisor:secure_boot="%t"`+
		` vxvisor:machine="%s" vxvisor:os_type="%s" vxvisor:disk_bus="%s" vxvisor:nic_model="%s" vxvisor:vga="%s"`+
		` vxvisor:guest_agent="%t" vxvisor:tpm="%t" vxvisor:network_id="%d" vxvisor:mac="%s"/>`,
		vm.ID, vm.OrgID, xmlEsc(vm.Firmware), vm.SecureBoot, xmlEsc(vm.MachineType), xmlEsc(vm.OSType),
		xmlEsc(vm.DiskBus), xmlEsc(vm.NICModel), xmlEsc(vm.VGA), vm.GuestAgent, vm.TPM, vm.NetID, xmlEsc(vm.MAC))
	fmt.Fprintf(&b, `<Section ovf:id="%s" ovf:required="false" xsi:type="ovf:OperatingSystemSection_Type"><Info>Guest Operating System</Info><Description>%s</Description></Section>`,
		vm.ID, osName(vm))
	fmt.Fprintf(&b, `<Section xsi:type="ovf:VirtualHardwareSection_Type"><Info>%d CPU, %d Memory</Info><System><vssd:VirtualSystemType>ENGINE 4.4.0.0</vssd:VirtualSystemType></System>`,
		cpus, vm.MemoryMB)
	fmt.Fprintf(&b, `<Item><rasd:Caption>%d virtual cpu</rasd:Caption><rasd:Description>Number of virtual CPU</rasd:Description><rasd:InstanceId>1</rasd:InstanceId><rasd:ResourceType>3</rasd:ResourceType>`+
		`<rasd:num_of_sockets>%d</rasd:num_of_sockets><rasd:cpu_per_socket>1</rasd:cpu_per_socket><rasd:threads_per_cpu>1</rasd:threads_per_cpu><rasd:VirtualQuantity>%d</rasd:VirtualQuantity></Item>`,
		cpus, cpus, cpus)
	fmt.Fprintf(&b, `<Item><rasd:Caption>%d MB of memory</rasd:Caption><rasd:Description>Memory Size</rasd:Description><rasd:InstanceId>2</rasd:InstanceId><rasd:ResourceType>4</rasd:ResourceType>`+
		`<rasd:AllocationUnits>MegaBytes</rasd:AllocationUnits><rasd:VirtualQuantity>%d</rasd:VirtualQuantity></Item>`,
		vm.MemoryMB, vm.MemoryMB)
	if d := vm.Disk; d != nil {
		fmt.Fprintf(&b, `<Item><rasd:Caption>%s</rasd:Caption><rasd:InstanceId>%s</rasd:InstanceId><rasd:ResourceType>17</rasd:ResourceType>`+
			`<rasd:HostResource>%s</rasd:HostResource><rasd:Parent>00000000-0000-0000-0000-000000000000</rasd:Parent><rasd:Template>00000000-0000-0000-0000-000000000000</rasd:Template>`+
			`<rasd:StorageId>%s</rasd:StorageId><rasd:StoragePoolId>%s</rasd:StoragePoolId><BootOrder>1</BootOrder><IsReadOnly>false</IsReadOnly><Alias>%s</Alias></Item>`,
			xmlEsc(d.Name), d.ID, d.ID, poolUUID(d.PoolID), s.dcID(), xmlEsc(d.Name))
	}
	fmt.Fprintf(&b, `<Item><rasd:Caption>Ethernet adapter on %d</rasd:Caption><rasd:InstanceId>%s</rasd:InstanceId><rasd:ResourceType>10</rasd:ResourceType>`+
		`<rasd:OtherResourceType>%d</rasd:OtherResourceType><rasd:ResourceSubType>3</rasd:ResourceSubType><rasd:Connection>%d</rasd:Connection>`+
		`<rasd:Linked>true</rasd:Linked><rasd:Name>nic1</rasd:Name><rasd:MACAddress>%s</rasd:MACAddress><rasd:speed>10000</rasd:speed></Item>`,
		vm.NetID, nicID(vm.ID), vm.NetID, vm.NetID, xmlEsc(vm.MAC))
	b.WriteString(`</Section></Content></ovf:Envelope>`)
	return b.String()
}

func ovfDiskIface(bus string) string {
	switch bus {
	case "virtio-scsi":
		return "VirtIO_SCSI"
	case "sata":
		return "SATA"
	}
	return "VirtIO"
}

// ovfInfo is what a restore takes from an OVF.
type ovfInfo struct {
	Name     string
	CPUs     int
	MemoryMB int
	BiosType int // -1 = absent
	OS       string
	MAC      string
	// From vxvisor:Instance (zero values when absent).
	Native      bool
	OrgID       int64
	NetID       int64
	Firmware    string
	SecureBoot  bool
	Machine     string
	OSType      string
	DiskBus     string
	NICModel    string
	VGA         string
	GuestAgent  bool
	TPM         bool
	SourceVMID  string
}

// parseOVF reads the fields a restore needs; unknown content is ignored.
func parseOVF(data string) (ovfInfo, error) {
	info := ovfInfo{BiosType: -1}
	dec := xml.NewDecoder(io.LimitReader(strings.NewReader(data), maxBody))
	var path []string
	var item map[string]string
	var text strings.Builder
	sectionInfo := ""
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, fmt.Errorf("invalid OVF: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			text.Reset()
			switch t.Name.Local {
			case "Item":
				item = map[string]string{}
			case "Instance":
				if t.Name.Space == ovfNS {
					info.Native = true
					for _, a := range t.Attr {
						v := a.Value
						switch a.Name.Local {
						case "id":
							info.SourceVMID = v
						case "org_id":
							info.OrgID, _ = strconv.ParseInt(v, 10, 64)
						case "network_id":
							info.NetID, _ = strconv.ParseInt(v, 10, 64)
						case "firmware":
							info.Firmware = v
						case "secure_boot":
							info.SecureBoot = v == "true"
						case "machine":
							info.Machine = v
						case "os_type":
							info.OSType = v
						case "disk_bus":
							info.DiskBus = v
						case "nic_model":
							info.NICModel = v
						case "vga":
							info.VGA = v
						case "guest_agent":
							info.GuestAgent = v == "true"
						case "tpm":
							info.TPM = v == "true"
						case "mac":
							info.MAC = v
						}
					}
				}
			}
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			v := strings.TrimSpace(text.String())
			parent := ""
			if len(path) >= 2 {
				parent = path[len(path)-2]
			}
			switch {
			case t.Name.Local == "Name" && parent == "Content":
				info.Name = v
			case t.Name.Local == "BiosType" && parent == "Content":
				if n, err := strconv.Atoi(v); err == nil {
					info.BiosType = n
				}
			case t.Name.Local == "Info" && parent == "Section":
				sectionInfo = v
			case t.Name.Local == "Description" && parent == "Section" && sectionInfo == "Guest Operating System":
				info.OS = v
			case parent == "Item" && item != nil:
				item[t.Name.Local] = v
			case t.Name.Local == "Item" && item != nil:
				switch item["ResourceType"] {
				case "3":
					n, _ := strconv.Atoi(item["VirtualQuantity"])
					if n <= 0 {
						s, _ := strconv.Atoi(item["num_of_sockets"])
						c, _ := strconv.Atoi(item["cpu_per_socket"])
						th, _ := strconv.Atoi(item["threads_per_cpu"])
						n = max(s, 1) * max(c, 1) * max(th, 1)
					}
					info.CPUs = n
				case "4":
					info.MemoryMB, _ = strconv.Atoi(item["VirtualQuantity"])
				case "10":
					if info.MAC == "" {
						info.MAC = item["MACAddress"]
					}
				}
				item = nil
			}
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
			text.Reset()
		}
	}
	return info, nil
}

// applyBios maps an oVirt bios type name onto a VMSpec.
func applyBios(spec *VMSpec, t string) {
	switch t {
	case "i440fx_sea_bios":
		spec.Firmware, spec.MachineType = "bios", "pc"
	case "q35_sea_bios":
		spec.Firmware, spec.MachineType = "bios", "q35"
	case "q35_secure_boot":
		spec.Firmware, spec.MachineType, spec.SecureBoot = "uefi", "q35", true
	case "q35_ovmf":
		spec.Firmware, spec.MachineType = "uefi", "q35"
	}
}

var biosByNum = map[int]string{0: "i440fx_sea_bios", 1: "q35_sea_bios", 2: "q35_ovmf", 3: "q35_secure_boot"}
