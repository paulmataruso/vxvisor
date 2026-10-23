// Package vmexport builds portable VM exports (disk image, OVA) from a VXVisor VM
// and can PUSH a VM into a vCenter/ESXi environment over OVF/NFC.
//
// It is deliberately a SEPARATE package from internal/vmware: that package is
// strictly read-only on a source being imported and is guarded by a test that
// forbids any mutating govmomi call in its files. Export is the opposite job —
// writing into a *target* VMware environment — so it lives here, keeping the
// import package's read-only guarantee intact and un-weakened.
package vmexport

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Hardware is the VM shape an OVF/OVA describes. One boot disk (the common case
// for an exported VXVisor instance); extra disks are a follow-up.
type Hardware struct {
	Name               string // VM / vApp name
	CPUs               int
	MemMB              int
	Firmware           string // bios | uefi
	OSType             string // linux | windows
	DiskHref           string // file name of the vmdk inside the OVA (e.g. "vm-disk1.vmdk")
	DiskCapacityBytes  int64  // virtual size
	DiskPopulatedBytes int64  // allocated size (optional, 0 = omit)
	NetworkName        string // logical network name the NIC connects to
}

const (
	diskID    = "vmdisk1"
	diskRefID = "file1"
	netName   = "VM Network"
	// streamOptimized VMDK format URI OVF uses to declare the disk encoding.
	vmdkFormatURI = "http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"
)

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// Descriptor renders the .ovf XML for hw. Targets OVF 1.0 with the VMware (vmw)
// extension for firmware, which ESXi/vCenter, VirtualBox and qemu all read.
func Descriptor(hw Hardware) string {
	net := hw.NetworkName
	if net == "" {
		net = netName
	}
	osID, osType := "36", "otherGuest"
	if hw.OSType == "windows" {
		osID, osType = "1", "windows9_64Guest"
	} else {
		osID, osType = "36", "other26xLinux64Guest"
	}
	populated := ""
	if hw.DiskPopulatedBytes > 0 {
		populated = fmt.Sprintf(` ovf:populatedSize="%d"`, hw.DiskPopulatedBytes)
	}
	firmware := "bios"
	if hw.Firmware == "uefi" || hw.Firmware == "efi" {
		firmware = "efi"
	}
	name := xmlEscape(hw.Name)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Envelope vmw:buildId="vxvisor" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="%s" ovf:id="%s"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="%d" ovf:capacityAllocationUnits="byte" ovf:diskId="%s" ovf:fileRef="%s" ovf:format="%s"%s/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="%s">
      <Description>The %s network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="%s">
    <Info>A virtual machine</Info>
    <Name>%s</Name>
    <OperatingSystemSection ovf:id="%s" vmw:osType="%s">
      <Info>The kind of installed guest operating system</Info>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>%s</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>%d virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>%d</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>%dMB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>%d</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/%s</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>%s</rasd:Connection>
        <rasd:Description>VmxNet3 ethernet adapter</rasd:Description>
        <rasd:ElementName>Network adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>
      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="%s"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
`,
		xmlEscape(hw.DiskHref), diskRefID,
		hw.DiskCapacityBytes, diskID, diskRefID, vmdkFormatURI, populated,
		xmlEscape(net), xmlEscape(net),
		name, name,
		osID, osType,
		name,
		hw.CPUs, hw.CPUs,
		hw.MemMB, hw.MemMB,
		diskID,
		xmlEscape(net),
		firmware,
	)
}

// WriteOVA builds an .ova (tar of ovf + manifest + the stream-optimized vmdk) at
// outPath. vmdkPath must already be a stream-optimized VMDK whose file name equals
// hw.DiskHref. The manifest carries SHA-256 of the descriptor and the disk.
func WriteOVA(hw Hardware, vmdkPath, outPath string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ovf := Descriptor(hw)
	ovfName := SanitizeName(hw.Name) + ".ovf"

	// Hash the descriptor and the disk for the manifest.
	ovfSum := fmt.Sprintf("%x", sha256.Sum256([]byte(ovf)))
	diskSum, diskSize, err := sha256File(vmdkPath)
	if err != nil {
		return err
	}
	manifest := fmt.Sprintf("SHA256(%s)= %s\nSHA256(%s)= %s\n", ovfName, ovfSum, hw.DiskHref, diskSum)
	mfName := SanitizeName(hw.Name) + ".mf"

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	tw := tar.NewWriter(out)
	defer tw.Close()

	now := time.Now()
	writeEntry := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: now, Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	// OVA ordering matters: descriptor first, then manifest, then disk(s).
	if err := writeEntry(ovfName, []byte(ovf)); err != nil {
		return err
	}
	if err := writeEntry(mfName, []byte(manifest)); err != nil {
		return err
	}
	logf("OVA: packing disk %s (%d MiB) into %s", hw.DiskHref, diskSize/(1<<20), filepath.Base(outPath))
	df, err := os.Open(vmdkPath)
	if err != nil {
		return err
	}
	defer df.Close()
	// PAX (not USTAR) for the disk entry: USTAR caps a single file at 8 GiB
	// (its octal size field is 11 digits), and a stream-optimized VMDK routinely
	// exceeds that. PAX encodes an arbitrary 64-bit size in an extended record
	// and is read by GNU tar, VirtualBox and ovftool alike.
	if err := tw.WriteHeader(&tar.Header{Name: hw.DiskHref, Mode: 0o644, Size: diskSize, ModTime: now, Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := io.Copy(tw, df); err != nil {
		return err
	}
	return nil
}

func sha256File(path string) (hexsum string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

func SanitizeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		case r == ' ' || r == '.':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "vm"
	}
	return string(out)
}
