package client

// This file adds the Import / Export client calls: connect to a vCenter/ESXi and
// list its VMs, start a single-VM import, poll import/export progress, and start
// an export. Thin wrappers over the CSRF-exempt REST API.
//
// DiscoveredVM/DiscoveredDisk/DiscoveredNIC mirror vmware.VMInfo et al., which
// the server serializes with NO json tags (PascalCase). ImportJob/ExportJob
// mirror service.VMwareImportState/VMExportState, which DO carry snake_case json
// tags.

// DiscoveredVM mirrors vmware.VMInfo (PascalCase, no server json tags).
type DiscoveredVM struct {
	MOID          string           `json:"MOID"`
	Name          string           `json:"Name"`
	PowerState    string           `json:"PowerState"` // poweredOn | poweredOff | suspended
	GuestID       string           `json:"GuestID"`
	GuestFullName string           `json:"GuestFullName"`
	NumCPU        int32            `json:"NumCPU"`
	MemMB         int32            `json:"MemMB"`
	Firmware      string           `json:"Firmware"` // bios | efi
	Disks         []DiscoveredDisk `json:"Disks"`
	Nets          []string         `json:"Nets"`
	NICs          []DiscoveredNIC  `json:"NICs"`
	HasSnapshots  bool             `json:"HasSnapshots"`
	Importable    bool             `json:"Importable"` // false → import is refused
	ImportNote    string           `json:"ImportNote"` // why not importable, or a caveat
}

// DiscoveredDisk mirrors vmware.DiskInfo.
type DiscoveredDisk struct {
	Label      string `json:"Label"`
	CapacityGB int64  `json:"CapacityGB"`
	Backing    string `json:"Backing"`
	Thin       bool   `json:"Thin"`
}

// DiscoveredNIC mirrors vmware.NICInfo.
type DiscoveredNIC struct {
	Label     string `json:"Label"`
	MAC       string `json:"MAC"`
	Type      string `json:"Type"`
	PortGroup string `json:"PortGroup"`
}

// ImportJob mirrors service.VMwareImportState (snake_case json tags).
type ImportJob struct {
	ID         string   `json:"id"`
	VMName     string   `json:"vm"`
	Status     string   `json:"status"` // connecting|exporting|converting|registering|done|failed
	Step       string   `json:"step"`
	Pct        int      `json:"pct"`
	DoneBytes  int64    `json:"done_bytes"`
	TotalBytes int64    `json:"total_bytes"`
	Nominal    int64    `json:"nominal"`
	Rate       int64    `json:"rate"`
	Image      string   `json:"image"`
	Err        string   `json:"err"`
	StartedAt  int64    `json:"started"`
	FinishedAt int64    `json:"finished"`
	HasLog     bool     `json:"has_log"`
	LogTail    []string `json:"log_tail"`
}

// ExportJob mirrors service.VMExportState (snake_case json tags).
type ExportJob struct {
	ID         string   `json:"id"`
	VMName     string   `json:"vm"`
	Target     string   `json:"target"` // download-image | download-ova | push
	Format     string   `json:"format"` // qcow2 | raw | vmdk
	Status     string   `json:"status"` // preparing|converting|packing|uploading|done|failed
	Step       string   `json:"step"`
	DoneBytes  int64    `json:"done_bytes"`
	TotalBytes int64    `json:"total_bytes"`
	Rate       int64    `json:"rate"`
	File       string   `json:"file"`
	Err        string   `json:"err"`
	StartedAt  int64    `json:"started"`
	FinishedAt int64    `json:"finished"`
	HasLog     bool     `json:"has_log"`
	LogTail    []string `json:"log_tail"`
}

// VMwareConnect connects read-only to a vCenter/ESXi and returns its VM
// inventory. The password is used in memory only (never audited server-side).
func (c *Client) VMwareConnect(host, user, pass string, insecure bool) ([]DiscoveredVM, error) {
	var out struct {
		VMs []DiscoveredVM `json:"vms"`
	}
	err := c.apiPostDecode("/api/v1/import/vmware/connect", map[string]any{
		"host": host, "user": user, "pass": pass, "insecure": insecure,
	}, &out)
	return out.VMs, err
}

// StartVMwareImport kicks off a single-VM async import and returns its tracking
// id. transport is "" | "nfc" | "datastore" | "vddk"; targetPoolID 0 = default
// disk dir. Poll ImportStatus for progress.
func (c *Client) StartVMwareImport(host, user, pass string, insecure bool, moid, osType, transport string, targetPoolID int64) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.apiPostDecode("/api/v1/import/vmware/start", map[string]any{
		"host": host, "user": user, "pass": pass, "insecure": insecure,
		"moid": moid, "os_type": osType, "transport": transport, "target_pool_id": targetPoolID,
	}, &out)
	return out.ID, err
}

// ImportStatus returns in-flight + recent import jobs.
func (c *Client) ImportStatus() ([]ImportJob, error) {
	var out []ImportJob
	if err := c.getJSON("/api/v1/import/status", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExportStatus returns in-flight + recent export jobs.
func (c *Client) ExportStatus() ([]ExportJob, error) {
	var out []ExportJob
	if err := c.getJSON("/api/v1/export/status", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ExportTarget carries the optional push-to-vCenter destination for an export.
// All fields are ignored unless the export target is "push".
type ExportTarget struct {
	URL          string
	User         string
	Pass         string
	Insecure     bool
	Name         string
	Datacenter   string
	ResourcePool string
	Datastore    string
	Folder       string
	Network      string
}

// StartExport kicks off an async export of a stopped VM and returns its tracking
// id. target is "download-image" | "download-ova" | "push"; format is
// "qcow2"|"raw"|"vmdk" (download-image only). push is used only for "push".
func (c *Client) StartExport(sessionID, target, format string, push ExportTarget) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	err := c.apiPostDecode("/api/v1/export/start", map[string]any{
		"session_id":     sessionID,
		"target":         target,
		"format":         format,
		"pvc_url":        push.URL,
		"pvc_user":       push.User,
		"pvc_pass":       push.Pass,
		"pvc_insecure":   push.Insecure,
		"pvc_name":       push.Name,
		"pvc_datacenter": push.Datacenter,
		"pvc_pool":       push.ResourcePool,
		"pvc_datastore":  push.Datastore,
		"pvc_folder":     push.Folder,
		"pvc_network":    push.Network,
	}, &out)
	return out.ID, err
}
