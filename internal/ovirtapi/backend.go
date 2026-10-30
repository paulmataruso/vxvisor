package ovirtapi

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/vmbackup"
)

// Backend is everything the engine API needs from vdxd. The service layer
// implements it, so authorization and audit stay in one place; this package
// only translates the oVirt model and runs the backup / transfer state
// machines. Caller is the opaque authenticated principal Login returned.
type Backend interface {
	// Login verifies credentials (the "@internal"-style profile suffix is
	// already stripped) and returns the caller. It audits both outcomes.
	Login(user, password, ip string) (Caller, error)
	// Bind re-validates a caller for one request from ip (the user must still
	// exist, be enabled and be allowed to use the API) and returns the caller
	// the request's backend calls get, carrying ip for their audit records.
	Bind(c Caller, ip string) (Caller, error)

	Host(c Caller) (Host, error)
	StoragePools(c Caller) ([]StoragePool, error)
	Networks(c Caller) ([]Network, error)
	VMs(c Caller) ([]VM, error)
	VM(c Caller, id string) (VM, error)
	// GuestIPs is what the guest agent (or the neighbour table) reports.
	GuestIPs(c Caller, vmID string) []string

	// BackupDisk pins the VM against lifecycle operations (start, delete,
	// storage moves) until release is called, and describes its disk.
	BackupDisk(c Caller, vmID string) (d vmbackup.Disk, release func(), err error)
	Checkpoints(c Caller, vmID string) ([]Checkpoint, error)
	AddCheckpoint(c Caller, cp Checkpoint) error
	RemoveCheckpoint(c Caller, vmID, id string) error

	// Staged disks: created detached (restore targets, worker images) and
	// attached to a VM later. WritableDisk pins a staged disk, or a stopped
	// VM's disk, for an upload.
	Disks(c Caller) ([]Disk, error)
	CreateDisk(c Caller, spec DiskSpec) (Disk, error)
	DeleteDisk(c Caller, id string) error
	WritableDisk(c Caller, id string) (path, format string, release func(), err error)

	CreateVM(c Caller, spec VMSpec) (VM, error)
	DeleteVM(c Caller, id string, keepDisks bool) error
	AttachDisk(c Caller, vmID, diskID, iface string) error
	DetachDisk(c Caller, vmID, diskID string) error
	SetNIC(c Caller, vmID, profileID, iface string) error
	StartVM(c Caller, id string) error
	StopVM(c Caller, id string) error

	// Audit records one mutation made through the API.
	Audit(c Caller, action, targetType, targetID, ip string, detail map[string]any)
}

// Caller is an authenticated principal (opaque to this package).
type Caller any

// ErrNotFound / ErrConflict / ErrForbidden / ErrBadRequest classify backend
// errors into HTTP faults; anything else is a 400 "Operation Failed".
var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
	ErrForbidden  = errors.New("forbidden")
	ErrBadRequest = errors.New("bad request")
)

// Host is the hypervisor node.
type Host struct {
	Name       string
	Address    string // what workers connect to (the API's public host)
	CPUModel   string
	CPUs       int
	Sockets    int
	MemoryMB   int64
	FreeMB     int64
	QEMUVer    string
	KernelVer  string
	OSVersion  string
	VMsRunning int
}

// StoragePool is a VXVisor storage pool (or the default disk directory).
type StoragePool struct {
	PoolID    int64 // 0 = default disk directory
	Name      string
	Kind      string // dir|nfs|cifs|zfs|lvm|rbd|...
	Available int64
	Used      int64
	// Uploadable: staged disks (restore targets) can be created here. Only
	// file-backed pools hold the qcow2 files staged disks are.
	Uploadable bool
}

// Network is a VXVisor port group (NetID 0 = the default NAT network).
type Network struct {
	NetID int64
	Name  string
	VLAN  int
	OrgID int64
}

// VM is one VXVisor instance.
type VM struct {
	ID, Name    string
	OrgID       int64
	Status      string // oVirt status: up | down | powering_up | migrating
	CPUs        int
	MemoryMB    int
	Firmware    string // uefi | bios
	SecureBoot  bool
	MachineType string // q35 | pc
	OSType      string // linux | windows
	DiskBus     string // virtio-blk | virtio-scsi | sata
	NICModel    string
	VGA         string
	GuestAgent  bool
	TPM         bool
	Created     time.Time
	NetID       int64
	MAC         string
	Disk        *Disk // nil = no disk attached
}

// Disk is a VM's disk or a staged one.
type Disk struct {
	ID, Name    string
	VMID        string // "" = staged / detached
	Path        string
	Format      string // qcow2 | raw
	PoolID      int64
	Provisioned int64
	Actual      int64
	Locked      bool // an upload or backup holds it
	Incremental bool // can carry checkpoints (qcow2 v3)
}

// Checkpoint is one persisted backup checkpoint.
type Checkpoint struct {
	ID, VMID, ParentID string
	Description        string
	Created            time.Time
	Invalid            bool
}

// DiskSpec creates a staged disk.
type DiskSpec struct {
	Name        string
	Provisioned int64
	PoolID      int64
	Sparse      bool
}

// VMSpec creates a VM without a disk (a restore target or a backup worker).
type VMSpec struct {
	Name        string
	OrgID       int64 // 0 = the provider (default) org
	CPUs        int
	MemoryMB    int
	Firmware    string
	SecureBoot  bool
	MachineType string
	OSType      string
	DiskBus     string
	NICModel    string
	VGA         string
	GuestAgent  bool
	TPM         bool
	// UserData is a cloud-init user-data document (oVirt
	// initialization.custom_script), delivered on a NoCloud seed.
	UserData string
	// Purpose records why the VM was made ("restore" | "worker"); API-made
	// workers are purged outright on delete, everything else goes to Trash.
	Purpose string
}

// Stable identifiers. oVirt ids are UUIDs; VXVisor VM ids already are, the
// rest are derived (UUIDv5) from a fixed namespace so they never change.
var ns = uuid.MustParse("6f1d9a3e-2c4b-5e7a-9d1f-0a8b7c6d5e4f")

func derive(kind, key string) string { return uuid.NewSHA1(ns, []byte(kind+":"+key)).String() }

// DiskIDForVM is the id of a VM disk that was not created through the API.
func DiskIDForVM(vmID string) string { return derive("disk", vmID) }

// PoolID / NetID map VXVisor ids to oVirt ids.
func poolUUID(id int64) string { return derive("sd", itoa(id)) }
func netUUID(id int64) string  { return derive("net", itoa(id)) }

// NetUUID is the oVirt network (and vNIC profile) id of a VXVisor port group.
func NetUUID(id int64) string { return netUUID(id) }

const blankTemplate = "00000000-0000-0000-0000-000000000000"
