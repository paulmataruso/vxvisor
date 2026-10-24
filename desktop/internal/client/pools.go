package client

import "fmt"

// Storage resources: registered pools (+ datastore browser), shared mounts
// (NFS/CIFS/Ceph), Ceph cluster status, and read-only ZFS/LVM/mdraid listings.
// Pool / SharedMount decode from PascalCase (server structs have no json tags);
// the browser entries, Ceph health, and the ZFS/LVM/mdraid types carry their
// own snake_case json tags server-side, so those are mirrored here.

// Pool is a registered storage pool (VM disk backend).
type Pool struct {
	ID         int64  `json:"ID"`
	Name       string `json:"Name"`
	Kind       string `json:"Kind"` // dir | zfs | lvm | rbd | nfs | cifs | ceph
	Path       string `json:"Path"`
	UsedBytes  int64  `json:"UsedBytes"`
	TotalBytes int64  `json:"TotalBytes"`
	CreatedAt  string `json:"CreatedAt"`
}

// PoolEntry is one item inside a pool (datastore browser row).
type PoolEntry struct {
	Name     string `json:"name"`
	Bytes    int64  `json:"bytes"`
	Kind     string `json:"kind"` // qcow2|iso|raw|file|dir|dataset|zvol|lv|image
	Modified string `json:"modified"`
}

// PoolBrowse is the datastore-browser response for one pool.
type PoolBrowse struct {
	Name    string      `json:"name"`
	Kind    string      `json:"kind"`
	Path    string      `json:"path"`
	Entries []PoolEntry `json:"entries"`
}

// SharedMount is an NFS/CIFS/Ceph mount registered as a pool.
type SharedMount struct {
	ID         int64  `json:"ID"`
	Kind       string `json:"Kind"` // nfs | cifs | ceph
	Name       string `json:"Name"`
	Spec       string `json:"Spec"`
	Options    string `json:"Options"`
	Mountpoint string `json:"Mountpoint"`
	Status     string `json:"Status"`
	CreatedAt  string `json:"CreatedAt"`
}

// CephHealth is a compact on-node Ceph cluster snapshot.
type CephHealth struct {
	Available  bool   `json:"available"`
	Configured bool   `json:"configured"`
	Status     string `json:"status"` // HEALTH_OK | HEALTH_WARN | HEALTH_ERR
	NumMons    int    `json:"num_mons"`
	NumOSDs    int    `json:"num_osds"`
	OSDsUp     int    `json:"osds_up"`
	OSDsIn     int    `json:"osds_in"`
	TotalBytes int64  `json:"total_bytes"`
	UsedBytes  int64  `json:"used_bytes"`
	AvailBytes int64  `json:"avail_bytes"`
	Summary    string `json:"summary"`
}

// ZFSPool is a live zpool.
type ZFSPool struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	AllocBytes int64  `json:"alloc_bytes"`
	FreeBytes  int64  `json:"free_bytes"`
	Health     string `json:"health"`
	CapPercent int    `json:"cap_percent"`
	FragPct    int    `json:"frag_pct"`
}

// LVMThinPool is a live LVM thin pool.
type LVMThinPool struct {
	VG        string  `json:"vg"`
	Name      string  `json:"name"`
	SizeBytes int64   `json:"size_bytes"`
	DataPct   float64 `json:"data_pct"`
	MetaPct   float64 `json:"meta_pct"`
}

// MDArray is a software-RAID (mdraid) array.
type MDArray struct {
	Name      string   `json:"name"`
	Dev       string   `json:"dev"`
	Level     string   `json:"level"`
	State     string   `json:"state"`
	SizeBytes int64    `json:"size_bytes"`
	Members   []string `json:"members"`
	Degraded  bool     `json:"degraded"`
	Sync      string   `json:"sync"`
	SizeH     string   `json:"size_h"`
	InUse     bool     `json:"in_use"`
	UseNote   string   `json:"use_note"`
}

// Pools lists the registered storage pools.
func (c *Client) Pools() ([]Pool, error) {
	var out []Pool
	if err := c.getJSON("/api/v1/pools", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertPool registers (or updates) a pool pointing at an existing backend.
func (c *Client) UpsertPool(name, kind, path string) error {
	return c.apiPostJSON("/api/v1/pools", map[string]any{"name": name, "kind": kind, "path": path})
}

// DeletePool removes a pool registry row by its numeric id.
func (c *Client) DeletePool(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/pools/%d/delete", id), nil)
}

// BrowsePool returns a read-only listing of a pool's contents.
func (c *Client) BrowsePool(id int64) (PoolBrowse, error) {
	var out PoolBrowse
	err := c.getJSON(fmt.Sprintf("/api/v1/pools/%d/browse", id), &out)
	return out, err
}

// SharedMounts lists NFS/CIFS/Ceph mounts (admin only server-side).
func (c *Client) SharedMounts() ([]SharedMount, error) {
	var out []SharedMount
	if err := c.getJSON("/api/v1/shared", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// AddNFS mounts an NFS export over the storage NIC and registers it as a pool.
func (c *Client) AddNFS(name, server, export, vers, options string) error {
	return c.apiPostJSON("/api/v1/shared/nfs", map[string]any{
		"name": name, "server": server, "export": export, "vers": vers, "options": options,
	})
}

// AddCIFS mounts an SMB/CIFS share (unc is //host/share).
func (c *Client) AddCIFS(name, unc, username, password, domain, vers, options string) error {
	return c.apiPostJSON("/api/v1/shared/cifs", map[string]any{
		"name": name, "unc": unc, "username": username, "password": password,
		"domain": domain, "vers": vers, "options": options,
	})
}

// AddCeph mounts CephFS over the storage NIC.
func (c *Client) AddCeph(name, mons, path, cephName, secret, options string) error {
	return c.apiPostJSON("/api/v1/shared/ceph", map[string]any{
		"name": name, "mons": mons, "path": path, "ceph_name": cephName,
		"secret": secret, "options": options,
	})
}

// UnmountShared unmounts a shared mount by id and removes its pool registration.
func (c *Client) UnmountShared(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/shared/%d/unmount", id), nil)
}

// CephStatus returns the on-node Ceph cluster snapshot.
func (c *Client) CephStatus() (CephHealth, error) {
	var out CephHealth
	err := c.getJSON("/api/v1/ceph", &out)
	return out, err
}

// ZFSPools lists live zpools (admin only server-side).
func (c *Client) ZFSPools() ([]ZFSPool, error) {
	var out []ZFSPool
	if err := c.getJSON("/api/v1/zfs/pools", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// LVMThinPools lists live LVM thin pools (admin only server-side).
func (c *Client) LVMThinPools() ([]LVMThinPool, error) {
	var out []LVMThinPool
	if err := c.getJSON("/api/v1/lvm/pools", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MDArrays lists software-RAID arrays (admin only server-side).
func (c *Client) MDArrays() ([]MDArray, error) {
	var out []MDArray
	if err := c.getJSON("/api/v1/mdraid", &out); err != nil {
		return nil, err
	}
	return out, nil
}
