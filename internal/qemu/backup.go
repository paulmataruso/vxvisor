package qemu

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Backup primitives: persistent dirty bitmaps (the checkpoints incremental
// backup is built on) and the QMP calls a pull-mode backup needs — a fleecing
// node held by a sync=none blockdev-backup job, exported read-only over QEMU's
// built-in NBD server. This is the same sequence libvirt uses for a pull-mode
// <domainbackup>; internal/vmbackup drives it.

// BitmapInfo is one dirty bitmap on a running VM's disk (query-block).
type BitmapInfo struct {
	Name         string `json:"name"`
	Recording    bool   `json:"recording"`
	Persistent   bool   `json:"persistent"`
	Busy         bool   `json:"busy"`
	Inconsistent bool   `json:"inconsistent"`
	Granularity  int64  `json:"granularity"`
	Count        int64  `json:"count"`
}

// DiskNode is what query-block reports for one drive: its top (format) node,
// the image's virtual size and format, and the dirty bitmaps on that node.
type DiskNode struct {
	NodeName    string
	VirtualSize int64
	Format      string
	Bitmaps     []BitmapInfo
}

// QueryDisk returns the format node, size and bitmaps of a -drive id.
func (q *QMP) QueryDisk(device string) (DiskNode, error) {
	res, err := q.Execute("query-block", nil)
	if err != nil {
		return DiskNode{}, err
	}
	var devs []struct {
		Device   string `json:"device"`
		Inserted *struct {
			NodeName string       `json:"node-name"`
			Drv      string       `json:"drv"`
			Bitmaps  []BitmapInfo `json:"dirty-bitmaps"`
			Image    struct {
				VirtualSize int64  `json:"virtual-size"`
				Format      string `json:"format"`
			} `json:"image"`
		} `json:"inserted"`
	}
	if err := json.Unmarshal(res, &devs); err != nil {
		return DiskNode{}, err
	}
	for _, d := range devs {
		if d.Device == device && d.Inserted != nil {
			f := d.Inserted.Image.Format
			if f == "" {
				f = d.Inserted.Drv
			}
			return DiskNode{NodeName: d.Inserted.NodeName, VirtualSize: d.Inserted.Image.VirtualSize,
				Format: f, Bitmaps: d.Inserted.Bitmaps}, nil
		}
	}
	return DiskNode{}, fmt.Errorf("no disk inserted for device %q", device)
}

// Transaction runs several QMP actions atomically: either all take effect at
// the same instant or none do. Each action is {"type": ..., "data": {...}}.
func (q *QMP) Transaction(actions ...map[string]any) error {
	_, err := q.Execute("transaction", map[string]any{"actions": actions})
	return err
}

// TxAction builds one transaction action.
func TxAction(typ string, data map[string]any) map[string]any {
	return map[string]any{"type": typ, "data": data}
}

// BlockdevAdd adds a block node graph (blockdev-add options).
func (q *QMP) BlockdevAdd(opts map[string]any) error {
	_, err := q.Execute("blockdev-add", opts)
	return err
}

// BlockdevDel removes a node added with BlockdevAdd.
func (q *QMP) BlockdevDel(node string) error {
	_, err := q.Execute("blockdev-del", map[string]any{"node-name": node})
	return err
}

// NBDServerStartUnix starts QEMU's built-in NBD server on a unix socket. A
// unix socket keeps the export off the network entirely; vdxd relays it.
func (q *QMP) NBDServerStartUnix(path string) error {
	_, err := q.Execute("nbd-server-start", map[string]any{
		"addr": map[string]any{"type": "unix", "data": map[string]any{"path": path}},
	})
	return err
}

// BlockExportAddReadOnly exports node over NBD read-only as name, optionally
// with dirty bitmaps (reachable from node) as qemu:dirty-bitmap:<name> meta
// contexts.
func (q *QMP) BlockExportAddReadOnly(id, node, name string, bitmaps []string) error {
	args := map[string]any{
		"type":      "nbd",
		"id":        id,
		"node-name": node,
		"name":      name,
		"writable":  false,
	}
	if len(bitmaps) > 0 {
		args["bitmaps"] = bitmaps
	}
	_, err := q.Execute("block-export-add", args)
	return err
}

// BlockExportDelHard removes an export, disconnecting any clients.
func (q *QMP) BlockExportDelHard(id string) error {
	_, err := q.Execute("block-export-del", map[string]any{"id": id, "mode": "hard"})
	return err
}

// BlockExportIDs lists the ids of the current block exports.
func (q *QMP) BlockExportIDs() ([]string, error) {
	res, err := q.Execute("query-block-exports", nil)
	if err != nil {
		return nil, err
	}
	var ex []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(res, &ex)
	out := make([]string, 0, len(ex))
	for _, e := range ex {
		out = append(out, e.ID)
	}
	return out, nil
}

// BlockJobIDs lists the ids (device field) of the current block jobs.
func (q *QMP) BlockJobIDs() ([]string, error) {
	jobs, err := q.BlockJobs()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Device)
	}
	return out, nil
}

// BlockJobCancelForce cancels a job by id (a sync=none backup job only ever
// ends this way).
func (q *QMP) BlockJobCancelForce(id string) error {
	_, err := q.Execute("block-job-cancel", map[string]any{"device": id, "force": true})
	return err
}

// NodeNames lists every named block node (query-named-block-nodes, flat).
func (q *QMP) NodeNames() ([]string, error) {
	res, err := q.Execute("query-named-block-nodes", map[string]any{"flat": true})
	if err != nil {
		return nil, err
	}
	var nodes []struct {
		NodeName string `json:"node-name"`
	}
	_ = json.Unmarshal(res, &nodes)
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.NodeName)
	}
	return out, nil
}

// BitmapRemove deletes a dirty bitmap (from the image too when persistent).
func (q *QMP) BitmapRemove(node, name string) error {
	_, err := q.Execute("block-dirty-bitmap-remove", map[string]any{"node": node, "name": name})
	return err
}

// HMP runs one human-monitor command and returns its text output. Used by the
// host tests to drive guest-less writes (qemu-io) through the block layer.
func (q *QMP) HMP(line string) (string, error) {
	res, err := q.Execute("human-monitor-command", map[string]any{"command-line": line})
	if err != nil {
		return "", err
	}
	var out string
	_ = json.Unmarshal(res, &out)
	return out, nil
}

// ---- offline (stopped VM) bitmap management via qemu-img -----------------

// ImageBitmap is one persistent bitmap stored in a qcow2 (qemu-img info).
// Flags holds "auto" (enabled/recording) and/or "in-use" — a bitmap still
// marked in-use while no QEMU has the image open was not saved cleanly (QEMU
// was killed) and is inconsistent: it can no longer be trusted.
type ImageBitmap struct {
	Name        string   `json:"name"`
	Flags       []string `json:"flags"`
	Granularity int64    `json:"granularity"`
}

// InUse reports whether the bitmap carries the in-use flag.
func (b ImageBitmap) InUse() bool {
	for _, f := range b.Flags {
		if f == "in-use" {
			return true
		}
	}
	return false
}

// ImageDetails is the subset of `qemu-img info` the backup path needs.
type ImageDetails struct {
	Format      string
	VirtualSize int64
	Compat      string // qcow2 "1.1" (v3: persistent bitmaps OK) or "0.10"
	Bitmaps     []ImageBitmap
}

// ImageInfo reads an image's format, size, qcow2 compat level and persistent
// bitmaps. -U (force-share) lets it read an image a running VM holds open.
func ImageInfo(path string) (ImageDetails, error) {
	out, err := exec.Command("qemu-img", "info", "-U", "--output=json", path).Output()
	if err != nil {
		return ImageDetails{}, fmt.Errorf("qemu-img info %s: %w", path, err)
	}
	return parseImageInfo(out)
}

func parseImageInfo(out []byte) (ImageDetails, error) {
	var info struct {
		Format         string `json:"format"`
		VirtualSize    int64  `json:"virtual-size"`
		FormatSpecific struct {
			Type string `json:"type"`
			Data struct {
				Compat  string        `json:"compat"`
				Bitmaps []ImageBitmap `json:"bitmaps"`
			} `json:"data"`
		} `json:"format-specific"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return ImageDetails{}, err
	}
	return ImageDetails{Format: info.Format, VirtualSize: info.VirtualSize,
		Compat: info.FormatSpecific.Data.Compat, Bitmaps: info.FormatSpecific.Data.Bitmaps}, nil
}

// BitmapAddOffline adds a persistent, enabled dirty bitmap to a qcow2 that no
// QEMU has open. Fails (image lock) if a VM is using the disk.
func BitmapAddOffline(path, name string) error {
	return imgBitmap(path, "--add", name)
}

// BitmapRemoveOffline removes a persistent bitmap from a qcow2 that no QEMU has
// open.
func BitmapRemoveOffline(path, name string) error {
	return imgBitmap(path, "--remove", name)
}

func imgBitmap(path, op, name string) error {
	if strings.HasPrefix(name, "-") || name == "" {
		return fmt.Errorf("invalid bitmap name %q", name)
	}
	cmd := exec.Command("qemu-img", "bitmap", op, "-f", "qcow2", path, name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qemu-img bitmap %s %s: %v: %s", op, name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
