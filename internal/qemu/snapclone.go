package qemu

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// qcow2 snapshot helpers beyond the offline create/apply/delete in qemu.go: the
// live (QMP, disk-only) internal snapshot, and turning an internal snapshot into
// an independent new qcow2 for an instant clone (docs/SNAPSHOTS.md).

// DiskDevice is the -drive id every VM's disk is launched with (see Spec.Args);
// the QMP block commands address the disk by it.
const DiskDevice = "disk0"

// runTool runs one host tool and returns its combined output (a var so tests
// can record the exact argv without qemu-img on the box).
var runTool = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func tool(name string, args ...string) (string, error) {
	out, err := runTool(name, args...)
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// QMPInternalSnapshot takes a disk-only internal qcow2 snapshot of a RUNNING VM
// (blockdev-snapshot-internal-sync): instant, no RAM dump, no pause. Unlike HMP
// savevm it only touches the disk, so it also works on UEFI VMs whose raw pflash
// NVRAM can't hold a snapshot.
func QMPInternalSnapshot(socket, device, name string) error {
	q, err := DialQMP(socket)
	if err != nil {
		return err
	}
	defer q.Close()
	_, err = q.Execute("blockdev-snapshot-internal-sync", map[string]any{"device": device, "name": name})
	return err
}

// QMPDeleteInternalSnapshot removes an internal snapshot from a running VM's disk
// (works for savevm-made snapshots too). Falls back to HMP delvm, which older
// rows were deleted with.
func QMPDeleteInternalSnapshot(socket, device, name string) error {
	q, err := DialQMP(socket)
	if err != nil {
		return err
	}
	defer q.Close()
	if _, err := q.Execute("blockdev-snapshot-delete-internal-sync", map[string]any{"device": device, "name": name}); err != nil {
		if _, herr := q.hmp("delvm " + name); herr != nil {
			return err
		}
	}
	return nil
}

type imgInfo struct {
	BackingFilename     string `json:"backing-filename"`
	FullBackingFilename string `json:"full-backing-filename"`
	BackingFormat       string `json:"backing-filename-format"`
	Snapshots           []struct {
		Name string `json:"name"`
	} `json:"snapshots"`
}

// imageInfo reads qemu-img info for path. -U (force-share) so it works on an
// image a running VM has open.
func imageInfo(path string) (imgInfo, error) {
	var in imgInfo
	out, err := tool("qemu-img", "info", "-U", "--output=json", path)
	if err != nil {
		return in, err
	}
	if err := json.Unmarshal([]byte(out), &in); err != nil {
		return in, fmt.Errorf("parse qemu-img info: %w", err)
	}
	return in, nil
}

// InternalSnapshots lists the names of a qcow2's internal snapshots.
func InternalSnapshots(path string) ([]string, error) {
	in, err := imageInfo(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, s := range in.Snapshots {
		names = append(names, s.Name)
	}
	return names, nil
}

// Clone methods recorded on the clone link.
const (
	CloneReflink = "reflink" // FICLONE copy of the file + apply the snapshot (instant)
	CloneConvert = "convert" // qemu-img convert of the snapshot's own data over the same base
)

// CloneSnapshot writes dst as an INDEPENDENT qcow2 holding src's internal
// snapshot tag, backed by the same read-only base image src is (if any). src is
// only ever read — it may belong to a running VM.
//
// Fast path (reflink-capable FS: XFS reflink=1, btrfs, OpenZFS ≥2.2 block
// cloning): cp --reflink=always shares every extent, then the copy is reverted
// to tag and stripped of the origin's snapshot list — O(metadata), instant.
// Fallback (ext4 etc.): qemu-img convert -l snapshot.name=tag -B <base> copies
// only the clusters the VM itself wrote (unallocated clusters fall through to
// the shared base), so the cost is the VM's own delta, never the whole disk.
// Both produce a file with no tie to src: purging the origin can't break it.
//
// live means a running VM has src open. The reflink path is then skipped: it
// copies the WHOLE file, including refcount/L2 metadata QEMU may be updating
// mid-copy, and reverting such a torn copy could corrupt it. The convert path is
// safe live: it reads only the snapshot's table, L1/L2 and data clusters, which
// QEMU flushed when it took the snapshot and never rewrites in place while the
// snapshot holds a reference to them (copy-on-write).
func CloneSnapshot(src, tag, dst string, live bool) (method string, err error) {
	if _, err := os.Stat(dst); err == nil {
		return "", fmt.Errorf("clone target %s already exists", dst)
	}
	in, err := imageInfo(src)
	if err != nil {
		return "", err
	}
	if !live {
		if err := reflinkClone(src, tag, dst); err == nil {
			return CloneReflink, nil
		}
		_ = os.Remove(dst)
	}
	args := []string{"convert", "-U", "-l", "snapshot.name=" + tag, "-O", "qcow2"}
	if base := in.FullBackingFilename; base != "" {
		fmtB := in.BackingFormat
		if fmtB == "" {
			fmtB = "qcow2"
		}
		args = append(args, "-B", base, "-F", fmtB)
	}
	args = append(args, src, dst)
	if _, err := tool("qemu-img", args...); err != nil {
		_ = os.Remove(dst)
		return "", err
	}
	return CloneConvert, nil
}

// reflinkClone is CloneSnapshot's fast path; any failure (notably "operation not
// supported" on a filesystem without reflink) sends the caller to the fallback.
func reflinkClone(src, tag, dst string) error {
	if _, err := tool("cp", "--reflink=always", "--", src, dst); err != nil {
		return err
	}
	if _, err := tool("qemu-img", "snapshot", "-a", tag, dst); err != nil {
		return err
	}
	names, err := InternalSnapshots(dst)
	if err != nil {
		return err
	}
	for _, n := range names { // the clone starts with no snapshot history
		if _, err := tool("qemu-img", "snapshot", "-d", n, dst); err != nil {
			return err
		}
	}
	// The copy was read from a live file: reclaim any leaked clusters (harmless,
	// but they'd waste space). check exits non-zero for leaks it just fixed.
	_, _ = tool("qemu-img", "check", "-r", "leaks", dst)
	return nil
}
