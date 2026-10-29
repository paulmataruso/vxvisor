package zfs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Snapshots and instant clones of the zvols that back VM disks (docs/SNAPSHOTS.md).
// Every call names one dataset/snapshot explicitly — nothing here recurses into
// datasets the caller didn't name, and no -r/-R flag that could reach clones is
// ever passed. The session layer decides WHICH snapshots are VXVisor's own.

// runCmd is the command runner the snapshot calls use, and devExists probes for
// a zvol's device node (vars so tests can record the exact argv without a ZFS host).
var (
	runCmd    = run
	devExists = func(p string) bool { _, err := os.Stat(p); return err == nil }
)

// validSnapTag guards the part after '@'. It flows into shell args, so keep it to
// the same strict charset as dataset names.
func validSnapTag(tag string) error {
	if tag == "" {
		return errors.New("snapshot tag required")
	}
	if err := validName(tag); err != nil {
		return fmt.Errorf("invalid snapshot tag %q", tag)
	}
	return nil
}

func snapName(dataset, tag string) (string, error) {
	if err := validDatasetName(dataset); err != nil {
		return "", err
	}
	if err := validSnapTag(tag); err != nil {
		return "", err
	}
	return dataset + "@" + tag, nil
}

// Snapshot takes an atomic, instant snapshot dataset@tag.
func Snapshot(dataset, tag string) error {
	sn, err := snapName(dataset, tag)
	if err != nil {
		return err
	}
	_, err = runCmd(30*time.Second, "zfs", "snapshot", sn)
	return err
}

// Rollback reverts dataset to dataset@tag. No -r: ZFS refuses when newer
// snapshots exist, so the caller must have removed them (its own, unlocked,
// clone-free ones) explicitly first — a rollback can never silently destroy a
// snapshot or a clone.
func Rollback(dataset, tag string) error {
	sn, err := snapName(dataset, tag)
	if err != nil {
		return err
	}
	_, err = runCmd(60*time.Second, "zfs", "rollback", sn)
	return err
}

// DestroySnapshot destroys exactly dataset@tag. ZFS refuses while clones depend
// on it (no -R is ever passed).
func DestroySnapshot(dataset, tag string) error {
	sn, err := snapName(dataset, tag)
	if err != nil {
		return err
	}
	_, err = runCmd(60*time.Second, "zfs", "destroy", sn)
	return err
}

// Clone creates target as an instant, space-sharing clone of dataset@tag and, for
// a zvol, waits for its /dev/zvol node (udev creates it after zfs returns).
func Clone(dataset, tag, target string) error {
	sn, err := snapName(dataset, tag)
	if err != nil {
		return err
	}
	if err := validDatasetName(target); err != nil {
		return err
	}
	if _, err := runCmd(60*time.Second, "zfs", "clone", sn, target); err != nil {
		return err
	}
	return waitZvol(target)
}

// Promote reverses a clone's dependency: target takes ownership of its origin
// snapshot (and every older one), and the former origin becomes the clone. Used
// before purging an origin so its dependent clones survive.
func Promote(dataset string) error {
	if err := validDatasetName(dataset); err != nil {
		return err
	}
	_, err := runCmd(60*time.Second, "zfs", "promote", dataset)
	return err
}

// ListSnapshotTags returns the tags of dataset's own snapshots (depth 1), oldest
// first by creation transaction group.
func ListSnapshotTags(dataset string) ([]string, error) {
	if err := validDatasetName(dataset); err != nil {
		return nil, err
	}
	out, err := runCmd(30*time.Second, "zfs", "list", "-H", "-t", "snapshot", "-d", "1",
		"-s", "createtxg", "-o", "name", dataset)
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if _, tag, ok := strings.Cut(strings.TrimSpace(ln), "@"); ok && tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags, nil
}

// SnapshotClones lists the datasets cloned from dataset@tag.
func SnapshotClones(dataset, tag string) ([]string, error) {
	sn, err := snapName(dataset, tag)
	if err != nil {
		return nil, err
	}
	out, err := runCmd(30*time.Second, "zfs", "get", "-H", "-o", "value", "clones", sn)
	if err != nil {
		return nil, err
	}
	v := strings.TrimSpace(out)
	if v == "" || v == "-" {
		return nil, nil
	}
	return strings.Split(v, ","), nil
}

// waitZvol waits for udev to publish /dev/zvol/<name> after a create/clone.
func waitZvol(name string) error {
	_, _ = runCmd(10*time.Second, "udevadm", "settle")
	dev := "/dev/zvol/" + name
	for i := 0; i < 50; i++ {
		if devExists(dev) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("zvol device %s did not appear", dev)
}
