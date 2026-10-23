// Package blkfs puts a plain filesystem on a block device and mounts it — the
// backend for an ext3/ext4/xfs "filesystem pool" (e.g. on top of an md array).
// Admin-gated by the caller; it only ever writes to the device it is told to.
package blkfs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

var validFS = map[string]bool{"ext3": true, "ext4": true, "xfs": true}

// FSTypes are the filesystems offered in the UI.
var FSTypes = []string{"ext4", "xfs", "ext3"}

func run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Mkfs makes a fresh ext3/ext4/xfs filesystem on dev (destroys its contents).
func Mkfs(fstype, dev string) error {
	if !validFS[fstype] {
		return fmt.Errorf("unsupported filesystem %q (ext3, ext4 or xfs)", fstype)
	}
	if !strings.HasPrefix(dev, "/dev/") {
		return fmt.Errorf("invalid device %q", dev)
	}
	args := []string{"-F", dev} // ext3/ext4: force
	if fstype == "xfs" {
		args = []string{"-f", dev} // xfs: force overwrite
	}
	if out, err := run(600*time.Second, "mkfs."+fstype, args...); err != nil {
		return fmt.Errorf("mkfs.%s: %v: %s", fstype, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UUID returns the filesystem UUID of a device ("" if none).
func UUID(dev string) string {
	b, _ := run(10*time.Second, "blkid", "-s", "UUID", "-o", "value", dev)
	return strings.TrimSpace(string(b))
}

// Mount creates the mountpoint and mounts dev there.
func Mount(dev, mnt string) error {
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return fmt.Errorf("create mountpoint: %w", err)
	}
	if out, err := run(30*time.Second, "mount", dev, mnt); err != nil {
		return fmt.Errorf("mount %s %s: %v: %s", dev, mnt, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PersistFstab adds a by-UUID fstab entry (nofail) so the pool remounts at boot.
// Idempotent and non-fatal if the UUID/mountpoint is already present.
func PersistFstab(uuid, mnt, fstype string) error {
	if uuid == "" {
		return fmt.Errorf("device has no filesystem UUID")
	}
	b, _ := os.ReadFile("/etc/fstab")
	if strings.Contains(string(b), "UUID="+uuid) || strings.Contains(string(b), " "+mnt+" ") {
		return nil
	}
	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("UUID=%s %s %s defaults,nofail 0 2\n", uuid, mnt, fstype))
	return err
}
