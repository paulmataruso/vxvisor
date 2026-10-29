package session

import (
	"errors"
	"testing"
)

// isGone decides whether a failed delete may still drop the row. A missing tool,
// a permission problem or an unreachable Ceph cluster must never count as
// "the snapshot is already gone" (that would orphan a real snapshot).
func TestIsGone(t *testing.T) {
	for msg, want := range map[string]bool{
		"cannot open 'tank/vdx-1@snap-1': dataset does not exist":                      true,
		"could not find any snapshots to destroy; check snapshot names.":               true,
		`Failed to find logical volume "VG0/vdx-1-snap-1"`:                             true,
		"rbd: failed to remove snapshot: (2) No such file or directory":                true,
		"qemu-img: Could not delete snapshot 'snap-1': snapshot not found":             true,
		"Snapshot with name 'snap-1' and id '' does not exist in device 'disk0'":       true,
		`exec: "qemu-img": executable file not found in $PATH`:                         false,
		"auth: unable to find a keyring on /etc/ceph/x: (2) No such file or directory": false,
		"did not load config file, using default settings: No such file":               false,
		"rbd: couldn't connect to the cluster!":                                        false,
		"lvremove: permission denied":                                                  false,
		"zfs destroy: timed out":                                                       false,
		"cannot destroy 'tank/vdx-1@snap-1': snapshot has dependent clones":            false,
	} {
		if got := isGone(errors.New(msg)); got != want {
			t.Errorf("isGone(%q) = %v, want %v", msg, got, want)
		}
	}
}
