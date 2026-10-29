package lvm

import (
	"fmt"
	"strings"
	"time"
)

// Thin snapshots and instant clones of the thin LVs that back VM disks
// (docs/SNAPSHOTS.md). A thin snapshot is a metadata-only operation inside the
// thin pool: instant, space-sharing, and — unlike a classic COW snapshot —
// INDEPENDENT of its origin (either can be removed without touching the other).
// Every call names one VG/LV explicitly; nothing here globs.

// runCmd is the command runner the snapshot calls use (a var so tests can record
// the exact argv without an LVM host).
var runCmd = run

// snapName is validName plus a leading letter or digit, so a VG/LV name can never
// be read as an option ("-f") by lvcreate / lvrename / lvremove.
func snapName(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	if c := name[0]; !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
		return fmt.Errorf("invalid name %q", name)
	}
	return nil
}

func vgLV(vg, lv string) (string, error) {
	if err := snapName(vg); err != nil {
		return "", err
	}
	if err := snapName(lv); err != nil {
		return "", err
	}
	return vg + "/" + lv, nil
}

// ThinSnapshot creates name as a thin snapshot of vg/origin. LVM sets the
// activation-skip flag on thin snapshots, so it stays inactive (no /dev node, no
// accidental mounts) until a clone or revert reads it. Safe on an origin a running
// VM has open: lvcreate suspends/resumes the dm device around the metadata update.
func ThinSnapshot(vg, origin, name string) error {
	src, err := vgLV(vg, origin)
	if err != nil {
		return err
	}
	if err := snapName(name); err != nil {
		return err
	}
	_, err = runCmd(60*time.Second, "lvcreate", "-s", "-n", name, src)
	return err
}

// ThinCopy creates name as a writable thin snapshot of vg/src and activates it
// (-kn clears the activation-skip flag): the new LV is an instant, independent
// copy of src's contents. Used for instant clones and for the revert swap.
func ThinCopy(vg, src, name string) error {
	from, err := vgLV(vg, src)
	if err != nil {
		return err
	}
	if err := snapName(name); err != nil {
		return err
	}
	if _, err := runCmd(60*time.Second, "lvcreate", "-s", "-kn", "-ay", "-n", name, from); err != nil {
		return err
	}
	_, _ = runCmd(30*time.Second, "udevadm", "settle")
	return nil
}

// RenameLV renames vg/from to vg/to.
func RenameLV(vg, from, to string) error {
	if _, err := vgLV(vg, from); err != nil {
		return err
	}
	if err := snapName(to); err != nil {
		return err
	}
	_, err := runCmd(30*time.Second, "lvrename", vg, from, to)
	return err
}

// RemoveNamed removes exactly vg/name.
func RemoveNamed(vg, name string) error {
	lv, err := vgLV(vg, name)
	if err != nil {
		return err
	}
	_, err = runCmd(60*time.Second, "lvremove", "-f", lv)
	return err
}

// RevertThin makes vg/lv's contents equal to its thin snapshot vg/snap, keeping
// the snapshot (and every other snapshot) intact and the disk's /dev/<vg>/<lv>
// path unchanged. lvconvert --merge would CONSUME the snapshot and, on an active
// origin, only merge on the next activation, so instead:
//
//  1. ThinCopy snap → <lv>-rv<sfx>  (a fresh thin LV holding the snapshot's data)
//  2. rename lv → <lv>-pre<sfx>      (the current contents, kept aside)
//  3. rename <lv>-rv<sfx> → lv       (the reverted disk takes the VM's path)
//  4. remove <lv>-pre<sfx>
//
// A failure at 1–3 undoes the earlier steps, so the VM always has a disk at its
// path. The VM must be stopped (the caller checks). Only step 4 discards data —
// the pre-revert state, which is what a revert means.
func RevertThin(vg, lv, snap, sfx string) error {
	if _, err := vgLV(vg, lv); err != nil {
		return err
	}
	if _, err := vgLV(vg, snap); err != nil {
		return err
	}
	tmp, aside := lv+"-rv"+sfx, lv+"-pre"+sfx
	if err := ThinCopy(vg, snap, tmp); err != nil {
		return fmt.Errorf("copy snapshot: %w", err)
	}
	if err := RenameLV(vg, lv, aside); err != nil {
		_ = RemoveNamed(vg, tmp)
		return fmt.Errorf("set current disk aside: %w", err)
	}
	if err := RenameLV(vg, tmp, lv); err != nil {
		if rerr := RenameLV(vg, aside, lv); rerr != nil {
			return fmt.Errorf("revert failed (%v) AND restoring %s/%s failed (%v): the original disk is %s/%s", err, vg, lv, rerr, vg, aside)
		}
		_ = RemoveNamed(vg, tmp)
		return fmt.Errorf("swap in reverted disk: %w", err)
	}
	_, _ = runCmd(30*time.Second, "udevadm", "settle")
	if err := RemoveNamed(vg, aside); err != nil {
		return fmt.Errorf("reverted, but removing the pre-revert disk %s/%s failed: %w", vg, aside, err)
	}
	return nil
}

// LVExists reports whether vg/name exists.
func LVExists(vg, name string) bool {
	lv, err := vgLV(vg, name)
	if err != nil {
		return false
	}
	out, err := runCmd(10*time.Second, "lvs", "--noheadings", "-o", "lv_name", lv)
	return err == nil && strings.TrimSpace(out) == name
}

// SplitDevPath splits a thin LV device path /dev/<vg>/<lv> into vg and lv.
func SplitDevPath(dev string) (vg, lv string, ok bool) {
	rest, found := strings.CutPrefix(dev, "/dev/")
	if !found {
		return "", "", false
	}
	vg, lv, found = strings.Cut(rest, "/")
	if !found || vg == "" || lv == "" || strings.Contains(lv, "/") {
		return "", "", false
	}
	return vg, lv, true
}
