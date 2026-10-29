package lvm

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveThinSnapshots exercises the real lvcreate/lvrename/lvremove path on a
// host. Opt-in only: VDX_LIVE_LVM=<vg>/<thinpool>. It creates ONLY scratch LVs
// named vdxtest-<random>-* in that thin pool and removes every one of them.
//
//	CGO_ENABLED=0 go test -c -o /tmp/lvm.test ./internal/lvm
//	sudo VDX_LIVE_LVM=VG/thinpool /tmp/lvm.test -test.run Live -test.v
func TestLiveThinSnapshots(t *testing.T) {
	spec := os.Getenv("VDX_LIVE_LVM")
	if spec == "" {
		t.Skip("set VDX_LIVE_LVM=<vg>/<thinpool> to run against a real thin pool")
	}
	vg, pool, ok := strings.Cut(spec, "/")
	if !ok {
		t.Fatal("VDX_LIVE_LVM must be <vg>/<thinpool>")
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	pfx := "vdxtest-" + hex.EncodeToString(b)
	disk, snapA, snapB, clone := pfx+"-disk", pfx+"-disk-snap-a", pfx+"-disk-snap-b", pfx+"-clone"

	// Remove exactly what we may have created, whatever happens.
	t.Cleanup(func() {
		for _, n := range []string{clone, snapB, snapA, disk, disk + "-rvx1", disk + "-prex1"} {
			if LVExists(vg, n) {
				if err := RemoveNamed(vg, n); err != nil {
					t.Errorf("cleanup %s: %v", n, err)
				}
			}
		}
		out, _ := run(10*time.Second, "lvs", "--noheadings", "-o", "lv_name", vg)
		if strings.Contains(out, pfx) {
			t.Errorf("left behind: %s", out)
		}
	})

	if err := CreateThinVolume(vg, pool, disk, 64<<20); err != nil {
		t.Fatal(err)
	}
	dev := func(n string) string { return "/dev/" + vg + "/" + n }
	_, _ = run(30*time.Second, "udevadm", "settle")
	write := func(n string, c byte) {
		t.Helper()
		f, err := os.OpenFile(dev(n), os.O_WRONLY|os.O_SYNC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteAt(bytes.Repeat([]byte{c}, 1<<20), 0); err != nil {
			t.Fatal(err)
		}
	}
	read := func(n string) byte {
		t.Helper()
		f, err := os.OpenFile(dev(n), os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		buf := make([]byte, 1<<20)
		if _, err := f.ReadAt(buf, 0); err != nil {
			t.Fatal(err)
		}
		for _, x := range buf {
			if x != buf[0] {
				t.Fatalf("%s: mixed content", n)
			}
		}
		return buf[0]
	}

	write(disk, 'A')
	if err := ThinSnapshot(vg, disk, snapA); err != nil {
		t.Fatal(err)
	}
	// A thin snapshot is created inactive with the activation-skip flag ('k').
	attr, _ := run(10*time.Second, "lvs", "--noheadings", "-o", "lv_attr", vg+"/"+snapA)
	t.Logf("snapshot lv_attr: %q", strings.TrimSpace(attr))
	if a := strings.TrimSpace(attr); len(a) < 10 || a[9] != 'k' {
		t.Errorf("snapshot not activation-skipped: %q", a)
	}
	write(disk, 'B')
	if err := ThinSnapshot(vg, disk, snapB); err != nil {
		t.Fatal(err)
	}
	write(disk, 'C')

	// Instant clone of snapshot A: holds A, independent of the origin.
	if err := ThinCopy(vg, snapA, clone); err != nil {
		t.Fatal(err)
	}
	if got := read(clone); got != 'A' {
		t.Fatalf("clone content %q, want A", got)
	}

	// Revert to A: disk reads A at the same path; BOTH snapshots survive.
	if err := RevertThin(vg, disk, snapA, "x1"); err != nil {
		t.Fatal(err)
	}
	if got := read(disk); got != 'A' {
		t.Fatalf("after revert to A: %q", got)
	}
	for _, n := range []string{snapA, snapB} {
		if !LVExists(vg, n) {
			t.Fatalf("revert removed snapshot %s", n)
		}
	}
	if LVExists(vg, disk+"-prex1") || LVExists(vg, disk+"-rvx1") {
		t.Fatal("revert left a temporary LV behind")
	}
	// Revert forward to B (a newer snapshot) also works: nothing was discarded.
	if err := RevertThin(vg, disk, snapB, "x1"); err != nil {
		t.Fatal(err)
	}
	if got := read(disk); got != 'B' {
		t.Fatalf("after revert to B: %q", got)
	}

	// Independence: writes to the clone don't touch the disk, and removing the
	// snapshot and then the origin leaves the clone intact.
	write(clone, 'Z')
	if got := read(disk); got != 'B' {
		t.Fatalf("clone write leaked into the disk: %q", got)
	}
	if err := RemoveNamed(vg, snapA); err != nil {
		t.Fatal(err)
	}
	if err := RemoveNamed(vg, disk); err != nil {
		t.Fatal(err)
	}
	if got := read(clone); got != 'Z' {
		t.Fatalf("clone after origin removal: %q", got)
	}
	// Strict names: nothing runs for an option-looking name.
	if err := ThinSnapshot(vg, clone, "-f"); err == nil {
		t.Fatal("accepted -f as an LV name")
	}
}
