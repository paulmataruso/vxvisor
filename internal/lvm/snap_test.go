package lvm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fakeLVM(t *testing.T, fail func(cmd string) bool) *[]string {
	t.Helper()
	var calls []string
	old := runCmd
	runCmd = func(_ time.Duration, name string, args ...string) (string, error) {
		c := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, c)
		if fail != nil && fail(c) {
			return "", errors.New("boom: " + c)
		}
		return "", nil
	}
	t.Cleanup(func() { runCmd = old })
	return &calls
}

func TestThinSnapshotCommands(t *testing.T) {
	calls := fakeLVM(t, nil)
	if err := ThinSnapshot("VG0", "vdx-1234abcd", "vdx-1234abcd-snap-01"); err != nil {
		t.Fatal(err)
	}
	if err := ThinCopy("VG0", "vdx-1234abcd-snap-01", "vdx-5678ef01"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveNamed("VG0", "vdx-1234abcd-snap-01"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"lvcreate -s -n vdx-1234abcd-snap-01 VG0/vdx-1234abcd",
		"lvcreate -s -kn -ay -n vdx-5678ef01 VG0/vdx-1234abcd-snap-01",
		"udevadm settle",
		"lvremove -f VG0/vdx-1234abcd-snap-01",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
}

func TestRevertThinSwap(t *testing.T) {
	calls := fakeLVM(t, nil)
	if err := RevertThin("VG0", "vdx-1", "vdx-1-snap-a", "x1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"lvcreate -s -kn -ay -n vdx-1-rvx1 VG0/vdx-1-snap-a",
		"udevadm settle",
		"lvrename VG0 vdx-1 vdx-1-prex1",
		"lvrename VG0 vdx-1-rvx1 vdx-1",
		"udevadm settle",
		"lvremove -f VG0/vdx-1-prex1",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
	// The snapshot itself is never removed or renamed by a revert.
	for _, c := range *calls {
		if strings.HasSuffix(c, "vdx-1-snap-a") && !strings.HasPrefix(c, "lvcreate") {
			t.Fatalf("revert touched the snapshot: %q", c)
		}
	}
}

func TestRevertThinRestoresOnFailure(t *testing.T) {
	// The swap-in rename fails: the original disk must be renamed back and the
	// temporary copy removed.
	calls := fakeLVM(t, func(c string) bool { return c == "lvrename VG0 vdx-1-rvx1 vdx-1" })
	if err := RevertThin("VG0", "vdx-1", "vdx-1-snap-a", "x1"); err == nil {
		t.Fatal("expected an error")
	}
	want := []string{
		"lvcreate -s -kn -ay -n vdx-1-rvx1 VG0/vdx-1-snap-a",
		"udevadm settle",
		"lvrename VG0 vdx-1 vdx-1-prex1",
		"lvrename VG0 vdx-1-rvx1 vdx-1",
		"lvrename VG0 vdx-1-prex1 vdx-1",
		"lvremove -f VG0/vdx-1-rvx1",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
	// The copy step fails: nothing else runs.
	calls = fakeLVM(t, func(c string) bool { return strings.HasPrefix(c, "lvcreate") })
	if err := RevertThin("VG0", "vdx-1", "vdx-1-snap-a", "x1"); err == nil {
		t.Fatal("expected an error")
	}
	if len(*calls) != 1 {
		t.Fatalf("ran more than the failed copy: %q", *calls)
	}
}

func TestSnapNamesRejected(t *testing.T) {
	calls := fakeLVM(t, nil)
	for _, n := range []string{"", "-f", "a b", "a/b", "..", "x;y"} {
		if ThinSnapshot("VG0", "vdx-1", n) == nil || ThinSnapshot(n, "vdx-1", "s") == nil ||
			RemoveNamed("VG0", n) == nil || RevertThin("VG0", "vdx-1", n, "x") == nil {
			t.Errorf("accepted %q", n)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("ran commands for invalid input: %q", *calls)
	}
}

func TestSplitDevPath(t *testing.T) {
	for in, want := range map[string][2]string{
		"/dev/VG0/vdx-1": {"VG0", "vdx-1"},
		"/dev/VG0":       {"", ""},
		"/dev/a/b/c":     {"", ""},
		"VG0/vdx-1":      {"", ""},
	} {
		vg, lv, ok := SplitDevPath(in)
		if (want[0] != "") != ok || vg != want[0] || lv != want[1] {
			t.Errorf("SplitDevPath(%q) = %q %q %v", in, vg, lv, ok)
		}
	}
}
