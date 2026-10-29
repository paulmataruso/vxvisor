package ceph

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The RBD path is unit-tested only (no Ceph is touched by tests).
func fakeRBD(t *testing.T, answer func(cmd string) (string, error)) *[]string {
	t.Helper()
	var calls []string
	old := runCmd
	runCmd = func(_ time.Duration, name string, args ...string) (string, error) {
		c := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, c)
		if answer != nil {
			return answer(c)
		}
		return "", nil
	}
	t.Cleanup(func() { runCmd = old })
	return &calls
}

func TestRBDSnapshotCommands(t *testing.T) {
	calls := fakeRBD(t, nil)
	for _, err := range []error{
		SnapCreate("vms", "vdx-1234abcd", "snap-01"),
		SnapRollback("vms", "vdx-1234abcd", "snap-01"),
		Clone("vms", "vdx-1234abcd", "snap-01", "vdx-5678ef01"),
		Flatten("vms", "vdx-5678ef01"),
		SnapRemove("vms", "vdx-1234abcd", "snap-01"),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		"rbd snap create vms/vdx-1234abcd@snap-01",
		"rbd snap rollback --no-progress vms/vdx-1234abcd@snap-01",
		"rbd snap protect vms/vdx-1234abcd@snap-01",
		"rbd clone vms/vdx-1234abcd@snap-01 vms/vdx-5678ef01",
		"rbd flatten --no-progress vms/vdx-5678ef01",
		"rbd snap unprotect vms/vdx-1234abcd@snap-01",
		"rbd snap rm --no-progress vms/vdx-1234abcd@snap-01",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
	for _, c := range *calls {
		if strings.Contains(c, "purge") || strings.Contains(c, "--force") {
			t.Fatalf("unexpected destructive flag in %q", c)
		}
	}
}

func TestRBDProtectIdempotentAndUnprotectedRemove(t *testing.T) {
	calls := fakeRBD(t, func(c string) (string, error) {
		switch {
		case strings.HasPrefix(c, "rbd snap protect"):
			return "", errors.New("rbd: snap is already protected")
		case strings.HasPrefix(c, "rbd snap unprotect"):
			return "", errors.New("rbd: snap is already unprotected")
		}
		return "", nil
	})
	if err := Clone("vms", "img", "s1", "img2"); err != nil {
		t.Fatalf("already-protected should be fine: %v", err)
	}
	if err := SnapRemove("vms", "img", "s1"); err != nil {
		t.Fatalf("never-protected snapshot should still be removed: %v", err)
	}
	if got := (*calls)[len(*calls)-1]; got != "rbd snap rm --no-progress vms/img@s1" {
		t.Fatalf("last call %q", got)
	}
}

func TestRBDRemoveRefusedWithChildren(t *testing.T) {
	// Unprotect fails while clones exist: the snapshot must NOT be removed.
	calls := fakeRBD(t, func(c string) (string, error) {
		if strings.HasPrefix(c, "rbd snap unprotect") {
			return "", errors.New("rbd: unprotecting snap failed: (16) Device or resource busy")
		}
		return "", nil
	})
	if err := SnapRemove("vms", "img", "s1"); err == nil {
		t.Fatal("expected a refusal")
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "rbd snap rm") {
			t.Fatalf("removed a snapshot with children: %q", *calls)
		}
	}
}

func TestRBDChildrenAndNames(t *testing.T) {
	fakeRBD(t, func(c string) (string, error) {
		return `[{"pool":"vms","pool_namespace":"","image":"vdx-2"}]`, nil
	})
	kids, err := Children("vms", "vdx-1", "s1")
	if err != nil || !reflect.DeepEqual(kids, []string{"vms/vdx-2"}) {
		t.Fatalf("children = %v, %v", kids, err)
	}
	calls := fakeRBD(t, nil)
	for _, bad := range []string{"", "-p", "a b", "a/b", "a@b", ".."} {
		if SnapCreate("vms", bad, "s") == nil || SnapCreate(bad, "img", "s") == nil || SnapCreate("vms", "img", bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("ran commands for invalid input: %q", *calls)
	}
}
