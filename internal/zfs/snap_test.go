package zfs

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeZFS records every command and answers from a canned map (joined argv →
// output). Unknown commands succeed with no output.
func fakeZFS(t *testing.T, answers map[string]string, fail map[string]bool) *[]string {
	t.Helper()
	var calls []string
	oldRun, oldDev := runCmd, devExists
	runCmd = func(_ time.Duration, name string, args ...string) (string, error) {
		c := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, c)
		if fail[c] {
			return "", errors.New("boom: " + c)
		}
		return answers[c], nil
	}
	devExists = func(string) bool { return true }
	t.Cleanup(func() { runCmd, devExists = oldRun, oldDev })
	return &calls
}

func TestSnapshotCommands(t *testing.T) {
	calls := fakeZFS(t, nil, nil)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(Snapshot("tank/vdx-1234abcd", "snap-01"))
	must(Rollback("tank/vdx-1234abcd", "snap-01"))
	must(DestroySnapshot("tank/vdx-1234abcd", "snap-01"))
	must(Clone("tank/vdx-1234abcd", "snap-01", "tank/vdx-5678ef01"))
	must(Promote("tank/vdx-5678ef01"))
	want := []string{
		"zfs snapshot tank/vdx-1234abcd@snap-01",
		"zfs rollback tank/vdx-1234abcd@snap-01",
		"zfs destroy tank/vdx-1234abcd@snap-01",
		"zfs clone tank/vdx-1234abcd@snap-01 tank/vdx-5678ef01",
		"udevadm settle",
		"zfs promote tank/vdx-5678ef01",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
	// Never a recursive flag that could reach clones or other datasets.
	for _, c := range *calls {
		for _, f := range []string{" -r", " -R", " -f"} {
			if strings.Contains(c, f) {
				t.Fatalf("unexpected %s in %q", f, c)
			}
		}
	}
}

func TestSnapshotRejectsBadNames(t *testing.T) {
	calls := fakeZFS(t, nil, nil)
	for _, c := range []struct{ ds, tag string }{
		{"tank/vdx-1", "a b"}, {"tank/vdx-1", "x;rm"}, {"tank/vdx-1", ""}, {"-o", "snap"},
		{"tank/vdx-1", "-r"}, {"tank/../etc", "snap"},
	} {
		if err := Snapshot(c.ds, c.tag); err == nil {
			t.Errorf("Snapshot(%q,%q) accepted", c.ds, c.tag)
		}
		if err := DestroySnapshot(c.ds, c.tag); err == nil {
			t.Errorf("DestroySnapshot(%q,%q) accepted", c.ds, c.tag)
		}
	}
	if err := Clone("tank/vdx-1", "snap", "bad target"); err == nil {
		t.Error("Clone accepted a bad target")
	}
	if len(*calls) != 0 {
		t.Fatalf("ran commands for invalid input: %q", *calls)
	}
}

func TestListSnapshotTagsAndClones(t *testing.T) {
	fakeZFS(t, map[string]string{
		"zfs list -H -t snapshot -d 1 -s createtxg -o name tank/vdx-1": "tank/vdx-1@snap-a\ntank/vdx-1@snap-b\n",
		"zfs get -H -o value clones tank/vdx-1@snap-a":                 "tank/vdx-2,tank/vdx-3\n",
		"zfs get -H -o value clones tank/vdx-1@snap-b":                 "-\n",
	}, nil)
	tags, err := ListSnapshotTags("tank/vdx-1")
	if err != nil || !reflect.DeepEqual(tags, []string{"snap-a", "snap-b"}) {
		t.Fatalf("tags = %v, %v", tags, err)
	}
	cl, err := SnapshotClones("tank/vdx-1", "snap-a")
	if err != nil || !reflect.DeepEqual(cl, []string{"tank/vdx-2", "tank/vdx-3"}) {
		t.Fatalf("clones = %v, %v", cl, err)
	}
	if cl, _ := SnapshotClones("tank/vdx-1", "snap-b"); cl != nil {
		t.Fatalf("no clones = %v", cl)
	}
}
