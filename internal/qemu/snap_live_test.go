package qemu

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLiveQcow2SnapshotClone exercises qemu-img and a scratch, device-less QEMU
// (QMP only: no network, no display, no guest) on a host. Opt-in only:
// VDX_LIVE_QEMU=<dir>. Everything lives in a fresh <dir>/vdxtest-* directory
// that is removed afterwards, and the scratch QEMU is killed.
//
//	CGO_ENABLED=0 go test -c -o /tmp/qemu.test ./internal/qemu
//	VDX_LIVE_QEMU=/tmp /tmp/qemu.test -test.run Live -test.v
func TestLiveQcow2SnapshotClone(t *testing.T) {
	base := os.Getenv("VDX_LIVE_QEMU")
	if base == "" {
		t.Skip("set VDX_LIVE_QEMU=<scratch dir> to run against real qemu-img / qemu-system")
	}
	dir, err := os.MkdirTemp(base, "vdxtest-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sh := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
		return string(out)
	}
	qio := func(img, cmd string) string { return sh("qemu-io", "-c", cmd, img) }
	expect := func(img, pattern, off string) {
		t.Helper()
		out, err := exec.Command("qemu-io", "-r", "-U", "-c", "read -P "+pattern+" "+off+" 1M", img).CombinedOutput()
		if err != nil || strings.Contains(string(out), "Pattern verification failed") {
			t.Fatalf("%s @%s: want pattern %s: %v %s", filepath.Base(img), off, pattern, err, out)
		}
	}

	baseImg, ov := filepath.Join(dir, "base.qcow2"), filepath.Join(dir, "vm.qcow2")
	sh("qemu-img", "create", "-q", "-f", "qcow2", baseImg, "64M")
	qio(baseImg, "write -P 0x42 0 1M") // base: B at 0
	if err := CreateOverlay(baseImg, ov); err != nil {
		t.Fatal(err)
	}
	qio(ov, "write -P 0x41 1M 1M") // VM's own data: A at 1M
	if err := SnapshotCreate(ov, "snap-1"); err != nil {
		t.Fatal(err)
	}
	qio(ov, "write -P 0x43 1M 1M") // after the snapshot: C at 1M

	// Offline clone of snap-1: the snapshot's view over the SAME base, no history.
	dst := filepath.Join(dir, "clone1.qcow2")
	m, err := CloneSnapshot(ov, "snap-1", dst, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("offline clone method: %s", m)
	expect(dst, "0x41", "1M")
	expect(dst, "0x42", "0")
	in, err := imageInfo(dst)
	if err != nil {
		t.Fatal(err)
	}
	if in.FullBackingFilename != baseImg || len(in.Snapshots) != 0 {
		t.Fatalf("clone info: backing %q snapshots %d", in.FullBackingFilename, len(in.Snapshots))
	}
	if st, _ := os.Stat(dst); st.Size() > 8<<20 {
		t.Fatalf("clone copied more than the VM's own delta: %d bytes", st.Size())
	}
	expect(ov, "0x43", "1M") // the origin is untouched

	// Live: a scratch QEMU holds the image open; the disk-only internal snapshot
	// goes through QMP, later writes don't leak into a clone of it.
	sock := filepath.Join(dir, "qmp.sock")
	q := exec.Command("qemu-system-x86_64", "-S", "-nodefaults", "-display", "none", "-machine", "none",
		"-drive", "file="+ov+",if=none,id="+DiskDevice+",format=qcow2",
		"-qmp", "unix:"+sock+",server=on,wait=off")
	if err := q.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Process.Kill(); _, _ = q.Process.Wait() })
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := QMPInternalSnapshot(sock, DiskDevice, "snap-live"); err != nil {
		t.Fatal(err)
	}
	qm, err := DialQMP(sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qm.hmp(`qemu-io ` + DiskDevice + ` "write -P 0x44 1M 1M"`); err != nil { // a "guest" write after the snapshot
		t.Fatal(err)
	}
	qm.Close()
	dst2 := filepath.Join(dir, "clone2.qcow2")
	m, err = CloneSnapshot(ov, "snap-live", dst2, true)
	if err != nil || m != CloneConvert {
		t.Fatalf("live clone: %q %v", m, err)
	}
	expect(dst2, "0x43", "1M") // the snapshot's state, not the later write
	names, err := InternalSnapshots(ov)
	if err != nil || strings.Join(names, ",") != "snap-1,snap-live" {
		t.Fatalf("snapshots on the live image: %v %v", names, err)
	}
	if err := QMPDeleteInternalSnapshot(sock, DiskDevice, "snap-live"); err != nil {
		t.Fatal(err)
	}
	_ = q.Process.Kill()
	_, _ = q.Process.Wait()
	if names, _ := InternalSnapshots(ov); strings.Join(names, ",") != "snap-1" {
		t.Fatalf("after live delete: %v", names)
	}
	expect(ov, "0x44", "1M")
	// Offline revert to snap-1 restores A; the image stays consistent throughout.
	if err := SnapshotApply(ov, "snap-1"); err != nil {
		t.Fatal(err)
	}
	expect(ov, "0x41", "1M")
	for _, img := range []string{ov, dst, dst2} {
		sh("qemu-img", "check", "-q", img)
	}
}
