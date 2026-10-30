package vmbackup

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"vdxclone/internal/imageio"
	"vdxclone/internal/nbd"
	"vdxclone/internal/qemu"
)

// TestHostPullBackup drives the whole data path against a real QEMU: a full
// backup that creates a checkpoint, point-in-time isolation while the "guest"
// keeps writing, an incremental from that checkpoint (dirty extents exactly
// the written ranges), the same on a stopped disk via qemu-nbd, the checkpoint
// rollback of a failed backup, a writable upload export, and the imageio server
// on top of a real NBD export.
//
// It needs qemu-system-x86_64, qemu-img, qemu-nbd and qemu-io, so it only runs
// with VDX_HOST_QEMU=1 (build with go test -c and run it on a VM host). The
// scratch QEMU has no network, no display, no guest (paused with -S): writes
// go through the block layer via HMP qemu-io.
func TestHostPullBackup(t *testing.T) {
	if os.Getenv("VDX_HOST_QEMU") != "1" {
		t.Skip("set VDX_HOST_QEMU=1 to run against a real QEMU")
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", img, "16M")
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -q -P 0x11 0 1M", img)

	qmpSock := filepath.Join(dir, "qmp.sock")
	vm := exec.Command("qemu-system-x86_64", "-nodefaults", "-display", "none", "-S",
		"-machine", "q35", "-accel", "tcg", "-m", "64",
		"-qmp", "unix:"+qmpSock+",server=on,wait=off",
		"-drive", "file="+img+",if=none,id=disk0,format=qcow2,cache=writeback",
		"-device", "virtio-blk-pci,drive=disk0")
	vm.Stderr = os.Stderr
	if err := vm.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = vm.Wait(); close(exited) }()
	defer func() { _ = vm.Process.Kill(); <-exited }()
	waitFor(t, qmpSock)

	d := Disk{VMID: "test-vm", Path: img, Format: "qcow2", Running: true, QMPSocket: qmpSock,
		WorkRoot: filepath.Join(dir, "work"), UID: -1, GID: -1}
	hmp := func(cmd string) {
		q, err := qemu.DialQMP(qmpSock)
		if err != nil {
			t.Fatal(err)
		}
		defer q.Close()
		out, err := q.HMP(`qemu-io disk0 "` + cmd + `"`)
		if err != nil || strings.Contains(out, "rror") {
			t.Fatalf("qemu-io %q: %v %s", cmd, err, out)
		}
	}

	// 1. Full backup creating checkpoint c1; the guest writes during it.
	e, err := Start(d, Request{To: "c1"})
	if err != nil {
		t.Fatalf("full backup start: %v", err)
	}
	hmp("write -P 0x22 0 64k") // after the point in time: must NOT show in the export
	c := dial(t, e, "base:allocation")
	got := make([]byte, e.Size)
	if _, err := c.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 16<<20)
	copy(want, bytes.Repeat([]byte{0x11}, 1<<20))
	if !bytes.Equal(got, want) {
		t.Fatalf("full backup is not the point-in-time image (byte0=%#x)", got[0])
	}
	// imageio on top of the real export: a ranged GET and zero extents.
	srv := imageio.NewServer()
	tid := "host-test-ticket-0001"
	if err := srv.Add(imageio.Ticket{ID: tid, Read: true, Size: e.Size, ZeroContext: "base:allocation",
		Dial: func() (imageio.Backend, error) { return nbd.Dial(e.Addr, e.Name, "base:allocation") }}); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv)
	req, _ := http.NewRequest("GET", hs.URL+"/images/"+tid, nil)
	req.Header.Set("Range", "bytes=1048570-1048579")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 206 || !bytes.Equal(body, append(bytes.Repeat([]byte{0x11}, 6), 0, 0, 0, 0)) {
		t.Fatalf("imageio ranged GET: %d %x", res.StatusCode, body)
	}
	res, err = http.Get(hs.URL + "/images/" + tid + "/extents")
	if err != nil {
		t.Fatal(err)
	}
	var zext []imageio.ZeroExtent
	_ = json.NewDecoder(res.Body).Decode(&zext)
	res.Body.Close()
	if len(zext) < 2 || zext[0].Zero || zext[0].Length < 1<<20 || !zext[len(zext)-1].Zero {
		t.Fatalf("zero extents over the fleecing node: %+v", zext)
	}
	srv.Remove(tid, 5*time.Second)
	hs.Close()
	c.Close()
	if err := e.Finish(true); err != nil {
		t.Fatalf("finish full: %v", err)
	}
	assertCheckpoints(t, d, "c1")

	// 2. More writes, then an incremental from c1 creating c2.
	hmp("write -P 0x33 2M 128k")
	e, err = Start(d, Request{From: "c1", To: "c2"})
	if err != nil {
		t.Fatalf("incremental start: %v", err)
	}
	c = dial(t, e, "base:allocation", e.DirtyContext)
	dirty, err := c.Extents(e.DirtyContext, 0, e.Size)
	if err != nil {
		t.Fatal(err)
	}
	assertDirty(t, dirty, [][2]uint64{{0, 64 << 10}, {2 << 20, 128 << 10}})
	buf := make([]byte, 128<<10)
	_, _ = c.ReadAt(buf, 2<<20)
	if !bytes.Equal(buf, bytes.Repeat([]byte{0x33}, 128<<10)) {
		t.Fatal("incremental read returned the wrong data")
	}
	c.Close()
	if err := e.Finish(true); err != nil {
		t.Fatal(err)
	}
	assertCheckpoints(t, d, "c1", "c2")
	if err := RemoveCheckpoint(d, "c1"); err != nil {
		t.Fatal(err)
	}
	assertCheckpoints(t, d, "c2")

	// 3. A failed backup must not leave its checkpoint behind.
	e, err = Start(d, Request{From: "c2", To: "c-failed"})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.Finish(false)
	assertCheckpoints(t, d, "c2")
	if _, err := Start(d, Request{From: "nope", To: "c3"}); err != ErrCheckpointInvalid {
		t.Fatalf("unknown base checkpoint: err=%v, want ErrCheckpointInvalid", err)
	}

	// 4. Shut QEMU down cleanly (persists bitmaps), write offline, then back
	//    up the STOPPED disk incrementally through qemu-nbd.
	q, err := qemu.DialQMP(qmpSock)
	if err != nil {
		t.Fatal(err)
	}
	_ = q.Quit()
	q.Close()
	<-exited
	run(t, "qemu-io", "-f", "qcow2", "-c", "write -q -P 0x44 8M 64k", img)
	d.Running = false
	assertCheckpoints(t, d, "c2")
	e, err = Start(d, Request{From: "c2", To: "c3"})
	if err != nil {
		t.Fatalf("stopped incremental: %v", err)
	}
	c = dial(t, e, "base:allocation", e.DirtyContext)
	dirty, _ = c.Extents(e.DirtyContext, 0, e.Size)
	assertDirty(t, dirty, [][2]uint64{{8 << 20, 64 << 10}}) // only what changed since c2
	c.Close()
	// The image lock keeps a VM (here qemu-io in write mode) off the disk.
	if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", "write 0 512", img).CombinedOutput(); err == nil {
		t.Fatalf("disk writable during a stopped-VM backup: %s", out)
	}
	_ = e.Finish(true)
	assertCheckpoints(t, d, "c2", "c3")
	e, _ = Start(d, Request{From: "c3", To: "c4"})
	_ = e.Finish(false)
	assertCheckpoints(t, d, "c2", "c3")

	// 5. A writable export (restore/upload) round-trips write/zero/flush.
	dst := filepath.Join(dir, "restore.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", dst, "16M")
	w, err := OpenWritable(dst, "qcow2", filepath.Join(dir, "up"))
	if err != nil {
		t.Fatal(err)
	}
	wc := dial(t, w)
	_, _ = wc.WriteAt(bytes.Repeat([]byte{0x55}, 1<<20), 0)
	_ = wc.WriteZeroes(4096, 4096)
	if err := wc.Flush(); err != nil {
		t.Fatal(err)
	}
	wc.Close()
	_ = w.Finish(true)
	out, _ := exec.Command("qemu-io", "-f", "qcow2", "-c", "read -P 0x55 0 4096", "-c", "read -P 0 4096 4096", dst).CombinedOutput()
	if strings.Contains(string(out), "Pattern verification failed") {
		t.Fatalf("restored image content wrong: %s", out)
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

func waitFor(t *testing.T, p string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(p); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", p)
}

func dial(t *testing.T, e *Export, metas ...string) *nbd.Client {
	t.Helper()
	c, err := nbd.Dial(e.Addr, e.Name, metas...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func assertCheckpoints(t *testing.T, d Disk, want ...string) {
	t.Helper()
	bs, err := Checkpoints(d)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range bs {
		if b.Inconsistent {
			t.Fatalf("checkpoint %s inconsistent", b.CheckpointID)
		}
		got = append(got, b.CheckpointID)
	}
	sort.Strings(got) // QEMU lists bitmaps newest first
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("checkpoints = %v, want %v", got, want)
	}
}

func assertDirty(t *testing.T, ext []nbd.Extent, want [][2]uint64) {
	t.Helper()
	var got [][2]uint64
	for _, e := range ext {
		if e.Flags&nbd.StateDirty != 0 {
			got = append(got, [2]uint64{e.Offset, e.Length})
		}
	}
	if len(got) != len(want) {
		t.Fatalf("dirty = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dirty = %v, want %v", got, want)
		}
	}
}
