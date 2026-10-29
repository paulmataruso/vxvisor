package service

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"vdxclone/internal/vmware"
)

// TestCBTCopyLiveNBDKit drives the warm-import copy path against a REAL nbdkit
// (the same server process the VDDK plugin runs in production, here with its
// file plugin over a scratch image): nbdkit start + unix socket, the parallel
// NBD readers with the size check, a sparse base copy, a delta that zeroes a
// region, and an abort that kills nbdkit mid-copy. Everything lives in a
// temp dir. Opt-in: VDX_CBT_LIVE_NBDKIT=1 on a host with nbdkit.
func TestCBTCopyLiveNBDKit(t *testing.T) {
	if os.Getenv("VDX_CBT_LIVE_NBDKIT") == "" {
		t.Skip("set VDX_CBT_LIVE_NBDKIT=1 to run against a real nbdkit")
	}
	if _, err := exec.LookPath("nbdkit"); err != nil {
		t.Skip("nbdkit not installed")
	}
	const size = 256 << 20
	dir := t.TempDir()
	img := filepath.Join(dir, "source.img")
	src := make([]byte, size)
	copy(src[0:], pattern(3<<20+5, 1))
	copy(src[64<<20:], pattern(9<<20, 2))
	copy(src[200<<20:], pattern(4096, 3))
	if err := os.WriteFile(img, src, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// dialNBDReaders owns its server (closes it on error and on close), so each
	// open gets its own nbdkit — as each disk-at-a-snapshot does in production.
	serve := func() *vmware.NBDServer {
		srv, err := vmware.ServeFile(ctx, img)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { srv.Close() })
		return srv
	}
	if _, err := dialNBDReaders(serve(), 1, size+4096); err == nil {
		t.Fatal("a size mismatch between the served disk and the recorded capacity must be refused")
	}
	srv := serve()
	disk, err := dialNBDReaders(srv, cbtReadConns, size)
	if err != nil {
		t.Fatalf("dial: %v (nbdkit stderr: %s)", err, srv.Stderr())
	}
	staging := filepath.Join(dir, ".vdxcbt-live-disk0.raw")
	f, err := os.OpenFile(staging, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	// The "*" query: everything allocated, including 32 MiB that reads as zeros.
	base := []vmware.ChangedArea{{Start: 0, Length: 4 << 20}, {Start: 32 << 20, Length: 32 << 20}, {Start: 64 << 20, Length: 9 << 20}, {Start: 200 << 20, Length: 4096}}
	t0 := time.Now()
	if err := cbtCopyExtents(ctx, disk.readers, f, base, true, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("base copy over nbdkit: %s", time.Since(t0))
	_ = f.Sync()
	got, _ := os.ReadFile(staging)
	if !bytes.Equal(got, src) {
		t.Fatal("base copy: staging differs from the source")
	}
	var st syscall.Stat_t
	if syscall.Stat(staging, &st) == nil && st.Blocks*512 > 20<<20 {
		t.Fatalf("staging is not sparse: %d MiB allocated for ~12 MiB of data", st.Blocks*512>>20)
	}

	// Delta: the guest rewrote one region and zeroed another.
	copy(src[64<<20+12345:], pattern(1<<20, 7))
	clear(src[0 : 2<<20])
	if err := os.WriteFile(img, src, 0o600); err != nil {
		t.Fatal(err)
	}
	delta := []vmware.ChangedArea{{Start: 0, Length: 2 << 20}, {Start: 64 << 20, Length: 2 << 20}}
	if err := cbtCopyExtents(ctx, disk.readers, f, delta, false, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(staging)
	if !bytes.Equal(got, src) {
		t.Fatal("delta: staging differs from the changed source")
	}
	disk.close()

	// Abort: killing nbdkit (what a cancel does) fails the copy instead of hanging.
	disk2, err := dialNBDReaders(serve(), cbtReadConns, size)
	if err != nil {
		t.Fatal(err)
	}
	defer disk2.close()
	cctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(cctx, disk2.abort)
	defer stop()
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	done := make(chan error, 1)
	go func() {
		done <- cbtCopyExtents(cctx, disk2.readers, f, []vmware.ChangedArea{{Start: 0, Length: size}}, false, nil)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Log("the copy finished before the abort landed (fast disk) — abort not exercised")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("an aborted copy hung")
	}
}
