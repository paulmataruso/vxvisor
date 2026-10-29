package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"vdxclone/internal/nbd"
	"vdxclone/internal/vmware"
)

// nbdDiskServer is a minimal fixed-newstyle NBD server over an in-memory disk
// (structured-reply ack, OPT_GO, READ as a simple reply, DISC) on a unix
// socket — enough to drive the real nbd.Client the way nbdkit does.
func nbdDiskServer(t *testing.T, disk []byte) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "nbd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	be := binary.BigEndian
	serve := func(c net.Conn) {
		defer c.Close()
		h := be.AppendUint64(nil, 0x4e42444d41474943)
		h = be.AppendUint64(h, 0x49484156454F5054)
		c.Write(be.AppendUint16(h, 1|2)) // fixed newstyle, no zeroes
		var cflags uint32
		if binary.Read(c, be, &cflags) != nil {
			return
		}
		rep := func(opt, typ uint32, data []byte) {
			b := be.AppendUint64(nil, 0x3e889045565a9)
			b = be.AppendUint32(b, opt)
			b = be.AppendUint32(b, typ)
			b = be.AppendUint32(b, uint32(len(data)))
			c.Write(append(b, data...))
		}
		for {
			var o struct {
				Magic    uint64
				Opt, Len uint32
			}
			if binary.Read(c, be, &o) != nil {
				return
			}
			io.CopyN(io.Discard, c, int64(o.Len))
			if o.Opt == 7 { // GO
				info := be.AppendUint16(nil, 0)
				info = be.AppendUint64(info, uint64(len(disk)))
				rep(o.Opt, 3, be.AppendUint16(info, 1|2)) // has flags, read-only
				rep(o.Opt, 1, nil)
				break
			}
			rep(o.Opt, 1, nil) // ack structured replies
		}
		for {
			var r struct {
				Magic       uint32
				Flags, Type uint16
				Handle, Off uint64
				Len         uint32
			}
			if binary.Read(c, be, &r) != nil || r.Type == 2 {
				return
			}
			b := be.AppendUint32(nil, 0x67446698)
			b = be.AppendUint32(b, 0)
			b = be.AppendUint64(b, r.Handle)
			c.Write(append(b, disk[r.Off:r.Off+uint64(r.Len)]...))
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return "unix:" + sock
}

func nbdReaders(t *testing.T, addr string, n int) []io.ReaderAt {
	t.Helper()
	var out []io.ReaderAt
	for i := 0; i < n; i++ {
		c, err := nbd.Dial(addr, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		out = append(out, c)
	}
	return out
}

// TestCBTCopyExtentsOverNBD drives the delta-apply path end to end against an
// NBD server: changed extents → parallel NBD reads → pwrite into staging. The
// base copy writes only the given areas into a fresh sparse file; a delta
// overwrites stale data, zeroed blocks included; an area past the disk is
// refused.
func TestCBTCopyExtentsOverNBD(t *testing.T) {
	const size = 9<<20 + 4096
	src := make([]byte, size)
	copy(src[0:], pattern(5000, 1))
	copy(src[1<<20:], pattern(4<<20+17, 2)) // spans chunks
	copy(src[8<<20:], pattern(1<<20, 3))
	areas := []vmware.ChangedArea{{Start: 0, Length: 5000}, {Start: 1 << 20, Length: 4<<20 + 17}, {Start: 8 << 20, Length: 1 << 20}, {Start: 6 << 20, Length: 8192}} // last: allocated but zero

	staging := filepath.Join(t.TempDir(), "stage.raw")
	f, err := os.OpenFile(staging, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Truncate(size)
	var moved int64
	if err := cbtCopyExtents(context.Background(), nbdReaders(t, nbdDiskServer(t, src), 3), f, areas, true, func(n int64) { moved += n }); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(staging)
	if !bytes.Equal(got, src) {
		t.Fatal("base copy: staging differs from the source")
	}
	if moved != 5000+4<<20+17+1<<20+8192 {
		t.Fatalf("progress reported %d bytes", moved)
	}

	// Delta: the guest rewrote one region, zeroed another, and wrote a third.
	src2 := append([]byte(nil), src...)
	copy(src2[1<<20+100:], pattern(70000, 9))
	clear(src2[8<<20 : 8<<20+65536])
	copy(src2[3<<20:], pattern(4096, 4))
	delta := []vmware.ChangedArea{{Start: 1 << 20, Length: 128 << 10}, {Start: 8 << 20, Length: 65536}, {Start: 3 << 20, Length: 4096}}
	if err := cbtCopyExtents(context.Background(), nbdReaders(t, nbdDiskServer(t, src2), 2), f, delta, false, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(staging)
	if !bytes.Equal(got, src2) {
		t.Fatal("delta: staging differs from the changed source (a zeroed block must overwrite stale data)")
	}

	if err := cbtCopyExtents(context.Background(), nbdReaders(t, nbdDiskServer(t, src2), 1), f, []vmware.ChangedArea{{Start: size - 10, Length: 20}}, false, nil); err == nil {
		t.Fatal("an area past the end of the disk must be refused")
	}
	got, _ = os.ReadFile(staging)
	if int64(len(got)) != size || !bytes.Equal(got, src2) {
		t.Fatal("a refused area must not change staging")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cbtCopyExtents(ctx, nbdReaders(t, nbdDiskServer(t, src2), 1), f, areas, false, nil); err == nil {
		t.Fatal("a cancelled copy must report it")
	}
}
