package nbd

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// fakeServer is a minimal fixed-newstyle NBD server over an in-memory disk:
// structured replies, base:allocation + one dirty bitmap, READ (answered as a
// data chunk then a hole chunk), WRITE, WRITE_ZEROES, FLUSH, BLOCK_STATUS.
type fakeServer struct {
	disk  []byte
	dirty [][2]uint64 // dirty [off, len) ranges
}

func (f *fakeServer) serve(t *testing.T, c net.Conn) {
	defer c.Close()
	be := binary.BigEndian
	w := func(b []byte) { c.Write(b) }
	h := be.AppendUint64(nil, nbdMagic)
	h = be.AppendUint64(h, optMagic)
	w(be.AppendUint16(h, flagFixedNew|flagNoZeroes))
	var cflags uint32
	binary.Read(c, be, &cflags)
	rep := func(opt, typ uint32, data []byte) {
		b := be.AppendUint64(nil, repMagic)
		b = be.AppendUint32(b, opt)
		b = be.AppendUint32(b, typ)
		b = be.AppendUint32(b, uint32(len(data)))
		w(append(b, data...))
	}
	ctx := map[uint32]string{}
	for {
		var o struct {
			Magic    uint64
			Opt, Len uint32
		}
		if binary.Read(c, be, &o) != nil {
			return
		}
		data := make([]byte, o.Len)
		io.ReadFull(c, data)
		switch o.Opt {
		case optStructured:
			rep(o.Opt, repAck, nil)
		case optSetMeta:
			n := be.Uint32(data)
			d := data[4+n:]
			q := be.Uint32(d)
			d = d[4:]
			for i := uint32(0); i < q; i++ {
				l := be.Uint32(d)
				name := string(d[4 : 4+l])
				d = d[4+l:]
				if name == "base:allocation" || name == "qemu:dirty-bitmap:b" {
					id := uint32(len(ctx) + 1)
					ctx[id] = name
					rep(o.Opt, repMetaCtx, append(be.AppendUint32(nil, id), name...))
				}
			}
			rep(o.Opt, repAck, nil)
		case optGo:
			info := be.AppendUint16(nil, infoExport)
			info = be.AppendUint64(info, uint64(len(f.disk)))
			rep(o.Opt, repInfo, be.AppendUint16(info, 0))
			rep(o.Opt, repAck, nil)
			goto transmission
		default:
			rep(o.Opt, repErrBit|1, nil)
		}
	}
transmission:
	chunk := func(flags, typ uint16, handle uint64, p []byte) {
		b := be.AppendUint32(nil, structMagic)
		b = be.AppendUint16(b, flags)
		b = be.AppendUint16(b, typ)
		b = be.AppendUint64(b, handle)
		b = be.AppendUint32(b, uint32(len(p)))
		w(append(b, p...))
	}
	simple := func(handle uint64) {
		b := be.AppendUint32(nil, simpleMagic)
		b = be.AppendUint32(b, 0)
		w(be.AppendUint64(b, handle))
	}
	for {
		var r struct {
			Magic       uint32
			Flags, Type uint16
			Handle, Off uint64
			Len         uint32
		}
		if binary.Read(c, be, &r) != nil {
			return
		}
		switch r.Type {
		case cmdRead:
			half := uint64(r.Len / 2)
			chunk(0, replyData, r.Handle, append(be.AppendUint64(nil, r.Off), f.disk[r.Off:r.Off+half]...))
			hole := be.AppendUint64(nil, r.Off+half)
			chunk(replyFlagDone, replyHole, r.Handle, be.AppendUint32(hole, r.Len-uint32(half)))
		case cmdWrite:
			io.ReadFull(c, f.disk[r.Off:r.Off+uint64(r.Len)])
			simple(r.Handle)
		case cmdWriteZeroes:
			clear(f.disk[r.Off : r.Off+uint64(r.Len)])
			simple(r.Handle)
		case cmdFlush:
			simple(r.Handle)
		case cmdBlockStatus:
			for id, name := range ctx {
				p := be.AppendUint32(nil, id)
				if name == "base:allocation" {
					p = be.AppendUint32(p, r.Len)
					p = be.AppendUint32(p, 0)
				} else {
					at, end := r.Off, r.Off+uint64(r.Len)
					for _, d := range f.dirty {
						if d[0] > at {
							p = be.AppendUint32(be.AppendUint32(p, uint32(d[0]-at)), 0)
						}
						p = be.AppendUint32(be.AppendUint32(p, uint32(d[1])), StateDirty)
						at = d[0] + d[1]
					}
					if at < end {
						p = be.AppendUint32(be.AppendUint32(p, uint32(end-at)), 0)
					}
				}
				chunk(0, replyBlockStat, r.Handle, p)
			}
			chunk(replyFlagDone, replyNone, r.Handle, nil)
		case cmdDisc:
			return
		}
	}
}

func dialFake(t *testing.T, f *fakeServer, metas ...string) *Client {
	a, b := net.Pipe()
	go f.serve(t, b)
	c, err := newClient(a, "", metas)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestReadWrite(t *testing.T) {
	f := &fakeServer{disk: bytes.Repeat([]byte{0xAA}, 1<<20)}
	c := dialFake(t, f)
	if c.Size() != 1<<20 {
		t.Fatalf("size %d", c.Size())
	}
	buf := make([]byte, 4096)
	if _, err := c.ReadAt(buf, 8192); err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0xAA || buf[2047] != 0xAA || buf[2048] != 0 || buf[4095] != 0 {
		t.Fatalf("a structured read must place the data chunk and zero the hole chunk")
	}
	if _, err := c.WriteAt([]byte("hello"), 100); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteZeroes(0, 10); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if string(f.disk[100:105]) != "hello" || f.disk[0] != 0 || f.disk[10] != 0xAA {
		t.Fatalf("write/zero did not land: %q %x %x", f.disk[100:105], f.disk[0], f.disk[10])
	}
}

func TestDirtyExtents(t *testing.T) {
	f := &fakeServer{disk: make([]byte, 1<<20), dirty: [][2]uint64{{65536, 65536}, {131072, 4096}, {524288, 65536}}}
	c := dialFake(t, f, "base:allocation", "qemu:dirty-bitmap:b", "qemu:dirty-bitmap:missing")
	if !c.HasContext("qemu:dirty-bitmap:b") || c.HasContext("qemu:dirty-bitmap:missing") {
		t.Fatalf("contexts: %v", c.ctx)
	}
	ext, err := c.Extents("qemu:dirty-bitmap:b", 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var dirty [][2]uint64
	for _, e := range ext {
		if e.Flags&StateDirty != 0 {
			dirty = append(dirty, [2]uint64{e.Offset, e.Length})
		}
	}
	// adjacent dirty ranges merge
	want := [][2]uint64{{65536, 69632}, {524288, 65536}}
	if len(dirty) != len(want) || dirty[0] != want[0] || dirty[1] != want[1] {
		t.Fatalf("dirty extents %v, want %v (all %v)", dirty, want, ext)
	}
	if _, err := c.Extents("qemu:dirty-bitmap:missing", 0, 10); err == nil {
		t.Fatalf("an un-negotiated context must be refused")
	}
}
