// Package nbd is a small NBD (Network Block Device) client: the fixed-newstyle
// handshake, structured replies, meta contexts (base:allocation and
// qemu:dirty-bitmap:*), and the READ / WRITE / WRITE_ZEROES / FLUSH /
// BLOCK_STATUS commands. It is what vdxd uses to read and write disks exported
// by QEMU's built-in NBD server, qemu-nbd, and nbdkit (e.g. the VDDK plugin).
//
// One Client is one connection and is not safe for concurrent use: requests are
// issued one at a time and each waits for its reply.
package nbd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	nbdMagic      = 0x4e42444d41474943 // "NBDMAGIC"
	optMagic      = 0x49484156454F5054 // "IHAVEOPT"
	repMagic      = 0x3e889045565a9
	reqMagic      = 0x25609513
	simpleMagic   = 0x67446698
	structMagic   = 0x668e33ef
	flagFixedNew  = 1
	flagNoZeroes  = 2
	optGo         = 7
	optStructured = 8
	optSetMeta    = 10
	repAck        = 1
	repInfo       = 3
	repMetaCtx    = 4
	repErrBit     = 1 << 31
	infoExport    = 0

	cmdRead        = 0
	cmdWrite       = 1
	cmdDisc        = 2
	cmdFlush       = 3
	cmdWriteZeroes = 6
	cmdBlockStatus = 7

	replyFlagDone  = 1
	replyNone      = 0
	replyData      = 1
	replyHole      = 2
	replyBlockStat = 5
	replyErr       = 32769
	replyErrOffset = 32770

	tflagReadOnly = 1 << 1

	// MaxRequest bounds one READ/WRITE; servers commonly refuse more than 32 MiB.
	MaxRequest = 32 << 20
)

// Extent flags: base:allocation uses StateHole/StateZero; a
// qemu:dirty-bitmap:* context reports StateDirty for changed blocks.
const (
	StateHole  = 1
	StateZero  = 2
	StateDirty = 1
)

// Extent is one block-status descriptor: Length bytes from Offset share Flags.
type Extent struct {
	Offset, Length uint64
	Flags          uint32
}

// Client is one NBD connection to one export.
type Client struct {
	c        net.Conn
	size     uint64
	readOnly bool
	ctx      map[string]uint32 // meta context name -> id
	handle   uint64
}

// Dial connects to an NBD server. addr is "unix:/path/to.sock" or "host:port";
// metaContexts (e.g. "base:allocation", "qemu:dirty-bitmap:vdx-1") are
// negotiated so BlockStatus can query them. The server must support the
// fixed-newstyle handshake and structured replies (QEMU, qemu-nbd, nbdkit do).
func Dial(addr, export string, metaContexts ...string) (*Client, error) {
	network, a := "tcp", addr
	if strings.HasPrefix(addr, "unix:") {
		network, a = "unix", strings.TrimPrefix(addr, "unix:")
	}
	conn, err := net.Dial(network, a)
	if err != nil {
		return nil, err
	}
	c, err := newClient(conn, export, metaContexts)
	if err != nil {
		return nil, fmt.Errorf("nbd handshake with %s: %w", addr, err)
	}
	return c, nil
}

func newClient(conn net.Conn, export string, metas []string) (*Client, error) {
	c := &Client{c: conn, ctx: map[string]uint32{}}
	if err := c.handshake(export, metas); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Size is the export's size in bytes.
func (c *Client) Size() uint64 { return c.size }

// ReadOnly reports whether the server exported the disk read-only.
func (c *Client) ReadOnly() bool { return c.readOnly }

// HasContext reports whether the server accepted the named meta context.
func (c *Client) HasContext(name string) bool { _, ok := c.ctx[name]; return ok }

// Close sends NBD_CMD_DISC and closes the connection.
func (c *Client) Close() error {
	c.handle++
	_ = c.sendReq(cmdDisc, 0, 0, 0, nil)
	return c.c.Close()
}

func (c *Client) handshake(export string, metas []string) error {
	var hdr struct {
		Magic, Opt uint64
		Flags      uint16
	}
	if err := binary.Read(c.c, binary.BigEndian, &hdr); err != nil {
		return err
	}
	if hdr.Magic != nbdMagic || hdr.Opt != optMagic {
		return errors.New("not a newstyle NBD server")
	}
	if hdr.Flags&flagFixedNew == 0 {
		return errors.New("server lacks fixed-newstyle negotiation")
	}
	cflags := uint32(flagFixedNew)
	if hdr.Flags&flagNoZeroes != 0 {
		cflags |= flagNoZeroes
	}
	if err := binary.Write(c.c, binary.BigEndian, cflags); err != nil {
		return err
	}
	// Structured replies are required for BLOCK_STATUS and sparse reads.
	if err := c.sendOpt(optStructured, nil); err != nil {
		return err
	}
	if err := c.expectAck(optStructured, nil); err != nil {
		return fmt.Errorf("structured replies: %w", err)
	}
	if len(metas) > 0 {
		b := appendStr32(nil, export)
		b = binary.BigEndian.AppendUint32(b, uint32(len(metas)))
		for _, m := range metas {
			b = appendStr32(b, m)
		}
		if err := c.sendOpt(optSetMeta, b); err != nil {
			return err
		}
		err := c.expectAck(optSetMeta, func(typ uint32, data []byte) error {
			if typ != repMetaCtx || len(data) < 4 {
				return fmt.Errorf("unexpected reply %d to SET_META_CONTEXT", typ)
			}
			c.ctx[string(data[4:])] = binary.BigEndian.Uint32(data)
			return nil
		})
		if err != nil {
			return fmt.Errorf("meta contexts: %w", err)
		}
	}
	b := appendStr32(nil, export)
	b = binary.BigEndian.AppendUint16(b, 0) // no extra info requests
	if err := c.sendOpt(optGo, b); err != nil {
		return err
	}
	return c.expectAck(optGo, func(typ uint32, data []byte) error {
		if typ != repInfo || len(data) < 2 {
			return nil
		}
		if binary.BigEndian.Uint16(data) == infoExport && len(data) >= 12 {
			c.size = binary.BigEndian.Uint64(data[2:])
			c.readOnly = binary.BigEndian.Uint16(data[10:])&tflagReadOnly != 0
		}
		return nil
	})
}

func appendStr32(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func (c *Client) sendOpt(opt uint32, data []byte) error {
	b := binary.BigEndian.AppendUint64(nil, optMagic)
	b = binary.BigEndian.AppendUint32(b, opt)
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	_, err := c.c.Write(append(b, data...))
	return err
}

// expectAck reads option replies until NBD_REP_ACK, passing every other
// non-error reply to each (if non-nil).
func (c *Client) expectAck(opt uint32, each func(typ uint32, data []byte) error) error {
	for {
		var r struct {
			Magic     uint64
			Opt, Type uint32
			Len       uint32
		}
		if err := binary.Read(c.c, binary.BigEndian, &r); err != nil {
			return err
		}
		if r.Magic != repMagic || r.Opt != opt {
			return fmt.Errorf("bad option reply (magic %#x, option %d)", r.Magic, r.Opt)
		}
		if r.Len > 1<<20 {
			return fmt.Errorf("option reply too large (%d bytes)", r.Len)
		}
		data := make([]byte, r.Len)
		if _, err := io.ReadFull(c.c, data); err != nil {
			return err
		}
		if r.Type&repErrBit != 0 {
			return fmt.Errorf("server refused option %d (error %#x): %s", opt, r.Type, data)
		}
		if r.Type == repAck {
			return nil
		}
		if each != nil {
			if err := each(r.Type, data); err != nil {
				return err
			}
		}
	}
}

func (c *Client) sendReq(typ uint16, flags uint16, off uint64, length uint32, data []byte) error {
	b := make([]byte, 0, 28+len(data))
	b = binary.BigEndian.AppendUint32(b, reqMagic)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint64(b, c.handle)
	b = binary.BigEndian.AppendUint64(b, off)
	b = binary.BigEndian.AppendUint32(b, length)
	_, err := c.c.Write(append(b, data...))
	return err
}

// Error is an error the server returned for one request.
type Error struct {
	Code uint32
	Msg  string
}

func (e *Error) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("nbd: server error %d: %s", e.Code, e.Msg)
	}
	return fmt.Sprintf("nbd: server error %d", e.Code)
}

// do issues one request and consumes its reply chunks. onChunk sees every
// structured data/hole/block-status chunk; for a simple reply to READ, buf is
// filled directly.
func (c *Client) do(typ uint16, off uint64, length uint32, data, buf []byte, onChunk func(typ uint16, payload []byte) error) error {
	c.handle++
	h := c.handle
	if err := c.sendReq(typ, 0, off, length, data); err != nil {
		return err
	}
	var reqErr error
	for {
		var m [4]byte
		if _, err := io.ReadFull(c.c, m[:]); err != nil {
			return err
		}
		switch binary.BigEndian.Uint32(m[:]) {
		case simpleMagic:
			var r struct {
				Err    uint32
				Handle uint64
			}
			if err := binary.Read(c.c, binary.BigEndian, &r); err != nil {
				return err
			}
			if r.Handle != h {
				return fmt.Errorf("nbd: reply for handle %d, want %d", r.Handle, h)
			}
			if r.Err != 0 {
				return &Error{Code: r.Err}
			}
			if typ == cmdRead {
				if _, err := io.ReadFull(c.c, buf); err != nil {
					return err
				}
			}
			return nil
		case structMagic:
			var r struct {
				Flags, Type uint16
				Handle      uint64
				Len         uint32
			}
			if err := binary.Read(c.c, binary.BigEndian, &r); err != nil {
				return err
			}
			if r.Handle != h {
				return fmt.Errorf("nbd: reply for handle %d, want %d", r.Handle, h)
			}
			if r.Len > MaxRequest+1024 {
				return fmt.Errorf("nbd: reply chunk too large (%d bytes)", r.Len)
			}
			p := make([]byte, r.Len)
			if _, err := io.ReadFull(c.c, p); err != nil {
				return err
			}
			switch {
			case r.Type == replyErr || r.Type == replyErrOffset:
				e := &Error{}
				if len(p) >= 6 {
					e.Code = binary.BigEndian.Uint32(p)
					if n := int(binary.BigEndian.Uint16(p[4:])); 6+n <= len(p) {
						e.Msg = string(p[6 : 6+n])
					}
				}
				if reqErr == nil {
					reqErr = e
				}
			case r.Type != replyNone && onChunk != nil && reqErr == nil:
				if err := onChunk(r.Type, p); err != nil {
					reqErr = err
				}
			}
			if r.Flags&replyFlagDone != 0 {
				return reqErr
			}
		default:
			return errors.New("nbd: bad reply magic")
		}
	}
}

// ReadAt reads len(p) bytes at off (it splits requests larger than MaxRequest).
// Holes read as zeroes.
func (c *Client) ReadAt(p []byte, off int64) (int, error) {
	done := 0
	for done < len(p) {
		n := len(p) - done
		if n > MaxRequest {
			n = MaxRequest
		}
		chunk := p[done : done+n]
		base := uint64(off) + uint64(done)
		err := c.do(cmdRead, base, uint32(n), nil, chunk, func(typ uint16, pl []byte) error {
			if len(pl) < 8 {
				return errors.New("nbd: short read chunk")
			}
			at := binary.BigEndian.Uint64(pl)
			if at < base {
				return errors.New("nbd: read chunk before the request")
			}
			rel := at - base
			switch typ {
			case replyData:
				if rel+uint64(len(pl)-8) > uint64(n) {
					return errors.New("nbd: read chunk past the request")
				}
				copy(chunk[rel:], pl[8:])
			case replyHole:
				if len(pl) < 12 {
					return errors.New("nbd: short hole chunk")
				}
				hl := uint64(binary.BigEndian.Uint32(pl[8:]))
				if rel+hl > uint64(n) {
					return errors.New("nbd: hole past the request")
				}
				clear(chunk[rel : rel+hl])
			}
			return nil
		})
		if err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

// WriteAt writes p at off.
func (c *Client) WriteAt(p []byte, off int64) (int, error) {
	done := 0
	for done < len(p) {
		n := len(p) - done
		if n > MaxRequest {
			n = MaxRequest
		}
		if err := c.do(cmdWrite, uint64(off)+uint64(done), uint32(n), p[done:done+n], nil, nil); err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

// WriteZeroes zeroes length bytes at off.
func (c *Client) WriteZeroes(off, length uint64) error {
	for length > 0 {
		n := length
		if n > 1<<30 {
			n = 1 << 30
		}
		if err := c.do(cmdWriteZeroes, off, uint32(n), nil, nil, nil); err != nil {
			return err
		}
		off, length = off+n, length-n
	}
	return nil
}

// Flush asks the server to persist completed writes.
func (c *Client) Flush() error { return c.do(cmdFlush, 0, 0, nil, nil, nil) }

// BlockStatus returns the extents of the named meta context covering
// [off, off+length). The server may answer for a shorter range; callers loop on
// the end of the last extent. Extents are clipped to the requested range.
func (c *Client) BlockStatus(context string, off, length uint64) ([]Extent, error) {
	id, ok := c.ctx[context]
	if !ok {
		return nil, fmt.Errorf("nbd: meta context %q was not negotiated", context)
	}
	if length > 1<<31 {
		length = 1 << 31
	}
	var out []Extent
	err := c.do(cmdBlockStatus, off, uint32(length), nil, nil, func(typ uint16, pl []byte) error {
		if typ != replyBlockStat || len(pl) < 4 || binary.BigEndian.Uint32(pl) != id {
			return nil
		}
		at := off
		for d := pl[4:]; len(d) >= 8; d = d[8:] {
			l := uint64(binary.BigEndian.Uint32(d))
			if end := off + length; at+l > end {
				l = end - at
			}
			if l == 0 {
				break
			}
			out = append(out, Extent{Offset: at, Length: l, Flags: binary.BigEndian.Uint32(d[4:])})
			at += l
		}
		return nil
	})
	return out, err
}

// Extents walks BlockStatus over the whole [off, off+length) range, merging
// adjacent extents with equal flags.
func (c *Client) Extents(context string, off, length uint64) ([]Extent, error) {
	var out []Extent
	end := off + length
	for off < end {
		ext, err := c.BlockStatus(context, off, end-off)
		if err != nil {
			return nil, err
		}
		if len(ext) == 0 {
			return nil, fmt.Errorf("nbd: empty block status at %d", off)
		}
		for _, e := range ext {
			if n := len(out); n > 0 && out[n-1].Flags == e.Flags && out[n-1].Offset+out[n-1].Length == e.Offset {
				out[n-1].Length += e.Length
			} else {
				out = append(out, e)
			}
			off = e.Offset + e.Length
		}
	}
	return out, nil
}
