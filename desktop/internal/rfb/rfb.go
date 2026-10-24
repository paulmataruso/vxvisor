// Package rfb is a minimal RFB (VNC) client that runs over the VXVisor console
// WebSocket proxy. It implements just enough of RFB 3.8 to drive a QEMU VNC
// server: ProtocolVersion, VNC (DES) auth, SetPixelFormat forcing 32bpp
// true-color, and SetEncodings advertising only Raw, CopyRect, Zlib and
// DesktopSize — QEMU honors the client's encoding list, so there is no Tight or
// ZRLE to decode. It also advertises the Cursor pseudo-encoding (-239) so the
// server sends the pointer *shape* instead of compositing it into the
// framebuffer; the viewer draws it as a hardware cursor that tracks the physical
// mouse with no round-trip, which is what makes the pointer feel instant.
//
// The WebSocket carries raw RFB bytes in binary frames (the server byte-bridges
// the socket to QEMU's loopback VNC port), so this package treats the
// connection as a plain io.ReadWriter of RFB protocol bytes.
package rfb

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"sync"
)

// Client is a live RFB session.
type Client struct {
	rw   io.ReadWriter
	br   *reader // buffered, order-preserving reader over rw
	name string

	mu  sync.Mutex // serializes writes to rw
	fbw int
	fbh int

	// Framebuffer. Guarded by imgMu so the UI can snapshot it while the read
	// loop writes into it.
	imgMu sync.RWMutex
	img   *image.RGBA

	// Damage: the regions changed since the viewer last consumed them, so the
	// tiled viewer can re-upload only the tiles that actually changed instead of
	// the whole framebuffer. Accumulated across FramebufferUpdates between repaints.
	damageMu sync.Mutex
	damage   []image.Rectangle

	// Local cursor. When the Cursor pseudo-encoding is advertised the server stops
	// compositing the pointer into the framebuffer and instead sends its shape, so
	// the viewer can draw it as a hardware cursor that tracks the physical mouse
	// with zero round-trip latency — the single biggest win for perceived mouse lag.
	cursorMu   sync.Mutex
	cursorImg  *image.RGBA // nil + cursorHave == true means "server hid the cursor"
	cursorHotX int
	cursorHotY int
	cursorHave bool

	// Persistent zlib stream (RFB zlib encoding is one continuous stream for the
	// whole connection). Compressed chunks are pushed through a pipe by a feeder
	// goroutine so the inflate reader blocks between rectangles instead of
	// hitting EOF.
	zr    io.ReadCloser
	zpw   *io.PipeWriter
	zfeed chan []byte

	// Callbacks (all optional).
	OnUpdate  func()            // a framebuffer region changed
	OnResize  func(w, h int)    // desktop size changed
	OnCutText func(text string) // server clipboard -> viewer
	OnCursor  func()            // the local cursor shape changed
	OnError   func(err error)   // fatal read-loop error
}

// Cursor returns the latest server cursor shape and its hot-spot. have is false
// until the first cursor update arrives (draw a default pointer until then); a
// nil img with have==true means the server asked for an invisible cursor.
func (c *Client) Cursor() (img *image.RGBA, hotX, hotY int, have bool) {
	c.cursorMu.Lock()
	defer c.cursorMu.Unlock()
	return c.cursorImg, c.cursorHotX, c.cursorHotY, c.cursorHave
}

// Dimensions returns the current framebuffer size.
func (c *Client) Dimensions() (int, int) {
	c.imgMu.RLock()
	defer c.imgMu.RUnlock()
	return c.fbw, c.fbh
}

// Name returns the desktop name reported by the server.
func (c *Client) Name() string { return c.name }

// Snapshot returns a copy-safe reference to the framebuffer image. The caller
// must only read it, and should do so quickly; the read loop mutates the same
// backing array, so tearing is possible but harmless for a management console.
func (c *Client) Image() *image.RGBA {
	c.imgMu.RLock()
	defer c.imgMu.RUnlock()
	return c.img
}

// Handshake performs the full RFB handshake over rw using the given VNC
// password (may be empty if the server offers "None"). On success the
// framebuffer is sized and the caller should start Run.
func Handshake(rw io.ReadWriter, password string) (*Client, error) {
	c := &Client{rw: rw, br: newReader(rw)}
	if err := c.protocolVersion(); err != nil {
		return nil, err
	}
	if err := c.security(password); err != nil {
		return nil, err
	}
	if err := c.clientInit(); err != nil {
		return nil, err
	}
	if err := c.serverInit(); err != nil {
		return nil, err
	}
	if err := c.setPixelFormat(); err != nil {
		return nil, err
	}
	if err := c.setEncodings(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) protocolVersion() error {
	hdr := make([]byte, 12)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return fmt.Errorf("read protocol version: %w", err)
	}
	// Always answer 3.8; QEMU supports it.
	if _, err := c.rw.Write([]byte("RFB 003.008\n")); err != nil {
		return fmt.Errorf("write protocol version: %w", err)
	}
	return nil
}

const (
	secInvalid = 0
	secNone    = 1
	secVNCAuth = 2
)

func (c *Client) security(password string) error {
	n, err := c.br.ReadByte()
	if err != nil {
		return fmt.Errorf("read security count: %w", err)
	}
	if n == 0 {
		// Followed by a reason string: handshake failed.
		reason := c.readString32()
		return fmt.Errorf("server refused connection: %s", reason)
	}
	types := make([]byte, n)
	if _, err := io.ReadFull(c.br, types); err != nil {
		return fmt.Errorf("read security types: %w", err)
	}
	chosen := byte(secInvalid)
	for _, t := range types {
		if t == secVNCAuth {
			chosen = secVNCAuth
			break
		}
	}
	if chosen == secInvalid {
		for _, t := range types {
			if t == secNone {
				chosen = secNone
				break
			}
		}
	}
	if chosen == secInvalid {
		return fmt.Errorf("no supported security type offered by server")
	}
	if _, err := c.rw.Write([]byte{chosen}); err != nil {
		return err
	}
	if chosen == secVNCAuth {
		if err := c.vncAuth(password); err != nil {
			return err
		}
	}
	// SecurityResult (RFB 3.8): 4-byte status, 0 = OK.
	var status uint32
	if err := binary.Read(c.br, binary.BigEndian, &status); err != nil {
		return fmt.Errorf("read security result: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("authentication failed: %s", c.readString32())
	}
	return nil
}

// vncAuth performs the classic VNC DES challenge-response. The DES key is the
// first 8 bytes of the password (NUL-padded), with each byte's bits reversed —
// a well-known VNC quirk.
func (c *Client) vncAuth(password string) error {
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(c.br, challenge); err != nil {
		return fmt.Errorf("read auth challenge: %w", err)
	}
	var key [8]byte
	copy(key[:], []byte(password))
	for i := range key {
		key[i] = reverseBits(key[i])
	}
	block, err := des.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("des: %w", err)
	}
	resp := make([]byte, 16)
	block.Encrypt(resp[0:8], challenge[0:8])
	block.Encrypt(resp[8:16], challenge[8:16])
	if _, err := c.rw.Write(resp); err != nil {
		return err
	}
	return nil
}

func (c *Client) clientInit() error {
	// shared-flag = 1: do not disconnect other clients.
	_, err := c.rw.Write([]byte{1})
	return err
}

func (c *Client) serverInit() error {
	head := make([]byte, 24)
	if _, err := io.ReadFull(c.br, head); err != nil {
		return fmt.Errorf("read server init: %w", err)
	}
	w := int(binary.BigEndian.Uint16(head[0:2]))
	h := int(binary.BigEndian.Uint16(head[2:4]))
	// head[4:20] is the server pixel format (we override it with SetPixelFormat).
	nameLen := binary.BigEndian.Uint32(head[20:24])
	name := make([]byte, nameLen)
	if _, err := io.ReadFull(c.br, name); err != nil {
		return fmt.Errorf("read desktop name: %w", err)
	}
	c.name = string(name)
	c.resize(w, h)
	return nil
}

// setPixelFormat forces a 32bpp, big-endian, true-color format with bytes laid
// out as [pad, R, G, B] so decoding is a straight copy into R,G,B,255.
func (c *Client) setPixelFormat() error {
	msg := []byte{
		0,       // message-type: SetPixelFormat
		0, 0, 0, // padding
		32,     // bits-per-pixel
		24,     // depth
		1,      // big-endian-flag
		1,      // true-colour-flag
		0, 255, // red-max   = 255
		0, 255, // green-max = 255
		0, 255, // blue-max  = 255
		16,      // red-shift
		8,       // green-shift
		0,       // blue-shift
		0, 0, 0, // padding
	}
	_, err := c.rw.Write(msg)
	return err
}

func (c *Client) setEncodings() error {
	// Order = preference, highest first. Prefer Raw over Zlib: the console runs
	// to VMs on local infrastructure over a LAN, where bytes are cheap but the
	// per-rectangle compress (on the busy host) + inflate (on the client) that
	// Zlib adds is pure latency. CopyRect still wins for scrolls; Zlib stays
	// listed as a fallback for a genuinely bandwidth-constrained link.
	encs := []int32{
		encCopyRect,
		encRaw,
		encZlib,
		encDesktopSize,
		encCursor, // local (hardware) cursor: server sends the shape, not pixels
	}
	buf := new(bytes.Buffer)
	buf.WriteByte(2) // message-type: SetEncodings
	buf.WriteByte(0) // padding
	binary.Write(buf, binary.BigEndian, uint16(len(encs)))
	for _, e := range encs {
		binary.Write(buf, binary.BigEndian, e)
	}
	_, err := c.rw.Write(buf.Bytes())
	return err
}

func reverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

func (c *Client) readString32() string {
	var n uint32
	if err := binary.Read(c.br, binary.BigEndian, &n); err != nil {
		return ""
	}
	if n > 1<<16 {
		n = 1 << 16
	}
	s := make([]byte, n)
	io.ReadFull(c.br, s)
	return string(s)
}

// addDamage records that a region of the framebuffer changed.
func (c *Client) addDamage(x, y, w, h int) {
	if w <= 0 || h <= 0 {
		return
	}
	c.damageMu.Lock()
	c.damage = append(c.damage, image.Rect(x, y, x+w, y+h))
	c.damageMu.Unlock()
}

// TakeDamage returns the regions changed since the last call and clears the
// accumulator. The viewer uses it to refresh only the affected tiles.
func (c *Client) TakeDamage() []image.Rectangle {
	c.damageMu.Lock()
	d := c.damage
	c.damage = nil
	c.damageMu.Unlock()
	return d
}

// CopyRegion copies the framebuffer region at (x,y) sized to dst into dst (a
// tightly-packed RGBA), under the framebuffer lock. dst must lie within the
// framebuffer (the tiled viewer sizes each tile to its clipped grid cell). Rows
// outside the framebuffer are skipped. This hands the GL painter a packed image
// (its *image.RGBA fast path ignores Stride), so a tile can't be a SubImage.
func (c *Client) CopyRegion(dst *image.RGBA, x, y int) {
	c.imgMu.RLock()
	defer c.imgMu.RUnlock()
	if c.img == nil {
		return
	}
	w := dst.Rect.Dx()
	h := dst.Rect.Dy()
	for row := 0; row < h; row++ {
		sy := y + row
		if sy < 0 || sy >= c.fbh {
			continue
		}
		n := w * 4
		if x+w > c.fbw {
			n = (c.fbw - x) * 4
		}
		if x < 0 || n <= 0 {
			continue
		}
		si := c.img.PixOffset(x, sy)
		di := row * dst.Stride
		copy(dst.Pix[di:di+n], c.img.Pix[si:si+n])
	}
}

// Close releases the zlib feeder goroutine. The underlying WebSocket is owned
// and closed by the caller.
func (c *Client) Close() {
	if c.zfeed != nil {
		close(c.zfeed)
		c.zfeed = nil
	}
	if c.zpw != nil {
		c.zpw.Close()
	}
}

func (c *Client) resize(w, h int) {
	c.imgMu.Lock()
	c.fbw, c.fbh = w, h
	c.img = image.NewRGBA(image.Rect(0, 0, w, h))
	// Opaque black to start.
	for i := 3; i < len(c.img.Pix); i += 4 {
		c.img.Pix[i] = 255
	}
	c.imgMu.Unlock()
	if c.OnResize != nil {
		c.OnResize(w, h)
	}
}
