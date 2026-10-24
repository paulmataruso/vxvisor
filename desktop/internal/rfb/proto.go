package rfb

import (
	"bufio"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"image"
	"io"
)

// Encoding numbers.
const (
	encRaw         int32 = 0
	encCopyRect    int32 = 1
	encZlib        int32 = 6
	encDesktopSize int32 = -223
	encCursor      int32 = -239 // "Cursor" pseudo-encoding: pointer shape + mask
)

// Server-to-client message types.
const (
	msgFramebufferUpdate   = 0
	msgSetColourMapEntries = 1
	msgBell                = 2
	msgServerCutText       = 3
)

// Run reads server messages until the connection closes or errors. It should be
// called in its own goroutine. The first FramebufferUpdateRequest (full) is
// sent here; thereafter the caller drives incremental requests via
// RequestUpdate (typically after each OnUpdate).
func (c *Client) Run() {
	if err := c.RequestUpdate(false); err != nil {
		c.fail(err)
		return
	}
	for {
		mtype, err := c.br.ReadByte()
		if err != nil {
			c.fail(err)
			return
		}
		switch mtype {
		case msgFramebufferUpdate:
			if err := c.readFramebufferUpdate(); err != nil {
				c.fail(err)
				return
			}
			if c.OnUpdate != nil {
				c.OnUpdate()
			}
			if err := c.RequestUpdate(true); err != nil {
				c.fail(err)
				return
			}
		case msgServerCutText:
			if err := c.readServerCutText(); err != nil {
				c.fail(err)
				return
			}
		case msgSetColourMapEntries:
			if err := c.skipColourMap(); err != nil {
				c.fail(err)
				return
			}
		case msgBell:
			// no-op
		default:
			c.fail(fmt.Errorf("unknown server message type %d", mtype))
			return
		}
	}
}

func (c *Client) fail(err error) {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = fmt.Errorf("console disconnected")
	}
	if c.OnError != nil {
		c.OnError(err)
	}
}

// RequestUpdate asks the server for a framebuffer update over the whole screen.
func (c *Client) RequestUpdate(incremental bool) error {
	c.imgMu.RLock()
	w, h := c.fbw, c.fbh
	c.imgMu.RUnlock()
	inc := byte(0)
	if incremental {
		inc = 1
	}
	msg := make([]byte, 10)
	msg[0] = 3 // FramebufferUpdateRequest
	msg[1] = inc
	binary.BigEndian.PutUint16(msg[2:4], 0)
	binary.BigEndian.PutUint16(msg[4:6], 0)
	binary.BigEndian.PutUint16(msg[6:8], uint16(w))
	binary.BigEndian.PutUint16(msg[8:10], uint16(h))
	return c.write(msg)
}

func (c *Client) readFramebufferUpdate() error {
	head := make([]byte, 3)
	if _, err := io.ReadFull(c.br, head); err != nil {
		return err
	}
	nRects := int(binary.BigEndian.Uint16(head[1:3]))
	for i := 0; i < nRects; i++ {
		rh := make([]byte, 12)
		if _, err := io.ReadFull(c.br, rh); err != nil {
			return err
		}
		x := int(binary.BigEndian.Uint16(rh[0:2]))
		y := int(binary.BigEndian.Uint16(rh[2:4]))
		w := int(binary.BigEndian.Uint16(rh[4:6]))
		h := int(binary.BigEndian.Uint16(rh[6:8]))
		enc := int32(binary.BigEndian.Uint32(rh[8:12]))
		switch enc {
		case encRaw:
			if err := c.decodeRaw(x, y, w, h); err != nil {
				return err
			}
			c.addDamage(x, y, w, h)
		case encCopyRect:
			if err := c.decodeCopyRect(x, y, w, h); err != nil {
				return err
			}
			c.addDamage(x, y, w, h)
		case encZlib:
			if err := c.decodeZlib(x, y, w, h); err != nil {
				return err
			}
			c.addDamage(x, y, w, h)
		case encDesktopSize:
			c.resize(w, h)
		case encCursor:
			// x,y are the hot-spot for this pseudo-encoding (not a position).
			if err := c.decodeCursor(x, y, w, h); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported encoding %d in update", enc)
		}
	}
	return nil
}

// decodeCursor reads the Cursor pseudo-encoding: w*h pixels in our 32bpp
// [pad,R,G,B] format followed by a 1-bpp transparency mask (rows padded to a
// byte, MSB first, 1 = opaque). It builds a premultiplied-alpha RGBA cursor and
// publishes it with hot-spot (hx,hy) so the viewer can draw a hardware cursor.
func (c *Client) decodeCursor(hx, hy, w, h int) error {
	if w < 0 || h < 0 || w > 1024 || h > 1024 {
		return fmt.Errorf("cursor size out of range: %dx%d", w, h)
	}
	var img *image.RGBA
	if w > 0 && h > 0 {
		pix := make([]byte, w*h*4)
		if _, err := io.ReadFull(c.br, pix); err != nil {
			return err
		}
		maskStride := (w + 7) / 8
		mask := make([]byte, maskStride*h)
		if _, err := io.ReadFull(c.br, mask); err != nil {
			return err
		}
		img = image.NewRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				opaque := mask[y*maskStride+x/8]&(0x80>>(uint(x)&7)) != 0
				di := img.PixOffset(x, y)
				if opaque {
					si := (y*w + x) * 4
					img.Pix[di+0] = pix[si+1] // R
					img.Pix[di+1] = pix[si+2] // G
					img.Pix[di+2] = pix[si+3] // B
					img.Pix[di+3] = 255
				}
				// transparent pixels stay zero (fully transparent)
			}
		}
	}
	c.cursorMu.Lock()
	c.cursorImg = img
	c.cursorHotX, c.cursorHotY = hx, hy
	c.cursorHave = true
	c.cursorMu.Unlock()
	if c.OnCursor != nil {
		c.OnCursor()
	}
	return nil
}

// decodeRaw reads w*h 32bpp pixels ([pad,R,G,B]) straight into the framebuffer.
func (c *Client) decodeRaw(x, y, w, h int) error {
	pix := make([]byte, w*h*4)
	if _, err := io.ReadFull(c.br, pix); err != nil {
		return err
	}
	c.blit(x, y, w, h, pix)
	return nil
}

func (c *Client) decodeCopyRect(x, y, w, h int) error {
	sp := make([]byte, 4)
	if _, err := io.ReadFull(c.br, sp); err != nil {
		return err
	}
	srcX := int(binary.BigEndian.Uint16(sp[0:2]))
	srcY := int(binary.BigEndian.Uint16(sp[2:4]))
	c.imgMu.Lock()
	defer c.imgMu.Unlock()
	if c.img == nil {
		return nil
	}
	src := image.Rect(srcX, srcY, srcX+w, srcY+h)
	// Copy row by row; handle vertical overlap by choosing copy direction.
	if srcY < y {
		for row := h - 1; row >= 0; row-- {
			c.copyRow(x, y+row, srcX, srcY+row, w)
		}
	} else {
		for row := 0; row < h; row++ {
			c.copyRow(x, y+row, srcX, srcY+row, w)
		}
	}
	_ = src
	return nil
}

func (c *Client) copyRow(dx, dy, sx, sy, w int) {
	if dy < 0 || dy >= c.fbh || sy < 0 || sy >= c.fbh {
		return
	}
	di := c.img.PixOffset(dx, dy)
	si := c.img.PixOffset(sx, sy)
	n := w * 4
	// Clamp to bounds.
	if di < 0 || si < 0 || di+n > len(c.img.Pix) || si+n > len(c.img.Pix) {
		return
	}
	copy(c.img.Pix[di:di+n], c.img.Pix[si:si+n])
}

// decodeZlib reads a length-prefixed compressed chunk, pushes it into the
// persistent zlib stream, and reads exactly w*h*4 decompressed pixel bytes.
//
// RFB's zlib encoding is one continuous zlib stream for the whole connection,
// so the inflate reader must survive across rectangles. A plain growing buffer
// does not work: Go's flate reader caches io.EOF once the buffer drains and
// never resumes. Instead, compressed chunks are written into an io.Pipe by a
// feeder goroutine; the inflate reader then blocks waiting for the next chunk
// rather than seeing EOF.
func (c *Client) decodeZlib(x, y, w, h int) error {
	var n uint32
	if err := binary.Read(c.br, binary.BigEndian, &n); err != nil {
		return err
	}
	comp := make([]byte, n)
	if _, err := io.ReadFull(c.br, comp); err != nil {
		return err
	}

	if c.zr == nil {
		pr, pw := io.Pipe()
		c.zpw = pw
		c.zfeed = make(chan []byte, 16)
		go func() {
			for b := range c.zfeed {
				if _, err := pw.Write(b); err != nil {
					return
				}
			}
			pw.Close()
		}()
		// Deliver the first chunk, then build the reader (which reads the zlib
		// header from the pipe, fed by the goroutine above).
		c.zfeed <- comp
		zr, err := zlib.NewReader(pr)
		if err != nil {
			return fmt.Errorf("zlib init: %w", err)
		}
		c.zr = zr
	} else {
		c.zfeed <- comp
	}

	pix := make([]byte, w*h*4)
	if _, err := io.ReadFull(c.zr, pix); err != nil {
		return fmt.Errorf("zlib read: %w", err)
	}
	c.blit(x, y, w, h, pix)
	return nil
}

// blit copies a rectangle of [pad,R,G,B] big-endian 32bpp pixels into the RGBA
// framebuffer as R,G,B,255.
func (c *Client) blit(x, y, w, h int, pix []byte) {
	c.imgMu.Lock()
	defer c.imgMu.Unlock()
	if c.img == nil {
		return
	}
	// Fast path: the whole rectangle is in bounds (the overwhelmingly common
	// case). Re-slice dst/src per row so the compiler elides bounds checks in
	// the hot inner loop — a per-pixel clamp here is what made full-frame
	// updates expensive.
	if x >= 0 && y >= 0 && x+w <= c.fbw && y+h <= c.fbh {
		rowBytes := w * 4
		for row := 0; row < h; row++ {
			di := c.img.PixOffset(x, y+row)
			dst := c.img.Pix[di : di+rowBytes : di+rowBytes]
			src := pix[row*rowBytes : row*rowBytes+rowBytes : row*rowBytes+rowBytes]
			for j := 0; j+4 <= rowBytes; j += 4 {
				// source bytes: [pad, R, G, B] -> R, G, B, 255
				dst[j+0] = src[j+1]
				dst[j+1] = src[j+2]
				dst[j+2] = src[j+3]
				dst[j+3] = 255
			}
		}
		return
	}
	// Slow path: rectangle extends past the framebuffer; clip per pixel.
	for row := 0; row < h; row++ {
		dy := y + row
		if dy < 0 || dy >= c.fbh {
			continue
		}
		di := c.img.PixOffset(x, dy)
		si := row * w * 4
		for col := 0; col < w; col++ {
			px := x + col
			if px < 0 || px >= c.fbw {
				di += 4
				si += 4
				continue
			}
			// source bytes: [pad, R, G, B]
			c.img.Pix[di+0] = pix[si+1]
			c.img.Pix[di+1] = pix[si+2]
			c.img.Pix[di+2] = pix[si+3]
			c.img.Pix[di+3] = 255
			di += 4
			si += 4
		}
	}
}

func (c *Client) readServerCutText() error {
	head := make([]byte, 7) // 3 padding + 4 length
	if _, err := io.ReadFull(c.br, head); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(head[3:7])
	if n > 1<<20 {
		n = 1 << 20
	}
	text := make([]byte, n)
	if _, err := io.ReadFull(c.br, text); err != nil {
		return err
	}
	if c.OnCutText != nil {
		c.OnCutText(string(text))
	}
	return nil
}

func (c *Client) skipColourMap() error {
	head := make([]byte, 5) // padding + first-colour(2) + number(2)
	if _, err := io.ReadFull(c.br, head); err != nil {
		return err
	}
	count := int(binary.BigEndian.Uint16(head[3:5]))
	_, err := io.CopyN(io.Discard, c.br, int64(count)*6)
	return err
}

// --- input (client -> server) ---

// SendPointer sends an absolute pointer event. buttonMask bit0=left, bit1=mid,
// bit2=right, bit3=wheel-up, bit4=wheel-down.
func (c *Client) SendPointer(x, y int, buttonMask byte) error {
	c.imgMu.RLock()
	w, h := c.fbw, c.fbh
	c.imgMu.RUnlock()
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	if w > 0 && x >= w {
		x = w - 1
	}
	if h > 0 && y >= h {
		y = h - 1
	}
	msg := make([]byte, 6)
	msg[0] = 5 // PointerEvent
	msg[1] = buttonMask
	binary.BigEndian.PutUint16(msg[2:4], uint16(x))
	binary.BigEndian.PutUint16(msg[4:6], uint16(y))
	return c.write(msg)
}

// SendKey sends a key press or release by X11 keysym.
func (c *Client) SendKey(keysym uint32, down bool) error {
	msg := make([]byte, 8)
	msg[0] = 4 // KeyEvent
	if down {
		msg[1] = 1
	}
	binary.BigEndian.PutUint32(msg[4:8], keysym)
	return c.write(msg)
}

// TapKey presses and releases a keysym.
func (c *Client) TapKey(keysym uint32) error {
	if err := c.SendKey(keysym, true); err != nil {
		return err
	}
	return c.SendKey(keysym, false)
}

// SendCutText sends viewer-clipboard text to the guest (Latin-1 only, per the
// base RFB spec).
func (c *Client) SendCutText(text string) error {
	b := []byte(text)
	msg := make([]byte, 8+len(b))
	msg[0] = 6 // ClientCutText
	binary.BigEndian.PutUint32(msg[4:8], uint32(len(b)))
	copy(msg[8:], b)
	return c.write(msg)
}

func (c *Client) write(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.rw.Write(b)
	return err
}

// --- helpers ---

// reader is a buffered reader over the websocket byte stream.
type reader struct{ *bufio.Reader }

func newReader(r io.Reader) *reader { return &reader{bufio.NewReaderSize(r, 64*1024)} }
