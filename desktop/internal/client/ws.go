package client

import (
	"io"

	"github.com/gorilla/websocket"
)

// WSReadWriter adapts a message-oriented gorilla WebSocket connection into a
// byte-stream io.ReadWriter, as the RFB client expects. The console proxy
// byte-bridges the socket to QEMU, so frame boundaries carry no meaning.
//
// Reads are only ever called from the RFB read loop (one goroutine); writes are
// serialized by the RFB client's own mutex. That satisfies gorilla's one-reader
// / one-writer concurrency rule.
type wsReadWriter struct {
	c   *websocket.Conn
	cur io.Reader
}

// WSReadWriter wraps a WebSocket connection as an io.ReadWriter.
func WSReadWriter(c *websocket.Conn) io.ReadWriter { return &wsReadWriter{c: c} }

func (w *wsReadWriter) Read(p []byte) (int, error) {
	for {
		if w.cur == nil {
			mt, r, err := w.c.NextReader()
			if err != nil {
				return 0, err
			}
			if mt != websocket.BinaryMessage && mt != websocket.TextMessage {
				continue
			}
			w.cur = r
		}
		n, err := w.cur.Read(p)
		if err == io.EOF {
			w.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (w *wsReadWriter) Write(p []byte) (int, error) {
	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
