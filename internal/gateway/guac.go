// Package gateway implements the browser-desktop gateway: a server-side client
// of guacd (the Apache Guacamole proxy daemon) that gives a full remote desktop
// in any browser tab with no plugin or client install. The browser runs
// guacamole-common-js over a WebSocket; this package speaks guacd's wire
// protocol, performs the connection handshake (selecting RDP so clipboard,
// audio, microphone and webcam ride RDP's virtual channels), and then relays the
// instruction stream between the browser and guacd.
//
// The guacd wire protocol is a stream of instructions, each a comma-separated
// list of LENGTH.VALUE elements terminated by a semicolon, e.g.
//
//	4.size,4.1024,3.768,2.96;
//
// LENGTH is the number of UTF-8 code points in VALUE.
package gateway

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// EncodeInstruction renders one guacd instruction (opcode + args).
func EncodeInstruction(opcode string, args ...string) []byte {
	var b strings.Builder
	writeElem(&b, opcode)
	for _, a := range args {
		b.WriteByte(',')
		writeElem(&b, a)
	}
	b.WriteByte(';')
	return []byte(b.String())
}

func writeElem(b *strings.Builder, v string) {
	b.WriteString(strconv.Itoa(utf8.RuneCountInString(v)))
	b.WriteByte('.')
	b.WriteString(v)
}

// ReadInstruction parses a single instruction from r into its element list
// (element 0 is the opcode). It reads exactly one instruction's bytes.
func ReadInstruction(r *bufio.Reader) ([]string, error) {
	var elems []string
	for {
		// Read the length prefix up to the '.'
		lenStr, err := r.ReadString('.')
		if err != nil {
			return nil, err
		}
		lenStr = strings.TrimRight(lenStr, ".")
		// A stray terminator between instructions.
		lenStr = strings.TrimLeft(lenStr, ";,")
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil {
			return nil, fmt.Errorf("guac: bad length %q: %w", lenStr, err)
		}
		// Read n runes of value.
		val := make([]rune, 0, n)
		for i := 0; i < n; i++ {
			ru, _, err := r.ReadRune()
			if err != nil {
				return nil, err
			}
			val = append(val, ru)
		}
		elems = append(elems, string(val))
		// Separator: ',' → more elements, ';' → end of instruction.
		sep, _, err := r.ReadRune()
		if err != nil {
			return nil, err
		}
		if sep == ';' {
			return elems, nil
		}
		// otherwise ',' — continue
	}
}

// Params are the RDP/VNC connection parameters guacd dials the guest with.
type Params struct {
	Protocol string // rdp | vnc
	Hostname string
	Port     string
	Username string
	Password string
	Width    int
	Height   int
	DPI      int
	// Enable the device-redirection virtual channels (RDP only).
	EnableAudio     bool
	EnableClipboard bool
	EnableMic       bool
	EnablePrinting  bool
}

// Handshake connects to guacd and negotiates a session, leaving conn positioned
// at the start of the post-"ready" instruction stream. It returns the connection
// UUID guacd assigned. This is the exact select→args→(size,audio,video,image)→
// connect→ready sequence guacd requires.
func Handshake(guacdAddr string, p Params) (net.Conn, string, error) {
	conn, err := net.DialTimeout("tcp", guacdAddr, 5*time.Second)
	if err != nil {
		return nil, "", fmt.Errorf("dial guacd %s: %w", guacdAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)

	proto := p.Protocol
	if proto == "" {
		proto = "rdp"
	}
	// 1. select the protocol.
	if _, err := conn.Write(EncodeInstruction("select", proto)); err != nil {
		conn.Close()
		return nil, "", err
	}
	// 2. guacd replies with "args": the ordered parameter names it expects.
	argsInstr, err := ReadInstruction(br)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read args: %w", err)
	}
	if len(argsInstr) == 0 || argsInstr[0] != "args" {
		conn.Close()
		return nil, "", fmt.Errorf("expected args, got %v", opcodeOf(argsInstr))
	}
	argNames := argsInstr[1:] // first element after opcode may be protocol version

	// 3. client capabilities.
	w := bufio.NewWriter(conn)
	width, height, dpi := p.Width, p.Height, p.DPI
	if width == 0 {
		width = 1280
	}
	if height == 0 {
		height = 720
	}
	if dpi == 0 {
		dpi = 96
	}
	w.Write(EncodeInstruction("size", strconv.Itoa(width), strconv.Itoa(height), strconv.Itoa(dpi)))
	w.Write(EncodeInstruction("audio", "audio/L16", "audio/L8"))
	w.Write(EncodeInstruction("video"))
	w.Write(EncodeInstruction("image", "image/png", "image/jpeg", "image/webp"))
	w.Write(EncodeInstruction("timezone", "UTC"))

	// 4. connect: supply a value for every arg name guacd listed, in order.
	values := make([]string, len(argNames))
	for i, name := range argNames {
		values[i] = p.value(name, width, height, dpi)
	}
	w.Write(EncodeInstruction("connect", values...))
	if err := w.Flush(); err != nil {
		conn.Close()
		return nil, "", err
	}

	// 5. guacd replies "ready,<UUID>".
	ready, err := ReadInstruction(br)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("read ready: %w", err)
	}
	if ready[0] != "ready" {
		conn.Close()
		return nil, "", fmt.Errorf("expected ready, got %q", ready[0])
	}
	uuid := ""
	if len(ready) > 1 {
		uuid = ready[1]
	}
	_ = conn.SetDeadline(time.Time{}) // clear; the relay manages its own lifetime
	// Hand back the buffered reader's leftover by wrapping conn in a reader view.
	return &bufConn{Conn: conn, r: br}, uuid, nil
}

// value maps a guacd parameter name to our configured value (empty if unknown).
func (p Params) value(name string, w, h, dpi int) string {
	onoff := func(b bool) string {
		if b {
			return "true"
		}
		return ""
	}
	// Handshake version negotiation: guacd lists its protocol version as the
	// first "arg"; the client echoes it back in the matching connect slot to
	// confirm the version it will speak.
	if strings.HasPrefix(name, "VERSION_") {
		return name
	}
	switch name {
	case "hostname":
		return p.Hostname
	case "port":
		if p.Port != "" {
			return p.Port
		}
		if p.Protocol == "vnc" {
			return "5900"
		}
		return "3389"
	case "username":
		return p.Username
	case "password":
		return p.Password
	case "width":
		return strconv.Itoa(w)
	case "height":
		return strconv.Itoa(h)
	case "dpi":
		return strconv.Itoa(dpi)
	case "security":
		return "any"
	case "ignore-cert":
		return "true"
	case "enable-audio", "audio-servername":
		return onoff(p.EnableAudio)
	case "enable-audio-input":
		return onoff(p.EnableMic)
	case "disable-audio":
		return onoff(!p.EnableAudio)
	case "enable-printing":
		return onoff(p.EnablePrinting)
	case "disable-copy", "disable-paste":
		return onoff(!p.EnableClipboard)
	case "resize-method":
		return "display-update"
	default:
		return ""
	}
}

func opcodeOf(instr []string) string {
	if len(instr) == 0 {
		return "<empty>"
	}
	return instr[0]
}

// bufConn lets callers keep reading through the bufio.Reader used in the
// handshake without losing buffered bytes.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Ensure bufConn satisfies io.ReadWriteCloser for the relay.
var _ io.ReadWriteCloser = (*bufConn)(nil)
