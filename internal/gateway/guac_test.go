package gateway

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEncodeInstruction(t *testing.T) {
	got := string(EncodeInstruction("size", "1024", "768", "96"))
	want := "4.size,4.1024,3.768,2.96;"
	if got != want {
		t.Fatalf("encode = %q, want %q", got, want)
	}
	// Multi-byte runes count code points, not bytes.
	if g := string(EncodeInstruction("name", "café")); g != "4.name,4.café;" {
		t.Fatalf("utf8 encode = %q", g)
	}
}

func TestReadInstructionRoundTrip(t *testing.T) {
	data := "4.args,8.hostname,4.port,8.password;5.ready,4.abcd;"
	r := bufio.NewReader(strings.NewReader(data))
	first, err := ReadInstruction(r)
	if err != nil {
		t.Fatal(err)
	}
	if first[0] != "args" || first[1] != "hostname" || first[3] != "password" {
		t.Fatalf("args parse = %v", first)
	}
	second, err := ReadInstruction(r)
	if err != nil {
		t.Fatal(err)
	}
	if second[0] != "ready" || second[1] != "abcd" {
		t.Fatalf("ready parse = %v", second)
	}
}

// TestLiveGuacdHandshake exercises the real guacd select→args step when guacd is
// listening locally. It proves the codec and framing against the actual daemon.
// It skips cleanly where guacd is absent (CI without the daemon).
func TestLiveGuacdHandshake(t *testing.T) {
	addr := "127.0.0.1:4822"
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Skipf("guacd not reachable at %s: %v", addr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(EncodeInstruction("select", "rdp")); err != nil {
		t.Fatal(err)
	}
	instr, err := ReadInstruction(bufio.NewReader(c))
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	if instr[0] != "args" {
		t.Fatalf("guacd replied %q, want args", instr[0])
	}
	// guacd must advertise the RDP hostname parameter.
	var hasHostname bool
	for _, a := range instr[1:] {
		if a == "hostname" {
			hasHostname = true
		}
	}
	if !hasHostname {
		t.Fatalf("rdp args lack hostname: %v", instr)
	}
	t.Logf("guacd rdp args (%d): %v", len(instr)-1, instr[1:])
}
