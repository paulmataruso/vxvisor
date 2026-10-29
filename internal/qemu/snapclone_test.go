package qemu

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func fakeTools(t *testing.T, answer func(cmd string) (string, error)) *[]string {
	t.Helper()
	var calls []string
	old := runTool
	runTool = func(name string, args ...string) ([]byte, error) {
		c := strings.Join(append([]string{name}, args...), " ")
		calls = append(calls, c)
		out, err := answer(c)
		return []byte(out), err
	}
	t.Cleanup(func() { runTool = old })
	return &calls
}

const infoWithBase = `{"backing-filename":"base.qcow2","full-backing-filename":"/img/base.qcow2","backing-filename-format":"qcow2","snapshots":[{"name":"snap-a"},{"name":"snap-b"}]}`

func TestCloneSnapshotConvertFallback(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src.qcow2"), filepath.Join(dir, "dst.qcow2")
	calls := fakeTools(t, func(c string) (string, error) {
		switch {
		case strings.HasPrefix(c, "qemu-img info"):
			return infoWithBase, nil
		case strings.HasPrefix(c, "cp --reflink=always"):
			return "cp: failed to clone: Operation not supported", errors.New("exit status 1")
		}
		return "", nil
	})
	m, err := CloneSnapshot(src, "snap-a", dst, false)
	if err != nil || m != CloneConvert {
		t.Fatalf("method %q err %v", m, err)
	}
	want := []string{
		"qemu-img info -U --output=json " + src,
		"cp --reflink=always -- " + src + " " + dst,
		"qemu-img convert -U -l snapshot.name=snap-a -O qcow2 -B /img/base.qcow2 -F qcow2 " + src + " " + dst,
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
}

func TestCloneSnapshotLiveNeverReflinks(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src.qcow2"), filepath.Join(dir, "dst.qcow2")
	calls := fakeTools(t, func(c string) (string, error) {
		if strings.HasPrefix(c, "qemu-img info") {
			return `{"snapshots":[{"name":"snap-a"}]}`, nil // no backing: a full image
		}
		return "", nil
	})
	if m, err := CloneSnapshot(src, "snap-a", dst, true); err != nil || m != CloneConvert {
		t.Fatalf("method %q err %v", m, err)
	}
	for _, c := range *calls {
		if strings.HasPrefix(c, "cp ") {
			t.Fatalf("reflink-copied a live image: %q", *calls)
		}
	}
	if last := (*calls)[len(*calls)-1]; last != "qemu-img convert -U -l snapshot.name=snap-a -O qcow2 "+src+" "+dst {
		t.Fatalf("convert argv %q", last)
	}
}

func TestCloneSnapshotReflink(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src.qcow2"), filepath.Join(dir, "dst.qcow2")
	calls := fakeTools(t, func(c string) (string, error) {
		if strings.HasPrefix(c, "qemu-img info") {
			return infoWithBase, nil
		}
		return "", nil
	})
	if m, err := CloneSnapshot(src, "snap-b", dst, false); err != nil || m != CloneReflink {
		t.Fatalf("method %q err %v", m, err)
	}
	want := []string{
		"qemu-img info -U --output=json " + src,
		"cp --reflink=always -- " + src + " " + dst,
		"qemu-img snapshot -a snap-b " + dst,
		"qemu-img info -U --output=json " + dst,
		"qemu-img snapshot -d snap-a " + dst,
		"qemu-img snapshot -d snap-b " + dst,
		"qemu-img check -r leaks " + dst,
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("argv:\n got %q\nwant %q", *calls, want)
	}
	// The source is only ever read.
	for _, c := range (*calls)[1:] {
		if strings.HasSuffix(c, " "+src) && !strings.HasPrefix(c, "qemu-img info") {
			t.Fatalf("modified the source: %q", c)
		}
	}
}

// ---- guest agent freeze/thaw ---------------------------------------------

// fakeAgent is a minimal qemu-guest-agent on a unix socket: it honours the 0xFF
// resync + guest-sync-delimited, freeze/thaw/status, and can be told to send a
// stale reply first or to hang on freeze.
type fakeAgent struct {
	mu         sync.Mutex
	frozen     bool
	cmds       []string
	staleFirst bool
	hangFreeze bool
}

func (a *fakeAgent) serve(t *testing.T, sock string) {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go a.handle(c)
		}
	}()
}

func (a *fakeAgent) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	if a.staleFirst {
		c.Write([]byte(`{"return": 12345}` + "\n")) // queued for an earlier client
	}
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		line = bytes.TrimLeft(line, "\xff")
		var req struct {
			Execute   string         `json:"execute"`
			Arguments map[string]any `json:"arguments"`
		}
		if json.Unmarshal(line, &req) != nil {
			continue
		}
		a.mu.Lock()
		a.cmds = append(a.cmds, req.Execute)
		a.mu.Unlock()
		reply := func(v any) {
			b, _ := json.Marshal(map[string]any{"return": v})
			c.Write(append(b, '\n'))
		}
		switch req.Execute {
		case "guest-sync-delimited":
			c.Write([]byte{0xFF})
			reply(req.Arguments["id"])
		case "guest-fsfreeze-freeze":
			a.mu.Lock()
			hang := a.hangFreeze
			a.mu.Unlock()
			if hang {
				a.mu.Lock()
				a.frozen = true // the freeze completes in the guest, but the reply never comes
				a.mu.Unlock()
				time.Sleep(3 * time.Second)
				return
			}
			a.mu.Lock()
			a.frozen = true
			a.mu.Unlock()
			reply(2)
		case "guest-fsfreeze-thaw":
			a.mu.Lock()
			a.frozen = false
			a.mu.Unlock()
			reply(2)
		case "guest-fsfreeze-status":
			a.mu.Lock()
			st := "thawed"
			if a.frozen {
				st = "frozen"
			}
			a.mu.Unlock()
			reply(st)
		}
	}
}

func (a *fakeAgent) isFrozen() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.frozen
}

func TestGuestFreezeThaw(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "qga")
	a := &fakeAgent{staleFirst: true}
	a.serve(t, sock)
	n, err := GuestFsFreeze(sock, 5*time.Second)
	if err != nil || n != 2 {
		t.Fatalf("freeze = %d, %v", n, err)
	}
	if !a.isFrozen() {
		t.Fatal("agent not frozen")
	}
	if err := GuestFsThaw(sock, 5*time.Second); err != nil {
		t.Fatalf("thaw: %v", err)
	}
	if a.isFrozen() {
		t.Fatal("agent still frozen")
	}
}

func TestGuestFreezeTimeoutStillThaws(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "qga")
	a := &fakeAgent{hangFreeze: true}
	a.serve(t, sock)
	start := time.Now()
	if _, err := GuestFsFreeze(sock, 500*time.Millisecond); err == nil {
		t.Fatal("expected a freeze timeout")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("freeze did not honour its timeout")
	}
	a.mu.Lock()
	a.hangFreeze = false
	a.mu.Unlock()
	// The guest DID freeze after we gave up: the unconditional thaw must undo it.
	if err := GuestFsThaw(sock, 5*time.Second); err != nil {
		t.Fatalf("thaw: %v", err)
	}
	if a.isFrozen() {
		t.Fatal("left the guest frozen")
	}
}

func TestGuestFreezeNoAgent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent")
	start := time.Now()
	if _, err := GuestFsFreeze(sock, 5*time.Second); err == nil {
		t.Fatal("expected an error with no agent")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("no-agent freeze took too long")
	}
	if err := GuestFsThaw(sock, 1500*time.Millisecond); err == nil {
		t.Fatal("thaw with no agent should report failure")
	}
}
