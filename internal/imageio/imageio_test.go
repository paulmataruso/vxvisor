package imageio

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"vdxclone/internal/nbd"
)

// memDisk is an in-memory Backend: data plus a per-64KiB "allocated" map and
// an optional dirty map, reported through the same NBD extent flags qemu uses.
type memDisk struct {
	mu      sync.Mutex
	data    []byte
	alloc   []bool // per block
	dirty   []bool
	flushes int
	closed  *int
}

const blk = 64 << 10

func newMemDisk(size int) *memDisk {
	n := (size + blk - 1) / blk
	return &memDisk{data: make([]byte, size), alloc: make([]bool, n), dirty: make([]bool, n), closed: new(int)}
}

func (m *memDisk) Size() uint64 { return uint64(len(m.data)) }
func (m *memDisk) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return copy(p, m.data[off:]), nil
}
func (m *memDisk) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for b := off / blk; b <= (off+int64(len(p))-1)/blk; b++ {
		m.alloc[b] = true
	}
	return copy(m.data[off:], p), nil
}
func (m *memDisk) WriteZeroes(off, length uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.data[off : off+length])
	return nil
}
func (m *memDisk) Flush() error { m.mu.Lock(); m.flushes++; m.mu.Unlock(); return nil }
func (m *memDisk) Close() error { m.mu.Lock(); *m.closed++; m.mu.Unlock(); return nil }
func (m *memDisk) Extents(ctx string, off, length uint64) ([]nbd.Extent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []nbd.Extent
	for b := range m.alloc {
		var f uint32
		switch ctx {
		case "base:allocation":
			if !m.alloc[b] {
				f = nbd.StateHole | nbd.StateZero
			}
		default:
			if m.dirty[b] {
				f = nbd.StateDirty
			}
		}
		l := uint64(blk)
		if rem := uint64(len(m.data)) - uint64(b)*blk; rem < l {
			l = rem
		}
		if n := len(out); n > 0 && out[n-1].Flags == f {
			out[n-1].Length += l
		} else {
			out = append(out, nbd.Extent{Offset: uint64(b) * blk, Length: l, Flags: f})
		}
	}
	return out, nil
}

const tid = "0123456789abcdef0123"

func setup(t *testing.T, tk Ticket, disk *memDisk) (*Server, *httptest.Server) {
	t.Helper()
	s := NewServer()
	tk.ID = tid
	tk.Size = disk.Size()
	tk.ZeroContext = "base:allocation"
	tk.Dial = func() (Backend, error) { return disk, nil }
	if err := s.Add(tk); err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(s)
	t.Cleanup(hs.Close)
	return s, hs
}

func do(t *testing.T, method, url string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func TestOptions(t *testing.T) {
	disk := newMemDisk(1 << 20)
	_, hs := setup(t, Ticket{Read: true}, disk)
	res, body := do(t, "OPTIONS", hs.URL+"/images/"+tid, nil, nil)
	if res.StatusCode != 200 || res.Header.Get("Allow") != "OPTIONS,GET" {
		t.Fatalf("status %d allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
	var o struct {
		Features   []string `json:"features"`
		MaxReaders int      `json:"max_readers"`
	}
	_ = json.Unmarshal(body, &o)
	if strings.Join(o.Features, ",") != "extents" || o.MaxReaders != 4 {
		t.Fatalf("read-only ticket options = %s", body)
	}
	res, body = do(t, "OPTIONS", hs.URL+"/images/*", nil, nil)
	if res.StatusCode != 200 || !strings.Contains(string(body), `"zero"`) {
		t.Fatalf("OPTIONS * = %d %s", res.StatusCode, body)
	}
	res, _ = do(t, "OPTIONS", hs.URL+"/images/nope-nope-nope-nope", nil, nil)
	if res.StatusCode != 403 {
		t.Fatalf("unknown ticket OPTIONS = %d, want 403", res.StatusCode)
	}
}

func TestGetRanges(t *testing.T) {
	disk := newMemDisk(1 << 20)
	for i := range disk.data {
		disk.data[i] = byte(i % 251)
	}
	_, hs := setup(t, Ticket{Read: true}, disk)
	url := hs.URL + "/images/" + tid

	res, body := do(t, "GET", url, nil, nil)
	if res.StatusCode != 200 || !bytes.Equal(body, disk.data) {
		t.Fatalf("full GET: %d len %d", res.StatusCode, len(body))
	}
	res, body = do(t, "GET", url, nil, map[string]string{"Range": "bytes=100-199"})
	if res.StatusCode != 206 || !bytes.Equal(body, disk.data[100:200]) ||
		res.Header.Get("Content-Range") != "bytes 100-199/1048576" {
		t.Fatalf("range GET: %d %q len %d", res.StatusCode, res.Header.Get("Content-Range"), len(body))
	}
	res, body = do(t, "GET", url, nil, map[string]string{"Range": "bytes=1048000-"})
	if res.StatusCode != 206 || !bytes.Equal(body, disk.data[1048000:]) {
		t.Fatalf("open-ended GET: %d len %d", res.StatusCode, len(body))
	}
	for _, bad := range []string{"bytes=1048576-", "bytes=0-1048576", "bytes=-10", "bytes=0-1,5-6"} {
		res, _ = do(t, "GET", url, nil, map[string]string{"Range": bad})
		if res.StatusCode != 416 {
			t.Fatalf("Range %q = %d, want 416", bad, res.StatusCode)
		}
	}
	res, _ = do(t, "GET", url, nil, map[string]string{"Range": "bytes=9-3"})
	if res.StatusCode != 400 {
		t.Fatalf("reversed range = %d, want 400", res.StatusCode)
	}
	// A read ticket cannot write.
	res, _ = do(t, "PUT", url, strings.NewReader("x"), nil)
	if res.StatusCode != 403 {
		t.Fatalf("PUT on read ticket = %d, want 403", res.StatusCode)
	}
}

func TestPutPatch(t *testing.T) {
	disk := newMemDisk(1 << 20)
	_, hs := setup(t, Ticket{Read: true, Write: true}, disk)
	url := hs.URL + "/images/" + tid

	payload := bytes.Repeat([]byte{0xab}, 4096)
	res, _ := do(t, "PUT", url+"?flush=n", bytes.NewReader(payload),
		map[string]string{"Content-Range": "bytes 65536-69631/*"})
	if res.StatusCode != 200 || !bytes.Equal(disk.data[65536:69632], payload) || disk.flushes != 0 {
		t.Fatalf("PUT: %d flushes=%d", res.StatusCode, disk.flushes)
	}
	res, _ = do(t, "PUT", url, bytes.NewReader(payload), nil) // default offset 0, flush=y
	if res.StatusCode != 200 || disk.data[0] != 0xab || disk.flushes != 1 {
		t.Fatalf("PUT@0: %d flushes=%d", res.StatusCode, disk.flushes)
	}
	res, _ = do(t, "PUT", url, bytes.NewReader(payload), map[string]string{"Content-Range": "bytes 1046529-1050624/*"})
	if res.StatusCode != 416 {
		t.Fatalf("PUT past end = %d, want 416", res.StatusCode)
	}
	res, _ = do(t, "PATCH", url, strings.NewReader(`{"op":"zero","offset":65536,"size":2048,"flush":true}`), nil)
	if res.StatusCode != 200 || disk.data[65536] != 0 || disk.data[65536+2048] != 0xab || disk.flushes != 2 {
		t.Fatalf("PATCH zero: %d flushes=%d", res.StatusCode, disk.flushes)
	}
	res, _ = do(t, "PATCH", url, strings.NewReader(`{"op":"flush"}`), nil)
	if res.StatusCode != 200 || disk.flushes != 3 {
		t.Fatalf("PATCH flush: %d", res.StatusCode)
	}
	for _, bad := range []string{`{"op":"trim"}`, `not json`, `{"op":"zero"}`} {
		res, _ = do(t, "PATCH", url, strings.NewReader(bad), nil)
		if res.StatusCode != 400 {
			t.Fatalf("PATCH %s = %d, want 400", bad, res.StatusCode)
		}
	}
	res, _ = do(t, "PATCH", url, strings.NewReader(`{"op":"zero","offset":1048000,"size":4096}`), nil)
	if res.StatusCode != 416 {
		t.Fatalf("PATCH zero past end = %d, want 416", res.StatusCode)
	}
}

// TestRawOnly: a raw upload ticket refuses a qcow2 container at offset 0 and
// accepts the same bytes elsewhere (guest data can contain anything).
func TestRawOnly(t *testing.T) {
	disk := newMemDisk(1 << 20)
	_, hs := setup(t, Ticket{Read: true, Write: true, RawOnly: true}, disk)
	url := hs.URL + "/images/" + tid
	img := append([]byte("QFI\xfb\x00\x00\x00\x03"), make([]byte, 504)...)
	res, body := do(t, "PUT", url, bytes.NewReader(img), map[string]string{"Content-Range": "bytes 0-511/*"})
	if res.StatusCode != 400 || !strings.Contains(string(body), "qcow2") || disk.data[0] != 0 {
		t.Fatalf("qcow2 header at 0: %d %s", res.StatusCode, body)
	}
	res, _ = do(t, "PUT", url, bytes.NewReader(img), map[string]string{"Content-Range": "bytes 4096-4607/*"})
	if res.StatusCode != 200 || disk.data[4096] != 'Q' {
		t.Fatalf("qcow2 bytes inside the disk: %d", res.StatusCode)
	}
}

func TestExtents(t *testing.T) {
	disk := newMemDisk(4 * blk)
	disk.alloc[1] = true
	disk.alloc[2] = true
	disk.dirty[2] = true
	disk.dirty[3] = true
	s, hs := setup(t, Ticket{Read: true}, disk)
	url := hs.URL + "/images/" + tid + "/extents"

	res, body := do(t, "GET", url, nil, nil)
	want := `[{"start":0,"length":65536,"zero":true,"hole":true},{"start":65536,"length":131072,"zero":false,"hole":false},{"start":196608,"length":65536,"zero":true,"hole":true}]`
	if res.StatusCode != 200 || string(body) != want {
		t.Fatalf("zero extents = %d %s", res.StatusCode, body)
	}
	res, _ = do(t, "GET", url+"?context=dirty", nil, nil)
	if res.StatusCode != 404 {
		t.Fatalf("dirty extents on a full-backup ticket = %d, want 404", res.StatusCode)
	}
	// An incremental ticket reports dirty extents, each split by zero-ness.
	s.Remove(tid, time.Second)
	_ = s.Add(Ticket{ID: tid, Read: true, Size: disk.Size(), ZeroContext: "base:allocation",
		DirtyContext: "qemu:dirty-bitmap:x", Dial: func() (Backend, error) { return disk, nil }})
	res, body = do(t, "GET", url+"?context=dirty", nil, nil)
	want = `[{"start":0,"length":65536,"dirty":false,"zero":true},{"start":65536,"length":65536,"dirty":false,"zero":false},{"start":131072,"length":65536,"dirty":true,"zero":false},{"start":196608,"length":65536,"dirty":true,"zero":true}]`
	if res.StatusCode != 200 || string(body) != want {
		t.Fatalf("dirty extents = %d %s", res.StatusCode, body)
	}
	res, _ = do(t, "GET", url+"?context=bogus", nil, nil)
	if res.StatusCode != 400 {
		t.Fatalf("bad context = %d", res.StatusCode)
	}
}

func TestMergeDirty(t *testing.T) {
	// The first dirty extent "0-0" keeps the zero split; adjacent equal
	// results coalesce.
	dirty := []nbd.Extent{{Offset: 0, Length: 100, Flags: 1}, {Offset: 100, Length: 50, Flags: 0}}
	zero := []ZeroExtent{{Start: 0, Length: 30, Zero: true}, {Start: 30, Length: 120}}
	got := MergeDirty(dirty, zero)
	want := []DirtyExtent{{0, 30, true, true}, {30, 70, true, false}, {100, 50, false, false}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("extent %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestTicketLifecycle(t *testing.T) {
	disk := newMemDisk(blk)
	s, hs := setup(t, Ticket{Read: true, InactivityTimeout: time.Minute}, disk)
	clock := time.Now()
	s.now = func() time.Time { return clock }
	url := hs.URL + "/images/" + tid

	if res, _ := do(t, "GET", url, nil, map[string]string{"Range": "bytes=0-9"}); res.StatusCode != 206 {
		t.Fatalf("live ticket GET = %d", res.StatusCode)
	}
	st, ok := s.Status(tid)
	if !ok || st.Transferred != 10 || st.Active || st.Expired {
		t.Fatalf("status = %+v ok=%v", st, ok)
	}
	clock = clock.Add(2 * time.Minute) // idle past the inactivity timeout
	if st, _ := s.Status(tid); !st.Expired {
		t.Fatal("ticket should report expired")
	}
	if res, _ := do(t, "GET", url, nil, nil); res.StatusCode != 403 {
		t.Fatalf("expired ticket GET = %d, want 403", res.StatusCode)
	}
	s.Remove(tid, time.Second)
	if *disk.closed != 1 {
		t.Fatalf("backend closed %d times, want 1", *disk.closed)
	}
	if res, _ := do(t, "GET", url, nil, nil); res.StatusCode != 403 {
		t.Fatalf("removed ticket GET = %d, want 403", res.StatusCode)
	}
	if _, ok := s.Status(tid); ok {
		t.Fatal("removed ticket still has a status")
	}
	// Deadline expiry.
	_ = s.Add(Ticket{ID: tid, Read: true, Size: blk, Deadline: clock.Add(-time.Second),
		Dial: func() (Backend, error) { return disk, nil }})
	if res, _ := do(t, "GET", url, nil, nil); res.StatusCode != 403 {
		t.Fatalf("past-deadline ticket GET = %d, want 403", res.StatusCode)
	}
	if err := s.Add(Ticket{ID: "short", Read: true, Dial: func() (Backend, error) { return disk, nil }}); err == nil {
		t.Fatal("a guessable short ticket id was accepted")
	}
}
