// Package imageio is an ovirt-imageio–compatible data server: the HTTPS
// protocol oVirt clients (the SDK's imageio client, Veeam's oVirt KVM workers)
// use to read and write disk images during backup, restore and upload.
//
//	OPTIONS /images/{ticket}            capabilities (JSON)
//	GET     /images/{ticket}            data, honouring a single byte Range
//	PUT     /images/{ticket}            data at the Content-Range offset (?flush=y|n)
//	PATCH   /images/{ticket}            {"op":"zero"|"flush", ...}
//	GET     /images/{ticket}/extents    ?context=zero|dirty (JSON)
//
// The ticket id in the URL is the only credential, exactly as in oVirt: the
// engine API mints a random one per transfer, scoped to one disk and one
// direction, and removes it when the transfer ends. A ticket also expires on
// its own after InactivityTimeout with no request in flight, or at Deadline.
//
// Each ticket is backed by NBD connections (internal/nbd) to the export
// internal/vmbackup set up; up to MaxConns run in parallel per ticket.
package imageio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/nbd"
)

// Backend is one connection to the disk behind a ticket. *nbd.Client
// satisfies it.
type Backend interface {
	Size() uint64
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	WriteZeroes(off, length uint64) error
	Flush() error
	Extents(context string, off, length uint64) ([]nbd.Extent, error)
	Close() error
}

// Ticket authorizes access to one disk.
type Ticket struct {
	ID    string
	Read  bool
	Write bool
	Size  uint64
	// ZeroContext is the NBD meta context for allocation extents
	// ("base:allocation"); "" reports the whole image as data.
	ZeroContext string
	// DirtyContext is the qemu:dirty-bitmap:* context of an incremental
	// backup; "" means the ticket has no dirty extents.
	DirtyContext string
	// InactivityTimeout expires the ticket once no request has been in flight
	// for this long (0 = never). Deadline is a hard expiry (zero = none).
	InactivityTimeout time.Duration
	Deadline          time.Time
	// MaxConns bounds parallel backend connections (default 4).
	MaxConns int
	// RawOnly refuses an upload whose data at offset 0 is a qcow2 header:
	// the backend takes guest data, so a client sending a qcow2 container
	// (oVirt format "cow" semantics) would otherwise write a corrupt disk.
	RawOnly bool
	// Dial opens one backend connection.
	Dial func() (Backend, error)
}

// Status is a ticket's live transfer state.
type Status struct {
	Active      bool   // a request is in flight
	Transferred uint64 // payload bytes read or written
	Idle        time.Duration
	Expired     bool
}

type ticket struct {
	Ticket
	mu          sync.Mutex
	cond        *sync.Cond
	idle        []Backend
	open        int
	inflight    int
	transferred uint64
	last        time.Time
	removed     bool
}

// Server serves the imageio protocol for its registered tickets.
type Server struct {
	mu      sync.Mutex
	tickets map[string]*ticket
	now     func() time.Time
	// MaxRequestBody bounds a PATCH body.
	maxPatch int64
}

// NewServer returns an empty server.
func NewServer() *Server {
	return &Server{tickets: map[string]*ticket{}, now: time.Now, maxPatch: 4096}
}

// Add registers a ticket.
func (s *Server) Add(t Ticket) error {
	if len(t.ID) < 16 || t.Dial == nil || (!t.Read && !t.Write) {
		return errors.New("imageio: invalid ticket")
	}
	if t.MaxConns <= 0 {
		t.MaxConns = 4
	}
	tk := &ticket{Ticket: t, last: s.now()}
	tk.cond = sync.NewCond(&tk.mu)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.tickets[t.ID]; dup {
		return errors.New("imageio: duplicate ticket")
	}
	s.tickets[t.ID] = tk
	return nil
}

// Remove revokes a ticket: new requests get 403 at once; idle connections are
// closed now and busy ones as their requests finish. Remove blocks until every
// connection is closed (or timeout), so the caller can then tear down the
// export underneath.
func (s *Server) Remove(id string, timeout time.Duration) {
	s.mu.Lock()
	tk := s.tickets[id]
	delete(s.tickets, id)
	s.mu.Unlock()
	if tk == nil {
		return
	}
	tk.mu.Lock()
	tk.removed = true
	for _, b := range tk.idle {
		_ = b.Close()
		tk.open--
	}
	tk.idle = nil
	tk.cond.Broadcast()
	deadline := time.Now().Add(timeout)
	for tk.open > 0 && time.Now().Before(deadline) {
		tk.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		tk.mu.Lock()
	}
	tk.mu.Unlock()
}

// Status reports a ticket's transfer state.
func (s *Server) Status(id string) (Status, bool) {
	s.mu.Lock()
	tk := s.tickets[id]
	s.mu.Unlock()
	if tk == nil {
		return Status{}, false
	}
	now := s.now()
	tk.mu.Lock()
	defer tk.mu.Unlock()
	return Status{Active: tk.inflight > 0, Transferred: tk.transferred, Idle: now.Sub(tk.last),
		Expired: tk.expiredLocked(now)}, true
}

func (tk *ticket) expiredLocked(now time.Time) bool {
	if !tk.Deadline.IsZero() && now.After(tk.Deadline) {
		return true
	}
	return tk.InactivityTimeout > 0 && tk.inflight == 0 && now.Sub(tk.last) > tk.InactivityTimeout
}

// errTicket is any authorization failure; the client sees 403, as in imageio.
type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

func herr(code int, format string, a ...any) error {
	return &httpError{code: code, msg: fmt.Sprintf(format, a...)}
}

// acquire looks up and authorizes a ticket for op ("read"/"write") and marks a
// request in flight. release must be called when the request ends.
func (s *Server) acquire(id, op string) (*ticket, error) {
	s.mu.Lock()
	tk := s.tickets[id]
	s.mu.Unlock()
	if tk == nil {
		return nil, herr(http.StatusForbidden, "You are not allowed to access this resource: No such ticket %s", id)
	}
	now := s.now()
	tk.mu.Lock()
	defer tk.mu.Unlock()
	if tk.removed || tk.expiredLocked(now) {
		return nil, herr(http.StatusForbidden, "You are not allowed to access this resource: Ticket %s expired", id)
	}
	if (op == "read" && !tk.Read) || (op == "write" && !tk.Write) {
		return nil, herr(http.StatusForbidden, "You are not allowed to access this resource: Ticket %s forbids %s", id, op)
	}
	tk.inflight++
	tk.last = now
	return tk, nil
}

func (s *Server) release(tk *ticket, n uint64) {
	tk.mu.Lock()
	tk.inflight--
	tk.transferred += n
	tk.last = s.now()
	tk.mu.Unlock()
}

// backend checks out a connection, dialing a new one while under MaxConns.
func (tk *ticket) backend(ctx context.Context) (Backend, error) {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	for {
		if tk.removed {
			return nil, herr(http.StatusForbidden, "ticket was removed")
		}
		if n := len(tk.idle); n > 0 {
			b := tk.idle[n-1]
			tk.idle = tk.idle[:n-1]
			return b, nil
		}
		if tk.open < tk.MaxConns {
			tk.open++
			tk.mu.Unlock()
			b, err := tk.Dial()
			tk.mu.Lock()
			if err != nil {
				tk.open--
				tk.cond.Broadcast()
				return nil, herr(http.StatusInternalServerError, "cannot open disk: %v", err)
			}
			return b, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		tk.cond.Wait()
	}
}

// put returns a connection; a broken one (err != nil) is closed instead.
func (tk *ticket) put(b Backend, broken bool) {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	if broken || tk.removed {
		_ = b.Close()
		tk.open--
	} else {
		tk.idle = append(tk.idle, b)
	}
	tk.cond.Broadcast()
}

// ServeHTTP routes /images/... requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/images/")
	if !ok {
		if r.URL.Path == "/info" || r.URL.Path == "/info/" {
			writeJSON(w, http.StatusOK, map[string]any{"version": Version})
			return
		}
		http.Error(w, "No such resource", http.StatusNotFound)
		return
	}
	id, sub, _ := strings.Cut(rest, "/")
	var err error
	switch {
	case sub == "extents" && r.Method == http.MethodGet:
		err = s.extents(w, r, id)
	case sub != "":
		err = herr(http.StatusNotFound, "No such resource")
	case r.Method == http.MethodOptions:
		err = s.options(w, id)
	case r.Method == http.MethodGet:
		err = s.get(w, r, id)
	case r.Method == http.MethodPut:
		err = s.put(w, r, id)
	case r.Method == http.MethodPatch:
		err = s.patch(w, r, id)
	default:
		w.Header().Set("Allow", "OPTIONS,GET,PUT,PATCH")
		err = herr(http.StatusMethodNotAllowed, "Method %s not allowed", r.Method)
	}
	if err != nil {
		var he *httpError
		code := http.StatusInternalServerError
		if errors.As(err, &he) {
			code = he.code
		}
		http.Error(w, err.Error(), code)
	}
}

// Version is the imageio protocol version reported by /info.
const Version = "2.5.0"

var allFeatures = []string{"extents", "zero", "flush"}

func (s *Server) options(w http.ResponseWriter, id string) error {
	allow := []string{"OPTIONS", "GET", "PUT", "PATCH"}
	features := allFeatures
	maxConns := 8
	if id != "*" {
		s.mu.Lock()
		tk := s.tickets[id]
		s.mu.Unlock()
		if tk == nil {
			return herr(http.StatusForbidden, "You are not allowed to access this resource: No such ticket %s", id)
		}
		allow = []string{"OPTIONS"}
		features = []string{}
		if tk.Read {
			allow = append(allow, "GET")
			features = []string{"extents"}
		}
		if tk.Write {
			allow = append(allow, "PUT", "PATCH")
			features = allFeatures
		}
		maxConns = tk.MaxConns
	}
	w.Header().Set("Allow", strings.Join(allow, ","))
	writeJSON(w, http.StatusOK, map[string]any{
		"features": features, "max_readers": maxConns, "max_writers": maxConns,
	})
	return nil
}

// parseRange parses a single "bytes=first-[last]" range against size. ok is
// false when there is no Range header.
func parseRange(h string, size uint64) (first, last uint64, ok bool, err error) {
	if h == "" {
		return 0, 0, false, nil
	}
	spec, found := strings.CutPrefix(h, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false, herr(http.StatusRequestedRangeNotSatisfiable, "Unsupported range %q", h)
	}
	a, b, _ := strings.Cut(spec, "-")
	if a == "" { // suffix ranges are not part of the imageio protocol
		return 0, 0, false, herr(http.StatusRequestedRangeNotSatisfiable, "Unsupported range %q", h)
	}
	first, err = strconv.ParseUint(a, 10, 64)
	if err != nil {
		return 0, 0, false, herr(http.StatusBadRequest, "Invalid range %q", h)
	}
	last = size - 1
	if b != "" {
		if last, err = strconv.ParseUint(b, 10, 64); err != nil || last < first {
			return 0, 0, false, herr(http.StatusBadRequest, "Invalid range %q", h)
		}
	}
	if size == 0 || first >= size || last >= size {
		return 0, 0, false, herr(http.StatusRequestedRangeNotSatisfiable, "Requested range %q not satisfiable (size %d)", h, size)
	}
	return first, last, true, nil
}

const chunk = 4 << 20

func (s *Server) get(w http.ResponseWriter, r *http.Request, id string) error {
	tk, err := s.acquire(id, "read")
	if err != nil {
		return err
	}
	var n uint64
	defer func() { s.release(tk, n) }()
	first, last, ranged, err := parseRange(r.Header.Get("Range"), tk.Size)
	if err != nil {
		if he := (*httpError)(nil); errors.As(err, &he) && he.code == http.StatusRequestedRangeNotSatisfiable {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", tk.Size))
		}
		return err
	}
	if !ranged {
		if tk.Size == 0 {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return nil
		}
		first, last = 0, tk.Size-1
	}
	b, err := tk.backend(r.Context())
	if err != nil {
		return err
	}
	length := last - first + 1
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatUint(length, 10))
	if ranged {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, tk.Size))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	buf := make([]byte, min(length, chunk))
	off := first
	broken := false
	for off <= last {
		p := buf[:min(uint64(len(buf)), last-off+1)]
		if _, err := b.ReadAt(p, int64(off)); err != nil {
			// Headers are gone; abort the connection so the client sees a
			// short body rather than silently wrong data.
			broken = true
			tk.put(b, true)
			panic(http.ErrAbortHandler)
		}
		if _, err := w.Write(p); err != nil {
			break // client went away; the backend is still fine
		}
		off += uint64(len(p))
		n += uint64(len(p))
	}
	if !broken {
		tk.put(b, false)
	}
	return nil
}

// contentRangeStart parses the offset from "bytes first-last/total|*".
func contentRangeStart(h string) (uint64, error) {
	if h == "" {
		return 0, nil
	}
	spec, ok := strings.CutPrefix(h, "bytes ")
	if !ok {
		return 0, herr(http.StatusBadRequest, "Invalid Content-Range %q", h)
	}
	a, _, _ := strings.Cut(spec, "-")
	v, err := strconv.ParseUint(a, 10, 64)
	if err != nil {
		return 0, herr(http.StatusBadRequest, "Invalid Content-Range %q", h)
	}
	return v, nil
}

func flushParam(r *http.Request, def bool) bool {
	switch r.URL.Query().Get("flush") {
	case "y":
		return true
	case "n":
		return false
	}
	return def
}

var qcow2Magic = []byte("QFI\xfb")

func (s *Server) put(w http.ResponseWriter, r *http.Request, id string) error {
	tk, err := s.acquire(id, "write")
	if err != nil {
		return err
	}
	var n uint64
	defer func() { s.release(tk, n) }()
	if r.ContentLength < 0 {
		return herr(http.StatusLengthRequired, "Content-Length required")
	}
	off, err := contentRangeStart(r.Header.Get("Content-Range"))
	if err != nil {
		return err
	}
	size := uint64(r.ContentLength)
	if off+size > tk.Size {
		return herr(http.StatusRequestedRangeNotSatisfiable, "Requested range not satisfiable: %d+%d > %d", off, size, tk.Size)
	}
	b, err := tk.backend(r.Context())
	if err != nil {
		return err
	}
	buf := make([]byte, min(max(size, 1), chunk))
	for n < size {
		p := buf[:min(uint64(len(buf)), size-n)]
		if _, err := io.ReadFull(r.Body, p); err != nil {
			tk.put(b, false)
			return herr(http.StatusBadRequest, "short request body: %v", err)
		}
		if tk.RawOnly && off+n == 0 && bytes.HasPrefix(p, qcow2Magic) {
			tk.put(b, false)
			return herr(http.StatusBadRequest, "this transfer takes raw guest data, not a qcow2 image; upload with format=raw")
		}
		if _, err := b.WriteAt(p, int64(off+n)); err != nil {
			tk.put(b, true)
			return herr(http.StatusInternalServerError, "write failed: %v", err)
		}
		n += uint64(len(p))
	}
	if flushParam(r, true) {
		if err := b.Flush(); err != nil {
			tk.put(b, true)
			return herr(http.StatusInternalServerError, "flush failed: %v", err)
		}
	}
	tk.put(b, false)
	w.WriteHeader(http.StatusOK)
	return nil
}

type patchReq struct {
	Op     string  `json:"op"`
	Offset *uint64 `json:"offset"`
	Size   *uint64 `json:"size"`
	Flush  bool    `json:"flush"`
}

func (s *Server) patch(w http.ResponseWriter, r *http.Request, id string) error {
	tk, err := s.acquire(id, "write")
	if err != nil {
		return err
	}
	defer s.release(tk, 0)
	var req patchReq
	if err := json.NewDecoder(io.LimitReader(r.Body, s.maxPatch)).Decode(&req); err != nil {
		return herr(http.StatusBadRequest, "Invalid JSON: %v", err)
	}
	b, err := tk.backend(r.Context())
	if err != nil {
		return err
	}
	switch req.Op {
	case "zero":
		if req.Size == nil {
			tk.put(b, false)
			return herr(http.StatusBadRequest, "Missing size")
		}
		off := uint64(0)
		if req.Offset != nil {
			off = *req.Offset
		}
		if off+*req.Size > tk.Size {
			tk.put(b, false)
			return herr(http.StatusRequestedRangeNotSatisfiable, "Requested range not satisfiable: %d+%d > %d", off, *req.Size, tk.Size)
		}
		if err := b.WriteZeroes(off, *req.Size); err != nil {
			tk.put(b, true)
			return herr(http.StatusInternalServerError, "zero failed: %v", err)
		}
		if req.Flush {
			if err := b.Flush(); err != nil {
				tk.put(b, true)
				return herr(http.StatusInternalServerError, "flush failed: %v", err)
			}
		}
	case "flush":
		if err := b.Flush(); err != nil {
			tk.put(b, true)
			return herr(http.StatusInternalServerError, "flush failed: %v", err)
		}
	default:
		tk.put(b, false)
		return herr(http.StatusBadRequest, "Unsupported operation %q", req.Op)
	}
	tk.put(b, false)
	w.WriteHeader(http.StatusOK)
	return nil
}

// ZeroExtent is one extent of context=zero.
type ZeroExtent struct {
	Start  uint64 `json:"start"`
	Length uint64 `json:"length"`
	Zero   bool   `json:"zero"`
	Hole   bool   `json:"hole"`
}

// DirtyExtent is one extent of context=dirty.
type DirtyExtent struct {
	Start  uint64 `json:"start"`
	Length uint64 `json:"length"`
	Dirty  bool   `json:"dirty"`
	Zero   bool   `json:"zero"`
}

func (s *Server) extents(w http.ResponseWriter, r *http.Request, id string) error {
	tk, err := s.acquire(id, "read")
	if err != nil {
		return err
	}
	defer s.release(tk, 0)
	ctxName := r.URL.Query().Get("context")
	if ctxName == "" {
		ctxName = "zero"
	}
	if ctxName != "zero" && ctxName != "dirty" {
		return herr(http.StatusBadRequest, "Invalid context %q", ctxName)
	}
	if ctxName == "dirty" && tk.DirtyContext == "" {
		return herr(http.StatusNotFound, "Ticket %s does not support dirty extents", id)
	}
	b, err := tk.backend(r.Context())
	if err != nil {
		return err
	}
	zero, err := zeroExtents(b, tk)
	if err != nil {
		tk.put(b, true)
		return herr(http.StatusInternalServerError, "extents: %v", err)
	}
	if ctxName == "zero" {
		tk.put(b, false)
		writeJSON(w, http.StatusOK, zero)
		return nil
	}
	dirty, err := b.Extents(tk.DirtyContext, 0, tk.Size)
	if err != nil {
		tk.put(b, true)
		return herr(http.StatusInternalServerError, "dirty extents: %v", err)
	}
	tk.put(b, false)
	writeJSON(w, http.StatusOK, MergeDirty(dirty, zero))
	return nil
}

func zeroExtents(b Backend, tk *ticket) ([]ZeroExtent, error) {
	if tk.Size == 0 {
		return []ZeroExtent{}, nil
	}
	if tk.ZeroContext == "" {
		return []ZeroExtent{{Start: 0, Length: tk.Size}}, nil
	}
	ext, err := b.Extents(tk.ZeroContext, 0, tk.Size)
	if err != nil {
		return nil, err
	}
	out := make([]ZeroExtent, 0, len(ext))
	for _, e := range ext {
		z := ZeroExtent{Start: e.Offset, Length: e.Length, Zero: e.Flags&nbd.StateZero != 0, Hole: e.Flags&nbd.StateHole != 0}
		if n := len(out); n > 0 && out[n-1].Zero == z.Zero && out[n-1].Hole == z.Hole {
			out[n-1].Length += z.Length
			continue
		}
		out = append(out, z)
	}
	return out, nil
}

// MergeDirty splits the dirty-bitmap extents at the zero extents' boundaries so
// each dirty extent also says whether it reads as zeroes (a client then skips
// the GET and writes a zero range instead). Both lists cover the same range
// contiguously from offset 0.
func MergeDirty(dirty []nbd.Extent, zero []ZeroExtent) []DirtyExtent {
	out := []DirtyExtent{}
	j := 0
	for _, d := range dirty {
		start, end := d.Offset, d.Offset+d.Length
		isDirty := d.Flags&nbd.StateDirty != 0
		for start < end {
			for j < len(zero) && zero[j].Start+zero[j].Length <= start {
				j++
			}
			segEnd, isZero := end, false
			if j < len(zero) && zero[j].Start <= start {
				segEnd = min(end, zero[j].Start+zero[j].Length)
				isZero = zero[j].Zero
			} else if j < len(zero) {
				segEnd = min(end, zero[j].Start)
			}
			x := DirtyExtent{Start: start, Length: segEnd - start, Dirty: isDirty, Zero: isZero}
			if n := len(out); n > 0 && out[n-1].Dirty == x.Dirty && out[n-1].Zero == x.Zero {
				out[n-1].Length += x.Length
			} else {
				out = append(out, x)
			}
			start = segEnd
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(code)
	_, _ = w.Write(b)
}
