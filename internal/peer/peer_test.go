package peer

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

// echo answers with the method, query and body it was given.
func echo(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, r.Method+" "+r.URL.RawQuery+" "+string(b))
}

func server(t *testing.T, a *Auth) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/x", a.Middleware(echo))
	mux.HandleFunc("/stream", a.MiddlewareStream(echo))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// rt rewrites requests or responses in flight (an attacker on the cluster net).
type rt struct {
	req  func(*http.Request)
	resp func(*http.Response)
}

func (f rt) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.req != nil {
		f.req(r)
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err == nil && f.resp != nil {
		f.resp(resp)
	}
	return resp, err
}

func TestRoundTrip(t *testing.T) {
	srv := server(t, NewAuth(secret))
	c := NewClient(secret)
	b, code, err := c.PostBody(srv.URL, "/x?id=7&kind=disk", []byte(`{"a":1}`))
	if err != nil || code != 200 || string(b) != `POST id=7&kind=disk {"a":1}` {
		t.Fatalf("PostBody: %q %d %v", b, code, err)
	}
	if b, code, err = c.Get(srv.URL, "/x"); err != nil || code != 200 || string(b) != "GET  " {
		t.Fatalf("Get: %q %d %v", b, code, err)
	}
	// A handler's own error status is MAC'd too: the caller can trust it.
	if _, code, err = c.Get(srv.URL, "/missing"); code != 404 || !errors.Is(err, ErrResponseAuth) {
		t.Fatalf("unrouted path (no middleware, no MAC): %d %v", code, err)
	}
}

// TestTamperedRequest: every signed part is bound.
func TestTamperedRequest(t *testing.T) {
	srv := server(t, NewAuth(secret))
	cases := map[string]func(*http.Request){
		"method": func(r *http.Request) { r.Method = http.MethodPut },
		"query":  func(r *http.Request) { r.URL.RawQuery = "id=8" },
		"path":   func(r *http.Request) { r.URL.Path = "/x/" },
		"body": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
		},
	}
	for name, mut := range cases {
		c := NewClient(secret)
		c.hc.Transport = rt{req: mut}
		_, code, _ := c.PostBody(srv.URL, "/x?id=7", []byte(`{"a":1}`))
		want := http.StatusForbidden
		if name == "path" {
			want = http.StatusNotFound // "/x/" isn't routed; signed for "/x" either way
		}
		if code != want {
			t.Errorf("%s tampered: status %d, want %d", name, code, want)
		}
	}
}

func TestReplayAndSkew(t *testing.T) {
	a := NewAuth(secret)
	srv := server(t, a)
	hdr := http.Header{}
	a.SetHeader(hdr, http.MethodGet, "/x", "")
	send := func(h string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
		req.Header.Set(authHeader, h)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := send(hdr.Get(authHeader)); c != 200 {
		t.Fatalf("first use: %d", c)
	}
	if c := send(hdr.Get(authHeader)); c != http.StatusForbidden {
		t.Fatalf("replay: %d, want 403", c)
	}
	old := time.Now().Add(-2 * skew).Unix()
	nonce := strings.Repeat("ab", 16)
	stale := strings.Join([]string{version, strconv.FormatInt(old, 10), nonce, digest(nil),
		a.requestSig(old, nonce, http.MethodGet, "/x", "", digest(nil), "")}, ".")
	if c := send(stale); c != http.StatusForbidden {
		t.Fatalf("stale timestamp: %d, want 403", c)
	}
	if c := send("1700000000.c2lnbmF0dXJl"); c != http.StatusForbidden {
		t.Fatalf("v1 header: %d, want 403", c)
	}
}

func TestWrongSecret(t *testing.T) {
	srv := server(t, NewAuth([]byte("another cluster's key, 32 bytes!")))
	_, code, err := NewClient(secret).Get(srv.URL, "/x")
	if code != http.StatusForbidden || !errors.Is(err, ErrResponseAuth) {
		t.Fatalf("wrong key: %d %v", code, err)
	}
}

func TestTamperedResponse(t *testing.T) {
	srv := server(t, NewAuth(secret))
	muts := map[string]func(*http.Response){
		"body": func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader("forged")) },
		"status": func(r *http.Response) {
			r.StatusCode = http.StatusInternalServerError
		},
		"location": func(r *http.Response) { r.Header.Set("Location", "http://evil/") },
		"cookie":   func(r *http.Response) { r.Header.Add("Set-Cookie", "vdx_session=x") },
	}
	for name, mut := range muts {
		c := NewClient(secret)
		c.hc.Transport = rt{resp: mut}
		if _, _, err := c.Get(srv.URL, "/x"); !errors.Is(err, ErrResponseAuth) {
			t.Errorf("%s tampered: err %v, want ErrResponseAuth", name, err)
		}
	}
	// A valid response to one request is not valid for another.
	a := NewAuth(secret)
	h1, h2 := http.Header{}, http.Header{}
	a.SetHeader(h1, http.MethodGet, "/x", "")
	a.SetHeader(h2, http.MethodGet, "/x", "")
	rec := httptest.NewRecorder()
	a.ServeSigned(rec, sigOf(h1.Get(authHeader)), func(w http.ResponseWriter) { io.WriteString(w, "ok") })
	if a.CheckResponse(sigOf(h2.Get(authHeader)), rec.Code, rec.Header(), rec.Body.Bytes()) {
		t.Fatalf("response accepted for a different request")
	}
	if !a.CheckResponse(sigOf(h1.Get(authHeader)), rec.Code, rec.Header(), rec.Body.Bytes()) {
		t.Fatalf("response rejected for its own request")
	}
}

func TestStream(t *testing.T) {
	srv := server(t, NewAuth(secret))
	c := NewClient(secret)
	payload := bytes.Repeat([]byte("disk-block "), 50000)
	b, code, err := c.PostStream(srv.URL, "/stream?id=1", bytes.NewReader(payload))
	if err != nil || code != 200 || string(b) != "POST id=1 "+string(payload) {
		t.Fatalf("stream: %d %v (len %d)", code, err, len(b))
	}

	// A body altered in flight fails the trailer check: the handler's read errors.
	old := streamClient.Transport
	t.Cleanup(func() { streamClient.Transport = old })
	streamClient.Transport = rt{req: func(r *http.Request) {
		r.Body = &flipFirst{ReadCloser: r.Body}
	}}
	_, code, err = c.PostStream(srv.URL, "/stream", bytes.NewReader(payload))
	if code != http.StatusBadRequest || err != nil {
		t.Fatalf("tampered stream: %d %v, want the handler's 400", code, err)
	}
	streamClient.Transport = old

	// A streamed body is refused on a buffered route, and needs its trailer.
	if _, code, _ = c.PostStream(srv.URL, "/x", bytes.NewReader(payload)); code != http.StatusForbidden {
		t.Fatalf("stream on a buffered route: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/stream", strings.NewReader("no trailer"))
	req.Header.Set(authHeader, c.auth.sign(http.MethodPost, "/stream", "", streamBody, ""))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("stream without a trailer: %d", resp.StatusCode)
	}
}

// flipFirst flips one bit of the first byte read.
type flipFirst struct {
	io.ReadCloser
	done bool
}

func (f *flipFirst) Read(b []byte) (int, error) {
	n, err := f.ReadCloser.Read(b)
	if n > 0 && !f.done {
		b[0] ^= 1
		f.done = true
	}
	return n, err
}

func TestAdminSignature(t *testing.T) {
	a := NewAuth(secret)
	var gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, sig, ok := a.VerifyAdmin(r)
		if !ok {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		gotUser = user
		a.ServeSigned(w, sig, func(w http.ResponseWriter) {
			http.Redirect(w, r, "/instances/1", http.StatusSeeOther)
		})
	}))
	defer srv.Close()
	post := func(mut func(*http.Request)) (*http.Response, string) {
		body := []byte("csrf=x&cpus=4")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/sessions/1/resize", bytes.NewReader(body))
		sig := a.SignAdmin(req, "alice", body)
		if mut != nil {
			mut(req)
		}
		cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp, sig
	}
	resp, sig := post(nil)
	rb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || gotUser != "alice" || !a.CheckResponse(sig, resp.StatusCode, resp.Header, rb) {
		t.Fatalf("admin round trip: %d user %q", resp.StatusCode, gotUser)
	}
	for name, mut := range map[string]func(*http.Request){
		"user": func(r *http.Request) { r.Header.Set(AdminUserHeader, "root") },
		"body": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("csrf=x&cpus=64"))
			r.ContentLength = 14
		},
		"method": func(r *http.Request) { r.Method = http.MethodPut },
		"as peer": func(r *http.Request) {
			r.Header.Set(authHeader, r.Header.Get(AdminHeader))
			r.Header.Del(AdminHeader)
		},
	} {
		if resp, _ := post(mut); resp.StatusCode != http.StatusForbidden {
			t.Errorf("admin request, %s changed: %d", name, resp.StatusCode)
		}
	}
	// A peer-API signature is not an admin one.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/sessions/1/resize", nil)
	a.SetHeader(req.Header, http.MethodPost, "/sessions/1/resize", "")
	req.Header.Set(AdminHeader, req.Header.Get(authHeader))
	req.Header.Set(AdminUserHeader, "alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("peer signature as admin: %d", resp.StatusCode)
	}
}

// TestWebsocketUpgradePassesThrough: an upgrade is authenticated but its
// handler gets the real ResponseWriter (it must hijack), so no response MAC.
func TestWebsocketUpgradePassesThrough(t *testing.T) {
	a := NewAuth(secret)
	var hijackable bool
	srv := httptest.NewServer(a.Middleware(func(w http.ResponseWriter, r *http.Request) {
		_, hijackable = w.(http.Hijacker)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/ws", nil)
	a.SetHeader(req.Header, http.MethodGet, "/ws", "")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || !hijackable {
		t.Fatalf("upgrade: %d hijackable=%v", resp.StatusCode, hijackable)
	}
}
