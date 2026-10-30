// Package peer is the authenticated node-to-node cluster API transport. It binds
// to the cluster NIC only and signs every request with keys derived from the
// shared cluster secret: the HMAC covers the method, path, query, a body digest,
// a timestamp and a single-use nonce, and every response carries a MAC bound to
// the request it answers. So aggregation, lifecycle proxying, migrations and
// account sync between nodes can't be forged, altered, or replayed by anyone on
// the cluster network without the secret. It is a leaf package (no service/web
// deps) so both the server side (web) and the client side (service/worker) can
// use it without import cycles.
package peer

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	authHeader = "X-Cluster-Auth"
	// AdminHeader / AdminUserHeader carry a cluster-admin reverse-proxy request
	// (an admin's action forwarded from the VIP to the node that owns the VM).
	// The user is covered by the signature.
	AdminHeader     = "X-Cluster-Admin"
	AdminUserHeader = "X-Cluster-Admin-User"
	// respHeader carries the response MAC (absent on a websocket upgrade).
	respHeader = "X-Cluster-Resp-Auth"
	// bodyTrailer carries a streamed request body's MAC, sent after the body.
	bodyTrailer = "X-Cluster-Body-Mac"
	version     = "v2"
	// streamBody is the body digest of a streamed request (see PostStream).
	streamBody = "stream"
	skew       = 30 * time.Second
	// maxBody caps a buffered (non-streamed) request body.
	maxBody = 32 << 20
)

// APIPort is the fixed port the node-to-node peer API listens on (cluster NIC).
const APIPort = 8767

// ErrResponseAuth: a peer's response had no valid MAC, so its body and status
// can't be trusted (a forged or altered reply, a node on another secret, or an
// older node that doesn't sign responses).
var ErrResponseAuth = errors.New("peer response failed authentication")

// Auth signs and verifies peer traffic with keys derived from the cluster secret
// (one per direction, so a request MAC can never pass as a response MAC).
type Auth struct {
	reqKey, respKey []byte
	nonces          *nonceCache
}

func NewAuth(secret []byte) *Auth {
	return &Auth{
		reqKey:  derive(secret, "vxvisor peer request v2"),
		respKey: derive(secret, "vxvisor peer response v2"),
		nonces:  &nonceCache{seen: map[string]int64{}},
	}
}

func derive(secret []byte, label string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(label))
	return h.Sum(nil)
}

func (a *Auth) mac(key []byte, parts ...string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strings.Join(parts, "\n")))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// requestSig signs one request. bodySum is the hex SHA-256 of the body, or
// streamBody for a streamed body authenticated by its trailer. principal is ""
// on the peer API and "admin:<user>" on the admin reverse proxy, so neither
// header can stand in for the other.
func (a *Auth) requestSig(ts int64, nonce, method, path, rawQuery, bodySum, principal string) string {
	return a.mac(a.reqKey, version, strconv.FormatInt(ts, 10), nonce, method, path, rawQuery, bodySum, principal)
}

// sign returns a signed auth header value for one request.
func (a *Auth) sign(method, path, rawQuery, bodySum, principal string) string {
	ts := time.Now().Unix()
	var nb [16]byte
	_, _ = rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	return strings.Join([]string{version, strconv.FormatInt(ts, 10), nonce, bodySum,
		a.requestSig(ts, nonce, method, path, rawQuery, bodySum, principal)}, ".")
}

// parsedAuth is a decoded X-Cluster-Auth header.
type parsedAuth struct {
	ts                  int64
	nonce, bodySum, sig string
}

func parseHeader(h string) (parsedAuth, bool) {
	f := strings.Split(h, ".")
	if len(f) != 5 || f[0] != version {
		return parsedAuth{}, false
	}
	ts, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || len(f[2]) != 32 || f[3] == "" || f[4] == "" {
		return parsedAuth{}, false
	}
	return parsedAuth{ts: ts, nonce: f[2], bodySum: f[3], sig: f[4]}, true
}

// verify checks a request header's signature, freshness and nonce (each nonce
// is accepted once). It does not check the body digest; the caller does.
func (a *Auth) verify(r *http.Request, header, principal string) (parsedAuth, bool) {
	p, ok := parseHeader(r.Header.Get(header))
	if !ok {
		return p, false
	}
	if d := time.Since(time.Unix(p.ts, 0)); d > skew || d < -skew {
		return p, false
	}
	want := a.requestSig(p.ts, p.nonce, r.Method, r.URL.Path, r.URL.RawQuery, p.bodySum, principal)
	if !hmac.Equal([]byte(p.sig), []byte(want)) {
		return p, false
	}
	return p, a.nonces.use(p.nonce, p.ts)
}

// readVerifiedBody buffers a request body (up to maxBody), checks it against
// the signed digest, and puts it back on the request.
func readVerifiedBody(r *http.Request, bodySum string) (int, bool) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(b) > maxBody {
		return http.StatusRequestEntityTooLarge, false
	}
	if !hmac.Equal([]byte(digest(b)), []byte(bodySum)) {
		return http.StatusForbidden, false
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return 0, true
}

// nonceCache remembers nonces for the skew window so a captured request can't
// be replayed. Entries older than the window are pruned on use.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

const maxNonces = 200000

func (c *nonceCache) use(nonce string, ts int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.seen[nonce]; dup {
		return false
	}
	if len(c.seen) >= maxNonces/2 {
		cutoff := time.Now().Add(-2 * skew).Unix()
		for n, t := range c.seen {
			if t < cutoff {
				delete(c.seen, n)
			}
		}
		if len(c.seen) >= maxNonces {
			return false // flooded with valid signatures: fail closed
		}
	}
	c.seen[nonce] = ts
	return true
}

// Middleware authenticates a peer request with a buffered body (up to maxBody)
// and MACs the response. A websocket upgrade is verified the same way (it has
// no body), but its response can't be MAC'd: the connection is hijacked.
func (a *Auth) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return a.middleware(next, false)
}

// MiddlewareStream is Middleware for a route that takes a streamed body (a
// disk copy). The body is passed through unbuffered; reading it to the end
// fails unless its trailer MAC matches, so the handler must read it fully
// and treat a read error as rejection before it commits anything.
func (a *Auth) MiddlewareStream(next http.HandlerFunc) http.HandlerFunc {
	return a.middleware(next, true)
}

func (a *Auth) middleware(next http.HandlerFunc, stream bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.verify(r, authHeader, "")
		if !ok {
			http.Error(w, "cluster auth failed", http.StatusForbidden)
			return
		}
		if p.bodySum == streamBody {
			if !stream {
				http.Error(w, "cluster auth failed", http.StatusForbidden)
				return
			}
			r.Body = &trailerVerifier{body: r.Body, req: r, h: sha256.New(), auth: a, sig: p.sig}
		} else if code, ok := readVerifiedBody(r, p.bodySum); !ok {
			http.Error(w, "cluster auth failed", code)
			return
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			next(w, r)
			return
		}
		a.ServeSigned(w, p.sig, func(w http.ResponseWriter) { next(w, r) })
	}
}

// VerifyAdmin authenticates a cluster-admin reverse-proxy request: the signed
// method, path, query, body and user. It returns the user and the request
// signature (for ServeSigned), or ok=false.
func (a *Auth) VerifyAdmin(r *http.Request) (user, sig string, ok bool) {
	user = r.Header.Get(AdminUserHeader)
	if user == "" || r.Header.Get(AdminHeader) == "" {
		return "", "", false
	}
	p, ok := a.verify(r, AdminHeader, "admin:"+user)
	if !ok || p.bodySum == streamBody {
		return "", "", false
	}
	if _, ok := readVerifiedBody(r, p.bodySum); !ok {
		return "", "", false
	}
	return user, p.sig, true
}

// SignAdmin signs an admin reverse-proxy request for user. body is exactly the
// request's body (nil for none).
func (a *Auth) SignAdmin(req *http.Request, user string, body []byte) string {
	h := a.sign(req.Method, req.URL.Path, req.URL.RawQuery, digest(body), "admin:"+user)
	req.Header.Set(AdminHeader, h)
	req.Header.Set(AdminUserHeader, user)
	return sigOf(h)
}

// ServeSigned runs h against a buffered response and writes it with a MAC
// bound to the request signature reqSig, covering the status, the body and
// the Location / Set-Cookie / Content-Type headers.
func (a *Auth) ServeSigned(w http.ResponseWriter, reqSig string, h func(http.ResponseWriter)) {
	rec := &bufferedResponse{header: w.Header(), status: http.StatusOK}
	h(rec)
	w.Header().Set(respHeader, a.responseMAC(reqSig, rec.status, w.Header(), rec.body.Bytes()))
	w.WriteHeader(rec.status)
	_, _ = w.Write(rec.body.Bytes())
}

func (a *Auth) responseMAC(reqSig string, status int, hdr http.Header, body []byte) string {
	return a.mac(a.respKey, version, reqSig, strconv.Itoa(status), hdr.Get("Location"),
		strings.Join(hdr.Values("Set-Cookie"), "\x00"), hdr.Get("Content-Type"), digest(body))
}

// trailerVerifier hashes a streamed body and, at its end, checks the trailer
// MAC (bound to the request signature). A mismatch or a missing trailer turns
// the final read into an error.
type trailerVerifier struct {
	body io.ReadCloser
	req  *http.Request
	h    hash.Hash
	auth *Auth
	sig  string
	done bool
}

func (t *trailerVerifier) Read(b []byte) (int, error) {
	n, err := t.body.Read(b)
	t.h.Write(b[:n])
	if err == io.EOF && !t.done {
		t.done = true
		want := t.auth.mac(t.auth.reqKey, version, "body", t.sig, hex.EncodeToString(t.h.Sum(nil)))
		if !hmac.Equal([]byte(t.req.Trailer.Get(bodyTrailer)), []byte(want)) {
			return n, errors.New("cluster stream failed authentication")
		}
	}
	return n, err
}

func (t *trailerVerifier) Close() error { return t.body.Close() }

// bufferedResponse holds a handler's response so the middleware can MAC it.
type bufferedResponse struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.wrote = true
	return b.body.Write(p)
}
func (b *bufferedResponse) WriteHeader(code int) {
	if !b.wrote {
		b.status = code
		b.wrote = true
	}
}

// CheckResponse verifies a response's MAC against the request signature.
func (a *Auth) CheckResponse(reqSig string, status int, hdr http.Header, body []byte) bool {
	return hmac.Equal([]byte(hdr.Get(respHeader)), []byte(a.responseMAC(reqSig, status, hdr, body)))
}

// Client issues signed requests to a peer's cluster API. Base is "http://<ip>:<port>".
type Client struct {
	auth *Auth
	hc   *http.Client
}

func NewClient(secret []byte) *Client {
	return &Client{
		auth: NewAuth(secret),
		hc:   &http.Client{Timeout: 8 * time.Second},
	}
}

// splitPath splits "path?query" into the two parts the signature covers.
func splitPath(p string) (string, string) {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// sigOf extracts the signature from an X-Cluster-Auth value.
func sigOf(h string) string { return h[strings.LastIndexByte(h, '.')+1:] }

func (c *Client) do(method, base, path string, body []byte) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		return nil, 0, err
	}
	p, q := splitPath(path)
	// The server verifies against the URL it parses; sign what will be sent.
	if req.URL.Path != p || req.URL.RawQuery != q {
		p, q = req.URL.Path, req.URL.RawQuery
	}
	h := c.auth.sign(method, p, q, digest(body), "")
	req.Header.Set(authHeader, h)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if !c.auth.CheckResponse(sigOf(h), resp.StatusCode, resp.Header, rb) {
		return rb, resp.StatusCode, ErrResponseAuth
	}
	return rb, resp.StatusCode, nil
}

// Get issues a signed GET to base+path.
func (c *Client) Get(base, path string) ([]byte, int, error) {
	return c.do(http.MethodGet, base, path, nil)
}

// Post issues a signed POST to base+path (no body).
func (c *Client) Post(base, path string) ([]byte, int, error) {
	return c.do(http.MethodPost, base, path, nil)
}

// PostBody issues a signed POST to base+path with a raw body.
func (c *Client) PostBody(base, path string, body []byte) ([]byte, int, error) {
	if body == nil {
		body = []byte{}
	}
	return c.do(http.MethodPost, base, path, body)
}

// streamClient carries large cold-migration disk transfers. It has NO overall
// deadline (a multi-GB copy must not be cut off), but bounds the dial and the
// wait for response headers so a dead peer still fails fast.
var streamClient = &http.Client{
	Timeout: 0,
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 3 * time.Hour,
		IdleConnTimeout:       90 * time.Second,
	},
}

// trailerSigner hashes a streamed body as it is sent and, at its end, sets the
// trailer MAC the server's MiddlewareStream checks.
type trailerSigner struct {
	src  io.Reader
	req  *http.Request
	h    hash.Hash
	auth *Auth
	sig  string
}

func (t *trailerSigner) Read(b []byte) (int, error) {
	n, err := t.src.Read(b)
	t.h.Write(b[:n])
	if err == io.EOF {
		t.req.Trailer.Set(bodyTrailer, t.auth.mac(t.auth.reqKey, version, "body", t.sig, hex.EncodeToString(t.h.Sum(nil))))
	}
	return n, err
}

// PostStream issues a signed POST that STREAMS body to base+path (used to copy a
// VM disk during cold migration). Unlike PostBody it does not buffer the body
// and uses the deadline-free streamClient; the body is authenticated by a MAC
// in a trailer sent after it. The (small) response is still read with a cap.
func (c *Client) PostStream(base, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	h := c.auth.sign(http.MethodPost, req.URL.Path, req.URL.RawQuery, streamBody, "")
	req.Header.Set(authHeader, h)
	req.Trailer = http.Header{bodyTrailer: nil}
	req.Body = io.NopCloser(&trailerSigner{src: body, req: req, h: sha256.New(), auth: c.auth, sig: sigOf(h)})
	req.ContentLength = -1 // chunked, so the trailer can follow the body
	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if !c.auth.CheckResponse(sigOf(h), resp.StatusCode, resp.Header, rb) {
		return rb, resp.StatusCode, ErrResponseAuth
	}
	return rb, resp.StatusCode, nil
}

// Auth exposes the signer.
func (c *Client) Auth() *Auth { return c.auth }

// SetHeader signs a body-less peer request (a websocket dial) into hdr.
// rawQuery is the URL's encoded query, "" for none.
func (a *Auth) SetHeader(hdr http.Header, method, path, rawQuery string) {
	hdr.Set(authHeader, a.sign(method, path, rawQuery, digest(nil), ""))
}

// BaseURL builds the peer base URL from a cluster-net address and port.
func BaseURL(clusterAddr string, port int) string {
	host := clusterAddr
	if h, _, err := net.SplitHostPort(clusterAddr); err == nil {
		host = h
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}
