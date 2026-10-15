// Package peer is the authenticated node-to-node cluster API transport. It binds
// to the cluster NIC only and signs every request with the shared cluster secret
// (HMAC over timestamp + path), so aggregation, lifecycle proxying and account
// sync between nodes cannot be forged or replayed from off-cluster. It is a leaf
// package (no service/web deps) so both the server side (web) and the client side
// (service/worker) can use it without import cycles.
package peer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const authHeader = "X-Cluster-Auth"

// APIPort is the fixed port the node-to-node peer API listens on (cluster NIC).
const APIPort = 8767

// Auth signs and verifies peer requests with the shared cluster secret.
type Auth struct{ secret []byte }

func NewAuth(secret []byte) *Auth { return &Auth{secret: secret} }

func (a *Auth) sign(ts int64, path string) string {
	h := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(h, "%d\n%s", ts, path)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Header returns the value to set on X-Cluster-Auth for a request to path.
func (a *Auth) Header(path string) string {
	ts := time.Now().Unix()
	return fmt.Sprintf("%d.%s", ts, a.sign(ts, path))
}

// Verify checks a header value against path within skew. A short skew window plus
// the path binding keeps replay to a tiny window on the trusted cluster net.
func (a *Auth) Verify(header, path string, skew time.Duration) bool {
	dot := strings.IndexByte(header, '.')
	if dot < 0 {
		return false
	}
	ts, err := strconv.ParseInt(header[:dot], 10, 64)
	if err != nil {
		return false
	}
	if d := time.Since(time.Unix(ts, 0)); d > skew || d < -skew {
		return false
	}
	return hmac.Equal([]byte(header[dot+1:]), []byte(a.sign(ts, path)))
}

// Middleware wraps an http.Handler, rejecting requests without a valid signature.
func (a *Auth) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.Verify(r.Header.Get(authHeader), r.URL.Path, 30*time.Second) {
			http.Error(w, "cluster auth failed", http.StatusForbidden)
			return
		}
		next(w, r)
	}
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

func (c *Client) do(method, base, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return nil, 0, err
	}
	// Sign over the PATH ONLY (no query string) so it matches the server's
	// r.URL.Path on verify.
	signPath := path
	if i := strings.IndexByte(signPath, '?'); i >= 0 {
		signPath = signPath[:i]
	}
	req.Header.Set(authHeader, c.auth.Header(signPath))
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
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
	return c.do(http.MethodPost, base, path, bytes.NewReader(body))
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

// PostStream issues a signed POST that STREAMS body to base+path (used to copy a
// VM disk during cold migration). Unlike PostBody it does not buffer the body and
// uses the deadline-free streamClient. The (small) response is still read with a
// cap.
func (c *Client) PostStream(base, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, base+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	signPath := path
	if i := strings.IndexByte(signPath, '?'); i >= 0 {
		signPath = signPath[:i]
	}
	req.Header.Set(authHeader, c.auth.Header(signPath))
	resp, err := streamClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return rb, resp.StatusCode, nil
}

// Auth exposes the signer (for WebSocket relays that set the header manually).
func (c *Client) Auth() *Auth { return c.auth }

// BaseURL builds the peer base URL from a cluster-net address and port.
func BaseURL(clusterAddr string, port int) string {
	host := clusterAddr
	if h, _, err := net.SplitHostPort(clusterAddr); err == nil {
		host = h
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}
