// Package ovirtapi is an oVirt-engine–compatible REST API (the subset backup
// software uses) in front of vdxd, plus the imageio data endpoints. It lets
// Veeam Backup & Replication's "oVirt KVM" plug-in — and anything else built
// on the oVirt SDKs — back up and restore VXVisor VMs as if this host were an
// oVirt engine with one data center, one cluster and one host.
//
// The object mapping, the security model and what is (and is not) supported
// are documented in docs/VEEAM-OVIRT-API.md. In short: data center + cluster +
// host = this node; storage domain = storage pool; VM = instance; network and
// vNIC profile = port group; checkpoints = persistent qcow2 dirty bitmaps; the
// data path is internal/vmbackup exported through internal/imageio.
package ovirtapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vdxclone/internal/imageio"
)

// Config is the engine's view of where it is reachable.
type Config struct {
	// PublicHost is the address clients (Veeam server and workers) use for
	// this host: it goes into transfer URLs and the host's address.
	PublicHost string
	// APIPort is the engine listener's port (443 for Veeam). The listener
	// also serves /images/, so proxy_url points here.
	APIPort int
	// ImageioPort is the dedicated imageio listener's port (54322, the
	// "daemon" port), used for transfer_url; 0 = proxy_url only.
	ImageioPort int
	// WorkRoot is vmbackup's work directory root.
	WorkRoot string
	// CAPEM is served at the pki-resource URL.
	CAPEM []byte
	// InstanceID identifies this engine (stable per install).
	InstanceID string
	// NodeName names the data center / cluster / host.
	NodeName string
	// ProductName is reported in product_info.
	ProductName string
}

// Server is the engine API.
type Server struct {
	cfg Config
	be  Backend
	io  *imageio.Server
	now func() time.Time

	mu        sync.Mutex
	tokens    map[string]*token
	basic     map[string]*token // sha256(user:pass) -> recently verified Basic credentials
	backups   map[string]*backup
	transfers map[string]*transfer
	snaps     map[string][]*snapshot // vm id -> recorded snapshots
	busyVM    map[string]string      // vm id -> backup id holding it
}

type token struct {
	caller  Caller
	user    string
	expires time.Time
	idle    time.Time
}

const (
	tokenLifetime = 12 * time.Hour
	tokenIdle     = time.Hour
	basicCacheTTL = time.Minute
)

// New builds the engine API around be. io is the imageio server both
// listeners share.
func New(cfg Config, be Backend, io *imageio.Server) *Server {
	if cfg.ProductName == "" {
		cfg.ProductName = "VXVisor oVirt-compatible API"
	}
	if cfg.NodeName == "" {
		cfg.NodeName = "vxvisor"
	}
	return &Server{cfg: cfg, be: be, io: io, now: time.Now,
		tokens: map[string]*token{}, basic: map[string]*token{},
		backups: map[string]*backup{}, transfers: map[string]*transfer{},
		snaps: map[string][]*snapshot{}, busyVM: map[string]string{}}
}

const apiPrefix = "/ovirt-engine/api"

func api(parts ...string) string { return apiPrefix + "/" + strings.Join(parts, "/") }

// Handler serves the engine listener: SSO, the CA, the API and /images/.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/images/") || p == "/info" || p == "/info/":
			s.io.ServeHTTP(w, r)
		case p == "/ovirt-engine/services/pki-resource":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			_, _ = w.Write(s.cfg.CAPEM)
		case p == "/ovirt-engine/sso/oauth/token":
			s.ssoToken(w, r)
		case p == "/ovirt-engine/services/sso-logout" || p == "/ovirt-engine/sso/oauth/revoke":
			s.ssoLogout(w, r)
		case p == apiPrefix || strings.HasPrefix(p, apiPrefix+"/"):
			s.serveAPI(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// ImageioHandler serves the dedicated imageio ("daemon") listener.
func (s *Server) ImageioHandler() http.Handler { return s.io }

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// stripProfile turns "admin@internal" (or "admin@ovirt@internal") into "admin".
func stripProfile(u string) string {
	if i := strings.Index(u, "@"); i > 0 {
		return u[:i]
	}
	return u
}

// ssoToken implements the oVirt SSO password grant. The engine accepts the
// form on GET or POST and answers in JSON; errors use the ovirt-app-api scope
// shape {"error_code","error"} with HTTP 400 (the SDK reads both).
func (s *Server) ssoToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ssoErr := func(code, msg string) {
		writeRaw(w, http.StatusBadRequest, "application/json", mustJSON(map[string]string{"error_code": code, "error": msg}))
	}
	if gt := r.Form.Get("grant_type"); gt != "" && gt != "password" {
		ssoErr("unsupported_grant_type", "only the password grant is supported")
		return
	}
	user, pass := r.Form.Get("username"), r.Form.Get("password")
	if user == "" || pass == "" {
		ssoErr("invalid_request", "username and password are required")
		return
	}
	caller, err := s.be.Login(stripProfile(user), pass, clientIP(r))
	if err != nil {
		ssoErr("access_denied", "Cannot authenticate user '"+user+"': the user name or password is incorrect, or the user may not use this API.")
		return
	}
	t := newToken()
	now := s.now()
	s.mu.Lock()
	s.tokens[t] = &token{caller: caller, user: stripProfile(user), expires: now.Add(tokenLifetime), idle: now.Add(tokenIdle)}
	s.mu.Unlock()
	writeRaw(w, http.StatusOK, "application/json", mustJSON(map[string]any{
		"access_token": t, "scope": "ovirt-app-api", "token_type": "bearer",
		"exp": strconv.FormatInt(now.Add(tokenLifetime).UnixMilli(), 10),
	}))
}

func (s *Server) ssoLogout(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	t := r.Form.Get("token")
	if t == "" {
		t = bearer(r)
	}
	s.mu.Lock()
	delete(s.tokens, t)
	s.mu.Unlock()
	writeRaw(w, http.StatusOK, "application/json", []byte("{}"))
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if v, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// authenticate resolves the caller from a Bearer token or Basic credentials.
func (s *Server) authenticate(r *http.Request) (Caller, string, bool) {
	now := s.now()
	if t := bearer(r); t != "" {
		s.mu.Lock()
		defer s.mu.Unlock()
		tk := s.tokens[t]
		if tk == nil || now.After(tk.expires) || now.After(tk.idle) {
			delete(s.tokens, t)
			return nil, "", false
		}
		tk.idle = now.Add(tokenIdle)
		return tk.caller, tk.user, true
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" {
		return nil, "", false
	}
	sum := sha256.Sum256([]byte(user + "\x00" + pass))
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	if tk := s.basic[key]; tk != nil && now.Before(tk.expires) {
		s.mu.Unlock()
		return tk.caller, tk.user, true
	}
	s.mu.Unlock()
	caller, err := s.be.Login(stripProfile(user), pass, clientIP(r))
	if err != nil {
		return nil, "", false
	}
	s.mu.Lock()
	s.basic[key] = &token{caller: caller, user: stripProfile(user), expires: now.Add(basicCacheTTL)}
	s.mu.Unlock()
	return caller, stripProfile(user), true
}

// ---- request plumbing -------------------------------------------------------

type req struct {
	s      *Server
	w      http.ResponseWriter
	r      *http.Request
	c      Caller
	user   string
	ip     string
	json   bool
	segs   []string
	q      url.Values
	follow map[string]bool
}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, apiPrefix)
	rest = strings.TrimPrefix(rest, "/v4")
	var segs []string
	for _, p := range strings.Split(rest, "/") {
		if p != "" {
			segs = append(segs, p)
		}
	}
	x := &req{s: s, w: w, r: r, ip: clientIP(r), segs: segs, q: r.URL.Query(), json: wantsJSON(r)}
	c, user, ok := s.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="ENGINE"`)
		x.fault(http.StatusUnauthorized, "Unauthorized", "authentication required")
		return
	}
	x.c, x.user = c, user
	x.follow = map[string]bool{}
	for _, f := range strings.Split(x.q.Get("follow"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			x.follow[f] = true
			if head, _, ok := strings.Cut(f, "."); ok {
				x.follow[head] = true
			}
		}
	}
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				panic(v)
			}
			log.Printf("ovirtapi: panic serving %s %s: %v", r.Method, r.URL.Path, v)
			x.fault(http.StatusInternalServerError, "Operation Failed", "internal error")
		}
	}()
	s.route(x)
}

// wantsJSON picks the response format. oVirt SDKs always ask for XML
// explicitly; Veeam's plug-in speaks JSON — and the oVirt emulators it is
// known to work with answer JSON unless XML is requested — so JSON is the
// default when the client doesn't ask for XML.
func wantsJSON(r *http.Request) bool {
	a := strings.ToLower(r.Header.Get("Accept"))
	switch {
	case strings.Contains(a, "json"):
		return true
	case strings.Contains(a, "xml"):
		return false
	}
	return true
}

// body parses the request body as XML or JSON (by Content-Type, else by
// sniffing). root names the element a JSON body stands for.
func (x *req) body(root string) (*Node, error) {
	ct := strings.ToLower(x.r.Header.Get("Content-Type"))
	br := newSniffer(x.r.Body)
	isXML := strings.Contains(ct, "xml")
	if !isXML && !strings.Contains(ct, "json") {
		isXML = br.first() == '<'
	}
	if isXML {
		return ParseXML(br)
	}
	if br.first() == 0 {
		return &Node{Name: root}, nil
	}
	return ParseJSON(br, root)
}

func (x *req) reply(code int, n *Node) {
	if x.json {
		writeRaw(x.w, code, "application/json", n.JSON())
		return
	}
	writeRaw(x.w, code, "application/xml", n.XML())
}

func (x *req) ok(n *Node)      { x.reply(http.StatusOK, n) }
func (x *req) created(n *Node) { x.reply(http.StatusCreated, n) }

// actionDone answers an action (start/finalize/...) or a delete.
func (x *req) actionDone(extra ...*Node) {
	x.ok(El("action", append([]*Node{T("status", "complete")}, extra...)...))
}

func (x *req) fault(code int, reason, detail string) {
	if x.json {
		writeRaw(x.w, code, "application/json", mustJSON(map[string]any{
			"reason": reason, "detail": "[" + detail + "]",
			"fault": map[string]string{"reason": reason, "detail": "[" + detail + "]"},
		}))
		return
	}
	writeRaw(x.w, code, "application/xml", El("fault", T("reason", reason), T("detail", "["+detail+"]")).XML())
}

// fail maps a backend error to a fault.
func (x *req) fail(err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		x.fault(http.StatusNotFound, "Not Found", err.Error())
	case errors.Is(err, ErrForbidden):
		x.fault(http.StatusForbidden, "Operation Failed", err.Error())
	case errors.Is(err, ErrConflict):
		x.fault(http.StatusConflict, "Operation Failed", err.Error())
	default:
		x.fault(http.StatusBadRequest, "Operation Failed", err.Error())
	}
}

func (x *req) notFound() { x.fault(http.StatusNotFound, "Not Found", "Entity not found: "+x.r.URL.Path) }

func (x *req) audit(action, typ, id string, detail map[string]any) {
	x.s.be.Audit(x.c, action, typ, id, x.ip, detail)
}

func writeRaw(w http.ResponseWriter, code int, ctype string, b []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- search / paging ---------------------------------------------------------

// matcher implements the subset of the oVirt search language clients use to
// look objects up: "name=x" (with * wildcards), "id=x", "status=x", joined by
// "and", plus "page N" with the max parameter. Unknown terms are ignored, as
// the known-working emulators do.
type matcher struct {
	terms map[string]string
	page  int
	max   int
}

func (x *req) matcher() matcher {
	m := matcher{terms: map[string]string{}, page: 1, max: -1}
	if v, err := strconv.Atoi(x.q.Get("max")); err == nil && v >= 0 {
		m.max = v
	}
	s := x.q.Get("search")
	fields := strings.Fields(s)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if strings.EqualFold(f, "and") {
			continue
		}
		if strings.EqualFold(f, "page") && i+1 < len(fields) {
			if p, err := strconv.Atoi(fields[i+1]); err == nil && p > 0 {
				m.page = p
			}
			i++
			continue
		}
		if k, v, ok := strings.Cut(f, "="); ok {
			m.terms[strings.ToLower(k)] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func (m matcher) match(key, val string) bool {
	want, ok := m.terms[key]
	if !ok {
		return true
	}
	if strings.Contains(want, "*") {
		return wildcard(strings.ToLower(want), strings.ToLower(val))
	}
	return strings.EqualFold(want, val)
}

func wildcard(pat, s string) bool {
	parts := strings.Split(pat, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(s, p)
		}
		j := strings.Index(s, p)
		if j < 0 {
			return false
		}
		s = s[j+len(p):]
	}
	return true
}

// pageOf applies page/max to n items, returning the [from, to) window.
func (m matcher) window(n int) (int, int) {
	if m.max < 0 {
		return 0, n
	}
	from := (m.page - 1) * m.max
	if from > n {
		from = n
	}
	return from, min(n, from+m.max)
}

// ---- misc ----------------------------------------------------------------------

type sniffer struct {
	r   interface{ Read([]byte) (int, error) }
	buf []byte
	pos int
	err error
}

func newSniffer(r interface{ Read([]byte) (int, error) }) *sniffer { return &sniffer{r: r} }

// first returns the first non-space byte (0 at EOF) without consuming input.
func (s *sniffer) first() byte {
	for {
		for _, c := range s.buf {
			if c != ' ' && c != '\n' && c != '\r' && c != '\t' {
				return c
			}
		}
		if s.err != nil || len(s.buf) > 4096 {
			return 0
		}
		tmp := make([]byte, 512)
		n, err := s.r.Read(tmp)
		s.buf = append(s.buf, tmp[:n]...)
		s.err = err
	}
}

func (s *sniffer) Read(p []byte) (int, error) {
	if s.pos < len(s.buf) {
		n := copy(p, s.buf[s.pos:])
		s.pos += n
		return n, nil
	}
	if s.err != nil {
		return 0, s.err
	}
	return s.r.Read(p)
}

func httpsURL(host string, port int, path string) string {
	h := host
	if port != 0 && port != 443 {
		h = net.JoinHostPort(host, strconv.Itoa(port))
	} else if strings.Contains(host, ":") {
		h = "[" + host + "]"
	}
	return "https://" + h + path
}
