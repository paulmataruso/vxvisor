// Package client is the VXVisor control-plane client used by the desktop app.
//
// It authenticates exactly like the browser does — username/password to obtain
// the vdx_session cookie — and then reuses that one cookie for everything: the
// REST API (GET/POST /api/v1/...), the cookie-only UI endpoints the REST API
// lacks (restart, guest info), and the raw-RFB console WebSocket. The CSRF token
// the UI POSTs require is reproduced client-side from the cookie value, the same
// way the server derives it.
package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const sessionCookie = "vdx_session"

// Client talks to one VXVisor host.
type Client struct {
	base  *url.URL
	hc    *http.Client
	jar   *cookiejar.Jar
	token string // raw vdx_session value, kept in memory only
	csrf  string // derived: sha256("csrf:"+token)[:16]
	User  string
}

// Session mirrors the server's session.Session JSON. The server serializes the
// struct with no json tags, so the keys are the Go field names verbatim
// (PascalCase). We decode only the fields the client needs.
type Session struct {
	ID          string `json:"ID"`
	Name        string `json:"Name"`
	State       string `json:"State"`
	Kind        string `json:"Kind"`
	OSType      string `json:"OSType"`
	GuestOS     string `json:"GuestOS"`
	CPUs        int    `json:"CPUs"`
	MemoryMB    int    `json:"MemoryMB"`
	DiskGB      int    `json:"DiskGB"`
	Display     string `json:"Display"`
	VNCPassword string `json:"VNCPassword"`
	MAC         string `json:"MAC"`
	NetworkID   int64  `json:"NetworkID"`
	Autostart   bool   `json:"Autostart"`
	CreatedAt   string `json:"CreatedAt"`

	// Hardware profile (for the hardware-edit dialog pre-fill; applied on next
	// start). Mirrors session.Session's launch-time knobs.
	Firmware    string `json:"Firmware"`
	MachineType string `json:"MachineType"`
	DiskBus     string `json:"DiskBus"`
	NICModel    string `json:"NICModel"`
	VGA         string `json:"VGA"`
	GuestAgent  bool   `json:"GuestAgent"`
	TPM         bool   `json:"TPM"`
	SecureBoot  bool   `json:"SecureBoot"`
	PinCPUs     bool   `json:"PinCPUs"`
	HugePages   bool   `json:"HugePages"`
}

// GuestInfo is the shape of GET /api/instances/{id}/guest (qemu.GuestInfo).
// We only surface the addresses; unknown fields are ignored.
type GuestInfo struct {
	Hostname  string   `json:"hostname"`
	OS        string   `json:"os"`
	Addresses []string `json:"addresses"`
}

// New builds a client for the given base address. host may be "http://ip:8766",
// "ip:8766", or "ip" (defaults to http and :8766).
func New(host string) (*Client, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("no host given")
	}
	if !strings.Contains(host, "://") {
		host = "http://" + host
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("bad host %q: %w", host, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("bad host %q", host)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "8766")
	}
	jar, _ := cookiejar.New(nil)
	return &Client{
		base: &url.URL{Scheme: u.Scheme, Host: u.Host},
		jar:  jar,
		hc: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			// Do not follow the post-login redirect; we inspect it directly.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// BaseURL returns the normalized base, e.g. http://10.0.0.5:8766.
func (c *Client) BaseURL() string { return c.base.String() }

// Login posts credentials to /login and captures the session cookie. The server
// redirects to / on success and to /login?error=1 on failure, so a successful
// login is detected by the presence of the vdx_session cookie.
func (c *Client) Login(user, pass string) error {
	form := url.Values{"username": {user}, "password": {pass}}
	resp, err := c.hc.PostForm(c.base.String()+"/login", form)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.base.Host, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	for _, ck := range c.jar.Cookies(c.base) {
		if ck.Name == sessionCookie && ck.Value != "" {
			c.token = ck.Value
			sum := sha256.Sum256([]byte("csrf:" + ck.Value))
			c.csrf = hex.EncodeToString(sum[:])[:16]
			c.User = user
			return nil
		}
	}
	return fmt.Errorf("login failed: check host, username, and password")
}

// Me is the identity of the logged-in principal plus the server build version,
// from GET /api/v1/me. IsAdmin drives which management pages the desktop client
// exposes; Version lets the client gate features on the server it is talking to.
type Me struct {
	Username string `json:"Username"`
	Role     string `json:"Role"`
	IsAdmin  bool   `json:"IsAdmin"`
	OrgID    int64  `json:"OrgID"`
	OrgRole  string `json:"OrgRole"`
	Unified  bool   `json:"Unified"`
	Version  string `json:"Version"`
}

// Me fetches the current principal's identity and the server version.
func (c *Client) Me() (*Me, error) {
	var m Me
	if err := c.getJSON("/api/v1/me", &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Image is a base image available to boot/clone from (GET /api/v1/images →
// image.Image, PascalCase).
type Image struct {
	Name      string `json:"Name"`
	Status    string `json:"Status"`
	SizeBytes int64  `json:"SizeBytes"`
}

// Images lists the base images registered on the server.
func (c *Client) Images() ([]Image, error) {
	var out []Image
	err := c.getJSON("/api/v1/images", &out)
	return out, err
}

// CreateVMInput is the body for POST /api/v1/sessions (json-tagged, snake_case —
// this endpoint predates the PascalCase convention and decodes snake_case).
type CreateVMInput struct {
	Name       string `json:"name"`
	Image      string `json:"image"`
	Kind       string `json:"kind,omitempty"`
	Firmware   string `json:"firmware,omitempty"`
	CPUs       int    `json:"cpus"`
	MemoryMB   int    `json:"memory_mb"`
	DiskGB     int    `json:"disk_gb"`
	CloudInit  *bool  `json:"cloud_init,omitempty"`
	CIUsername string `json:"ci_username,omitempty"`
	CIPassword string `json:"ci_password,omitempty"`
	CISSHKey   string `json:"ci_ssh_key,omitempty"`
}

// CreateVM provisions a new VM from a base image.
func (c *Client) CreateVM(in CreateVMInput) error {
	return c.apiPostJSON("/api/v1/sessions", in)
}

// Sessions returns all VMs visible to the logged-in user.
func (c *Client) Sessions() ([]Session, error) {
	var out []Session
	if err := c.getJSON("/api/v1/sessions", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Folder is one node of the inventory tree (ParentID 0 = top level).
type Folder struct {
	ID       int64  `json:"ID"`
	ParentID int64  `json:"ParentID"`
	Name     string `json:"Name"`
}

// FolderData is the org's folder tree plus the VM→folder assignment map (VMs
// absent from Members are at the root).
type FolderData struct {
	Folders []Folder         `json:"Folders"`
	Members map[string]int64 `json:"Members"`
}

// Folders returns the org inventory folders and VM assignments.
func (c *Client) Folders() (FolderData, error) {
	var out FolderData
	err := c.getJSON("/api/v1/folders", &out)
	return out, err
}

// CreateFolder adds a folder under parent (0 = top level).
func (c *Client) CreateFolder(parent int64, name string) error {
	return c.apiPostJSON("/api/v1/folders", map[string]any{"parent": parent, "name": name})
}

// RenameFolder renames a folder.
func (c *Client) RenameFolder(id int64, name string) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/folders/%d/rename", id), map[string]any{"name": name})
}

// DeleteFolder removes a folder (its VMs/subfolders move up a level).
func (c *Client) DeleteFolder(id int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/folders/%d/delete", id), nil)
}

// MoveFolder reparents a folder under newParent (0 = top level).
func (c *Client) MoveFolder(id, newParent int64) error {
	return c.apiPostJSON(fmt.Sprintf("/api/v1/folders/%d/move", id), map[string]any{"parent": newParent})
}

// MoveVM files a VM into folder (0 = root/ungrouped).
func (c *Client) MoveVM(vm string, folder int64) error {
	return c.apiPostJSON("/api/v1/folders/move-vm", map[string]any{"vm": vm, "folder": folder})
}

// ClientRelease describes the newest desktop-client build the server offers for
// a given os/arch (from GET /clients/latest).
type ClientRelease struct {
	Version  string `json:"version"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// LatestClient asks the server for the newest client build for goos/goarch.
func (c *Client) LatestClient(goos, goarch string) (ClientRelease, error) {
	var out ClientRelease
	err := c.getJSON("/clients/latest?os="+url.QueryEscape(goos)+"&arch="+url.QueryEscape(goarch), &out)
	return out, err
}

// DownloadTo streams an authenticated GET of urlPath into w, returning the
// hex sha256 of what was written (so the caller can verify integrity).
func (c *Client) DownloadTo(urlPath string, w io.Writer) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, c.base.String()+urlPath, nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", urlPath, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(w, h), resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Usage is the org usage/billing summary from GET /api/v1/usage
// (service.UsageReport — no json tags, so keys are PascalCase).
type Usage struct {
	Days          int     `json:"Days"`
	VCPUSeconds   int64   `json:"VCPUSeconds"`
	MemMBSeconds  int64   `json:"MemMBSeconds"`
	InstanceHours float64 `json:"InstanceHours"`
	CostCredits   float64 `json:"CostCredits"`
}

// Usage returns the org's usage report for the trailing window (default 30d).
func (c *Client) Usage() (*Usage, error) {
	var u Usage
	if err := c.getJSON("/api/v1/usage", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// GuestInfo fetches guest-agent info (hostname, IP addresses) for one VM.
func (c *Client) GuestInfo(id string) (*GuestInfo, error) {
	var gi GuestInfo
	if err := c.getJSON("/api/instances/"+url.PathEscape(id)+"/guest", &gi); err != nil {
		return nil, err
	}
	return &gi, nil
}

// Start / Stop / Delete go through the CSRF-exempt REST API (cookie-authed).
func (c *Client) Start(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/start")
}
func (c *Client) Stop(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/stop")
}
func (c *Client) Delete(id string) error {
	return c.apiPost("/api/v1/sessions/" + url.PathEscape(id) + "/delete")
}

// Restart is not exposed by the REST API, so it uses the cookie-authed UI
// endpoint with the reproduced CSRF token.
func (c *Client) Restart(id string) error {
	form := url.Values{"csrf": {c.csrf}}
	resp, err := c.hc.PostForm(c.base.String()+"/sessions/"+url.PathEscape(id)+"/restart", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	// The UI handler replies with a redirect (303/302) on success and 403 on a
	// bad CSRF token.
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("restart rejected (csrf)")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("restart failed: %s", resp.Status)
	}
	return nil
}

// ConsoleWSURL returns the ws:// (or wss://) URL for the VNC console of a VM.
func (c *Client) ConsoleWSURL(id string) string {
	scheme := "ws"
	if c.base.Scheme == "https" {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://%s/console/%s/ws", scheme, c.base.Host, url.PathEscape(id))
}

// SerialWSURL returns the ws:// URL for the serial (text) console of a VM.
func (c *Client) SerialWSURL(id string) string {
	scheme := "ws"
	if c.base.Scheme == "https" {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://%s/console/%s/serial/ws", scheme, c.base.Host, url.PathEscape(id))
}

// DialWS opens an authenticated WebSocket to the given console URL, carrying the
// session cookie and the "binary" subprotocol the proxy expects.
func (c *Client) DialWS(wsURL string) (*websocket.Conn, error) {
	d := websocket.Dialer{
		Subprotocols:     []string{"binary"},
		HandshakeTimeout: 15 * time.Second,
	}
	h := http.Header{}
	h.Set("Cookie", sessionCookie+"="+c.token)
	conn, resp, err := d.Dial(wsURL, h)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("console connect failed: %s", resp.Status)
		}
		return nil, fmt.Errorf("console connect failed: %w", err)
	}
	return conn, nil
}

func (c *Client) getJSON(path string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, c.base.String()+path, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("not authorized (session may have expired)")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// apiPostJSON POSTs a JSON body (nil = no body) and reports a server error
// message if one comes back, like apiPost.
func (c *Client) apiPostJSON(path string, body any) error {
	var r io.Reader
	req, _ := http.NewRequest(http.MethodPost, c.base.String()+path, nil)
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
		req, _ = http.NewRequest(http.MethodPost, c.base.String()+path, r)
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(rb, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return nil
}

func (c *Client) apiPost(path string) error {
	req, _ := http.NewRequest(http.MethodPost, c.base.String()+path, nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return nil
}
