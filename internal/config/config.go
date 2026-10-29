// Package config loads and defaults the daemon configuration.
//
// Design note: this is an original, simplified configuration model inspired by
// the general shape of a VM appliance (a [server] block, an [images] cache,
// a [network] mode). It is not a copy of any vendor's config file.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server  ServerConfig  `toml:"server"`
	Paths   PathsConfig   `toml:"paths"`
	Network NetworkConfig `toml:"network"`
	VM      VMConfig      `toml:"vm"`
	Cluster ClusterConfig `toml:"cluster"`
	OIDC    OIDCConfig    `toml:"oidc"`
	AD      ADConfig      `toml:"ad"`
	Update  UpdateConfig  `toml:"update"`
	License LicenseConfig `toml:"license"`
	Guac    GuacConfig    `toml:"guac"`
	Ovirt   OvirtConfig   `toml:"ovirt"`
}

// OvirtConfig is the OPTIONAL oVirt-engine–compatible backup API (for Veeam
// Backup & Replication's oVirt KVM plug-in and other oVirt-SDK clients). It is
// OFF unless Enabled is true; leaving the [ovirt] section out is a complete
// rollback. Its two TLS listeners bind a specific address — the management IP
// by default — and never a wildcard. See docs/VEEAM-OVIRT-API.md.
type OvirtConfig struct {
	// Enabled turns the API on. Default false.
	Enabled bool `toml:"enabled"`
	// Listen is the engine API listener ("<ip>:443"). Empty = the [server]
	// addr's IP on port 443; with a wildcard [server] addr it must be set.
	Listen string `toml:"listen"`
	// ImageioListen is the imageio data listener ("<ip>:54322"). Empty = the
	// Listen IP on port 54322. Transfers also work through Listen alone.
	ImageioListen string `toml:"imageio_listen"`
	// PublicHost is the name or IP clients reach this host by (the TLS
	// certificate's name and the host in transfer URLs). Empty = the Listen IP.
	PublicHost string `toml:"public_host"`
	// ProductName is reported as the engine's product name.
	ProductName string `toml:"product_name"`
	// WorkDir holds backup scratch (fleecing images, NBD sockets); it must be
	// on local disk with room for guest writes made during a backup. Empty =
	// <data_dir>/backup-work.
	WorkDir string `toml:"work_dir"`
}

// OvirtAddrs resolves the backup API's listen addresses. It refuses a
// wildcard or hostname bind: the API must sit on one known interface.
func (c *Config) OvirtAddrs() (api, imageio string, err error) {
	api = c.Ovirt.Listen
	if api == "" {
		host, _, e := net.SplitHostPort(c.Server.Addr)
		if e != nil || !specificIP(host) {
			return "", "", fmt.Errorf("[ovirt] listen is not set and [server] addr %q has no specific IP; set listen to the management IP and port 443", c.Server.Addr)
		}
		api = net.JoinHostPort(host, "443")
	}
	host, _, e := net.SplitHostPort(api)
	if e != nil || !specificIP(host) {
		return "", "", fmt.Errorf("[ovirt] listen %q must be a specific IP and port (never a wildcard)", api)
	}
	imageio = c.Ovirt.ImageioListen
	if imageio == "" {
		imageio = net.JoinHostPort(host, "54322")
	}
	if h, _, e := net.SplitHostPort(imageio); e != nil || !specificIP(h) {
		return "", "", fmt.Errorf("[ovirt] imageio_listen %q must be a specific IP and port (never a wildcard)", imageio)
	}
	return api, imageio, nil
}

func specificIP(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && !ip.IsUnspecified()
}

// GuacConfig is the OPTIONAL rustguac "advanced console" integration — a test
// add-on that fronts a local rustguac+guacd (browser SSH/RDP/VNC/SPICE) through
// vdxd's own authentication. It is OFF unless Enabled is true and Upstream +
// APIKey are set, so leaving the [guac] section out (or Enabled=false) is a
// complete rollback: vdxd behaves exactly as before and noVNC is untouched.
type GuacConfig struct {
	// Enabled turns the whole feature on. Default false.
	Enabled bool `toml:"enabled"`
	// Upstream is the loopback address of the local rustguac server (never
	// network-exposed), e.g. "127.0.0.1:8089".
	Upstream string `toml:"upstream"`
	// APIKey is the rustguac admin API key vdxd uses server-to-server to mint
	// sessions and single-use WebSocket tickets. Never sent to the browser.
	APIKey string `toml:"api_key"`
	// ProxyAddr is the address vdxd's cookie-gated reverse proxy for rustguac
	// listens on (a browser-reachable mgmt address + port, e.g.
	// "172.16.0.163:8767"). rustguac itself stays on loopback; this is the only
	// path a browser can reach it, and it requires a valid vdxd session.
	ProxyAddr string `toml:"proxy_addr"`
}

// ClusterConfig describes multi-node operation: the VXLAN overlay that stitches
// every node's VM bridge into one L2 segment, the gossip membership layer that
// replaces a central coordinator, and the migration transport. All of it is OFF
// by default — a fresh single-host install needs none of it.
type ClusterConfig struct {
	// Overlay turns on the VXLAN fabric. When false, bridge-mode VMs attach to a
	// plain local bridge (single-host LAN) and no encapsulation is set up.
	Overlay bool `toml:"overlay"`
	// VNI is the VXLAN network identifier shared by every node in the cluster.
	VNI int `toml:"vni"`
	// Underlay is the physical NIC the VXLAN rides on (e.g. eth0). Its IP is the
	// VTEP source address other nodes encapsulate to.
	Underlay string `toml:"underlay"`
	// Bridge is the host bridge VM taps are enslaved to (default vdxbr0). The
	// VXLAN device is also enslaved here, so guests and the overlay share one L2.
	Bridge string `toml:"bridge"`
	// Subnet is the CIDR the overlay hands guest IPs from via the IPAM leases
	// table (e.g. 10.77.0.0/16). Gateway is this subnet's router address.
	Subnet  string `toml:"subnet"`
	Gateway string `toml:"gateway"`
	// Nameservers are the DNS resolvers written into a bridge/overlay guest's
	// cloud-init network-config. A static guest has no DHCP-provided resolver, so
	// without these its apt/package install (desktop, guest agent) can't resolve.
	// Empty falls back to public resolvers (1.1.1.1, 8.8.8.8), reachable via NAT.
	Nameservers []string `toml:"nameservers"`
	// DHCP, when true, makes bridge-mode guests lease their address from the
	// bridged LAN's own DHCP server instead of the platform's static 10.77.0.0/16
	// IPAM. Set this when the VM bridge (Bridge) is enslaved to a real LAN uplink.
	DHCP bool `toml:"dhcp"`
	// MigratePort is the TCP port the destination QEMU listens on (-incoming) and
	// the source streams RAM to during a live migration.
	MigratePort int `toml:"migrate_port"`
	// SharedStorage, when set, is a directory visible on every node at the same
	// path (an NFS/Ceph mount). Live migration refuses without it, because a
	// local-only disk cannot follow the guest to the destination host.
	SharedStorage string `toml:"shared_storage"`
	// Gossip configures the memberlist cluster. BindAddr/BindPort is where this
	// node speaks gossip; Seeds are optional static peers to join; MDNS enables
	// zero-config peer discovery via mDNS so nodes find each other with no seeds.
	GossipBind string   `toml:"gossip_bind"`
	GossipPort int      `toml:"gossip_port"`
	Seeds      []string `toml:"seeds"`
	MDNS       bool     `toml:"mdns"`
	// NodeName overrides the gossip/registry name for this node (default: hostname).
	NodeName string `toml:"node_name"`

	// ---- cluster mode (leader election, VIP, single-pane) --------------------
	// Enabled turns on cluster mode: gossip-based leader election, the floating
	// management VIP, cluster-wide account sync, and the leader-aggregated view.
	// Off (default) keeps the single-host behaviour untouched.
	Enabled bool `toml:"enabled"`
	// Primary marks this node as the startup/tiebreak-preferred leader and the
	// node that keeps the VIP on a cluster-link-only partition. Exactly one node
	// in a 2-node cluster should set this (the other stays secondary).
	Primary bool `toml:"primary"`
	// Advertise is the cluster-network IP this node announces for gossip,
	// migration and the peer API (e.g. 10.10.2.11). MUST be the dedicated cluster
	// NIC's address, never the mgmt NIC.
	Advertise string `toml:"advertise"`
	// MgmtAddr is this node's management IP (ens18) the VIP floats near and that
	// peers probe for liveness before promoting. Default: auto-detected.
	MgmtAddr string `toml:"mgmt_addr"`
	// APIAddr is the peer cluster-API listen address, bound to the cluster NIC
	// (e.g. 10.10.2.11:8767). Used for aggregation, proxying and account sync.
	APIAddr string `toml:"api_addr"`
	// SecretFile holds the shared cluster secret (gossip encryption key + peer-API
	// HMAC + VIP MAC derivation). Empty = <data_dir>/cluster.key, auto-created.
	// The SAME file contents must exist on every node (copy it when joining).
	SecretFile string `toml:"secret_file"`
	// VIPDHCP obtains the floating management VIP via DHCP on a stable virtual MAC
	// (the lease follows the MAC, so the IP floats to the leader). VIPIface is the
	// mgmt NIC the macvlan child attaches to (e.g. ens18).
	VIPDHCP  bool   `toml:"vip_dhcp"`
	VIPIface string `toml:"vip_iface"`
	// VIP is a static alternative to DHCP ("10.0.0.5/24"); when set, VIPDHCP is
	// ignored and this address is added/removed on VIPIface by the leader.
	VIP string `toml:"vip"`
	// AdminPort is the mgmt-UI port peers probe for liveness (default 8766).
	AdminPort int `toml:"admin_port"`
}

type LicenseConfig struct {
	// Enabled turns on license enforcement. Default false → everything allowed
	// (NoopEnforcer), zero network calls. This is the deferred M9 seam.
	Enabled bool `toml:"enabled"`
	// File is the path to the signed license; Key is the operator's symmetric
	// signing/verification key (offline, operator-held — not a vendor secret).
	File string `toml:"file"`
	Key  string `toml:"key"`
	// HeartbeatURL, when set, enables an opt-in signed status POST to a URL the
	// operator controls. Empty (default) = no outbound heartbeat whatsoever.
	HeartbeatURL string `toml:"heartbeat_url"`
}

type OIDCConfig struct {
	// Enabled turns on the "Sign in with SSO" button. All fields come from the
	// operator's identity provider; nothing is hard-coded or phoned home.
	Enabled      bool   `toml:"enabled"`
	Issuer       string `toml:"issuer"` // e.g. https://accounts.example.com
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
	RedirectURL  string `toml:"redirect_url"` // https://<this-host>/oidc/callback
}

// ADConfig configures Active Directory / LDAP bind authentication. When enabled,
// a user who is not a local account (or whose local password fails) is
// authenticated by binding to AD; on success a local account is JIT-provisioned.
// Set up is intentionally minimal: URL + domain is enough for UPN-bind auth; the
// service-account + group fields are only needed for admin-group → role mapping.
type ADConfig struct {
	Enabled  bool   `toml:"enabled"`
	URL      string `toml:"url"`      // ldap://dc.example.com:389 or ldaps://dc.example.com:636
	Domain   string `toml:"domain"`   // AD domain for UPN bind, e.g. corp.example.com (user → user@domain)
	StartTLS bool   `toml:"starttls"` // upgrade a plain ldic:// connection to TLS before bind
	Insecure bool   `toml:"insecure"` // skip TLS cert verification (lab/self-signed only)

	// Optional directory search (for role mapping and/or sAMAccountName→DN). Needs
	// a read-only service account to bind as first.
	BindDN       string `toml:"bind_dn"` // service account DN (or UPN)
	BindPassword string `toml:"bind_password"`
	BaseDN       string `toml:"base_dn"`     // search base, e.g. DC=corp,DC=example,DC=com
	UserFilter   string `toml:"user_filter"` // default (&(objectClass=user)(sAMAccountName=%s))
	AdminGroup   string `toml:"admin_group"` // users in this group (CN or full DN) become instance admins
}

type UpdateConfig struct {
	// FeedURL points at an operator-controlled JSON manifest describing the
	// latest build (version, url, sha256). No vendor server is involved. When set,
	// it overrides GitHubRepo (air-gapped / self-hosted feed).
	FeedURL string `toml:"feed_url"`

	// GitHubRepo is the "owner/name" whose GitHub Releases the Update page checks
	// (only when an admin clicks "Check for updates" — never automatically). Empty
	// falls back to the built-in default.
	GitHubRepo string `toml:"github_repo"`
}

// Repo returns the configured GitHub repo or the built-in default.
func (u UpdateConfig) Repo() string {
	if u.GitHubRepo != "" {
		return u.GitHubRepo
	}
	return "paulmataruso/vxvisor"
}

type ServerConfig struct {
	// Addr is the listen address for the combined web UI + REST API.
	Addr string `toml:"addr"`
	// VNCPortBase is the first TCP port handed out to per-session QEMU VNC
	// websocket consoles; each session takes the next free port above it.
	VNCPortBase int `toml:"vnc_port_base"`
}

type PathsConfig struct {
	// DataDir holds the SQLite database and per-session runtime state.
	DataDir string `toml:"data_dir"`
	// ImageDir caches downloaded base images (qcow2).
	ImageDir string `toml:"image_dir"`
	// DiskDir holds per-session overlay disks.
	DiskDir string `toml:"disk_dir"`
	// ISODir holds uploaded/pulled installer ISOs.
	ISODir string `toml:"iso_dir"`
	// BackupDir holds compressed VM disk backups and control-plane DB snapshots.
	BackupDir string `toml:"backup_dir"`
}

type NetworkConfig struct {
	// Mode is "user" (QEMU SLIRP user networking, no privileges needed) or
	// "tap" (per-session TAP + host NAT, needs root). MVP ships "user".
	Mode string `toml:"mode"`
	// ForwardHost is the host IP that user-mode port forwards bind to. Empty
	// means the loopback address 127.0.0.1 (reachable only via an SSH tunnel);
	// set it to a routable host IP to expose guest SSH/RDP on the LAN.
	ForwardHost string `toml:"forward_host"`
	// ForwardPortBase is the first host port handed out for port forwards.
	ForwardPortBase int `toml:"forward_port_base"`
}

type VMConfig struct {
	// RunAs, when set to an existing non-root user, makes QEMU drop to that
	// user after it has opened its resources. The daemon chowns each VM's
	// runtime files to that user first. Empty = run VMs as the daemon user.
	RunAs string `toml:"run_as"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Addr:        ":8766",
			VNCPortBase: 5900,
		},
		Paths: PathsConfig{
			DataDir:   "/var/lib/vdxclone",
			ImageDir:  "/var/cache/vdxclone/images",
			DiskDir:   "/var/lib/vdxclone/disks",
			ISODir:    "/var/cache/vdxclone/isos",
			BackupDir: "/var/lib/vdxclone/backups",
		},
		Network: NetworkConfig{Mode: "user", ForwardPortBase: 20000},
		Cluster: ClusterConfig{
			VNI:         42,
			Bridge:      "vdxbr0",
			Subnet:      "10.77.0.0/16",
			Gateway:     "10.77.0.1",
			MigratePort: 49200,
			GossipBind:  "0.0.0.0",
			GossipPort:  7946,
			AdminPort:   8766,
		},
	}
}

// Load reads config from path, falling back to built-in defaults for any field
// left unset. A missing file is not an error — defaults are used.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	if _, err := os.Stat(path); err == nil {
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// EnsureDirs creates the runtime directories if they do not exist.
func (c *Config) EnsureDirs() error {
	for _, d := range []string{c.Paths.DataDir, c.Paths.ImageDir, c.Paths.DiskDir, c.Paths.ISODir, c.Paths.BackupDir} {
		if d == "" {
			continue
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) DBPath() string { return filepath.Join(c.Paths.DataDir, "vdxclone.db") }

// ClusterSecretPath is the shared cluster secret file (gossip key + peer-API
// HMAC + VIP MAC seed). Defaults to <data_dir>/cluster.key.
func (c *Config) ClusterSecretPath() string {
	if c.Cluster.SecretFile != "" {
		return c.Cluster.SecretFile
	}
	return filepath.Join(c.Paths.DataDir, "cluster.key")
}

// ClusterAdminPort is the mgmt-UI port peers probe for liveness.
func (c *Config) ClusterAdminPort() int {
	if c.Cluster.AdminPort > 0 {
		return c.Cluster.AdminPort
	}
	return 8766
}
