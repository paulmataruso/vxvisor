// Package config loads and defaults the daemon configuration.
//
// Design note: this is an original, simplified configuration model inspired by
// the general shape of a VM/VDI appliance (a [server] block, an [images] cache,
// a [network] mode). It is not a copy of any vendor's config file.
package config

import (
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server  ServerConfig  `toml:"server"`
	Paths   PathsConfig   `toml:"paths"`
	Network NetworkConfig `toml:"network"`
	VM      VMConfig      `toml:"vm"`
	Cluster ClusterConfig `toml:"cluster"`
	Gateway GatewayConfig `toml:"gateway"`
	Public  PublicConfig  `toml:"public"`
	Broker  BrokerConfig  `toml:"broker"`
	OIDC    OIDCConfig    `toml:"oidc"`
	AD      ADConfig      `toml:"ad"`
	Update  UpdateConfig  `toml:"update"`
	License LicenseConfig `toml:"license"`
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

// GatewayConfig configures the browser-desktop gateway: a WebSocket↔guacd tunnel
// that gives a full remote desktop (RDP, with clipboard/audio/mic/webcam virtual
// channels) in any browser tab, with no plugin or client install.
type GatewayConfig struct {
	// Enabled turns on the /desktop route and the guacd tunnel.
	Enabled bool `toml:"enabled"`
	// GuacdAddr is the guacd daemon address (default 127.0.0.1:4822).
	GuacdAddr string `toml:"guacd_addr"`
	// Protocol is the remote-desktop protocol guacd connects to the guest with:
	// "rdp" (default — carries audio/clipboard/mic/webcam) or "vnc".
	Protocol string `toml:"protocol"`
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

// PublicConfig is the internet-facing VDI portal listener. It is SEPARATE from
// the admin UI (Server.Addr): it serves only login, the "My Desktops" broker,
// and the desktop gateway — never the management screens. Terminate TLS in front
// of it with a reverse proxy (Caddy/nginx); bind it to loopback so only the
// proxy can reach it.
type PublicConfig struct {
	Enabled bool   `toml:"enabled"`
	Addr    string `toml:"addr"` // e.g. 127.0.0.1:8768 (behind the TLS proxy)
	// BaseURL is the public https origin users reach, used in OIDC redirects and
	// absolute links (e.g. https://desktops.example.com).
	BaseURL string `toml:"base_url"`
}

// BrokerConfig tunes the VDI broker: how connection tokens and pooled desktops
// behave.
type BrokerConfig struct {
	// SecretFile holds the HMAC key for connection tokens. Empty = a key file is
	// created under the data dir on first start. Never hardcode a key.
	SecretFile string `toml:"secret_file"`
	// IdleMinutes reclaims a leased pooled desktop after this much inactivity
	// (0 = default 30). Persistent desktops are only stopped, never unassigned.
	IdleMinutes int `toml:"idle_minutes"`
}

type OIDCConfig struct {
	// Enabled turns on the "Sign in with SSO" button. All fields come from the
	// operator's identity provider; nothing is hard-coded or phoned home.
	Enabled      bool   `toml:"enabled"`
	Issuer       string `toml:"issuer"`        // e.g. https://accounts.example.com
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
	RedirectURL  string `toml:"redirect_url"`  // https://<this-host>/oidc/callback
}

// ADConfig configures Active Directory / LDAP bind authentication. When enabled,
// a user who is not a local account (or whose local password fails) is
// authenticated by binding to AD; on success a local account is JIT-provisioned.
// Set up is intentionally minimal: URL + domain is enough for UPN-bind auth; the
// service-account + group fields are only needed for admin-group → role mapping.
type ADConfig struct {
	Enabled bool   `toml:"enabled"`
	URL     string `toml:"url"`     // ldap://dc.example.com:389 or ldaps://dc.example.com:636
	Domain  string `toml:"domain"`  // AD domain for UPN bind, e.g. corp.example.com (user → user@domain)
	StartTLS bool  `toml:"starttls"` // upgrade a plain ldic:// connection to TLS before bind
	Insecure bool  `toml:"insecure"` // skip TLS cert verification (lab/self-signed only)

	// Optional directory search (for role mapping and/or sAMAccountName→DN). Needs
	// a read-only service account to bind as first.
	BindDN       string `toml:"bind_dn"`       // service account DN (or UPN)
	BindPassword string `toml:"bind_password"`
	BaseDN       string `toml:"base_dn"`       // search base, e.g. DC=corp,DC=example,DC=com
	UserFilter   string `toml:"user_filter"`   // default (&(objectClass=user)(sAMAccountName=%s))
	AdminGroup   string `toml:"admin_group"`   // users in this group (CN or full DN) become instance admins
}

type UpdateConfig struct {
	// FeedURL points at an operator-controlled JSON manifest describing the
	// latest build (version, url, sha256). No vendor server is involved.
	FeedURL string `toml:"feed_url"`
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
		Gateway: GatewayConfig{
			GuacdAddr: "127.0.0.1:4822",
			Protocol:  "rdp",
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
