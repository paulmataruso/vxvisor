// Package db opens the SQLite database and runs forward-only migrations.
//
// The schema is an original model for a multi-tenant VM manager. Migrations
// are numbered and tracked in schema_migrations so the database upgrades in
// place across releases. Pure-Go driver (modernc.org/sqlite), no CGO.
package db

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

// migration is one forward-only schema step. Steps run in order, once each.
type migration struct {
	version int
	name    string
	sql     string
}

// migrations is the ordered schema history. Never edit an applied migration;
// add a new one. Each runs inside its own transaction.
var migrations = []migration{
	{1, "core", `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',   -- instance role: 'admin' | 'user'
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS web_sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS images (
    name       TEXT PRIMARY KEY,
    path       TEXT NOT NULL,
    source_url TEXT,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'ready',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    image_name  TEXT NOT NULL REFERENCES images(name),
    disk_path   TEXT NOT NULL,
    cpus        INTEGER NOT NULL DEFAULT 2,
    memory_mb   INTEGER NOT NULL DEFAULT 2048,
    state       TEXT NOT NULL DEFAULT 'stopped',
    pid         INTEGER NOT NULL DEFAULT 0,
    vnc_port    INTEGER NOT NULL DEFAULT 0,
    qmp_socket  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);`},

	{2, "tenancy", `
CREATE TABLE IF NOT EXISTS orgs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    settings_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS org_members (
    org_id  INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL DEFAULT 'member',  -- owner|admin|member|viewer
    PRIMARY KEY (org_id, user_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER,
    actor_id    INTEGER,
    actor_kind  TEXT NOT NULL DEFAULT 'user',  -- user|apikey|system
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    hash       TEXT NOT NULL UNIQUE,
    prefix     TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    scopes_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used  TEXT,
    expires_at TEXT,
    revoked    INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE users ADD COLUMN oidc_sub TEXT;
ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0;

ALTER TABLE web_sessions ADD COLUMN current_org_id INTEGER;

ALTER TABLE images ADD COLUMN visibility TEXT NOT NULL DEFAULT 'global'; -- global|org
ALTER TABLE images ADD COLUMN org_id INTEGER;
ALTER TABLE images ADD COLUMN os_family TEXT NOT NULL DEFAULT '';
ALTER TABLE images ADD COLUMN checksum TEXT NOT NULL DEFAULT '';

ALTER TABLE sessions ADD COLUMN org_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'desktop';     -- desktop|server
ALTER TABLE sessions ADD COLUMN firmware TEXT NOT NULL DEFAULT 'bios';    -- bios|uefi
ALTER TABLE sessions ADD COLUMN ovmf_vars_path TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN boot_iso_id INTEGER;
ALTER TABLE sessions ADD COLUMN boot_order TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN template_id INTEGER;
ALTER TABLE sessions ADD COLUMN disk_gb INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN mac TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN network_id INTEGER;
ALTER TABLE sessions ADD COLUMN deleted_at TEXT;
ALTER TABLE sessions ADD COLUMN retention_at TEXT;
ALTER TABLE sessions ADD COLUMN last_started_at TEXT;
ALTER TABLE sessions ADD COLUMN vnc_password TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN ws_port INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN pid_start_time TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_sessions_org_state ON sessions(org_id, state);
CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(owner_id);
CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit_log(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
`},

	{3, "backfill-default-org", `
INSERT INTO orgs(name, slug)
    SELECT 'Default', 'default'
    WHERE NOT EXISTS (SELECT 1 FROM orgs WHERE slug='default');

INSERT OR IGNORE INTO org_members(org_id, user_id, role)
    SELECT (SELECT id FROM orgs WHERE slug='default'), id,
           CASE WHEN role='admin' THEN 'owner' ELSE 'member' END
    FROM users;

UPDATE sessions
    SET org_id = (SELECT id FROM orgs WHERE slug='default')
    WHERE org_id = 0 OR org_id IS NULL;
`},

	{4, "compute-m2", `
-- Per-VM cloud-init (NoCloud) first-boot identity and the generated seed ISO.
-- This is a single-tenant lab control plane; the first-boot password is stored
-- alongside the per-VM VNC password (already plaintext) so the detail screen can
-- surface it once. Rotate by recreating the instance.
ALTER TABLE sessions ADD COLUMN cloud_init  INTEGER NOT NULL DEFAULT 1;  -- attach seed ISO
ALTER TABLE sessions ADD COLUMN ci_username TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN ci_password TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN ci_ssh_key  TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN seed_path   TEXT NOT NULL DEFAULT '';

-- Normalize legacy rows created before M2 (firmware defaulted, no cloud-init).
UPDATE sessions SET cloud_init = 0 WHERE ci_username = '' AND seed_path = '';
UPDATE sessions SET firmware = 'bios' WHERE firmware = '' OR firmware IS NULL;
`},

	{5, "storage-m3", `
-- Bootable/installer ISO library (per org, plus global).
CREATE TABLE IF NOT EXISTS isos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    source_url TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    checksum   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'ready',   -- ready|downloading|error
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_isos_org ON isos(org_id);

-- Reusable instance specifications (one-click create).
CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL,
    name        TEXT NOT NULL,
    image_name  TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'server',
    firmware    TEXT NOT NULL DEFAULT 'uefi',
    cpus        INTEGER NOT NULL DEFAULT 2,
    memory_mb   INTEGER NOT NULL DEFAULT 2048,
    disk_gb     INTEGER NOT NULL DEFAULT 10,
    cloud_init  INTEGER NOT NULL DEFAULT 1,
    ci_username TEXT NOT NULL DEFAULT 'vdx',
    ci_ssh_key  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_templates_org ON templates(org_id);

-- Disk snapshots (qcow2 internal snapshots keyed by tag).
CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    tag        TEXT NOT NULL,                    -- qcow2 snapshot tag
    online     INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_snapshots_session ON snapshots(session_id);

-- Compressed disk backups + their schedules.
CREATE TABLE IF NOT EXISTS backups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL DEFAULT '',
    compressor TEXT NOT NULL DEFAULT '',         -- zstd|gzip|none
    size_bytes INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'pending',  -- pending|running|ready|error
    error      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_backups_org ON backups(org_id);
CREATE INDEX IF NOT EXISTS idx_backups_session ON backups(session_id);

CREATE TABLE IF NOT EXISTS backup_schedules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id         INTEGER NOT NULL,
    session_id     TEXT NOT NULL,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    keep           INTEGER NOT NULL DEFAULT 7,
    enabled        INTEGER NOT NULL DEFAULT 1,
    last_run_at    TEXT,
    next_run_at    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_bsched_next ON backup_schedules(enabled, next_run_at);

-- Storage pools (dir first; iscsi/nfs/cifs carry mount details in config_json).
CREATE TABLE IF NOT EXISTS storage_pools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL DEFAULT 'dir',
    path        TEXT NOT NULL DEFAULT '',
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
`},

	{6, "network-m4", `
-- Virtual networks a NIC can attach to. 'user' = SLIRP NAT (no host changes);
-- 'bridge' = tap on an existing host bridge; 'vlan' = 802.1q on a bridge.
CREATE TABLE IF NOT EXISTS networks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL,
    name        TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'user',    -- user|bridge|vlan
    bridge      TEXT NOT NULL DEFAULT '',        -- host bridge name (bridge/vlan)
    vlan_id     INTEGER NOT NULL DEFAULT 0,
    cidr        TEXT NOT NULL DEFAULT '',        -- e.g. 10.20.0.0/24 (IP pool)
    gateway     TEXT NOT NULL DEFAULT '',
    pool_start  TEXT NOT NULL DEFAULT '',
    pool_end    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_networks_org ON networks(org_id);

-- Static IP leases handed out from a network's pool.
CREATE TABLE IF NOT EXISTS ip_leases (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    ip         TEXT NOT NULL,
    mac        TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(network_id, ip)
);

-- user-mode port forwards (QEMU hostfwd) so a NAT'd guest is reachable.
CREATE TABLE IF NOT EXISTS port_forwards (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    proto      TEXT NOT NULL DEFAULT 'tcp',
    host_ip    TEXT NOT NULL DEFAULT '',
    host_port  INTEGER NOT NULL,
    guest_port INTEGER NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pf_session ON port_forwards(session_id);

-- nftables firewall rules rendered per network and applied on VM start.
CREATE TABLE IF NOT EXISTS firewall_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    priority   INTEGER NOT NULL DEFAULT 100,
    action     TEXT NOT NULL DEFAULT 'accept',   -- accept|drop
    proto      TEXT NOT NULL DEFAULT 'tcp',
    dport      TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},

	{7, "observability-m5", `
-- Periodic metric rollups. scope is 'host' (target_id '') or 'vm' (session id).
CREATE TABLE IF NOT EXISTS metric_samples (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scope     TEXT NOT NULL,                 -- host|vm
    target_id TEXT NOT NULL DEFAULT '',
    cpu_pct   REAL NOT NULL DEFAULT 0,
    mem_used  INTEGER NOT NULL DEFAULT 0,    -- bytes (host) / RSS (vm)
    mem_total INTEGER NOT NULL DEFAULT 0,
    disk_used INTEGER NOT NULL DEFAULT 0,
    disk_total INTEGER NOT NULL DEFAULT 0,
    ts        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_metric_scope_ts ON metric_samples(scope, target_id, ts);

-- Threshold alert rules evaluated by the worker.
CREATE TABLE IF NOT EXISTS alert_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER,
    name       TEXT NOT NULL,
    metric     TEXT NOT NULL,                -- host.cpu_pct|host.mem_pct|host.disk_pct
    op         TEXT NOT NULL DEFAULT '>',
    threshold  REAL NOT NULL,
    channel_id INTEGER,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Alert firings (open/resolved).
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    state       TEXT NOT NULL DEFAULT 'firing',   -- firing|resolved
    value       REAL NOT NULL DEFAULT 0,
    fired_at    TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_state ON alerts(rule_id, state);

-- Notification channels (webhook now; email documented).
CREATE TABLE IF NOT EXISTS alert_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'webhook',   -- webhook|email
    target     TEXT NOT NULL DEFAULT '',          -- URL or email address
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},

	{8, "billing-m6", `
-- Local usage metering ledger (no phone-home): one row per running VM per tick.
CREATE TABLE IF NOT EXISTS usage_ledger (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER NOT NULL,
    session_id      TEXT NOT NULL,
    seconds         INTEGER NOT NULL DEFAULT 0,
    vcpu_seconds    INTEGER NOT NULL DEFAULT 0,
    mem_mb_seconds  INTEGER NOT NULL DEFAULT 0,
    ts              TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_usage_org_ts ON usage_ledger(org_id, ts);

-- Billing plans (local definitions; rates in micro-credits to avoid floats).
CREATE TABLE IF NOT EXISTS plans (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL UNIQUE,
    vcpu_micros_per_hr INTEGER NOT NULL DEFAULT 0,
    mem_micros_per_gbhr INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Per-org resource quotas (0 = unlimited) enforced locally at create/start.
CREATE TABLE IF NOT EXISTS org_quotas (
    org_id        INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    plan_id       INTEGER,
    max_servers   INTEGER NOT NULL DEFAULT 0,
    max_running   INTEGER NOT NULL DEFAULT 0,
    max_vcpus     INTEGER NOT NULL DEFAULT 0,
    max_memory_mb INTEGER NOT NULL DEFAULT 0,
    max_disk_gb   INTEGER NOT NULL DEFAULT 0,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
`},

	{9, "cluster-m7", `
-- Cluster nodes. The control node (this daemon's host) auto-registers as 'local'
-- and drives remote worker nodes over SSH. Scheduling places VMs by free RAM/CPU.
CREATE TABLE IF NOT EXISTS nodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    address    TEXT NOT NULL DEFAULT '',        -- host:port for SSH (empty = local)
    ssh_user   TEXT NOT NULL DEFAULT 'root',
    role       TEXT NOT NULL DEFAULT 'worker',  -- local|worker
    status     TEXT NOT NULL DEFAULT 'unknown', -- ready|unreachable|unknown
    cpus       INTEGER NOT NULL DEFAULT 0,
    mem_total  INTEGER NOT NULL DEFAULT 0,
    mem_free   INTEGER NOT NULL DEFAULT 0,
    last_seen  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Which node a VM is placed on (NULL/0 = the local control node).
ALTER TABLE sessions ADD COLUMN node_id INTEGER;
`},

	{10, "platform-m8", `
-- PCI/USB passthrough assignments for a VM (vfio-pci / usb-host). Applied only
-- when the host pre-flight confirms IOMMU + vfio are available.
ALTER TABLE sessions ADD COLUMN passthrough TEXT NOT NULL DEFAULT '';  -- csv of pci addrs / usb ids
`},
	{11, "vdi-broker", `
-- Desktop pools: a named template a set of users may draw a desktop from. In
-- 'pooled' mode a free VM is leased on connect and reclaimed on disconnect; in
-- 'persistent' mode each grantee keeps a dedicated VM across sessions.
CREATE TABLE IF NOT EXISTS desktop_pools (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    image_name  TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'desktop',
    assign_mode TEXT NOT NULL DEFAULT 'pooled',   -- 'pooled' | 'persistent'
    cpus        INTEGER NOT NULL DEFAULT 2,
    memory_mb   INTEGER NOT NULL DEFAULT 2048,
    disk_gb     INTEGER NOT NULL DEFAULT 20,
    min_size    INTEGER NOT NULL DEFAULT 0,        -- warm VMs kept ready
    max_size    INTEGER NOT NULL DEFAULT 5,        -- hard cap on pool VMs
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, name)
);
-- Which users may draw from a pool.
CREATE TABLE IF NOT EXISTS pool_grants (
    pool_id INTEGER NOT NULL REFERENCES desktop_pools(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (pool_id, user_id)
);
-- Pool bookkeeping on each VM that belongs to a pool.
ALTER TABLE sessions ADD COLUMN pool_id INTEGER;         -- NULL = not a pool VM
ALTER TABLE sessions ADD COLUMN assigned_to INTEGER;     -- user currently holding it (NULL = free)
ALTER TABLE sessions ADD COLUMN leased_at TEXT;          -- when it was leased
ALTER TABLE sessions ADD COLUMN last_activity TEXT;      -- last desktop-WS activity (idle reclaim)
CREATE INDEX IF NOT EXISTS idx_sessions_pool ON sessions(pool_id, assigned_to);
`},
	{12, "net-storage-l3", `
-- Storage pools gain backend awareness: a VM disk may live on a registered
-- storage pool (dir/zfs/lvm). storage_pool_id is SEPARATE from the VDI pool_id.
ALTER TABLE sessions ADD COLUMN storage_pool_id INTEGER;  -- NULL = default disk dir
-- A pool may describe how to place a disk on its backend.
ALTER TABLE storage_pools ADD COLUMN backend TEXT NOT NULL DEFAULT 'dir';  -- dir|zfs|lvm
ALTER TABLE storage_pools ADD COLUMN vg TEXT NOT NULL DEFAULT '';           -- lvm: volume group
ALTER TABLE storage_pools ADD COLUMN thinpool TEXT NOT NULL DEFAULT '';     -- lvm: thin pool LV
-- Per-network L3 opt-in: whether this network is routed and SNAT'd at the edge.
ALTER TABLE networks ADD COLUMN routed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE networks ADD COLUMN nat INTEGER NOT NULL DEFAULT 0;
-- Single managed L3 config (uplink, static routes, OSPF, BGP, firewall) as JSON.
CREATE TABLE IF NOT EXISTS routing_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO routing_config(id, config_json) VALUES (1, '{}');
`},
	{13, "vmware-net", `
-- NIC bonds (link aggregation / teaming) that back vSwitch uplinks.
CREATE TABLE IF NOT EXISTS net_bonds (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    mode       TEXT NOT NULL,                 -- lacp | etherchannel | active-backup
    members    TEXT NOT NULL DEFAULT '',      -- csv of member NICs
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- vSwitches: VLAN-filtering bridges with an uplink (a NIC or a bond).
CREATE TABLE IF NOT EXISTS net_vswitches (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    bridge     TEXT NOT NULL,                 -- host bridge device name
    uplink     TEXT NOT NULL DEFAULT '',      -- NIC or bond name (trunk)
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},
	{14, "iso-install-sentinel", `
-- Reserved image row so a VM can be created with NO base image (install from a
-- boot ISO onto a blank disk). sessions.image_name is a NOT NULL FK to
-- images(name); ISO-install VMs reference this row. status != 'ready' keeps it
-- out of the image picker.
INSERT OR IGNORE INTO images(name,path,source_url,size_bytes,status)
VALUES('(install from ISO)','','',0,'reserved');
`},
	{15, "metric-throughput", `
-- Disk and network throughput (bytes/sec) on metric samples, for history charts.
ALTER TABLE metric_samples ADD COLUMN disk_read  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE metric_samples ADD COLUMN disk_write INTEGER NOT NULL DEFAULT 0;
ALTER TABLE metric_samples ADD COLUMN net_rx     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE metric_samples ADD COLUMN net_tx     INTEGER NOT NULL DEFAULT 0;
`},
	{16, "metric-pressure", `
-- IOWAIT and PSI (pressure stall info) for cpu/memory/io on host samples.
ALTER TABLE metric_samples ADD COLUMN iowait   REAL NOT NULL DEFAULT 0;
ALTER TABLE metric_samples ADD COLUMN cpu_pres REAL NOT NULL DEFAULT 0;
ALTER TABLE metric_samples ADD COLUMN mem_pres REAL NOT NULL DEFAULT 0;
ALTER TABLE metric_samples ADD COLUMN io_pres  REAL NOT NULL DEFAULT 0;
`},
	{17, "shared-storage", `
-- Simple host-wide key/value settings (e.g. the dedicated storage interface).
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
-- NFS/CIFS/Ceph mounts managed from the UI. Each is also registered as a
-- storage pool (storage_pools) at its mountpoint for VM disk placement.
CREATE TABLE IF NOT EXISTS shared_mounts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,                 -- nfs|cifs|ceph
    name       TEXT NOT NULL UNIQUE,
    spec       TEXT NOT NULL,                 -- server:/export | mon1,mon2:/path
    options    TEXT NOT NULL DEFAULT '',
    mountpoint TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'mounted', -- mounted|error
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- iSCSI sessions (login state) managed from the UI.
CREATE TABLE IF NOT EXISTS iscsi_targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    portal     TEXT NOT NULL,                 -- ip:port
    target     TEXT NOT NULL,                 -- iqn...
    status     TEXT NOT NULL DEFAULT 'loggedin',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(portal, target)
);
`},
	{18, "lxc-containers", `
-- LXC system containers (managed alongside QEMU VM sessions).
CREATE TABLE IF NOT EXISTS containers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    org_id     INTEGER NOT NULL DEFAULT 0,
    owner_id   INTEGER NOT NULL DEFAULT 0,
    dist       TEXT NOT NULL DEFAULT '',
    release    TEXT NOT NULL DEFAULT '',
    arch       TEXT NOT NULL DEFAULT 'amd64',
    lxcpath    TEXT NOT NULL DEFAULT '',
    bridge     TEXT NOT NULL DEFAULT '',
    cpus       INTEGER NOT NULL DEFAULT 1,
    memory_mb  INTEGER NOT NULL DEFAULT 512,
    status     TEXT NOT NULL DEFAULT 'creating', -- creating|stopped|error
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},
	{19, "spice-display", `
-- Per-VM console display mode + loopback SPICE port.
ALTER TABLE sessions ADD COLUMN display    TEXT NOT NULL DEFAULT 'vnc'; -- vnc|spice
ALTER TABLE sessions ADD COLUMN spice_port INTEGER NOT NULL DEFAULT 0;
`},
	{20, "disk-backend", `
-- Disk backend: qcow2 file (default) or a raw ZFS zvol block device.
ALTER TABLE sessions ADD COLUMN disk_backend TEXT NOT NULL DEFAULT 'qcow2'; -- qcow2|zvol
`},
	{21, "storage-overlay", `
-- VXLAN storage overlays: a shared L2 for storage traffic over an existing
-- underlay, so storage works when nodes are not on the same physical segment.
CREATE TABLE IF NOT EXISTS storage_overlays (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  name         TEXT NOT NULL UNIQUE,        -- overlay iface name
  vni          INTEGER NOT NULL,
  underlay_dev TEXT NOT NULL,               -- device the UDP rides over
  local_ip     TEXT NOT NULL,               -- underlay source IP
  overlay_cidr TEXT NOT NULL,               -- this node's overlay address/CIDR
  dstport      INTEGER NOT NULL DEFAULT 4789,
  mtu          INTEGER NOT NULL DEFAULT 1450,
  peers        TEXT NOT NULL DEFAULT '',    -- CSV of peer underlay IPs
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
`},
	{22, "vm-hardware", `
-- Per-VM hardware knobs. Defaults reproduce the previously-hardcoded launch
-- exactly (q35 / virtio-blk / virtio-net / qxl / no guest-agent / no TPM /
-- no secure boot / linux), so existing VMs migrate with byte-identical hardware.
ALTER TABLE sessions ADD COLUMN machine_type TEXT    NOT NULL DEFAULT 'q35';        -- q35|pc
ALTER TABLE sessions ADD COLUMN disk_bus     TEXT    NOT NULL DEFAULT 'virtio-blk';  -- virtio-blk|virtio-scsi|sata
ALTER TABLE sessions ADD COLUMN nic_model    TEXT    NOT NULL DEFAULT 'virtio';      -- virtio|e1000e|rtl8139
ALTER TABLE sessions ADD COLUMN vga          TEXT    NOT NULL DEFAULT 'qxl';         -- qxl|virtio|std
ALTER TABLE sessions ADD COLUMN guest_agent  INTEGER NOT NULL DEFAULT 0;             -- 0/1 qemu-guest-agent channel
ALTER TABLE sessions ADD COLUMN tpm          INTEGER NOT NULL DEFAULT 0;             -- 0/1 swtpm TPM 2.0
ALTER TABLE sessions ADD COLUMN secureboot   INTEGER NOT NULL DEFAULT 0;             -- 0/1 UEFI Secure Boot (MS keys)
ALTER TABLE sessions ADD COLUMN os_type      TEXT    NOT NULL DEFAULT 'linux';       -- linux|windows
`},
	{23, "storage-vmotion", `
-- Persisted storage-vMotion state machine. The invariant is that the VM is
-- always recoverable from the UNTOUCHED source until a move is durably
-- committed; these columns let a crash/restart recover safely (never auto-start
-- on a half-written target; keep the source until an explicit reclaim).
ALTER TABLE sessions ADD COLUMN migration_state TEXT NOT NULL DEFAULT 'idle';  -- idle|offline|mirroring|pivoting
ALTER TABLE sessions ADD COLUMN mig_target_path TEXT NOT NULL DEFAULT '';      -- disk being written during a move
ALTER TABLE sessions ADD COLUMN mig_source_path TEXT NOT NULL DEFAULT '';      -- retained pre-move source (for rollback/reclaim)
`},
	{24, "vxlan-networks", `
-- First-class VXLAN VM networks: each network is its own L2 overlay segment with
-- its own VNI/underlay/peers (not the single cluster-wide overlay). VMs attach to
-- a per-network bridge. These columns are empty for non-VXLAN networks.
ALTER TABLE networks ADD COLUMN vni           INTEGER NOT NULL DEFAULT 0;
ALTER TABLE networks ADD COLUMN underlay      TEXT    NOT NULL DEFAULT '';   -- underlay NIC carrying the UDP
ALTER TABLE networks ADD COLUMN vxlan_local   TEXT    NOT NULL DEFAULT '';   -- underlay source IP (optional)
ALTER TABLE networks ADD COLUMN vxlan_peers   TEXT    NOT NULL DEFAULT '';   -- CSV of peer underlay IPs (head-end replication)
ALTER TABLE networks ADD COLUMN vxlan_dstport INTEGER NOT NULL DEFAULT 4789;
ALTER TABLE networks ADD COLUMN vxlan_mtu     INTEGER NOT NULL DEFAULT 1450;
`},
	{25, "ad-identity", `
-- Active Directory / LDAP identity mapping for JIT-provisioned users.
ALTER TABLE users ADD COLUMN ad_dn TEXT;
`},
	{26, "published-apps", `
-- VDI published-app library: apps an admin publishes to the end-user portal.
-- kind 'desktop' = full desktop from a pool; 'remoteapp' = a single Windows
-- RemoteApp (seamless) from a pool VM; 'web' = a link tile (throwaway browser
-- target), no VM. Pool apps inherit the pool's per-user grants.
CREATE TABLE IF NOT EXISTS published_apps (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id     INTEGER NOT NULL,
  pool_id    INTEGER NOT NULL DEFAULT 0,          -- backing VDI pool (0 for web)
  name       TEXT    NOT NULL,
  kind       TEXT    NOT NULL DEFAULT 'desktop',  -- desktop|remoteapp|web
  target     TEXT    NOT NULL DEFAULT '',         -- web: URL; remoteapp: program/|| alias
  args       TEXT    NOT NULL DEFAULT '',         -- remoteapp arguments
  icon       TEXT    NOT NULL DEFAULT '',         -- short glyph/label for the tile
  created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
`},
	{27, "guest-os", `
-- Detected guest OS (from qemu-guest-agent) for VMs installed from an ISO, so
-- the UI can show the real OS instead of the "(install from ISO)" placeholder.
ALTER TABLE sessions ADD COLUMN guest_os TEXT;
`},
	{28, "perf-knobs", `
-- Per-VM performance toggles: pin vCPU threads 1:1 to host CPUs, and back guest
-- RAM with hugepages (when the host has a reserved pool). Both default off.
ALTER TABLE sessions ADD COLUMN perf_pin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN perf_hugepages INTEGER NOT NULL DEFAULT 0;
`},
	{29, "eject-virtio", `
-- When set, don't auto-attach the virtio-win driver CD to this (Windows) VM —
-- i.e. the user ejected it after installing the drivers. Applies on next start.
ALTER TABLE sessions ADD COLUMN eject_virtio INTEGER NOT NULL DEFAULT 0;
`},
	{30, "backup-targets", `
-- Where a backup's file lands: 0 = the local default backup dir, else the id of
-- a registered storage_pools row whose Path is a writable directory (local dir,
-- NFS/CIFS/CephFS mount, or a ZFS filesystem). Block pools (lvm-thin/zvol) are
-- not valid targets. Schedules carry the same so every run writes to one place.
ALTER TABLE backups ADD COLUMN target_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE backup_schedules ADD COLUMN target_id INTEGER NOT NULL DEFAULT 0;
`},
	{31, "backup-targets-table", `
-- First-class backup targets, managed on the Backups page and INDEPENDENT of
-- storage pools. kind: local (a directory) | nfs | cifs | cephfs. Network kinds
-- are mounted at 'mountpoint' (/var/lib/vdxclone/backup-mounts/<id>) on boot and
-- before each run. 'secret' holds an AES-GCM sealed (enc:) CIFS password / Ceph
-- key. target_id 0 (in backups/backup_schedules) still means the built-in local
-- default backup dir, so existing rows keep working.
CREATE TABLE IF NOT EXISTS backup_targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL,                  -- local|nfs|cifs|cephfs
    mountpoint TEXT NOT NULL DEFAULT '',        -- local: the dir; network: mount dir
    server     TEXT NOT NULL DEFAULT '',        -- nfs/cifs host; cephfs mon list
    share      TEXT NOT NULL DEFAULT '',        -- nfs export / cifs share / ceph path
    username   TEXT NOT NULL DEFAULT '',        -- cifs user / ceph client name
    secret     TEXT NOT NULL DEFAULT '',        -- sealed (enc:) cifs pass / ceph key
    domain     TEXT NOT NULL DEFAULT '',        -- cifs domain/workgroup
    vers       TEXT NOT NULL DEFAULT '',        -- nfs/cifs protocol version
    options    TEXT NOT NULL DEFAULT '',        -- extra mount options
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_bktargets_org ON backup_targets(org_id);
`},
	{32, "audit-actor-name", `
-- Snapshot the actor's display name AT WRITE TIME so the audit trail is immutable
-- about WHO did something even if that user is later renamed or deleted. Old rows
-- (empty actor_name) fall back to a live users JOIN at read time.
ALTER TABLE audit_log ADD COLUMN actor_name TEXT NOT NULL DEFAULT '';
`},
	{33, "desktop-creds", `
-- Optional per-VM guest credentials for the browser desktop (guac RDP). Needed
-- because RDP with NLA (Windows default) blanks without valid credentials, and a
-- Windows VM has no cloud-init user. secret is AES-GCM sealed (enc:). When absent
-- for an RDP-capable VM, the desktop falls back to VNC (the guest's login screen).
CREATE TABLE IF NOT EXISTS desktop_creds (
    session_id TEXT PRIMARY KEY,
    username   TEXT NOT NULL DEFAULT '',
    secret     TEXT NOT NULL DEFAULT '',
    domain     TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},
	{34, "pool-os-type", `
-- Desktop pools deliver full Linux or Windows desktops; record which so the VDI
-- VMs are created with the right guest OS profile (RTC, drivers) and the UI can
-- label the pool.
ALTER TABLE desktop_pools ADD COLUMN os_type TEXT NOT NULL DEFAULT 'linux'; -- linux|windows
`},
	{35, "vdi-desktops", `
-- A VDI desktop is simply an existing VM tagged to a specific user: that user
-- sees it on the portal and connects over VNC. One assignee per VM; a user may
-- hold several. VMs listed here are hidden from the regular instances page.
CREATE TABLE IF NOT EXISTS vdi_desktops (
    session_id TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    org_id     INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vdi_user ON vdi_desktops(user_id);
`},
	{36, "vm-autostart", `
-- "Start at boot": when set, vdxd powers the VM on automatically after a HOST
-- reboot (detected via the kernel boot_id, so a plain control-plane restart does
-- NOT touch running/stopped VMs). Default ON so existing VMs come back after a
-- power cycle; clear it per-VM to keep one powered off across reboots.
ALTER TABLE sessions ADD COLUMN autostart INTEGER NOT NULL DEFAULT 1;
`},
	{37, "vrouter", `
-- NSX-lite virtual routers. A vRouter is a dedicated routing instance (an LXC
-- container or a network namespace running its own FRR) that routes between a
-- "transit link" (a free physical NIC) and one or more internal-only port
-- groups that VMs attach to. runtime=vm (a QEMU appliance from a user-supplied
-- image) is reserved for a later release and rejected by the service layer.
CREATE TABLE IF NOT EXISTS vrouters (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id         INTEGER NOT NULL,
    owner_id       INTEGER NOT NULL DEFAULT 0,
    name           TEXT NOT NULL UNIQUE,
    runtime        TEXT NOT NULL DEFAULT 'lxc',    -- lxc|netns|vm
    container_name TEXT NOT NULL DEFAULT '',       -- lxc: the container name (vrtr-<id>)
    netns_name     TEXT NOT NULL DEFAULT '',       -- netns: the namespace name (vrtr-<id>)
    vm_session_id  TEXT NOT NULL DEFAULT '',        -- vm (reserved): backing VM session id
    image          TEXT NOT NULL DEFAULT '',        -- vm (reserved): user-supplied appliance image
    lxcpath        TEXT NOT NULL DEFAULT '',
    dist           TEXT NOT NULL DEFAULT 'debian',
    release        TEXT NOT NULL DEFAULT 'trixie',  -- FRR 10.x (matches the frr.conf version banner)
    cpus           INTEGER NOT NULL DEFAULT 1,
    mem_mb         INTEGER NOT NULL DEFAULT 512,
    frr_json       TEXT NOT NULL DEFAULT '{}',       -- per-vRouter routing.Config (protocols)
    status         TEXT NOT NULL DEFAULT 'creating', -- creating|stopped|running|error
    error          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vrouters_org ON vrouters(org_id);

-- A vRouter's interfaces. idx 0 is the transit leg (eth0); idx 1.. are internal
-- legs (eth1..), each backing one isolated bridge + a networks row VMs bind to.
CREATE TABLE IF NOT EXISTS vrouter_legs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vrouter_id  INTEGER NOT NULL REFERENCES vrouters(id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,            -- lxc.net.N / ethN inside the runtime
    kind        TEXT NOT NULL,               -- transit|internal
    bridge      TEXT NOT NULL DEFAULT '',    -- host bridge this leg's veth lands on
    phys_iface  TEXT NOT NULL DEFAULT '',    -- transit: the enslaved physical NIC
    network_id  INTEGER NOT NULL DEFAULT 0,  -- internal: the networks row VMs bind to
    iface_name  TEXT NOT NULL DEFAULT '',    -- eth0/eth1.. inside the runtime
    cidr        TEXT NOT NULL DEFAULT '',    -- leg IP (zebra assigns it from frr.conf)
    mac         TEXT NOT NULL DEFAULT '',
    dhcp        INTEGER NOT NULL DEFAULT 0,  -- internal: run dnsmasq on this leg
    dhcp_range  TEXT NOT NULL DEFAULT '',    -- e.g. 10.60.0.100,10.60.0.200
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vrouter_legs_vr ON vrouter_legs(vrouter_id);
`},
	{38, "vrouter-dhcp-dns", `
-- DNS servers a vRouter internal leg's DHCP hands out (dnsmasq option 6), CSV.
ALTER TABLE vrouter_legs ADD COLUMN dhcp_dns TEXT NOT NULL DEFAULT '';
`},
	{39, "vrouter-firewall", `
-- Per-vRouter zone-based firewall (ZBFW). A "zone" is a security label (App
-- Zone, DB Zone, …) that owns one or more of the vRouter's legs (port groups);
-- a "policy" allows/denies traffic between a pair of zones. The whole config is
-- a JSON blob (mirrors frr_json) rendered to an nftables table that is applied
-- INSIDE the vRouter runtime's own netfilter instance — never on the host.
ALTER TABLE vrouters ADD COLUMN fw_json TEXT NOT NULL DEFAULT '{}';
`},
	{40, "net-firewall", `
-- Distributed firewall / microsegmentation for REGULAR port groups (non-vRouter
-- vSwitch bridges). Per-network zones group VMs (by MAC); policies allow/deny
-- east-west traffic between them, enforced on the HOST via an nftables
-- BRIDGE-family table (bridge vdxdfw) that matches VM MACs. Default stance is
-- ALLOW (enabling never blackholes a live segment). Separate from the vRouter
-- zone firewall and from the host L3 table inet vdxclone.
CREATE TABLE IF NOT EXISTS net_firewall (
    network_id INTEGER PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
    fw_json    TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},
	{41, "org-firewall", `
-- Unified NSX-style firewall (one document per org). Supersedes the two older,
-- separate models (vrouters.fw_json + net_firewall), which now become DERIVED
-- output of the compiler. The source of truth is a single JSON document holding:
--   groups   : VM Groups (VMs by MAC and/or whole port groups), each in a zone
--   rules_ns : North-South rules (compiled to each vRouter's inet vdxfw table)
--   rules_ew : East-West rules  (compiled to the host bridge vdxdfw table)
-- A group can span port groups and outlive any one vRouter, so it lives here at
-- org scope rather than on a vrouter/network row.
CREATE TABLE IF NOT EXISTS org_firewall (
    org_id     INTEGER PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    fw_json    TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`},
	{42, "drop-vdi", `
-- The VDI feature (both the "VM tagged to a user" model and the older desktop
-- pool / published-app broker + guacd gateway) has been removed. Drop every
-- table it owned. The vestigial sessions columns from migration 11 (pool_id,
-- assigned_to, leased_at, last_activity) are intentionally LEFT in place: SQLite
-- rewrites the whole table on DROP COLUMN, and nothing reads them anymore, so
-- there is no reason to churn the live sessions table.
DROP TABLE IF EXISTS vdi_desktops;
DROP TABLE IF EXISTS published_apps;
DROP TABLE IF EXISTS desktop_creds;
DROP TABLE IF EXISTS pool_grants;
DROP TABLE IF EXISTS desktop_pools;
`},
}

// Open connects to the SQLite database, enables WAL, and applies migrations.
//
// SQLite serializes writes; to avoid "database is locked" under the background
// workers we cap the pool at a single connection. WAL still lets that one
// connection interleave reads and writes efficiently. (A separate read pool can
// be split out later if read throughput becomes a concern.)
func Open(path string) (*DB, error) {
	// synchronous(FULL) + WAL: writes are fsynced before the txn reports success,
	// so a power cut can't lose a committed transaction (the durability the
	// storage-vMotion commit relies on). busy_timeout avoids "database is locked"
	// under the background workers; the pool is a single connection (writes
	// serialize in SQLite anyway).
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=wal_autocheckpoint(1000)&_txlock=immediate"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	d := &DB{sqldb}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

// OpenResilient opens the control-plane DB with self-healing. It:
//  1. opens path and runs PRAGMA quick_check;
//  2. if the file is unopenable or fails integrity, quarantines it and restores
//     the newest VERIFIED backup from backupDir;
//  3. if no good backup exists, starts a FRESH database.
//
// In every branch it NEVER touches VM disks or QEMU processes — a broken control
// plane must not disrupt running VMs, which are re-adopted separately on boot.
// It is the entrypoint the daemon uses; plain Open stays for tools/tests.
func OpenResilient(path, backupDir string) (*DB, error) {
	if d, err := Open(path); err == nil {
		if qc := d.quickCheck(); qc == nil {
			return d, nil
		} else {
			log.Printf("db: integrity check FAILED on %s: %v — attempting self-heal", path, qc)
			_ = d.Close()
		}
	} else {
		log.Printf("db: could not open %s: %v — attempting self-heal", path, err)
	}

	quarantine(path) // keep the bad file (+WAL/SHM) aside for forensics

	if bak := newestGoodBackup(backupDir); bak != "" {
		if err := copyFile(bak, path); err == nil {
			if d, err := Open(path); err == nil && d.quickCheck() == nil {
				log.Printf("db: RESTORED control plane from verified backup %s", bak)
				return d, nil
			} else if d != nil {
				_ = d.Close()
			}
		}
		log.Printf("db: restore from %s did not verify — falling back to a fresh database", bak)
		quarantine(path)
	}

	log.Printf("db: no usable backup — starting a FRESH control-plane database (running VMs are unaffected and will be re-adopted on boot)")
	d, err := Open(path)
	if err != nil {
		return nil, fmt.Errorf("db: unrecoverable: %w", err)
	}
	return d, nil
}

// quickCheck runs PRAGMA quick_check (cheaper than integrity_check) and returns
// an error unless it reports "ok".
func (d *DB) quickCheck() error {
	var res string
	if err := d.QueryRow(`PRAGMA quick_check`).Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("quick_check: %s", res)
	}
	return nil
}

// Backup writes a consistent, VERIFIED snapshot of the DB to dir via VACUUM INTO
// and returns its path. A snapshot that fails its own integrity check is deleted
// and an error returned, so we never keep a backup we couldn't restore.
func (d *DB) Backup(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	// VACUUM INTO refuses to write to a path that already exists ("output file
	// already exists"), so we target a UNIQUE temp (pid+nanoseconds) that we also
	// clear first, verify it, then atomically rename into the final timestamped
	// name. This fixes repeated backup failures when a target name collided (e.g.
	// two snapshots landing in the same clock second after a restart), and means a
	// reader never sees a half-written snapshot.
	now := time.Now().UTC()
	tmp := filepath.Join(dir, fmt.Sprintf(".controlplane-%d-%d.tmp", os.Getpid(), now.UnixNano()))
	_ = os.Remove(tmp)
	if _, err := d.Exec(`VACUUM INTO ?`, tmp); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if !verifyDBFile(tmp) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("backup failed verification")
	}
	dest := filepath.Join(dir, "controlplane-"+now.Format("20060102T150405.000")+".db")
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

// PruneBackups keeps the newest `keep` controlplane-*.db snapshots in dir and
// removes older ones (best effort).
func PruneBackups(dir string, keep int) {
	baks := listBackups(dir)
	for i := 0; i+keep < len(baks); i++ {
		_ = os.Remove(baks[i])
	}
}

// listBackups returns controlplane-*.db paths in dir sorted OLDEST→newest (the
// timestamped names sort lexicographically in chronological order).
func listBackups(dir string) []string {
	if dir == "" {
		return nil
	}
	m, _ := filepath.Glob(filepath.Join(dir, "controlplane-*.db"))
	sort.Strings(m)
	return m
}

// newestGoodBackup returns the newest backup that passes integrity verification,
// scanning newest→oldest, or "" if none.
func newestGoodBackup(dir string) string {
	baks := listBackups(dir)
	for i := len(baks) - 1; i >= 0; i-- {
		if verifyDBFile(baks[i]) {
			return baks[i]
		}
		log.Printf("db: backup %s failed verification, trying older", baks[i])
	}
	return ""
}

// verifyDBFile opens a DB file READ-ONLY (no migrations, no writes) and runs
// quick_check. Used to vet backups before trusting them.
func verifyDBFile(file string) bool {
	if _, err := os.Stat(file); err != nil {
		return false
	}
	ro, err := sql.Open("sqlite", file+"?_pragma=query_only(1)&_txlock=deferred")
	if err != nil {
		return false
	}
	defer ro.Close()
	ro.SetMaxOpenConns(1)
	var res string
	if err := ro.QueryRow(`PRAGMA quick_check`).Scan(&res); err != nil {
		return false
	}
	return res == "ok"
}

// quarantine renames a (corrupt) DB file and its WAL/SHM sidecars aside with a
// timestamp, so the file is preserved for inspection but out of the way.
func quarantine(path string) {
	suffix := ".corrupt-" + time.Now().UTC().Format("20060102T150405")
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			_ = os.Rename(p, p+suffix)
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func (d *DB) migrate() error {
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`); err != nil {
		return fmt.Errorf("migrations table: %w", err)
	}
	var current int
	_ = d.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&current)

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, name) VALUES(?,?)`, m.version, m.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", m.version, err)
		}
	}
	return nil
}
