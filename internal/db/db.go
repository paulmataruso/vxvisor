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
	{43, "vm-folders", `
-- Inventory folders: organize instances into a nestable tree (VMware-style).
-- Folders are org-scoped and shared across the org; a VM lives in at most one
-- folder. Membership is tracked in a SEPARATE table (absent = root/ungrouped) so
-- the tightly-coupled sessions table and its scan logic stay untouched. Both FKs
-- cascade, and foreign_keys is ON, so deleting a VM or a folder auto-clears the
-- stale membership rows.
CREATE TABLE IF NOT EXISTS vm_folders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    parent_id  INTEGER REFERENCES vm_folders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_vm_folders_org ON vm_folders(org_id, parent_id);
CREATE TABLE IF NOT EXISTS vm_folder_members (
    vm_id     TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    org_id    INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    folder_id INTEGER NOT NULL REFERENCES vm_folders(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vm_folder_members_folder ON vm_folder_members(folder_id);
`},
	{44, "tenant-networks", `
-- Tenant networks: a first-class, per-org isolated network. v1 ships the
-- "isolated" mode — a dedicated per-org Linux bridge (device vdxt<network_id>)
-- that is its own L2 broadcast domain with no uplink, so two orgs' VMs can never
-- share a segment. Each tenant network OWNS a backing 'networks' row (the normal
-- port group VMs attach to via the existing tap path); network_id references it
-- with the DEFAULT (NO ACTION / RESTRICT) foreign-key action ON PURPOSE, so the
-- raw /networks delete errors on a tenant-owned row and callers must go through
-- DeleteTenantNetwork (which tears down the host bridge). ext_mode/ext_ref/
-- vrouter_id are reserved for the routed/l2bridge/vrouter external modes landing
-- in a later release. Deleting an org cascades the row away (there is no
-- DeleteOrg yet; when added it must tear down host devices explicitly first).
CREATE TABLE IF NOT EXISTS tenant_networks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    network_id  INTEGER NOT NULL REFERENCES networks(id),
    ext_mode    TEXT NOT NULL DEFAULT 'isolated',
    ext_ref     TEXT NOT NULL DEFAULT '',
    vrouter_id  INTEGER NOT NULL DEFAULT 0,
    state       TEXT NOT NULL DEFAULT 'applied',
    error       TEXT NOT NULL DEFAULT '',
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_tnet_org ON tenant_networks(org_id);
CREATE INDEX IF NOT EXISTS idx_tnet_network ON tenant_networks(network_id);
`},
	{45, "tenant-net-v2", `
-- Tenant networking v2. Two changes:
--
-- (1) net_segments: a transactional allocator that reserves a globally-unique
--     segment identity (a VXLAN VNI) per tenant segment. In v2 this is an
--     IDENTITY ONLY — no vxlan device is created from it (segments realize as
--     plain uplink-less bridges, which is stronger isolation on a single host
--     than a peerless vxlan that would expose a host-wide UDP:4789 ingress). The
--     reserved VNI + cluster-wide allocator + device materialization are the v3
--     multi-host growth path. The composite PRIMARY KEY makes a double allocation
--     impossible.
CREATE TABLE IF NOT EXISTS net_segments (
    seg_type   TEXT NOT NULL,              -- 'vxlan' (v2); 'vlan' reserved
    seg_id     INTEGER NOT NULL,           -- the allocated VNI (identity)
    org_id     INTEGER NOT NULL,
    net_id     INTEGER NOT NULL,           -- backing networks.id this identity belongs to
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (seg_type, seg_id)
);
CREATE INDEX IF NOT EXISTS idx_net_segments_net ON net_segments(net_id);
CREATE INDEX IF NOT EXISTS idx_net_segments_org ON net_segments(org_id);

-- (2) Rebuild vrouters so router names are unique PER ORG, not globally. The old
--     column-level "name TEXT NOT NULL UNIQUE" collided across tenants (two orgs
--     could not both name a router "core") and leaked another org's name via the
--     constraint error. SQLite cannot drop a column constraint in place, so we
--     rebuild. This runs with foreign_keys=ON: we first copy vrouter_legs into a
--     constraint-free temp table and DROP the real vrouter_legs, so that when we
--     DROP vrouters nothing references it (no implicit cascade can wipe legs),
--     then we recreate vrouters with UNIQUE(org_id,name) and restore the legs.
CREATE TABLE vrouter_legs_tmp45 AS SELECT * FROM vrouter_legs;
DROP TABLE vrouter_legs;
CREATE TABLE vrouters_new45 (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id         INTEGER NOT NULL,
    owner_id       INTEGER NOT NULL DEFAULT 0,
    name           TEXT NOT NULL,
    runtime        TEXT NOT NULL DEFAULT 'lxc',
    container_name TEXT NOT NULL DEFAULT '',
    netns_name     TEXT NOT NULL DEFAULT '',
    vm_session_id  TEXT NOT NULL DEFAULT '',
    image          TEXT NOT NULL DEFAULT '',
    lxcpath        TEXT NOT NULL DEFAULT '',
    dist           TEXT NOT NULL DEFAULT 'debian',
    release        TEXT NOT NULL DEFAULT 'trixie',
    cpus           INTEGER NOT NULL DEFAULT 1,
    mem_mb         INTEGER NOT NULL DEFAULT 512,
    frr_json       TEXT NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT 'creating',
    error          TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    fw_json        TEXT NOT NULL DEFAULT '{}',
    UNIQUE(org_id, name)
);
INSERT INTO vrouters_new45 (id,org_id,owner_id,name,runtime,container_name,netns_name,vm_session_id,image,lxcpath,dist,release,cpus,mem_mb,frr_json,status,error,created_at,fw_json)
    SELECT id,org_id,owner_id,name,runtime,container_name,netns_name,vm_session_id,image,lxcpath,dist,release,cpus,mem_mb,frr_json,status,error,created_at,fw_json FROM vrouters;
DROP TABLE vrouters;
ALTER TABLE vrouters_new45 RENAME TO vrouters;
CREATE INDEX IF NOT EXISTS idx_vrouters_org ON vrouters(org_id);
CREATE TABLE vrouter_legs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vrouter_id  INTEGER NOT NULL REFERENCES vrouters(id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    bridge      TEXT NOT NULL DEFAULT '',
    phys_iface  TEXT NOT NULL DEFAULT '',
    network_id  INTEGER NOT NULL DEFAULT 0,
    iface_name  TEXT NOT NULL DEFAULT '',
    cidr        TEXT NOT NULL DEFAULT '',
    mac         TEXT NOT NULL DEFAULT '',
    dhcp        INTEGER NOT NULL DEFAULT 0,
    dhcp_range  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    dhcp_dns    TEXT NOT NULL DEFAULT ''
);
INSERT INTO vrouter_legs (id,vrouter_id,idx,kind,bridge,phys_iface,network_id,iface_name,cidr,mac,dhcp,dhcp_range,created_at,dhcp_dns)
    SELECT id,vrouter_id,idx,kind,bridge,phys_iface,network_id,iface_name,cidr,mac,dhcp,dhcp_range,created_at,dhcp_dns FROM vrouter_legs_tmp45;
CREATE INDEX IF NOT EXISTS idx_vrouter_legs_vr ON vrouter_legs(vrouter_id);
DROP TABLE vrouter_legs_tmp45;
`},
	{46, "tenant-net-v3", `
-- Tenant networking v3: virtual uplinks + admin egress-mapping console.
--
-- STRICTLY ADDITIVE: new tables + one nullable column on tenant_networks, NO
-- table rebuilds, NO data mutation (unlike migration 45). An older binary rolled
-- back over this schema runs zero migrations (the runner only applies versions
-- greater than MAX(version)) and serves correctly, because the networks/sessions
-- scans use explicit column lists. Statement ORDER matters: ext_trunks and
-- tenant_uplinks must exist before the ALTER that references them. Partial
-- uniqueness is a STANDALONE index (an inline "UNIQUE(...) WHERE" is a syntax
-- error on modernc and would quarantine the live DB via OpenResilient).

-- ext_trunks: a physical NIC/bond the instance admin designates as external-
-- capable and ROLE-DEDICATED (never also a raw vSwitch uplink — enforced by a
-- service-layer guard). It is the parent for per-tenant VLAN subinterfaces
-- (<iface>.<vid>), not enslaved to any bridge. orig_mtu/orig_offload capture the
-- pre-designation state ONCE so teardown restores it byte-for-byte;
-- teardown_pending makes the boot-reapply converge-to-desired-state (crash-safe).
CREATE TABLE IF NOT EXISTS ext_trunks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    iface            TEXT NOT NULL UNIQUE,
    kind             TEXT NOT NULL DEFAULT 'nic',     -- 'nic' | 'bond'
    mtu              INTEGER NOT NULL DEFAULT 1600,
    qinq_capable     INTEGER NOT NULL DEFAULT 0,
    offload_disabled INTEGER NOT NULL DEFAULT 0,
    orig_mtu         INTEGER NOT NULL DEFAULT 0,
    orig_offload     TEXT NOT NULL DEFAULT '',
    teardown_pending INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- tenant_vlan_pools: an admin-reserved allocatable outer-VID range per (org,
-- trunk). Mirrors Neutron network_vlan_ranges / Network Segment Ranges.
CREATE TABLE IF NOT EXISTS tenant_vlan_pools (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id    INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    trunk_id  INTEGER NOT NULL REFERENCES ext_trunks(id) ON DELETE RESTRICT,
    vid_min   INTEGER NOT NULL,
    vid_max   INTEGER NOT NULL,
    UNIQUE(org_id, trunk_id)
);
CREATE INDEX IF NOT EXISTS idx_vlan_pools_org ON tenant_vlan_pools(org_id);

-- tenant_uplinks: the realized egress binding a tenant connects a vSwitch to by
-- name. mode: 'access' (single 802.1q tag), 'qinq' (802.1ad S-tag, inner tags
-- preserved), 'dedicated' (a whole NIC). outer_vid=0 is the sentinel for
-- dedicated/unbound rows; the partial unique index below lets many 0-rows coexist
-- on a trunk while rejecting a duplicate non-zero tag. The admin owns this table;
-- an org admin only picks which of THEIR uplinks a network connects to.
CREATE TABLE IF NOT EXISTS tenant_uplinks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    trunk_id        INTEGER REFERENCES ext_trunks(id) ON DELETE RESTRICT,
    mode            TEXT NOT NULL DEFAULT 'access',
    outer_vid       INTEGER NOT NULL DEFAULT 0,
    dedicated_iface TEXT NOT NULL DEFAULT '',
    egress_bridge   TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'unbound',  -- 'unbound' | 'bound' | 'error'
    error           TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_uplinks_org ON tenant_uplinks(org_id);
CREATE INDEX IF NOT EXISTS idx_uplinks_trunk ON tenant_uplinks(trunk_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_uplink_trunk_vid ON tenant_uplinks(trunk_id, outer_vid) WHERE outer_vid > 0;

-- The tenant-facing reference lives on tenant_networks (the v2 substrate, behind
-- its RESTRICT FK) — NOT on networks — so there is one source of truth and the
-- v2 lifecycle is preserved. NULL = internal/no egress (an old "segment").
ALTER TABLE tenant_networks ADD COLUMN uplink_id INTEGER REFERENCES tenant_uplinks(id);
`},
	{47, "ext-trunk-shared", `
-- A "shared" external trunk is a NIC/bond that is ALSO the management vSwitch's
-- uplink (e.g. the mgmt bond): the admin wants tenant egress to ride the same
-- physical link as management, separated only by VLAN tag. It is access-only
-- (single 802.1q subinterfaces) and the parent is NEVER modified (no MTU raise,
-- no offload toggles) so management is never disturbed; QinQ (which must change
-- the parent's MTU/offload) is refused on a shared trunk in the service layer.
-- STRICTLY ADDITIVE: one column with a constant default — an older binary rolled
-- back over this schema ignores it (its ext_trunks scan uses an explicit column
-- list) and behaves exactly as before.
ALTER TABLE ext_trunks ADD COLUMN shared INTEGER NOT NULL DEFAULT 0;
`},
	{48, "tenant-portgroups", `
-- Tenant vSwitches + port groups. A tenant network (tenant_networks row) IS the
-- tenant's vSwitch: its bridge vdxt<network_id>, its uplink, and its untagged
-- default port group (the backing networks row). A tenant port group is an extra
-- 802.1q VLAN (2-4094, private to the vSwitch, so two tenants' VLAN 10s never
-- meet) on that bridge, with its own backing networks row (bridge + vlan_id)
-- that VMs attach to as an access port. The bridge turns vlan_filtering on only
-- once it has a tagged port group, so existing segments are untouched.
-- STRICTLY ADDITIVE: a new table + constant-default columns.
CREATE TABLE tenant_portgroups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    tnet_id     INTEGER NOT NULL REFERENCES tenant_networks(id) ON DELETE RESTRICT,
    name        TEXT NOT NULL,
    vlan_id     INTEGER NOT NULL CHECK (vlan_id BETWEEN 2 AND 4094),
    network_id  INTEGER NOT NULL REFERENCES networks(id) ON DELETE RESTRICT,
    dhcp        INTEGER NOT NULL DEFAULT 0,
    dhcp_range  TEXT NOT NULL DEFAULT '',
    dhcp_dns    TEXT NOT NULL DEFAULT '',
    vrouter_id  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tpg_vswitch_vlan ON tenant_portgroups(tnet_id, vlan_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tpg_vswitch_name ON tenant_portgroups(tnet_id, name);

-- Which port group rides an ACCESS uplink untagged (0 = the untagged default
-- port group). QinQ / dedicated uplinks carry every port group tagged.
ALTER TABLE tenant_networks ADD COLUMN native_vlan INTEGER NOT NULL DEFAULT 0;

-- vRouter legs on a tenant port group sit on the vSwitch bridge as an access
-- port of that VLAN. An "uplink" leg (the router's external side, on the port
-- group that leaves through the vSwitch's uplink) carries the upstream gateway
-- (installed as the router's default route) and whether to SNAT out of it.
ALTER TABLE vrouter_legs ADD COLUMN vlan_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vrouter_legs ADD COLUMN upstream_gw TEXT NOT NULL DEFAULT '';
ALTER TABLE vrouter_legs ADD COLUMN snat INTEGER NOT NULL DEFAULT 0;
`},
	{49, "tenant-vswitch-dhcp", `
-- The untagged port group's host DHCP settings, saved like a VLAN port group's
-- (tenant_portgroups.dhcp/dhcp_range/dhcp_dns). Before this they were rebuilt at
-- boot from defaults (.100-.200, 1.1.1.1/8.8.8.8), so a vSwitch created with its
-- own range or DNS — or with DHCP off — came back different after a restart.
-- Existing rows get dhcp=1 and empty range/DNS, which the service reads as
-- exactly those old defaults: nothing changes for them. STRICTLY ADDITIVE.
ALTER TABLE tenant_networks ADD COLUMN dhcp INTEGER NOT NULL DEFAULT 1;
ALTER TABLE tenant_networks ADD COLUMN dhcp_range TEXT NOT NULL DEFAULT '';
ALTER TABLE tenant_networks ADD COLUMN dhcp_dns TEXT NOT NULL DEFAULT '';
`},
	{50, "tenant-vswitch-unique", `
-- An uplink rides one vSwitch, and an org has at most one default vSwitch — so
-- far enforced only by the service layer (racy). Standalone partial unique
-- indexes make both hard (an inline UNIQUE ... WHERE is a syntax error on
-- modernc). Any duplicates a race left behind are resolved first, or the index
-- would fail and quarantine the DB: the uplink stays with the vSwitch it is
-- actually wired into (its egress_bridge), else the oldest; the oldest default
-- stays the default.
UPDATE tenant_networks SET uplink_id=NULL
 WHERE uplink_id IS NOT NULL AND id <> COALESCE(
   (SELECT t2.id FROM tenant_networks t2 JOIN tenant_uplinks u ON u.id=t2.uplink_id
     WHERE t2.uplink_id=tenant_networks.uplink_id AND u.egress_bridge='vdxt'||t2.network_id ORDER BY t2.id LIMIT 1),
   (SELECT MIN(t3.id) FROM tenant_networks t3 WHERE t3.uplink_id=tenant_networks.uplink_id));
CREATE UNIQUE INDEX IF NOT EXISTS ux_tnet_uplink ON tenant_networks(uplink_id) WHERE uplink_id IS NOT NULL;
UPDATE tenant_networks SET is_default=0
 WHERE is_default=1 AND id <> (SELECT MIN(t2.id) FROM tenant_networks t2 WHERE t2.org_id=tenant_networks.org_id AND t2.is_default=1);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tnet_org_default ON tenant_networks(org_id) WHERE is_default=1;
`},
	{51, "vswitch-mtu", `
-- A vSwitch's MTU (jumbo frames), applied to its bridge, its physical adapter
-- and the VM taps on it. 0 = never set: the kernel default (1500) is left alone.
-- STRICTLY ADDITIVE: one constant-default column; older binaries ignore it.
ALTER TABLE net_vswitches ADD COLUMN mtu INTEGER NOT NULL DEFAULT 0;
`},
	{52, "container-portgroup", `
-- LXC containers attach to a PORT GROUP the org owns (networks.id), like VMs,
-- instead of a free-text host bridge from the request (which let a member put a
-- container on the management bridge or another tenant's bridge, and inject
-- lxc.* config keys). The bridge (+ VLAN) is resolved server-side from this row;
-- containers.bridge stays as the resolved name for display/topology. 0 = the
-- Default org's lxcbr0 NAT (or a legacy row created before this migration).
-- STRICTLY ADDITIVE: one column with a constant default — an older binary
-- ignores it (its containers queries use explicit column lists).
ALTER TABLE containers ADD COLUMN network_id INTEGER NOT NULL DEFAULT 0;
`},
	{53, "vmware-cbt-import", `
-- CBT warm migration from vCenter/ESXi (docs/CBT-IMPORT.md). The whole state
-- machine lives here so a vdxd restart resumes or cleans up: which snapshots WE
-- created on the source (so only those are ever removed), the CBT state we
-- found (so it is put back), each disk's staging file and last applied change
-- id. STRICTLY ADDITIVE: new tables only.
--
-- vmware_cbt_imports: one warm import. consent=1 is the operator's tick of
-- "Use CBT (warm migration)" — the only thing that lets vdxd change the source.
-- vc_pass_enc is the vCenter password sealed with the install key (encSeal),
-- needed to resume/clean up after a restart; it is wiped when the import ends.
-- cbt_orig: CBT as found before we touched it (-1 = not read yet, 0 off, 1 on).
-- state: starting|base-copy|syncing|cutover|finishing|cleanup|done|cancelled|error;
-- in 'cleanup', end_state is where it lands once cleanup succeeds.
CREATE TABLE IF NOT EXISTS vmware_cbt_imports (
    id             TEXT PRIMARY KEY,
    org_id         INTEGER NOT NULL DEFAULT 0,
    user_id        INTEGER NOT NULL DEFAULT 0,
    vc_url         TEXT NOT NULL,
    vc_host        TEXT NOT NULL,
    vc_user        TEXT NOT NULL,
    vc_pass_enc    TEXT NOT NULL DEFAULT '',
    vc_insecure    INTEGER NOT NULL DEFAULT 0,
    moid           TEXT NOT NULL,
    vm_name        TEXT NOT NULL DEFAULT '',
    consent        INTEGER NOT NULL DEFAULT 0,
    cbt_orig       INTEGER NOT NULL DEFAULT -1,
    cbt_enabled_by_us INTEGER NOT NULL DEFAULT 0,
    state          TEXT NOT NULL DEFAULT 'starting',
    end_state      TEXT NOT NULL DEFAULT '',
    cancel_req     INTEGER NOT NULL DEFAULT 0,
    step           TEXT NOT NULL DEFAULT '',
    last_error     TEXT NOT NULL DEFAULT '',
    fail_count     INTEGER NOT NULL DEFAULT 0,
    os_type        TEXT NOT NULL DEFAULT 'linux',
    target_pool_id INTEGER NOT NULL DEFAULT 0,
    interval_sec   INTEGER NOT NULL DEFAULT 1800,
    next_run_at    INTEGER NOT NULL DEFAULT 0,
    last_sync_at   INTEGER NOT NULL DEFAULT 0,
    passes         INTEGER NOT NULL DEFAULT 0,
    snap_seq       INTEGER NOT NULL DEFAULT 0,
    base_bytes     INTEGER NOT NULL DEFAULT 0,
    shutdown_guest INTEGER NOT NULL DEFAULT 0,
    result_image   TEXT NOT NULL DEFAULT '',
    result_session TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at    TEXT NOT NULL DEFAULT ''
);
-- One row per source disk: its sparse raw staging file on this host and the
-- CBT change id of the last snapshot whose changes are applied to it.
CREATE TABLE IF NOT EXISTS vmware_cbt_disks (
    import_id  TEXT NOT NULL REFERENCES vmware_cbt_imports(id),
    device_key INTEGER NOT NULL,
    idx        INTEGER NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    capacity   INTEGER NOT NULL,
    staging    TEXT NOT NULL,
    change_id  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (import_id, device_key)
);
-- Every snapshot vdxd creates on a source. The row is written BEFORE the create
-- call (name only), the moref filled in when it returns — so even a crash in
-- between leaves a record to find it by its unique vxvisor-cbt-* name. A row is
-- never deleted; removed_at marks it gone. Nothing outside this table is ever
-- removed from a source.
CREATE TABLE IF NOT EXISTS vmware_cbt_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id  TEXT NOT NULL REFERENCES vmware_cbt_imports(id),
    moid       TEXT NOT NULL,
    name       TEXT NOT NULL,
    moref      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT 0,
    removed_at INTEGER NOT NULL DEFAULT 0
);
-- One row per copy pass (base, delta, final): what it moved, for the UI.
CREATE TABLE IF NOT EXISTS vmware_cbt_passes (
    import_id   TEXT NOT NULL REFERENCES vmware_cbt_imports(id),
    pass        INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    extents     INTEGER NOT NULL DEFAULT 0,
    started_at  INTEGER NOT NULL DEFAULT 0,
    finished_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (import_id, pass)
);
`},
	{54, "vmware-cbt-import-unique", `
-- Race backstops for the warm import (standalone indexes — an inline UNIQUE ...
-- WHERE is a syntax error on modernc): at most one ACTIVE warm import per source
-- VM, and snapshot names unique (a name is how a snapshot whose create was
-- interrupted is found again). The tables are new in 53, so no existing rows
-- can violate these. STRICTLY ADDITIVE.
CREATE UNIQUE INDEX IF NOT EXISTS ux_cbt_active_vm ON vmware_cbt_imports(vc_host, moid)
    WHERE state NOT IN ('done','cancelled','error');
CREATE UNIQUE INDEX IF NOT EXISTS ux_cbt_snap_name ON vmware_cbt_snapshots(name);
CREATE INDEX IF NOT EXISTS ix_cbt_snap_pending ON vmware_cbt_snapshots(import_id) WHERE removed_at = 0;
`},
	{55, "snapshot-policies", `
-- Scheduled snapshot policies (docs/SNAPSHOTS.md). A policy snapshots one VM,
-- every VM in a folder (sub-folders included), or every VM of an org at once (a
-- best-effort consistency group), on an hourly / daily / weekly schedule, and
-- prunes by "keep the last N" and/or "keep for D days". immutable locks each
-- snapshot it takes until created + keep_days, so it requires keep_days (CHECK).
-- org_id scopes every query; an org admin sees and manages only their own org.
CREATE TABLE IF NOT EXISTS snapshot_policies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    target_kind   TEXT NOT NULL CHECK (target_kind IN ('vm','folder','org')),
    target_vm     TEXT NOT NULL DEFAULT '',     -- sessions.id when target_kind='vm'
    target_folder INTEGER NOT NULL DEFAULT 0,   -- vm_folders.id when target_kind='folder'
    schedule      TEXT NOT NULL CHECK (schedule IN ('hourly','daily','weekly')),
    at_minute     INTEGER NOT NULL DEFAULT 0,   -- minute past the hour / of HH:MM
    at_hour       INTEGER NOT NULL DEFAULT 0,   -- daily/weekly HH (host local time)
    weekday       INTEGER NOT NULL DEFAULT 0,   -- weekly: 0=Sunday … 6=Saturday
    keep_last     INTEGER NOT NULL DEFAULT 0,   -- 0 = no count rule
    keep_days     INTEGER NOT NULL DEFAULT 0,   -- 0 = no age rule
    immutable     INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    last_run_at   TEXT,
    next_run_at   TEXT,
    last_status   TEXT NOT NULL DEFAULT '',
    created_by    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK (immutable = 0 OR keep_days > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_snappol_org_name ON snapshot_policies(org_id, name);
CREATE INDEX IF NOT EXISTS idx_snappol_due ON snapshot_policies(enabled, next_run_at);
`},
	{56, "snapshots-v2", `
-- Snapshots for every disk backend, not just qcow2 internal tags. backend is the
-- disk's backend when the snapshot was taken; ref is the backend locator
-- (zvol: pool/ds@tag, lvm: vg/lv, rbd: pool/image@tag; '' = the qcow2 internal
-- tag). consistency records how it was taken: offline (VM stopped), app (guest
-- filesystems frozen via the guest agent) or crash. locked_until is the
-- immutability lock (absolute; never shortened by later policy edits/deletes).
-- STRICTLY ADDITIVE: an older binary keeps using id/session_id/name/tag/online.
ALTER TABLE snapshots ADD COLUMN backend      TEXT NOT NULL DEFAULT 'qcow2';
ALTER TABLE snapshots ADD COLUMN ref          TEXT NOT NULL DEFAULT '';
ALTER TABLE snapshots ADD COLUMN consistency  TEXT NOT NULL DEFAULT '';
ALTER TABLE snapshots ADD COLUMN vars_path    TEXT NOT NULL DEFAULT '';  -- UEFI NVRAM copy taken with the snapshot
ALTER TABLE snapshots ADD COLUMN policy_id    INTEGER REFERENCES snapshot_policies(id) ON DELETE SET NULL;
ALTER TABLE snapshots ADD COLUMN group_id     TEXT NOT NULL DEFAULT '';  -- one policy run = one group
ALTER TABLE snapshots ADD COLUMN locked_until TEXT;                      -- RFC3339 UTC; NULL = not immutable
ALTER TABLE snapshots ADD COLUMN expires_at   TEXT;                      -- RFC3339 UTC age cutoff (policy keep_days)
ALTER TABLE snapshots ADD COLUMN transient    INTEGER NOT NULL DEFAULT 0; -- taken only as an instant clone's base
UPDATE snapshots SET consistency = CASE WHEN online = 1 THEN 'crash' ELSE 'offline' END WHERE consistency = '';
CREATE INDEX IF NOT EXISTS idx_snapshots_policy ON snapshots(policy_id);
`},
	{57, "snapshot-clones", `
-- Instant clones: which VM a clone came from, and — ONLY while the clone's disk
-- still shares blocks with it (a zfs clone / rbd child) — the snapshot it depends
-- on. snapshot_id is RESTRICT: the DB refuses to drop a snapshot (directly, or by
-- cascade when its VM is purged) while a clone still depends on it; the purge path
-- detaches dependents first (zfs promote / rbd flatten) and NULLs the column.
-- origin_id has no FK on purpose: an independent clone outlives its origin.
CREATE TABLE IF NOT EXISTS snapshot_clones (
    clone_id      TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    origin_id     TEXT NOT NULL,
    origin_name   TEXT NOT NULL DEFAULT '',
    snapshot_id   INTEGER REFERENCES snapshots(id) ON DELETE RESTRICT,
    snapshot_name TEXT NOT NULL DEFAULT '',
    backend       TEXT NOT NULL DEFAULT 'qcow2',
    method        TEXT NOT NULL DEFAULT '',     -- zfs-clone|rbd-clone|lvm-thin|reflink|convert
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_snapclones_snapshot ON snapshot_clones(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_snapclones_origin ON snapshot_clones(origin_id);
`},
	{58, "ovirt-checkpoints", `
-- Backup checkpoints made through the oVirt-compatible backup API ([ovirt]).
-- Each row names one persistent qcow2 dirty bitmap "vdxckpt-<id>" on the VM's
-- disk; the bitmap is the authority, this row is what the API lists. A bitmap
-- with no row is a leftover of a failed backup and is pruned at the next one.
-- Rows go with the VM (ON DELETE CASCADE) and are dropped whenever the disk is
-- rewritten outside a backup (snapshot revert, storage move, resize), which
-- forces the next backup to be a full one.
-- STRICTLY ADDITIVE: a new table no older binary reads.
CREATE TABLE ovirt_checkpoints (
	id          TEXT PRIMARY KEY,
	vm_id       TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
	parent_id   TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX ix_ovirt_checkpoints_vm ON ovirt_checkpoints(vm_id, created_at);
`},
	{59, "ovirt-disks", `
-- Disks created through the oVirt-compatible API (restore targets, backup
-- worker images). vm_id is NULL while the disk is staged (detached) and set
-- once it is attached, so the disk keeps the id the client created it with;
-- attaching also records the file as the VM's disk_path. ovirt_vms marks VMs
-- the API created and why ("restore" | "worker"): a worker is purged outright
-- when the client deletes it, anything else goes to Trash like a UI delete.
-- STRICTLY ADDITIVE: new tables no older binary reads.
CREATE TABLE ovirt_disks (
	id         TEXT PRIMARY KEY,
	vm_id      TEXT REFERENCES sessions(id) ON DELETE CASCADE,
	name       TEXT NOT NULL DEFAULT '',
	path       TEXT NOT NULL,
	format     TEXT NOT NULL DEFAULT 'qcow2',
	pool_id    INTEGER NOT NULL DEFAULT 0,
	size       INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE UNIQUE INDEX ux_ovirt_disks_vm ON ovirt_disks(vm_id) WHERE vm_id IS NOT NULL;
CREATE TABLE ovirt_vms (
	vm_id      TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
	purpose    TEXT NOT NULL DEFAULT 'restore',
	created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
`},
	{60, "fabric", `
-- VXVisor Fabric (docs/FABRIC.md §14). fabric_intent holds the replicated
-- intent: ONE versioned JSON document (fabric.Intent), identical on every node
-- at a given version, changed only by a unanimous two-phase commit. Everything
-- else here is this node's own realization of it and never replicates:
--   fabric_pg_networks maps a fabric port group (UUID) to the local networks
--   row VMs attach to (mode 'fabric', bridge vxfb<vni>); RESTRICT so the raw
--   network delete can't orphan it;
--   fabric_underlay records what vdxd did to the underlay interface (MTU before,
--   the VLAN subinterface it made) so leaving the fabric restores it exactly.
-- STRICTLY ADDITIVE: new tables no older binary reads.
CREATE TABLE fabric_intent (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	version    INTEGER NOT NULL DEFAULT 0,
	body       TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
INSERT INTO fabric_intent(id, version, body) VALUES (1, 0, '{}');
CREATE TABLE fabric_pg_networks (
	pg_uuid    TEXT PRIMARY KEY,
	network_id INTEGER NOT NULL UNIQUE REFERENCES networks(id) ON DELETE RESTRICT
);
CREATE TABLE fabric_underlay (
	fabric_uuid TEXT PRIMARY KEY,
	iface       TEXT NOT NULL,
	dev         TEXT NOT NULL,
	tep         TEXT NOT NULL,
	made_vlan   INTEGER NOT NULL DEFAULT 0,
	orig_mtu    INTEGER NOT NULL DEFAULT 0,
	state       TEXT NOT NULL DEFAULT '',
	error       TEXT NOT NULL DEFAULT '',
	updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
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
