# VXVisor — Technical Overview

This is the deep dive: how VXVisor is put together and what each module does.
It's written for people who want to understand the internals, not a user guide
(for that, see [`README.md`](README.md) and [`docs/INSTALL.md`](docs/INSTALL.md)).

## Design principles

- **One binary, no runtime deps of its own.** The daemon/CLI is `vdxd`. The web
  UI (HTML templates) and static assets are compiled in with `go:embed`. State
  lives in an embedded **SQLite** database via `modernc.org/sqlite` — a pure-Go
  SQLite, so the whole thing builds `CGO_ENABLED=0` and ships as a single static
  file.
- **It drives the host, it is not an agent mesh.** VXVisor shells out to the
  standard Linux tooling (QEMU/KVM, LXC, ZFS/LVM, `mdadm`, FRR, `nftables`,
  `ceph`, `smartctl`, …) and owns the config it generates. There is no guest
  agent requirement beyond the optional QEMU guest agent.
- **The service layer is the only authority.** Every mutating action goes
  through `internal/service`, which is the single place authorization and audit
  happen. The web and API layers never touch the database directly.
- **Safe by default.** No telemetry/outbound calls; licensing enforcement is off
  by default; consoles bind to loopback and are only reachable through the
  authenticated WebSocket proxy; destructive operations refuse to touch the
  management NIC or in-use disks.

## The daemon — `cmd/vdxd`

A single binary with subcommands: `serve` (run the web UI + REST API + workers),
`user`/`org` (account bootstrap), `image pull`, `import`, `self-update`,
`shutdown-vms` (graceful guest power-down at host shutdown), `migrate-recv`
(inbound live-migration receiver), and `license`. `serve` wires everything
together: opens the DB, constructs the service, starts the HTTP listener on
`:8766`, launches the background worker, and — in cluster mode — the gossip
layer, leader election, and the node-to-node peer API.

## Core layers

- **`config`** — loads and defaults the TOML config (`/etc/vdxclone/config.toml`):
  server address, paths, network mode, cluster, OIDC/AD, licensing. A missing
  file is not an error; built-in defaults fill the gaps.
- **`db`** — opens SQLite (WAL, `synchronous=FULL`, single writer connection) and
  runs **forward-only, append-only numbered migrations**. It also self-heals: a
  verified backup is taken at boot and pruned to a rolling set, so a corrupt DB
  can be recovered without disrupting running VMs.
- **`store`** — the typed data-access layer for tenancy (orgs, users, members,
  roles, API keys) and other first-class rows. Raw SQL lives here.
- **`auth` / `oidc` / `ad`** — password hashing and cookie sessions
  (`vdx_session`); a minimal OpenID Connect authorization-code login; and Active
  Directory / LDAP bind auth with just-in-time account provisioning.
- **`service`** — the business-logic layer. A `Principal` carries the
  user/org/role; every method gates with role checks and writes an audit record.
  This is the largest package and the hub everything else calls.
- **`web`** — the browser UI: two HTTP listeners share one server, `html/template`
  with embedded assets, a `render()` helper that injects the principal/CSRF
  token, CSRF enforcement on every POST, and WebSocket proxies for the consoles.
- **`api`** — a small JSON REST surface (sessions, images) for automation, keyed
  by API tokens.
- **`policy` / `license`** — the enforcement seam. The default enforcer is a
  no-op (everything allowed, zero network). When enabled, `license` verifies an
  offline, locally-signed license and enforces seat/resource limits.
- **`secrets`** — tiny helper for per-install key files (cluster key, AD key):
  a 32-byte random secret persisted at `0600`, never hardcoded.

## Compute

- **`session`** — the VM lifecycle manager: create (overlay disk, UEFI NVRAM,
  cloud-init seed, DB row), start/stop/restart, resize, delete/purge, and
  snapshots. It **adopts** already-running QEMU processes by PID on startup, so a
  control-plane restart never kills guests. Stop is a graceful ACPI powerdown
  that escalates to SIGTERM then SIGKILL.
- **`qemu`** — builds the QEMU argument vector (`Spec.Args()`) and manages the
  processes. It auto-selects performant defaults: KVM + host CPU, q35, disks on a
  dedicated iothread with io_uring/native AIO, `virtio` net with vhost +
  multiqueue on bridged taps, `virtio-rng`/`balloon`, a loopback VNC (+ WebSocket)
  display, a QMP control socket, a vdagent clipboard channel, and optional swtpm
  TPM 2.0 for Windows 11.
- **`cloudinit`** — generates a NoCloud "seed" ISO (user-data + network-config)
  that cloud-init consumes on first boot to set the user/password/SSH key,
  network, optional desktop, and the QEMU guest agent.
- **`image`** — manages base images (qcow2 cloud images): pulls them into a cache
  and tracks their status; new VMs overlay onto them for instant provisioning.
- **`lxc`** — wraps the liblxc CLI tools to run system containers (create/start/
  stop/destroy/info), attach them to host bridges, and set CPU/RAM live.

## Storage

- **`storage`** — the "images & storage" entity owner: the ISO library, instance
  disks, and the registry of storage pools a VM disk can live on.
- **`zfs` / `lvm`** — wrap the ZFS (`zpool`/`zfs`) and LVM2 CLIs. ZFS handles
  pools, datasets, zvols (raw VM disks), and cache/log devices; LVM handles thin
  pools and thin volumes. Creating a pool registers it; destroying it removes it.
- **`blkfs`** — puts a plain filesystem (ext4/xfs/…) on a block device or RAID
  array, mounts it, and registers it as a pool.
- **`mdraid` / `raidctl`** — `mdraid` creates and manages Linux software RAID via
  `mdadm` (the array becomes a plain block device usable by any pool backend);
  `raidctl` reads the health of the **physical** drives hidden behind a *hardware*
  RAID controller (PERC/storcli, HPE, Adaptec, …) that the kernel never exposes,
  surfacing per-drive SMART/controller state.
- **`sharedstg`** — mounts and manages network storage: NFS, SMB/CIFS, CephFS,
  and iSCSI. It enforces the storage-network rule: shared storage must ride the
  dedicated storage interface, never the management NIC.
- **`ceph`** — stands up and manages a hyperconverged Ceph cluster *on* the nodes
  (monitor + OSDs + an RBD pool for VM disks), so compute and storage share the
  same boxes and VM disks can live-migrate without copying.

## Networking

- **`netdrv`** — the host network driver. It renders and applies the host's L2
  data plane: bridges (vSwitches), VLAN port groups, bonded/teamed uplinks, VM
  taps, container veth pairs, and VXLAN overlays. The management-NIC conversion
  to a vSwitch is done with an automatic rollback so the admin IP can't be lost.
- **`routing`** — host L3: kernel IP forwarding, `nftables` NAT/firewall, and a
  single managed FRR configuration for static routes, OSPF, BGP, and EIGRP.
- **`vrouter`** — per-tenant virtual routers, each a dedicated routing instance
  (an LXC container or a network namespace running its own FRR) that routes
  between a transit link on a spare NIC and internal-only port groups, with its
  own zone firewall.
- **`lldp`** — reads link-layer neighbor info from `lldpd` so the topology view
  can show the upstream switch/port a NIC is cabled to.

## Clustering

- **`cluster`** — multi-node state: a node registry, a free-resource view for
  scheduling placement, leader election, and the floating management address (a
  single pane that always points at the current leader).
- **`gossip`** — decentralized membership built on `memberlist`: nodes discover
  each other via mDNS and/or seeds and gossip live capacity, with no central
  coordinator. Encrypted/authenticated with the shared cluster secret.
- **`peer`** — the authenticated node-to-node API transport (HMAC-signed, bound
  to the cluster NIC): aggregation, lifecycle proxying, console relay, and
  account sync between nodes.
- **`remoteprov`** — provisions a brand-new worker node over SSH: configures its
  management and cluster interfaces and verifies reachability before committing,
  with an automatic revert so a node can never be stranded.

## Import / export & platform

- **`vmware`** — a thin, **read-only** wrapper over `govmomi` for importing VMs
  from vCenter/ESXi. The source VM is never powered on, snapshotted, or modified.
- **`vmexport`** — builds portable exports of a VXVisor VM: a disk image, an OVA,
  or a direct push into a target vCenter/ESXi.
- **`platform`** — operator-facing platform features: in-place self-update, disk
  import/conversion, and PCI passthrough plumbing.

## Operations

- **`metrics`** — samples host and per-VM CPU, memory, disk/network throughput,
  IOWAIT, and pressure, keeping a short in-memory window plus history for the
  charts and alerts.
- **`hostinfo`** — introspects the host: network interfaces, block devices, and
  capabilities, feeding the pickers and status views.
- **`worker`** — supervised background loops (each a ticker): the reconciler,
  session/web-session GC, backup scheduler, DB backups, metrics collection,
  alert evaluation, metering, node health, account sync, and guest-OS detection.
  Cluster-singleton loops run only on the leader.

## Data flow, end to end

A request hits `web` (or `api`) → it resolves the `Principal` and CSRF → it calls
a `service` method → `service` authorizes, performs the action through a domain
package (`session`, `netdrv`, `zfs`, …), writes an audit row, and returns a view
model → `web` renders a template. Background reconciliation and scheduled work
run in `worker`. In a cluster, actions targeting a VM owned by another node are
transparently proxied over `peer` to that node.
