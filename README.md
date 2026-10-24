<p align="center">
  <img src="docs/vxicon.png" alt="" height="96">
</p>
<p align="center">
  <img src="docs/vxwordmark.svg" alt="VXVisor" height="60">
</p>

<p align="center"><b>A single-binary VM &amp; infrastructure control plane for Linux.</b></p>

<p align="center">
  <a href="LICENSE"><img alt="License: BSL 1.1" src="https://img.shields.io/badge/license-BSL%201.1-blue.svg"></a>
  <a href="https://github.com/paulmataruso/vxvisor/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/paulmataruso/vxvisor?include_prereleases&label=release&color=18a3f0"></a>
  <img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/paulmataruso/vxvisor?logo=go&color=00ADD8">
  <img alt="Platform: Linux" src="https://img.shields.io/badge/platform-linux-informational?logo=linux&logoColor=white">
  <img alt="Top language" src="https://img.shields.io/github/languages/top/paulmataruso/vxvisor?color=00ADD8">
  <img alt="Code size" src="https://img.shields.io/github/languages/code-size/paulmataruso/vxvisor">
  <img alt="Last commit" src="https://img.shields.io/github/last-commit/paulmataruso/vxvisor">
</p>

<p align="center">
  <img alt="QEMU/KVM" src="https://img.shields.io/badge/QEMU%2FKVM-virtualization-ff6600?logo=qemu&logoColor=white">
  <img alt="LXC" src="https://img.shields.io/badge/LXC-containers-2496ED">
  <img alt="ZFS" src="https://img.shields.io/badge/ZFS-pools-7a40c2">
  <img alt="Ceph" src="https://img.shields.io/badge/Ceph-RBD-ef5c55">
  <img alt="FRR" src="https://img.shields.io/badge/FRR-OSPF%20%C2%B7%20BGP-00875a">
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-embedded-003B57?logo=sqlite&logoColor=white">
  <img alt="Wails" src="https://img.shields.io/badge/desktop-Wails-df0000">
  <img alt="No telemetry" src="https://img.shields.io/badge/telemetry-none-brightgreen">
</p>

Run virtual machines and containers, software-defined storage and networking,
and multi-node clustering — all from one web UI (and a native desktop client),
backed by one self-contained Go binary with no external database and no agents.

VXVisor is an original, from-scratch platform inspired by the shape of Proxmox
and vSphere. It installs in minutes, ships as a single binary (templates and
assets embedded, pure-Go SQLite — no CGO), and makes no outbound/telemetry
calls.

![VXVisor overview](docs/homepage.png)

---

## Highlights

- **Compute** — QEMU/KVM virtual machines and **LXC** system containers, with
  live console (noVNC), snapshots, backups, and cloud-init provisioning.
- **Storage** — directory, NFS, CIFS, Ceph and iSCSI pools; **ZFS** (pools,
  datasets, caches) and **LVM**; software RAID; qcow2 or raw disks.
- **Networking** — VMware-style vSwitches → port groups (VLANs) → uplinks with
  teaming; built-in **L3 routing** (static, OSPF, BGP) and NAT/firewall;
  virtual routers and a drag-and-drop firewall.
- **Clustering** — join multiple hosts, manage them from one address, place and
  **live-migrate** VMs between nodes.
- **Import / Export** — bring VMs in from VMware vCenter/ESXi (read-only, the
  source is never changed) and export them back out.
- **Operations** — live and historical metrics, alerts, audit log, quotas, and
  usage reporting.
- **Multi-tenant** — organizations, members, roles, API keys, and Active
  Directory / OIDC single sign-on.

---

## Screenshots

### Instances & monitoring
| Instances | Monitoring |
|---|---|
| ![Instances](docs/instances.png) | ![Monitoring](docs/monitoring.png) |

### Networking
| vSwitches & port groups | Uplinks & teaming |
|---|---|
| ![Networking](docs/network_1.png) | ![Networking](docs/network_2.png) |

![Network topology](docs/network_topology.png)

### Virtual routers & firewall
| Virtual routers | Firewall |
|---|---|
| ![Virtual routers](docs/vrouters.png) | ![Firewall](docs/vfirewall.png) |

![Virtual router detail](docs/vrouters_2.png)

### Storage
| Pools | Disks | Build a pool |
|---|---|---|
| ![Storage pools](docs/storage_pool_1.png) | ![Disks](docs/storage_pool_2.png) | ![Build a pool](docs/storage_pool_3.png) |

### Containers, clustering & migration
| Containers | Clustering |
|---|---|
| ![Containers](docs/containers.png) | ![Clustering](docs/cluster.png) |

| Import / Export (VMware) | ISO library |
|---|---|
| ![Import / Export](docs/import-export.png) | ![ISO library](docs/iso_library.png) |

---

## Quick start

On a 64-bit Linux host with hardware virtualization (`/dev/kvm`):

```bash
# 1. Build the binary (or use a prebuilt vdxd)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o dist/vdxd ./cmd/vdxd

# 2. Copy the binary + deploy/ to the host, then on the host:
sudo ./install.sh --ip <this-host-IP>   # installs deps, service, config
sudo vdxd user add admin --admin         # create the first admin
sudo systemctl enable --now vdxd
```

Open **`http://<this-host-IP>:8766`** and sign in.

👉 **Full step-by-step guide:** [`docs/INSTALL.md`](docs/INSTALL.md)
(prerequisites, installer options, first steps, upgrading, and where files live).

> **Production tip:** front the admin UI with a TLS reverse proxy (Caddy/nginx).

---

## Configuration

- Config file: `/etc/vdxclone/config.toml` (a starter is written on install).
- Data (database, VM disks, backups): `/var/lib/vdxclone/`.
- Images and ISOs: `/var/cache/vdxclone/`.
- Logs: `journalctl -u vdxd -f`.

The admin UI listens on `:8766`. Most day-to-day settings are configured from
the UI itself.

---

## Architecture

- **One binary.** The daemon/CLI is `vdxd`. The web UI and assets are embedded.
- **No external services.** State lives in an embedded SQLite database
  (`modernc.org/sqlite`, pure Go). Migrations run automatically on start.
- **No agents.** VXVisor drives standard host tooling (QEMU/KVM, LXC, ZFS/LVM,
  FRR, nftables) directly; in a cluster, nodes coordinate over an authenticated
  peer channel with a floating management address.
- **Safe by default.** Licensing enforcement is off, there are no telemetry or
  outbound calls, consoles bind to loopback and are only reachable through the
  authenticated proxy, and destructive operations guard the management interface
  and in-use disks.

See [`OVERVIEW.md`](OVERVIEW.md) for a module-by-module technical breakdown.

---

## License

VXVisor is licensed under the **Business Source License 1.1** (see
[`LICENSE`](LICENSE)).

In short:
- You can **read, modify, self-host, and use it in production** — including
  commercially, for your own organization.
- You **cannot** offer VXVisor to third parties as a competing hosted or managed
  service.
- Each released version automatically converts to the **Apache License 2.0** on
  its Change Date (four years after release).

This is a source-available license, not an OSI open-source license (until the
Change Date). For other arrangements, open an issue.

VXVisor bundles third-party components under their own permissive licenses
(MIT, BSD, Apache-2.0, MPL-2.0), and invokes separate programs at runtime
(QEMU, FRR, LXC, smartmontools, and others) that keep their own licenses.

---

## Docs

- [`docs/INSTALL.md`](docs/INSTALL.md) — installation guide.
- [`OVERVIEW.md`](OVERVIEW.md) — technical overview: how each module works.
- [`docs/TUNING.md`](docs/TUNING.md) — performance tuning.

> Note: the Go module is named `vdxclone` for historical reasons; the product is
> **VXVisor**. The repository name and module path differ, which is fine.
