# VXVisor

A single-binary **VM control plane** for Linux — an original, from-scratch
platform (inspired by Proxmox / vSphere) written in Go with no CGO.

![VXVisor overview](docs/homepage.png)

- **Compute:** QEMU/KVM virtual machines + **LXC** system containers
- **Storage:** directory / NFS / CIFS / Ceph / iSCSI pools, **ZFS** (pools, datasets,
  zvols, replace/L2ARC/SLOG), **LVM-thin**; qcow2 or **raw zvol** VM disks
- **Networking:** VMware-style **vSwitches → port groups (VLANs) → uplinks/LAG**,
  **L3 routing** (FRR static/OSPF/BGP + nftables NAT/firewall), all button-driven
- **Consoles:** in-browser **noVNC** graphical console + serial text console per VM
- **Observability:** live + historical metrics (CPU, RAM, disk/net throughput,
  IOWAIT, PSI pressure), alerts, audit log, quotas, billing/usage
- **Multi-tenant:** orgs, members, roles, API keys, OIDC SSO

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

## Build

```bash
# static, CGO-free linux/amd64 binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o dist/vdxd ./cmd/vdxd
```

The binary is `vdxd`. Templates and static assets are embedded (`go:embed`), so the
single binary is self-contained. SQLite via `modernc.org/sqlite` (pure Go, no CGO).

## Bootstrap a host

```bash
# copy the binary + deploy/ to the host, then:
sudo deploy/install.sh        # installs deps, run-as user, systemd unit, dirs
sudo vdxd user add admin --admin   # create the first admin
sudo systemctl enable --now vdxd
```

- **Admin UI:** `http://<host>:8766` (front with TLS in production)
- Config: `/etc/vdxclone/config.toml` · data: `/var/lib/vdxclone/`

Host packages used (installed by `deploy/install.sh` or as needed): `qemu-system-x86`,
`qemu-utils`, `ovmf`, `zfsutils-linux`, `lvm2`, `lxc`, `frr`, `nftables`, `smartmontools`,
and `open-iscsi`.

## Docs
- `CLAUDE.md` — detailed architecture, conventions, and gotchas (read this first when hacking).
- `docs/TUNING.md` — every performance knob (auto + host-level).
- `PLAN.md` — original design/milestones.

## Notes
- Licensing is **off by default** (no network calls).
- The Go module is `vdxclone` (historical); the product is **VXVisor**. Repo name ≠ module path, which is fine.
