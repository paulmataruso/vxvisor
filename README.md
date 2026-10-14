# VXVisor

A single-binary **VM + VDI control plane** for Linux — an original, from-scratch
platform (inspired by VDX Cloud Desktop / Proxmox) written in Go with no CGO.

- **Compute:** QEMU/KVM virtual machines + **LXC** system containers
- **Storage:** directory / NFS / CIFS / Ceph / iSCSI pools, **ZFS** (pools, datasets,
  zvols, replace/L2ARC/SLOG), **LVM-thin**; qcow2 or **raw zvol** VM disks
- **Networking:** VMware-style **vSwitches → port groups (VLANs) → uplinks/LAG**,
  **L3 routing** (FRR static/OSPF/BGP + nftables NAT/firewall), all button-driven
- **VDI:** desktop pools (pooled/persistent, warm pre-provisioning) + a public
  **web portal**; browser consoles via **noVNC** and the **guacd** gateway (VNC/RDP/SPICE)
- **Observability:** live + historical metrics (CPU, RAM, disk/net throughput,
  IOWAIT, PSI pressure), alerts, audit log, quotas, billing/usage
- **Multi-tenant:** orgs, members, roles, API keys, OIDC SSO

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
- **Public VDI portal:** `http://<host>:8768` (enable `[public]` in the config)
- Config: `/etc/vdxclone/config.toml` · data: `/var/lib/vdxclone/`

Host packages used (installed by `deploy/install.sh` or as needed): `qemu-system-x86`,
`qemu-utils`, `ovmf`, `zfsutils-linux`, `lvm2`, `lxc`, `frr`, `nftables`, `smartmontools`,
`open-iscsi`, and `guacd` (built from source — see `deploy/guacd-from-source.sh`).

## Docs
- `CLAUDE.md` — detailed architecture, conventions, and gotchas (read this first when hacking).
- `docs/TUNING.md` — every performance knob (auto + host-level).
- `PLAN.md` — original design/milestones.

## Notes
- Licensing is **off by default** (no network calls).
- The Go module is `vdxclone` (historical); the product is **VXVisor**. Repo name ≠ module path, which is fine.
