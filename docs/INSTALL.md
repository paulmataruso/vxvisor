# Installing VXVisor

VXVisor is a single self-contained binary (`vdxd`) plus a host installer that
sets up its dependencies, a service, and a starting config. A typical install
takes a few minutes.

---

## 1. Requirements

**Host**
- A 64-bit Linux host with **hardware virtualization** (Intel VT-x / AMD-V) and
  `/dev/kvm` available. VXVisor is developed and tested on **Ubuntu 24.04 / 26.04**.
- Root (sudo) access.
- At least one network interface. A second interface is recommended if you plan
  to use shared storage or Ceph (they require a dedicated storage network).
- Disk space for VM images and disks (under `/var/lib/vdxclone`).

**Your workstation (to build the binary)**
- Go 1.26+ if you build from source. If you were given a prebuilt `vdxd`
  binary, you can skip the build step.

The installer pulls in everything a feature in the UI can use, including:
`qemu-system-x86`, `qemu-utils`, `ovmf`, `swtpm`, `zfsutils-linux`, `lvm2`,
`lxc`, `frr`, `nftables`, `smartmontools`, `nfs-common`, `cifs-utils`,
`ceph-common`, `open-iscsi`, `chrony`, and `tuned`. Packages with no install
candidate on your release are skipped; a package that exists but fails to
install is treated as an error.

---

## 2. Build the binary (skip if you already have `vdxd`)

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o dist/vdxd ./cmd/vdxd
```

The result is a static, CGO-free `dist/vdxd`. Templates and web assets are
embedded, so it is fully self-contained.

---

## 3. Copy the files to the host

Copy the binary and the `deploy/` folder to the host:

```bash
scp dist/vdxd deploy/* you@your-host:/tmp/vxvisor/
```

---

## 4. Run the installer

On the host:

```bash
cd /tmp/vxvisor
sudo ./install.sh --ip <this-host-IP>
```

The installer:
- installs the runtime dependencies,
- installs `vdxd` to `/usr/local/bin`,
- creates an unprivileged `vdx` user that VMs run as,
- installs and enables the `vdxd` systemd service,
- writes a starting config to `/etc/vdxclone/config.toml` (left untouched if it
  already exists), bound to the IP you gave.

It is **safe to re-run** — re-running upgrades the binary in place and keeps
your existing config.

### Installer options

| Option | What it does |
|---|---|
| `--ip <ip>` | The address the admin UI binds to (auto-detected if omitted). |
| `--mgmt-vswitch` | Turn the management interface into a default vSwitch bridge so VMs can share the uplink. Safe: it clones the NIC's MAC, keeps the exact addressing, and automatically rolls back if the host would become unreachable. |
| `--mgmt-vswitch-name NAME` | Name for that vSwitch (default `vSwitch0`). |
| `--no-vswitch` | Don't offer to create the management vSwitch. |
| `--no-tune` | Skip the safe host performance tuning. |
| `--hugepages PCT` | Reserve this percentage of RAM as hugepages for VMs. |
| `--no-virtio-win` | Don't download the Windows (virtio) driver ISO. |
| `--no-admin` | Don't prompt to create the first admin user. |

---

## 5. Create the first admin and start

```bash
sudo vdxd user add admin --admin      # prompts for a password
sudo systemctl enable --now vdxd
```

Then open the admin UI:

```
http://<this-host-IP>:8766
```

Sign in with the admin account you just created.

> **Production tip:** put a TLS-terminating reverse proxy (Caddy, nginx, or
> similar) in front of port 8766. This encrypts the session and also makes
> one-click clipboard copy/paste in the VM console work without browser
> permission prompts.

---

## 6. First steps in the UI

1. **Pull a base image** (a ready-to-boot cloud image) so you can create VMs
   instantly:
   ```bash
   sudo VDX_CONFIG=/etc/vdxclone/config.toml vdxd image pull ubuntu-24.04
   ```
   or upload an installer ISO from the **ISO Library** page.
2. **Create an instance** from the Instances page — pick the image (or an ISO),
   CPU/memory/disk, and a network.
3. **Open the console** to watch it boot, and you're running.

---

## Where things live

| Path | Contents |
|---|---|
| `/usr/local/bin/vdxd` | The binary. |
| `/etc/vdxclone/config.toml` | Host configuration. |
| `/var/lib/vdxclone/` | Database, VM disks, backups, runtime state. |
| `/var/cache/vdxclone/` | Base images and ISOs. |
| `journalctl -u vdxd -f` | Live logs. |

---

## Upgrading

Copy the new `vdxd` binary over and restart:

```bash
sudo install -o root -g root -m 0755 /tmp/vdxd /usr/local/bin/vdxd
sudo systemctl restart vdxd
vdxd version
```

Restarting the service does **not** stop running VMs — they are re-adopted
automatically. Database migrations run automatically on start.

---

## Related docs

- [`../OVERVIEW.md`](../OVERVIEW.md) — technical overview of how VXVisor works.
- [`TUNING.md`](TUNING.md) — performance tuning (automatic and host-level).
