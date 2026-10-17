# CLAUDE.md — VXVisor engineering guide

Read this before changing anything. It captures the architecture, the non-obvious
conventions, and the gotchas that will bite you otherwise.

VXVisor is a **single-binary VM + VDI control plane** for Linux, written from scratch
in Go (CGO-free). The daemon/CLI is `vdxd`. Product name is **VXVisor**; the Go module
is still `vdxclone` (historical — do NOT rename it, it's 40+ files of churn for zero
runtime benefit). Repo: `github.com/paulmataruso/vxvisor` (name ≠ module path, that's fine).

## Hard constraints (never violate)
- **Licensing is OFF by default** (NoopEnforcer). No outbound/telemetry calls.
- **guacd, VNC, QMP, SPICE bind loopback only.** The only external path to a console is
  the authenticated WebSocket proxy / guac gateway. Never bind these to 0.0.0.0.
- **Per-connection HMAC tokens** for the public desktop WS (`internal/broker/token.go`).
- **Never brute-force / guess guest or user passwords.**
- **Management NIC is sacred.** `service.guardMgmt()` refuses to bond/trunk/assign the NIC
  that carries the admin listener IP. The **storage NIC rule**: NFS/iSCSI/Ceph refuse
  unless a dedicated storage interface (≠ mgmt) is set and the target is on its subnet.
- **Disk safety:** `service.deviceInUse()` refuses to wipe any in-use disk (mounted / PV /
  has mounted children) — this is what stops someone wiping the OS/boot disk.

## Build / deploy / verify
```bash
# build (static, pure-Go sqlite, embedded templates/assets)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=X.Y.Z-$(date +%Y%m%d)" -o dist/vdxd ./cmd/vdxd

# deploy to a host (scp binary, install over the old one, restart)
scp dist/vdxd HOST:/tmp/vdxd.new
ssh HOST 'sudo install -o root -g root -m 0755 /tmp/vdxd.new /usr/local/bin/vdxd \
  && sudo systemctl restart vdxd && vdxd version'
```
- Bump the version each deploy (`X.Y.Z-YYYYMMDD`); keep a backup of the previous binary.
- Before deploying template changes, **parse-check** them. A standalone parser MUST
  register the template funcs or it false-fails:
  ```go
  template.New("root").Funcs(template.FuncMap{"humanBytes": func(int64) string {return ""}}).
    ParseGlob("internal/web/templates/*.html")
  ```
- `go build ./...` + `go vet ./internal/...` before every deploy.

## Repo layout (`internal/`)
- `config/` — TOML config (`Config`: Server[:8766], Public[:8768 portal], Broker, Gateway,
  Cluster, Network, Paths, OIDC). `Paths.DataDir` default `/var/lib/vdxclone/data`.
- `db/` — SQLite (`modernc.org/sqlite`), **numbered append-only migrations** (see below).
- `auth/` — sessions (cookie `vdx_session`), password hashing, OIDC.
- `service/` — **the authz + audit layer; all handlers go through it.** `Principal` carries
  user/org/role. Gate with `p.IsAdmin` or `p.atLeast("member"|"viewer"|...)`; call `s.audit(...)`.
- `web/` — two HTTP listeners share one `Server`: admin `Routes(mux)` (:8766) and public
  portal `PublicRoutes(pmux)` (:8768). `html/template`, embedded. `render()` injects P/CSRF/
  Active/PortalURL. `writeJSON()` for AJAX/API.
- `session/` — VM lifecycle (`manager.go`): Create/Start/Stop/Delete/Purge/Resize, QEMU launch.
- `qemu/` — builds the QEMU argv (`Spec.Args()`), OVMF, qcow2/zvol helpers, QMP.
- `zfs/`, `lvm/`, `sharedstg/` (NFS/CIFS/Ceph/iSCSI), `netdrv/` (bonds/vSwitches/taps),
  `routing/` (FRR+nft), `lxc/` (containers), `cloudinit/` (NoCloud seed), `metrics/`,
  `broker/` (VDI pools+token), `gateway/` (guacd wire protocol), `image/`, `storage/`,
  `platform/` (passthrough/import), `cluster/`, `worker/` (background loops), `api/` (REST, admin listener).

## Conventions you MUST follow
### DB migrations (`internal/db/db.go`)
- A numbered slice; **append only**, never edit an applied migration. Current max: **35**
  (`vdi-desktops`). Add `{N, "name", "SQL"}`.
- `ALTER TABLE sessions ADD COLUMN ...` is the pattern for new VM fields.

### `sessions` column discipline (`internal/session/manager.go`)
- `sessionCols` (the canonical SELECT list) and `scanSession()` must stay in exact sync,
  and the `INSERT` in `Create()` must match. When adding a VM column: add the struct field,
  append `COALESCE(col, default)` to `sessionCols` **before `created_at`**, append `&s.Field`
  to `scanSession` **before `&s.CreatedAt`**, and add it to the INSERT column list + values.

### Web UI
- **Modal create pattern:** list cards show existing items with a `.card-head` + an
  `+ Add` button `data-modal="m-x"`; the create form lives in `<div class="modal" id="m-x">`
  with `<form class="mform">`. Open/close JS + the **submit-spinner reset on `pageshow`** are
  in `foot.html` (the pageshow reset fixes "stuck spinning button after Back").
- Every `data-modal="X"` needs a matching `id="X"`.
- `{{humanBytes n}}` template func formats bytes. Inside `{{with .O}}` use `$.P` for the
  principal, never `.P` (that cost a silent truncated overview page once).
- CSRF: hidden `{{.CSRF}}` on every POST form; handlers call `s.checkCSRF(p, r)`.

### Service methods
- Admin-gated host ops: `if !p.IsAdmin { return ErrUnauthorized }`. Audit every mutation.

## Subsystem notes / gotchas
- **Real DB path** is `<Paths.DataDir>/vdxclone.db` → `/var/lib/vdxclone/data/vdxclone.db`
  (NOT `/var/lib/vdxclone/vdxclone.db` — querying the wrong path returns an empty/old file).
- **QEMU perf (auto, in `qemu.Spec.Args`):** `-enable-kvm -cpu host -machine q35`; disk on a
  dedicated `iothread` with `aio=io_uring,cache=writeback` (qcow2) or `aio=native,cache=none`
  (raw zvol), `virtio-blk num-queues=vCPUs`, `discard=unmap`; net `vhost=on` + multiqueue
  (`queues=vCPUs`, `mq=on`) on bridged taps (SLIRP user-net = 1 queue); `-vga qxl`;
  `qemu-xhci + usb-tablet + usb-kbd` (absolute pointer); `virtio-rng`, `virtio-balloon`.
  See `docs/TUNING.md` for host-level knobs. Guest needs `ethtool -L <nic> combined N` for net mq.
- **zvol:** `zfs.CreateZvol` **waits for the `/dev/zvol/<name>` udev node** (settle+poll) —
  qemu-img convert races udev otherwise. Purge does `zfs destroy`, not file remove. Resize =
  `zfs set volsize`. zvol VMs can't use qemu-img snapshots (would need zfs snapshots — TODO).
- **ZFS registration:** creating a zpool/LVM registers a `storage_pools` row; destroy removes it.
  Use `DeleteStoragePool`/`deleteStoragePool` (NOT `DeletePool`, which is the VDI broker's).
- **FRR:** apply via `/usr/lib/frr/frr-reload.py --reload` (NOT `systemctl reload frr`, which
  hangs against watchfrr). vdxd owns `/etc/frr/frr.conf` + nft table `inet vdxclone`.
- **ISO upload** streams via `r.MultipartReader()` (NO `ParseMultipartForm`/`FormFile` — those
  buffer to `os.TempDir()` which is tmpfs/RAM and OOM-kills on multi-GB ISOs). Form field order:
  csrf, name, file. `TMPDIR` is set to disk in the systemd unit.
- **ISO pull / container create / warm pool** are async (status rows: downloading/creating/error);
  pages auto-refresh while in progress.
- **Console/desktop:** admin console = noVNC (`/console/{id}`) with a Proxmox-style control bar
  (send-keys, clipboard, fullscreen). "Open desktop" = guac gateway (`/desktop/{id}`), protocol
  rdp (routable guest) / spice (display=spice) / vnc fallback. Public portal always re-mints a
  token via `/connect` (idempotent — reuses the user's held VM).
- **Desktops on weak/no-GPU hosts:** GNOME = slow (llvmpipe). Use a **lightweight live desktop
  ISO** (Lubuntu/LXQt, Xubuntu/XFCE) pulled host-side and booted live — do NOT install a desktop
  via cloud-init apt over SLIRP user-NAT (it crawls/stalls). LXC containers are fastest.
- **Networking for throughput:** bridged/tap (vhost+mq), not SLIRP user-NAT (convenience only).

## Secrets / git hygiene
- `.gitignore` excludes `/run/`, `/dist/`, `/bin/` and `/vdxd`. `run/data/broker.key`, the live
  DB, VM disks, ISOs, and backups live under `/run/` (local) or `/var/lib/vdxclone/` (host) —
  **never commit them.** No host IPs/passwords/tokens in the repo.

## Current state (migrate when the new host is ready)
- Feature set complete through M22 (see the session memory / `PLAN.md`). Latest: VDI portal
  buildout + admin link, perf tuning (`docs/TUNING.md`).
- The old test host was an **Intel Atom C2758** (weak; fine for servers/LXC/light desktops).
  A faster host is being provisioned — on it, apply `docs/TUNING.md` §B (tuned, hugepages,
  CPU pinning, ZFS ARC cap, bridged+multiqueue net; GPU passthrough via vfio for desktops).
- Bootstrap a fresh host with `deploy/install.sh`, then `vdxd user add admin --admin`.
