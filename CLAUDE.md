# CLAUDE.md — VXVisor engineering guide

Read this before changing anything. It captures the architecture, the non-obvious
conventions, and the gotchas that will bite you otherwise.

VXVisor is a **single-binary VM control plane** for Linux, written from scratch
in Go (CGO-free). The daemon/CLI is `vdxd`. Product name is **VXVisor**; the Go module
is still `vdxclone` (historical — do NOT rename it, it's 40+ files of churn for zero
runtime benefit). Repo: `github.com/paulmataruso/vxvisor` (name ≠ module path, that's fine).

## Hard constraints (never violate)
- **Licensing is OFF by default** (NoopEnforcer). No outbound/telemetry calls.
- **VNC, QMP, SPICE bind loopback only.** The only external path to a console is the
  authenticated noVNC WebSocket proxy (`/console/{id}`). Never bind these to 0.0.0.0.
- **Never brute-force / guess guest or user passwords.**
- **Management NIC is sacred.** `service.guardMgmt()` refuses to bond/trunk/assign the NIC
  that carries the admin listener IP. The **storage NIC rule**: NFS/iSCSI/Ceph refuse
  unless a dedicated storage interface (≠ mgmt) is set and the target is on its subnet.
- **Disk safety:** `service.deviceInUse()` refuses to wipe any in-use disk (mounted / PV /
  has mounted children) — this is what stops someone wiping the OS/boot disk.
- **`deploy/install.sh` MUST install EVERY tool any UI feature can configure.** If the UI
  exposes it, the host must have the software for it — no "optional" gaps. Current coverage:
  qemu/ovmf/swtpm (VMs/TPM), lvm2+zfsutils (ZFS/LVM pools), nfs-common/cifs-utils/ceph-common/
  open-iscsi (shared storage), **frr+frr-pythontools (routing — OSPF/BGP/static)**, lxc stack
  (containers), chrony (time), tuned (perf), bridge/nft/ethtool
  (networking). `apt_opt` skips only packages with NO install candidate on the release; an
  available package that fails to install is a **hard error** (never `|| true`-swallowed).

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
- `config/` — TOML config (`Config`: Server[:8766], Cluster, Network, VM, Paths, OIDC, AD,
  License, Update). `Paths.DataDir` default `/var/lib/vdxclone/data`.
- `db/` — SQLite (`modernc.org/sqlite`), **numbered append-only migrations** (see below).
- `auth/` — sessions (cookie `vdx_session`), password hashing, OIDC.
- `service/` — **the authz + audit layer; all handlers go through it.** `Principal` carries
  user/org/role. Gate with `p.IsAdmin` or `p.atLeast("member"|"viewer"|...)`; call `s.audit(...)`.
- `web/` — the admin HTTP listener `Routes(mux)` (:8766); in cluster mode a separate
  cluster-NIC peer listener via `PeerRoutes`. `html/template`, embedded. `render()` injects
  P/CSRF/Active. `writeJSON()` for AJAX/API.
- `session/` — VM lifecycle (`manager.go`): Create/Start/Stop/Delete/Purge/Resize, QEMU launch.
- `qemu/` — builds the QEMU argv (`Spec.Args()`), OVMF, qcow2/zvol helpers, QMP.
- `zfs/`, `lvm/`, `sharedstg/` (NFS/CIFS/Ceph/iSCSI), `netdrv/` (bonds/vSwitches/taps),
  `routing/` (FRR+nft), `lxc/` (containers), `cloudinit/` (NoCloud seed), `metrics/`,
  `secrets/` (per-install key files), `image/`, `storage/`,
  `platform/` (passthrough/import), `cluster/`, `worker/` (background loops), `api/` (REST, admin listener).

## Conventions you MUST follow
### DB migrations (`internal/db/db.go`)
- A numbered slice; **append only**, never edit an applied migration. Current max: **48**
  (`tenant-portgroups`). Add `{N, "name", "SQL"}`.
- **Partial-unique constraints MUST be a standalone `CREATE UNIQUE INDEX ... WHERE`** — an
  inline `UNIQUE(...) WHERE` is a syntax error on modernc, and because `OpenResilient`
  quarantines the live DB and falls back to a FRESH empty one on ANY `Open()` error, a bad
  migration statement can WIPE the control plane. Validate new migrations against the real
  driver (a `db` test that opens a fresh DB) before shipping.
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
  Use `DeleteStoragePool`/`deleteStoragePool` to remove a storage pool.
- **FRR:** apply via `/usr/lib/frr/frr-reload.py --reload` (NOT `systemctl reload frr`, which
  hangs against watchfrr). vdxd owns `/etc/frr/frr.conf` + nft table `inet vdxclone`.
- **ISO upload** streams via `r.MultipartReader()` (NO `ParseMultipartForm`/`FormFile` — those
  buffer to `os.TempDir()` which is tmpfs/RAM and OOM-kills on multi-GB ISOs). Form field order:
  csrf, name, file. `TMPDIR` is set to disk in the systemd unit.
- **ISO pull / container create / warm pool** are async (status rows: downloading/creating/error);
  pages auto-refresh while in progress.
- **Console:** admin console = noVNC (`/console/{id}`) with a Proxmox-style control bar
  (send-keys, clipboard, fullscreen) + a serial text console (`/console/{id}/serial`). VNC binds
  loopback; the only external path is the authenticated WebSocket proxy. (The old VDI feature —
  the per-user desktop portal, the pool/published-app broker, and the guacd `/desktop` gateway —
  was removed; see the session memory.)
- **Graphical guests on weak/no-GPU hosts:** GNOME = slow (llvmpipe). Use a **lightweight live desktop
  ISO** (Lubuntu/LXQt, Xubuntu/XFCE) pulled host-side and booted live — do NOT install a desktop
  via cloud-init apt over SLIRP user-NAT (it crawls/stalls). LXC containers are fastest.
- **Networking for throughput:** bridged/tap (vhost+mq), not SLIRP user-NAT (convenience only).

## Secrets / git hygiene
- `.gitignore` excludes `/run/`, `/dist/`, `/bin/` and `/vdxd`. `run/data/cluster.key`,
  `run/data/ad.key`, the live DB, VM disks, ISOs, and backups live under `/run/` (local) or
  `/var/lib/vdxclone/` (host) — **never commit them.** No host IPs/passwords/tokens in the repo.

## Current state (migrate when the new host is ready)
- The VDI feature (desktop portal + pool/app broker + guacd gateway) was removed — VXVisor
  is a pure VM/host control plane.
- Bootstrap a fresh host with `deploy/install.sh`, then `vdxd user add admin --admin`.
- Deploy to a host over SSH as a normal user with sudo (NOT root login); the desktop client
  is cross-built (Linux + Windows, both on the build host) with `desktop/build.sh` (Wails)
  and published to a host's `<DataDir>/clients`.

### Recent subsystems (not in the older notes above)
- **rustguac "advanced console" (OPTIONAL test add-on, config-gated).** Browser SSH/RDP/VNC/
  SPICE via a local [rustguac](https://github.com/sol1/rustguac) + its own guacd, built from
  source under `/opt/rustguac` (systemd `rustguac` + `rustguac-guacd`). rustguac binds **loopback
  only** (`127.0.0.1:8089`); its guacd runs on **4823** (the pre-existing Apache guacd on 4822 is
  left untouched). vdxd fronts it: the `[guac]` config block (`enabled/upstream/api_key/
  proxy_addr`) turns on `internal/service/guac_service.go` (`AdvancedConsole` brokers a session +
  single-use WS ticket server-side with the admin API key) and a **second cookie-gated reverse-
  proxy listener** (`internal/web/guac_proxy.go`, `cmd/vdxd/main.go`) on `proxy_addr`
  (172.16.0.163:8767) that forwards to loopback rustguac — so a browser reaches rustguac only
  through a valid `vdx_session`. Route `GET /console/{id}/advanced` (broker→302 to the proxy),
  and an "⚡ RustGuac" button on console.html shown only when `GuacEnabled()`. **No DB migration**
  — the whole feature is config-only. **Rollback:** set `[guac] enabled=false` + restart (instant,
  reversible; noVNC untouched), or full uninstall via `~/rollback-rustguac.sh` on the host. Install
  caveats on Ubuntu 26.04: install.sh's apt step was edited to drop `freerdp3-dev` (already present
  at 3.24.2; the 3.32.1 security candidate conflicts) and the Xvnc/Chromium web-session deps
  (chromium is a snap, no `chromium-sandbox` .deb) — neither affects VNC/SPICE/RDP/SSH consoles.

- **Inventory folders** (migration 43): org-scoped nestable folder tree to organize
  instances. `vm_folders` + `vm_folder_members` tables (separate from `sessions`),
  `internal/service/folders_service.go`, REST + web (`/instances` List/Folders views with
  drag-and-drop), and a desktop-client sidebar tree. Deleting a folder never deletes VMs.
- **In-app updates** — two tiers: the desktop client self-updates from its server; vdxd
  self-updates from GitHub Releases via the admin **Updates** page (Stable/Preview channels,
  manual-only GitHub check — no automatic outbound calls). Releases are cut with
  `deploy/release.sh` (bundles vdxd + both clients + `SHA256SUMS`). **Full details in
  `docs/UPDATES.md` — read it before touching anything update-related.** Branch model:
  `dev` → prereleases (Preview), `main` → stable. The repo is **public** so the server can
  read releases anonymously.
- **Desktop client** (`desktop/`, a **Wails v2** app — Go + system webview, module `vxconsole`):
  a thin branded shell. The connect screen (`frontend/dist/index.html`) navigates the webview
  to the chosen VXVisor server, so the client renders the server's **actual web UI** (every
  page incl. the topology diagram, and the noVNC consoles) — 100% parity by construction.
  Native window menu (Server: connect-to-another / reload / fullscreen / quit) in `app.go`.
  (Was a Fyne app that hand-ported each page; pivoted 2026-10-24 because matching a web UI in
  native canvas is endless approximation.) **Cross-builds BOTH targets on a Linux build host**
  via `desktop/build.sh`: Linux `wails build -s -tags webkit2_41`; Windows
  `CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 wails build -s -platform windows/amd64`. Build-host
  deps: wails CLI, `libgtk-3-dev` + `libwebkit2gtk-4.1-dev` (Linux), `gcc-mingw-w64-x86-64`
  (Windows). Version baked via `-ldflags -X main.version` (Wails forwards it, unlike fyne-cross).
  The shell self-updates from its server's public `/clients/latest` before connecting
  (`desktop/update.go`, v1.84.0+); older shells are downloaded once from the `/clients` page.

- **Tenant networks** (migration 44, `tenant_networks`): first-class per-org isolated
  networks. v1 ships the **isolated** mode — a dedicated per-org bridge `vdxt<network_id>`
  with no uplink (its own L2 domain; two orgs can never share a segment). Each tenant network
  OWNS a backing `networks` row (the port group VMs attach to) referenced by a **RESTRICT** FK
  so the raw `/networks` delete can't orphan it. New orgs get a default isolated network
  (`CreateOrg`→`provisionDefaultForOrg`) and their VMs auto-attach to it (`manager.Create`
  binds `network_id` when it's 0 and the org has a default); the pre-existing default org is
  unchanged. `internal/service/tenantnet_service.go`, host DHCP in `netdrv/tenantdhcp.go`
  (dnsmasq bound strictly to the tenant bridge), boot rebuild `ReensureTenantNetworks()` (after
  vRouters). Groundwork: the netns vRouter `ApplyLegs` is idempotent (was a hard 2nd-apply bug).
- **Tenant networking v2** (migration 45): a per-org admin (`atLeast("admin")`, not just an
  instance admin) now self-serves their org's whole **logical** network surface, fully isolated;
  the **physical** layer (NICs, bonds, vSwitch uplinks, host `/routing`, vRouter **transit**
  links, raw port-group/VXLAN forms) stays instance-admin. Pieces: (a) `net_segments` — a
  transactional VNI **identity** allocator (`service/segment_alloc.go`, range 200000–1048575,
  excludes in-use `networks`/`storage_overlays` VNIs, composite PK = no collision); in v2 the VNI
  is identity-only — **segments realize as plain bridges, NOT vxlan devices** (a peerless vxlan on
  one host would open a host-wide UDP:4789 injection surface and the node-local allocator can't be
  cluster-safe yet — both are the v3 multi-host path). (b) Segments can be **standalone** (own
  gateway+DHCP) or **routed/gatewayless** and attached to a per-org **netns** vRouter whose leg
  becomes their sole gateway — `AttachSegment`/`DetachSegment` bind to the segment's OWN bridge
  (never client input, org-scoped), no live gateway-handoff. (c) `/vrouters` + `/vfirewall`
  re-gated to `OrgAdmin` (transit + lxc stay instance-only; tenant routers are netns-only);
  `DeleteVRouter` preserves attached segments and refuses a tenant deleting a transit-bearing
  router. (d) `vrouters.name` → `UNIQUE(org_id,name)` (was global). (e) `ReplaceBridgeFW` validates
  in check-mode before tearing down the host-global EW table. Full design + the two adversarial
  reviews + the deferred v3 (cluster-wide allocator + segment replication + vxlan materialization +
  UDP:4789 ingress filter) in `docs/TENANT-NETWORKING.md` §14–24.
- **Tenant networking v3** (migration 46): per-tenant **virtual uplinks** + an instance-admin
  **egress-mapping console** (`/trunks`, "Tenant Egress" nav). A tenant builds isolated networks
  normally and connects one to a named **uplink**; the admin decides what that uplink really is on
  the wire. Model: an **external trunk** (`ext_trunks`) is a role-dedicated NIC/bond (NOT a raw
  vSwitch uplink — `guardTrunk` enforces this in CreateVSwitch/CreateBond/UpgradeVSwitchToBond/
  AddTransitLink + TransitCandidates); per-tenant **VLAN pools** (`tenant_vlan_pools`, Neutron-style
  range, live used/available); **uplinks** (`tenant_uplinks`) in mode `access` (single 802.1q),
  `qinq` (802.1ad outer S-tag, tenant inner VLANs preserved), or `dedicated` (whole NIC). Data plane
  = per-tenant VLAN **subinterfaces** `<trunk>.<vid>` (`netdrv/trunk.go`; proto per-sub so 802.1q and
  802.1ad tenants coexist on one trunk) enslaved into the tenant network's PLAIN bridge, so inner
  C-tags survive and the tenant's private VLAN numbering never collides across tenants. Allocator
  `service/vlan_alloc.go` (mirrors segment_alloc: outer_vid lives on the uplink row, standalone
  partial unique index `ux_uplink_trunk_vid` is the race backstop, free-after-device-gone). QinQ
  raises MTU + disables NIC VLAN offload on the trunk + every bond slave, recording the ORIGINAL
  state ONCE at designation for byte-for-byte restore; `VerifyQinQ` is a pre-trust check and true
  wire behavior must be tcpdump-confirmed on the host's NICs. **Rollback**: a "Disable tenant egress"
  teardown (crash-safe via `teardown_pending`) deletes every subinterface and restores every trunk;
  migration 46 is strictly additive so a binary rollback is clean. Boot: `ReensureExtTrunks` (before
  tenant nets) + `ReensureUplinks` (after). The vRouter external leg (`vrouter.LegUplink`) is modeled
  (WAN-zone classified); its attach path shipped in v1.106 (`AttachUplinkLeg`, below).
  - **Shared mgmt-uplink trunks** (migration 47, `ext_trunks.shared`): a trunk may be the management
    vSwitch's own uplink (e.g. the mgmt bond). It's **access-only** (single 802.1q subinterfaces) and the
    **parent is NEVER modified** — no MTU raise, no offload toggle — so management is never disturbed; tenant
    egress rides the same physical link as untagged management, separated only by VLAN tag. `isMgmtBridgeUplink`
    detects it and `DesignateTrunk` bypasses the "enslaved / is a vSwitch uplink" refusals **only** for that
    device; QinQ on a shared trunk is refused. Shared trunks are excluded from `extTrunkIfaces` (so `guardTrunk`
    doesn't fight the mgmt vSwitch) and from every `EnsureTrunk`/`RestoreTrunk` path
    (Reensure/Undesignate/DisableTenantEgress). `SharedTrunkCandidates` surfaces the mgmt uplink in the
    designate modal under a separate "shared with management" group.

- **Tenant view + tenant vSwitches / port groups** (migration 48, v1.106): an instance admin switched
  into a tenant org sees exactly that org (`Principal.TenantView`; `ProviderAdmin` keeps only quota /
  member-password actions). A **tenant network IS the tenant's vSwitch** (bridge `vdxt<network_id>`,
  its backing `networks` row = the untagged default port group); `tenant_portgroups` adds VLAN 2–4094
  port groups on the same bridge (`service/tenantpg_service.go`, host driver `netdrv/tenantvlan.go`).
  The bridge turns on `vlan_filtering` only once it has a tagged PG. Uplink port VLANs: carries the
  vSwitch's **native** PG untagged (`native_vlan`, 0 = untagged PG); access = only that one, QinQ /
  dedicated = also every other PG tagged. A PG **carried out the uplink** has its host gateway + DHCP
  **suspended** (the host must never answer DHCP / hold an IP on the provider's wire) and can't be
  router-gatewayed. **Host isolation**: every tenant bridge / `<bridge>.<vid>` gets per-iface
  `forwarding=0` + `disable_ipv6=1` and the host nft `table inet vdxtenant` (in: DHCP + ping of the
  iface's own IP only; forward: never route in/out) — rebuilt by `applyTenantIsolation()`, re-run after
  host `routing.Apply`. Tenant DHCP dnsmasq is `port=0` (no host resolver). L3 out = a netns router with
  a **VLAN leg** on a routed PG (`AttachPortGroup`) and an **uplink leg** on the carried PG
  (`AttachUplinkLeg`: default route via upstream GW rendered into FRR, SNAT `table ip vdxnat` + netns
  `ip_forward=1` via `vrouter.EdgeApplier`). Uplink disconnect **keeps** its outer VID (only delete /
  global teardown frees it). `DeleteVRouter` never deletes a tenant vSwitch bridge (PG + uplink legs
  just release). Live E2E verified all of it, incl. netns leg addresses + default route (needs the next bullet).
- **netns vRouter FRR vs AppArmor (Ubuntu 26.04)** — the old "netns runtime broken" root cause:
  the stock `abstractions/frr` allows only flat `/run/frr/<daemon>.pid`; a `-N <id>` pathspace puts it in
  `/run/frr/<id>/`, so confined staticd/bgpd/ospfd died at start → no leg addresses / routes. Fixed by the
  site file `deploy/apparmor/frr.d-vxvisor` (same grants one dir down), which `install.sh` installs as
  `/etc/apparmor.d/abstractions/frr.d/vxvisor` + `apparmor_parser -r` of every profile including the
  abstraction (owner-approved 2026-10-28; profiles stay in enforce mode). In-app updates replace only the
  binary — an existing host needs install.sh re-run (or the file + reload) once. FRR ≥9 also needs
  `mgmtd` for static routes; the netns launcher starts it after zebra.

### Onboarding a NEW Claude on a migrated host
When this project folder is moved to a new host, prior-session context from the previous
host's Claude memory is snapshotted in **`.claude-memory/`** (gitignored — contains host
IPs/creds, so it is NEVER committed; it travels only via a manual folder copy). Read
`.claude-memory/MEMORY.md` first for the index, then the per-topic files. Treat anything in
there about hosts/IPs/credentials as **stale** until re-verified on the new host.
