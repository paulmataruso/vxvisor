# VDX Clone — Complete Build Plan

An original, self-hosted VM/VDI management platform with full feature parity to VDX
Cloud Desktop. Built from scratch; no copied code or markup. Single Go binary `vdxd`
serving a web UI + REST API over QEMU/KVM on the host.

> This plan was drafted, then revised against an adversarial critique that probed the
> host and read the current code. Host facts baked in: **Ubuntu 22.04.5, running as root,
> QEMU 6.2.0 (old), KVM usable, nftables usable, OVMF present.** Findings from that review
> are folded into the milestones below (see the ▲ callouts).

---

## 0. Principles & non-goals

- **Original work.** Feature and screen-*inventory* parity; our own code, schema, markup,
  and visual design. Nothing extracted from the vendor binary is reproduced.
- **Self-hosted, admin owns the keys.** No call-home, no remote kill-switch, no
  vendor-pushed ISOs, no metered lease. The vendor's heartbeat-driven licensing is
  deferred (M9) and ships **off by default**, enforced locally only if ever enabled.
- **Single static binary.** Pure-Go, CGO-free, cross-compilable, one file + config.
- **Modular monolith** now; only the cluster layer (M7) talks off-box, over SSH to peer
  `vdxd` instances — still no external SaaS.
- **Every milestone is shippable** and demoable on `172.16.1.67:8766`.

---

## 1. Architecture

### 1.1 Layering
```
cmd/vdxd              CLI entrypoints (serve, migrate, user, org, image, backup…)
internal/web          HTML handlers, templates (embed), CSRF, session cookies
internal/api          REST/JSON handlers (same services; token/cookie auth)
internal/service      business logic, one package per domain; the ONLY layer that
                      enforces authz + calls the Enforcer; emits audit events
internal/store        SQL (hand-written) behind interfaces; no logic
internal/qemu         QEMU cmdline, QMP, qcow2, migration driver
internal/storage      pools (dir/iscsi/nfs/cifs), snapshots, backups
internal/netdrv       host networking (user/bridge/vlan, nftables, IP pools)
internal/stats        host + per-VM metrics collector
internal/worker       supervised background loops (reconciler, metering, retention,
                      backup scheduler, stats)
internal/auth         bcrypt, cookie sessions, API keys, OIDC
internal/policy       Enforcer interface (+ NoopEnforcer; real one at M9)
internal/config       TOML config + defaults
internal/db           connection, migration runner
```
**Rule:** handlers never import `store`; they call `service`. `service` is the single
authz + audit choke point. Multi-tenant isolation lives in exactly one layer.

▲ **The WS console path must obey this rule too.** `/console/{id}/ws` cannot carry its own
weaker authz — it calls the same `service` check (org membership + role) as the HTML
console handler. (Critique B2: otherwise any logged-in user guesses a UUID and attaches.)

### 1.2 Concurrency & SQLite
- **WAL mode + split pools.** DSN gets `_pragma=journal_mode(WAL)` (missing today).
  Single **writer** connection (`SetMaxOpenConns(1)` on the write pool); separate read
  pool. All writes go through `service`, never from a worker's own connection.
- **De-N+1 the session layer (critique M-3).** `List()` must be one query, not a per-row
  `Get()`. **Reconciliation moves OUT of the read path** into one owned reconciler
  goroutine — today `Get()` issues an `UPDATE` on every read, which races the workers.
- **Session manager locking.** One `sync.Mutex`-guarded in-memory map of running VMs,
  rebuilt from DB on boot. Port allocation (**both** `VNCPort` and `VNCPort+1000`
  websocket — the latter is untracked today, D-3) + liveness under lock.
- **Worker supervisor.** One `errgroup` with `ctx`; each ticker loop recovers from panics
  and continues; graceful drain on SIGTERM.

### 1.3 VM lifecycle correctness (critique M-4)
- **Graceful stop.** `Stop()` sends QMP `system_powerdown` (we already built
  `QMP.Powerdown()`), waits with timeout, then SIGTERM, then SIGKILL — never SIGTERM-first
  (dirty qcow2 / data loss on server VMs).
- **Crash recovery.** On boot, reconcile DB `running` rows against reality using a
  **pidfile + process start-time** (or a QMP ping), not a bare `FindProcess(pid)` — reused
  PIDs from a prior boot otherwise read as "running".

### 1.4 The Enforcer seam (why deferral is clean)
```go
// internal/policy
type Decision struct{ Allow bool; Reason string }
type Enforcer interface {
    CanStartSession(ctx, org OrgID, kind SessionKind, cur Counts) Decision
    CanCreateServer(ctx, org OrgID, cur Counts) Decision
    OnUsage(ctx, sample UsageSample)        // metering sink
    Quota(ctx, org OrgID) Quota             // seat/server/storage caps
}
type NoopEnforcer struct{}                  // MVP: Allow, unlimited, drop
```
▲ **Call sites land in M2, not M6 (critique D-4).** The create/start path calls
`enforcer.CanStartSession(...)` from the start (NoopEnforcer), even though quota tables
arrive at M6 — so M9 is a swap, not a scavenger hunt.

---

## 2. Data model (complete)

Numbered SQL migrations in `embed.FS`, applied via `schema_migrations(version)`,
forward-only. Timestamps = RFC3339 UTC text. **Every session list filters
`WHERE deleted_at IS NULL`.**

### 2.1 Existing (extended)
- `users`(id, username, password_hash, role, created_at, **oidc_sub**, **disabled**)
- `web_sessions`(token, user_id, created_at, expires_at) — INDEX(expires_at)
- `images`(name PK, path, source_url, size_bytes, status, created_at, **visibility**
  global|org, **org_id NULL**, **os_family**, **checksum**)
- `sessions`(id, name, owner_id, image_name, disk_path, cpus, memory_mb, state, pid,
  **pid_start_time**, vnc_port, **ws_port**, **vnc_password**, qmp_socket, created_at,
  **org_id**, **kind** desktop|server, **firmware** uefi|bios, **ovmf_vars_path**,
  **boot_iso_id**, **boot_order**, **template_id**, **disk_gb**, **mac**, **network_id**,
  **deleted_at**, **retention_at**, **last_started_at**)

### 2.2 Tenancy & access
- `orgs`(id, name, slug UNIQUE, created_at, settings_json)
- `org_members`(org_id, user_id, role owner|admin|member|viewer, PK(org_id,user_id))
- `api_keys`(id, org_id, hash UNIQUE, prefix, label, scopes_json, created_at, last_used,
  expires_at, revoked)
- `audit_log`(id, org_id, actor_id, actor_kind user|apikey|system, action, target_type,
  target_id, detail_json, ip, created_at) — INDEX(org_id, created_at)
- `oidc_providers`(id, name, issuer, client_id, client_secret_enc, scopes, enabled)

### 2.3 Images & storage
▲ **One tenancy model for images AND isos** (critique D-2): global catalog + per-org
visibility; no divergent schemes.
- `isos`(id, visibility global|org, org_id NULL, name, path, source_url, size_bytes,
  checksum, status, created_at)
- `templates`(id, org_id, name, base_image, cpus, memory_mb, disk_gb, firmware,
  cloudinit_user_data, cloudinit_network, created_at)
- `snapshots`(id, session_id, name, qcow2_path, parent_snapshot_id, size_bytes, state,
  created_at) — INDEX(session_id)
- `backups`(id, session_id, org_id, path, size_bytes, compressor zstd|gzip, state, error,
  created_at) — INDEX(org_id, created_at)
- `backup_schedules`(id, target_kind session|template, target_id, cron_expr,
  retention_days, enabled, last_run, next_run)
- `storage_pools`(id, name, kind dir|iscsi|nfs|cifs, config_json, mount_path, total_bytes,
  used_bytes, state, created_at)
- `disk_usage`(pool_id, session_id, bytes, measured_at)

### 2.4 Networking
- `networks`(id, org_id, name, kind user|bridge|vlan, cidr, gateway, bridge_name, vlan_id,
  dhcp_enabled, created_at)
- `ip_pools`(id, network_id, range_start, range_end)
- `ip_leases`(id, pool_id, session_id, ip UNIQUE, mac, leased_at, released_at)
- `firewall_rules`(id, network_id, priority, direction in|out, proto, port_range, cidr,
  action allow|drop, enabled)

### 2.5 Cluster
- `nodes`(id, name, addr, ssh_user, ssh_key_ref, role control|worker, state, cpu_total,
  mem_total_mb, last_seen, version)
- `node_resources`(node_id, cpu_used, mem_used_mb, vms_running, measured_at)
- `placements`(session_id, node_id, assigned_at)
- `migrations`(id, session_id, src_node, dst_node, state, progress, started_at,
  finished_at, error)

### 2.6 Billing/metering (local)
- `plans`(id, name, seat_cap, server_cap, storage_cap_gb, rate_per_hour, created_at)
- `org_quotas`(org_id, plan_id, seat_cap_override, server_cap_override,
  storage_cap_override)
- `usage_ledger`(id, org_id, session_id, period_start, period_end, seconds, rate, credits)
  — INDEX(org_id, period_start)

### 2.7 Observability & platform
- `alert_rules`(id, org_id, name, metric, comparator, threshold, duration_s, enabled,
  channel_json)
- `alerts`(id, rule_id, org_id, state firing|resolved, value, started_at, resolved_at)
  — INDEX(org_id, state)
- `settings`(key PK, value) — instance singletons (base URL, SMTP, update channel, master
  key ref…)
- `update_artifacts`(version, channel, url, checksum, published_at)

**Indexes (critique D-1), minimum:** `sessions(org_id,state)`, `sessions(owner_id)`,
`audit_log(org_id,created_at)`, `web_sessions(expires_at)`, `usage_ledger(org_id,period_start)`,
`isos(org_id)`, `snapshots(session_id)`, `backups(org_id,created_at)`.

---

## 3. UI (original design, ~25 screens)

- **Our own visual language:** left vertical rail nav (vendor uses a top bar), our theme
  and component shapes. Server-rendered `html/template` base + partials; vanilla JS only
  for live bits (console, stats, progress). No SPA framework.
- **Design tokens** (CSS custom properties) defined once in M1; dark/light via
  `prefers-color-scheme` + `data-theme` override.
- **Screen groups:** Compute (list, create, detail/console), Images & Storage (images,
  ISOs, templates, snapshots, backups, pools), Networking (networks, IP pools, firewall),
  Cluster (nodes, placements, migrations), Observability (dashboard, alerts, audit),
  Tenancy & Billing (orgs, members, API keys, usage, plans, Trash), Settings (OIDC,
  update, SMTP, instance).
- **CSRF** token on every mutating form; security headers; **console authz re-checked per
  WS connection** against org membership.

---

## 4. Milestones

Each milestone = schema migration + service + store + web + api + tests + demo.
**MVP POC = end of M2.**

### M1 — Foundation + Tenancy + Security hardening
*(Folds the former standalone "M0 refactor" in — critique M-1: no empty milestones.)*
- **Layers & plumbing:** stand up `store`, `service`, `policy.NoopEnforcer`, `worker`
  supervisor, migration runner, WAL + split pools, audit plumbing. Port the existing
  desktop-session flow onto them.
- **Session-layer fixes (M-3/M-4):** one-query `List`, reconcile goroutine out of the read
  path, QMP-graceful `Stop` w/ fallback, boot-time recovery via pidfile+start-time.
- **▲ B1 — Lock down the console (blocker):** bind QEMU VNC/websocket to **127.0.0.1 only**
  (`-vnc 127.0.0.1:N,websocket=127.0.0.1:P`), never 0.0.0.0; the app WS proxy on 8766 is
  the sole external path; add a **per-session VNC password / one-time token**.
- **▲ B2 — Single authz for console (blocker):** `service.CanAccessConsole(user,session)`
  called by BOTH the HTML and WS handlers; org membership + role, not `owns()`.
- **Tenancy:** orgs, org_members, RBAC middleware (role→permission matrix), audit_log +
  viewer, API-key issue/revoke, the new UI shell + rail nav + org switcher, users/members
  admin. Backfill a default org owning existing users/sessions.
- **Login rate-limiting (D-3):** throttle per-IP/per-user (bcrypt is a DoS lever).
- **Exit:** all data org-scoped, cross-org access denied in `service` + tested; raw VNC
  ports unreachable from the LAN; console works only through authorized proxy.

### M2 — Compute parity  ← **MVP POC line**
- Server/persistent VMs (`kind`); **Enforcer call sites wired here** (NoopEnforcer).
- **▲ UEFI done right (M-2):** per-VM **writable OVMF_VARS** copy (`OVMF_VARS_4M.fd`) +
  readonly `OVMF_CODE`; BIOS path = SeaBIOS. Persist `ovmf_vars_path`.
- **▲ ISO boot wired (M-2):** `-cdrom`/`-drive media=cdrom` + `-boot order=...`; not free.
- CPU/mem/disk sizing + offline resize; per-VM detail screen (state, specs, console,
  events).
- **cloud-init (D-3):** NoCloud seed ISO for first-boot user/SSH keys/creds — required for
  a *usable* VM. Secrets written to the seed, not logged.
- **Disk-space accounting (D-3):** check pool free space before `CreateOverlay`.
- **Exit:** create→boot a real Ubuntu cloud image with cloud-init login→console→stop, as a
  non-owner org admin.

### M3 — Images & Storage
- ISO library (upload + URL pull, checksum, status).
- Templates (spec + cloud-init) → one-click create.
- Snapshots: qcow2 external; **online** via QMP `snapshot-save`/`blockdev-snapshot`;
  revert/delete; parent chain. *(QEMU 6.2 supports these; verify flag names.)*
- Backups: the decompiled pipeline — `detectCompressor` (zstd→gzip), stream disk
  (`qemu-img convert` offline / blockdev live) through compressor to file, byte counting,
  stderr capture. Restore path.
- Backup schedules (cron worker) + retention pruning.
- **Retention/auto-deprovision worker:** the decompiled `deprovisionPastCutoff` query →
  soft-delete to Trash past `retention_at`; Trash restore/purge UI.
- Storage pools: `dir` first; `iscsi` (open-iscsi), `nfs`/`cifs` (mount) via config_json;
  usage into `disk_usage`.
- **Control-plane DB backup (D-3):** scheduled `VACUUM INTO` snapshot of the sqlite DB
  alongside VM backups.

### M4 — Networking + privilege separation
▲ Reframed (critique M-6): we already run as root, so bridge/VLAN work *today* — the real
fix is to stop running VMs as root.
- **Drop VM privileges:** run QEMU as a dedicated `vdx` user with `/dev/kvm` access; grant
  only specific `CAP_NET_ADMIN`/sudo-helper for bridge/tap setup.
- Modes: `user` (SLIRP, **default**) → `bridge` (host bridge + tap) → `vlan` (802.1q).
  Per-session NIC attach to a `network`.
- IP pools + leases (static; DHCP via host dnsmasq optional).
- Firewall: render `firewall_rules` → **nftables** per network; apply on VM start.
- Port-forward helper for `user` mode (hostfwd) so RDP/console reachable without bridging.

### M5 — Observability
- `stats` collector goroutine: host (CPU/mem/disk/net) + per-VM (QMP `query-blockstats`,
  proc/cgroup for the qemu pid). Ring buffer + periodic DB rollup.
- Live dashboard over WebSocket; per-VM charts.
- alert_rules evaluation in worker → alerts firing/resolved → channels (email/webhook).
- Audit log viewer with filters.

### M6 — Tenancy & Billing (local, no phone-home)
- Metering worker (shape of decompiled `StartCreditMetering`): per running session, per
  interval, append to `usage_ledger` (seconds×rate); feeds `Enforcer.OnUsage`.
- plans + org_quotas CRUD; per-org usage reports.
- API-key scopes enforced; API rate limiting.
- Trash/retention surfaced in UI (ties to M3 worker).

### M7 — Cluster  *(stretch; de-risked and split — critique M-5)*
- **M7a — Multi-node + scheduling:** nodes registry; control node drives workers over
  **SSH** (qemu/qemu-img/QMP tunneled); scheduler picks node by free CPU/mem →
  `placements`; node health in `node_resources`.
- **M7b — Live migration:** `-incoming` on dst + QMP `migrate tcp:` on src; **requires**
  shared storage (NFS pool) or `blockdev-mirror` disk copy; matching CPU model; progress
  from `query-migrate`. ▲ QEMU **6.2** across nodes is finicky — pin identical versions;
  treat as its own effort.

### M8 — Platform  *(five independent stretch items — critique M-5; do not anchor schedule)*
- **M8a — OIDC/SSO:** `golang.org/x/oauth2` + OIDC discovery; map `oidc_sub`→user; JIT
  org provisioning by claim.
- **M8b — Terraform provider:** **separate repo/binary** (terraform-plugin-framework) over
  our REST API (org, session, template, network, snapshot). Not in the daemon.
- **M8c — Self-update:** local `update_artifacts` feed + `vdxd self-update` (checksum
  verify, binary swap, systemd restart). No vendor server.
- **M8d — Import:** ESXi (ovftool/VMDK→qcow2 via `qemu-img convert`) + Proxmox (vma/qcow2).
- **M8e — Passthrough:** GPU (vfio-pci bind, `-device vfio-pci`) + USB (`-device usb-host`),
  behind host pre-flight (IOMMU on). ▲ Needs VFIO/IOMMU host reconfig + reboot — **likely
  not demoable on this box**; document setup, gate behind capability check.

### M9 — Licensing (deferred, off by default)
Implement real `policy.Enforcer`: **local signed license file** (offline) enforcing
seat/server/storage caps + optional metered plan. Optional outbound heartbeat (the
decompiled `licenseSig` HMAC-SHA256 + `/heartbeat` shape) only if an operator opts in,
pointing at a URL *they* control. Default config: enforcement off, zero network calls.

---

## 5. Cross-cutting concerns

- **Secrets at rest:** OIDC client secret, SMTP creds, SSH keys, VM creds encrypted with
  AES-GCM; key from an operator-provided master key (or host keyring) referenced in
  `settings`. Never logged.
- **Console security:** per-session VNC password; proxy only after per-connection org
  check; VNC bound to loopback (see M1/B1).
- **Crash recovery:** boot reconcile by pidfile+start-time; re-adopt QMP sockets where
  possible, else mark stopped.
- **Disk accounting:** pool used/total tracked; refuse create over quota/space.
- **Control-plane DB backup:** scheduled sqlite snapshot (M3).
- **Graceful shutdown:** SIGTERM → stop accepting, drain workers; VMs may stay detached and
  be re-adopted on restart.
- **Rate limiting + CSRF + security headers** on all surfaces.

## 6. Testing

- Unit: services + stores against sqlite in tmpdir; a `qemu` **fake** (interface) for
  driver logic (cmdline, QMP sequencing) with no real VM.
- Integration: one real create→start→console→stop smoke per compute-affecting milestone,
  behind a build tag (needs qemu).
- `go vet` + `-race` in CI; migration up-tests (apply all, assert schema).

## 7. Sequencing

Strict M1→M9, each reviewed before the next. **MVP POC = end of M2.** Full parity core =
end of M6. Stretch = M7–M8 (independently deferrable). Licensing = M9.

## 8. Risk register

| Risk | Where | Mitigation |
|---|---|---|
| Unauth VNC on LAN (**present today**) | M1/B1 | bind loopback + VNC password; proxy is sole path |
| Cross-org console hijack | M1/B2 | single service-layer authz for HTML+WS |
| SQLite write contention under workers | M1 | WAL + single writer + reconcile out of read path |
| Dirty qcow2 from SIGTERM stop | M1 | QMP graceful stop + fallback |
| UEFI won't boot (no VARS) | M2 | per-VM writable OVMF_VARS |
| Online snapshot/backup consistency | M3 | QMP-coordinated / guest-agent fsfreeze / pause-copy |
| Bridge/VLAN while VMs run as root | M4 | privilege separation; SLIRP default |
| Live migration on QEMU 6.2 | M7b | shared storage + pinned versions; own effort |
| GPU passthrough host-specific | M8e | IOMMU pre-flight; not default; may be undemoable here |
| Scope creep | M7/M8 | each independently deferrable after MVP |
