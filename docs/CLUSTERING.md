# VXVisor Clustering — architecture & implementation plan

Status: design approved 2026-10-14. Target test bed: **test01** (172.16.0.159 / cluster
10.10.2.11) + **test02** (172.16.0.160 / cluster 10.10.2.12), active/active.

## Goals (from the operator)
1. **Active/active** — both nodes run VMs; neither is a passive standby.
2. **Single pane of glass** in cluster mode — manage every node's VMs/resources from one place.
3. **Management VIP (floating IP)** — one IP manages the whole cluster; it follows the leader.
   Obtained via **DHCP** (no hand-picked static), so it "just appears" on the mgmt LAN.
4. **Cluster-wide user accounts** — a login works from any node / the VIP.
5. **Failover** — planned moves via **live migration** now; **HA auto-restart** on node death
   when **shared storage** lands (coming soon — hooks built now, enablement gated).

## What already exists (build on it, don't rewrite)
- `internal/gossip` — memberlist SWIM + mDNS, per-node Meta (name/addr/cpu/mem). Gated off today.
- `internal/cluster/cluster.go` — `nodes` registry, `Schedule`, `PlaceSession`, gated **live
  migration** QMP sequence (auto-converge+xbzrle, SSH `vdxd migrate-recv` receiver, block-migrate
  fallback), ownership flip.
- `internal/worker` — all background loops (currently every node runs **all** of them — bug in a cluster).
- `internal/netdrv/overlay.go` — VXLAN overlay to put all nodes' VM taps on one L2.
- `internal/web/cluster_handlers.go` + `cluster.html` — node list/add/delete/probe + migrate.
- `cmd/vdxd/main.go` — gossip start (gated), `migrate-recv` subcommand, overlay bring-up.
- DB migrations: max id **20**; `nodes` table + `sessions.node_id` exist.

## Design

### Cluster mode switch
`[cluster] enabled=true` (implied when `seeds` set). Off → today's single-host behaviour, untouched.

### 1. Membership (gossip on the CLUSTER net)
- Bind gossip to **ens19 / 10.10.2.x** (new `GossipBind` = cluster IP), **static seeds** = peer
  cluster IPs (reliable; mDNS stays optional). Heartbeat/capacity never touch mgmt.
- Extend `gossip.Meta`: add `MgmtAddr`, `ClusterAddr`, `Leader bool`, `Term uint64`, `Epoch`,
  `Started` (for lowest-uptime/id tiebreak). Keep under the memberlist meta size limit.

### 2. Quorum + leader election (new: `internal/cluster/leader.go`)
- Quorum = a node sees `> N/2` alive members (N = max members ever seen, persisted). 2-node
  degenerate case handled per policy below.
- **Leader** = the quorum-connected alive member with the lowest `(Started, NodeID)` that also
  claims the current term. Leadership is a **gossiped, term-stamped lease**; a node renews its own
  lease each tick, and steps down immediately if it loses quorum. Deterministic tiebreak → no flap.
- `cluster.Role` exposes `IsLeader()`, `Leader() Member`, `HasQuorum()`, `Members()`.
- **2-node policy (no majority):** `test01` is the configured **primary** (`[cluster] primary=true`).
  On a clean partition the primary keeps leadership+VIP; the secondary only assumes leadership when
  it believes the primary is truly down (gossip dead + optional mgmt-side liveness probe). Documented
  split-brain caveat until a 3rd node / witness exists. Quorum logic is generic for N≥3.

### 3. Singleton loops gated on leadership
`internal/worker`: split loops into **node-local** (always run: reconcile own QEMU, metrics,
node-health/gossip, web-session GC) and **cluster-singleton** (leader-only: backup-scheduler,
retention, warm-pool, desktop-reclaim, db-backup, alerts, migration orchestration, account-sync
push, HA monitor). Guard singletons with `if role != nil && !role.IsLeader() { return }`.

### 4. Management VIP — DHCP-leased floating IP (new: `internal/cluster/vip.go`)
- The leader owns the VIP; everyone else does not.
- Implementation: leader creates a **macvlan** child on `vip_iface` (ens18) named `vdxvip0` with a
  **deterministic cluster MAC** (`02:` + first 5 bytes of sha256(cluster_id)). It runs a **pure-Go
  DHCP client** (`github.com/insomniacslk/dhcp`, CGO-free) on `vdxvip0` to obtain a lease, applies
  the address with `ip addr add`, and sends a **gratuitous ARP** (raw AF_PACKET) so the switch
  relearns the MAC. Lease is renewed at T1; released on demotion (`ip link del vdxvip0`).
- Because the **MAC is stable**, when leadership moves the new leader recreates the same
  macvlan+MAC and DHCPs → the server returns the **same IP** (lease affinity) → the IP floats.
- The leased VIP is **advertised in gossip** (`Meta.VIP`) and shown in the UI ("Cluster address").
- Config: `[cluster] vip_dhcp=true`, `vip_iface="ens18"`. (A static `vip="x/24"` is also supported
  for when DHCP isn't wanted.)
- Admin UI (:8766), API, and portal (:8768) already bind `0.0.0.0`, so they answer on the VIP
  automatically — no listener change needed.

### 5. Node-to-node cluster API (new: `internal/api/cluster_api.go`, bound to cluster net)
- Authenticated peer RPC over the **cluster net** for aggregation, proxying, and sync.
- Auth: a **shared cluster secret** (`/var/lib/vdxclone/data/cluster.key`, generated at
  cluster-init, distributed to joiners) → HMAC-signed, timestamped requests (reuse the broker
  signer pattern). Reject anything not from the cluster subnet.
- Endpoints (all read/act on the **local** node only):
  - `GET  /cluster/v1/sessions` — this node's VMs (for leader aggregation).
  - `GET  /cluster/v1/health` — live cpu/mem/load.
  - `POST /cluster/v1/sessions/{id}/{action}` — start/stop/restart/console-token (proxy target).
  - `GET/POST /cluster/v1/accounts/...` — account-sync pull/push (§6).
- Served on a **separate listener** bound to the cluster IP (`[cluster] api_addr=10.10.2.x:8767`).

### 6. Cluster-wide accounts (leader-authoritative replication)
- Replicated tables: `users`, `orgs`, `org_members`, `api_keys`, `pool_grants`. (`web_sessions`
  stay node-local — the VIP terminates auth on the leader; on failover users re-login.)
- Each replicated row gets a monotonic `rev` (per-node logical clock) + `updated_at`; a new
  `account_sync` cursor table tracks "last rev pulled from leader".
- **Writes** go to the leader (UI lives at the VIP = leader). A follower that receives an account
  write **redirects/proxies it to the leader**. Leader applies locally, bumps `rev`.
- **Pull:** followers poll `GET /cluster/v1/accounts?since=<rev>` from the leader each tick and
  upsert rows (last-writer-wins by `rev`). On join, a follower does a full pull. On promotion, the
  new leader already has the latest (it was pulling), so it becomes authority seamlessly.
- Admin-gated; all peer calls HMAC-authenticated.

### 7. Single pane of glass (leader-aggregated view)
- At the VIP (leader), cluster-wide pages show the **union** across nodes:
  - **Nodes:** from gossip (exists).
  - **Instances:** leader merges its own `sessions` with each peer's `GET /cluster/v1/sessions`,
    tagging each row with its node name. Lifecycle actions on a **remote** VM are **proxied** to the
    owning node's cluster API (`POST /cluster/v1/sessions/{id}/{action}`); console/desktop tokens are
    minted by the owning node and the gateway connects there.
  - Placement: `Schedule()` already picks the least-loaded node; `Create` on the leader can target a
    chosen node (new "node" select on the create modal, default = auto/least-loaded).
- Followers' own :8766 still works (active/active) but shows a banner "managed via cluster VIP x.x.x.x".

### 8. Live migration (verify) + HA hooks (gated)
- Live migration already coded → **verify** test01⇄test02 with a small VM using the **block-migrate**
  path (no shared storage yet). Preconditions already met (identical QEMU 10.2.1, `-cpu host`).
  Guest L2 identity preserved via the overlay (or a shared cluster VLAN) + gARP.
- **HA restart (node death):** add `sessions.ha_policy` (none|restart). Leader's **HA monitor**
  (singleton) watches gossip; when a node goes `failed`, for its `ha_policy=restart` VMs it
  re-creates/starts them on a surviving node. **Gated on shared storage** (a dead node's local disk
  is unreachable) — built now, enabled when the shared pool exists. Fencing noted as a prerequisite.

## DB migrations (append after 20)
- `21 cluster-accounts-rev`: add `rev`/`updated_at` to users/orgs/org_members/api_keys/pool_grants;
  `account_sync(peer TEXT, last_rev INTEGER)`; a `cluster_meta(key,value)` kv (cluster_id, max_members).
- `22 session-ha`: `ALTER TABLE sessions ADD COLUMN ha_policy TEXT NOT NULL DEFAULT 'none'`.
  (Follow `sessionCols`/`scanSession` discipline — append before `created_at`.)

## Config additions (`[cluster]`)
`enabled`, `primary`, `cluster_iface` (ens19), `cluster_bind` (10.10.2.x), `seeds` (peer cluster
IPs), `api_addr` (10.10.2.x:8767), `vip_dhcp`, `vip_iface` (ens18), `vip` (static alt). Defaults keep
single-host installs unchanged.

## Deploy / test plan (on test01+test02)
1. Build, deploy both, write `[cluster]` config (test01 primary), restart.
2. **Membership:** both show 2 ready members in gossip + `/cluster`.
3. **Leader+VIP:** exactly one leader; VIP appears via DHCP on the leader's ens18; reachable;
   `curl http://<vip>:8766/login` = 200. Stop leader → VIP + leadership move to the other node;
   `curl` recovers. Restart → primary reclaims.
4. **Singletons:** confirm only the leader runs backup/warm-pool/etc (logs).
5. **Accounts:** create a user at the VIP → appears on both nodes' DB; login works via VIP and via
   each node directly.
6. **Single pane:** create a VM on each node → the VIP UI lists both, tagged by node; start/stop a
   remote VM through the VIP (proxied).
7. **Live migration:** small VM test01→test02 and back; guest stays up (ping/VNC), ownership flips.
8. Fix whatever breaks; re-deploy; re-test.

## Non-goals this pass
- Full raft-replicated control plane (chose leader-aggregated). Documented upgrade path.
- Automatic HA restart enablement (waits on shared storage). Hooks + policy land now.
- Storage clustering (Ceph/shared NFS) — separate workstream, coming soon.

---
## Critic revisions (folded in before implementation)
- **B1 QMP migrate:** `internal/qemu/qmp.go` sends `blk`/`inc` — **removed in QEMU 9.1**, so
  block (diskless) migration is dead on 10.2.1. Fix: drop the arg; **live migration requires
  shared storage**. For the test NOW, stand up a **temporary NFS** mount between the two nodes at
  the same path and migrate a VM off it (validates the RAM-migration + ownership flip). Real NBD/
  blockdev-mirror diskless migration = documented future work; real shared storage = production.
- **B2 split-brain:** a secondary may assume leadership/VIP ONLY when it holds quorum AND a
  **mandatory** mgmt-side liveness probe of the primary fails. Non-quorum ⇒ never owns the VIP.
  2-node has no true split-brain protection until a 3rd node/witness — documented.
- **B3 gossip auth:** set `memberlist SecretKey` = the shared cluster secret (leadership is
  gossiped, so it must be authenticated+encrypted). Same key on both nodes.
- **B4 cross-node console:** the leader tunnels console/desktop WS to the owning node via an
  **authenticated WS reverse-proxy** on the cluster API, using a **cluster-signed** token (web
  sessions are node-local). Lifecycle actions proxy; console relays.
- **M2/M3/M9 VIP:** pin DHCP **client-id = stable MAC** (so the lease/IP floats); set
  `arp_ignore=1 arp_announce=2` on parent+child; the VIP macvlan is an explicit, additive,
  `guardMgmt`-sanctioned child of ens18 (parent keeps its own IP + admin listener).
- **M6 advertise:** gossip `Advertise` = cluster IP explicitly; migration/SSH use `ClusterAddr`;
  add `MgmtAddr` separately. **M5:** never truncate `NodeMeta` — size-guard + log.
- **M7 failover:** dedicated sub-second leadership ticker (not the 30s loop); strict
  **release-before-claim**; **non-preemptive/sticky** leadership (healthy leader keeps it;
  primary preference only breaks startup ties) to avoid double-outage failback.
- **M8 portal:** do NOT bind :8768 to 0.0.0.0 (plaintext creds). Only the admin UI (:8766,
  already 0.0.0.0) answers on the VIP; the portal stays behind its TLS proxy.
- **Minors:** reconcile config names; `cluster.key` under `DataDir` (like `broker.key`);
  migration-21 columns `NOT NULL DEFAULT`; VXLAN underlay pinned to ens19; gossip `NodeName` ==
  local node row name; per-migration port via `MigratePortFor`; HMAC nonce + short window.

---
## Implementation status (2026-10-14, vdxd 0.14.0) — ALL MILESTONES DONE + live-tested

Verified on the 2-node cluster (test01 primary / test02):
- **M1 Membership + VIP:** authenticated gossip on the cluster NIC; leader election
  (sticky/non-preemptive, primary preference); **DHCP floating VIP 172.16.0.162** via a
  cluster-stable macvlan MAC (lease affinity floats the IP); ~4s failover; clean teardown
  (in-proc release + `ExecStopPost` + startup cleanup). **Split-brain safe:** a secondary
  promotes only after a MANDATORY mgmt-probe of the last-known leader *fails* — a cluster-link
  partition makes the follower stand down (no dual-VIP). Admin UI rebound `0.0.0.0:8766` to
  answer on the VIP. Singleton loops (warm pool / reclaim) run leader-only.
- **M2 Accounts + single pane:** account tables (users/orgs/members/api_keys) replicate
  leader→followers (upsert); a user made on the leader logs in on the follower and via the VIP;
  follower account writes refused. The VIP `/cluster` page aggregates every node's VMs over the
  authenticated peer API (:8767, HMAC); lifecycle actions on a remote VM are proxied; **cross-node
  console** relays the VNC WebSocket to the owning node (verified: RFB handshake through the VIP).
- **M3 Live migration:** QMP `migrate` fixed (dropped the removed `blk`/`inc`); the receiver is
  launched over the **peer API** (no inter-node SSH keys); migration runs on **shared storage**
  (validated with a temporary NFS mount over the cluster net); clean cutover — source VM is
  `quit` after completion (verified test01→test02: QEMU moved, source gone).

### Known limitations (follow-ups)
1. **Migration record ownership:** migration moves the running QEMU and flips `sessions.node_id`,
   but the session ROW stays in the source node's DB (not transferred to the dst's DB). So the
   aggregated view shows a migrated VM under its original node, and back-migration must re-resolve
   the host. Follow-up: transfer the session record to the destination on completion.
2. **Diskless migration:** inline block migration is gone in QEMU ≥9.1 — live migration needs
   shared storage (coming soon). NBD/blockdev-mirror storage migration is future work.
3. **Account deletions** don't propagate to followers (upsert-only, to avoid cascade-wiping a
   follower's VMs). New users / password / role changes DO propagate. Do destructive account ops
   at the leader.
4. **2-node split-brain:** a FULL (mgmt+cluster) partition has no protection — needs a 3rd node /
   witness. Node death and cluster-link-only partition ARE handled.
