# Tenant Networking (per-tenant isolated networks) — design

Status: **PLAN (v1 implementation in progress)**. Author: engineering, 2026-10-25.

## 1. Goal (the user's vision, verbatim intent)

> Each tenant can have its own VRF / namespace / dedicated internal VLAN per tenant,
> which we then direct to the external network however we want — L2, L3, vRouter, etc.

Hard requirements:
- **100% UI-driven.** No CLI, no hand-editing host files.
- **Never get locked out.** No tenant network operation may touch the management NIC,
  the host default route, the host `main` routing table, or the admin/SSH path.
- **Tenant changes can NEVER affect another tenant.** Isolation is structural, not
  by convention. One tenant's create/edit/delete/apply/failure cannot perturb another's
  data plane, routing, or firewall.
- **Easy.** A tenant network is one object the user creates with a mode; the system
  wires everything (L2 segment + addressing + external attachment) automatically.

A "tenant" is an **org** (`orgs` table). This builds on existing primitives and does
**not** reinvent an SDN.

## 2. What already exists (reuse, don't rebuild)

- `networks` (port groups, org-scoped: modes `user|bridge|vlan|vxlan`, `vni`, `bridge`,
  `vlan_id`, `cidr`, `gateway`) — `internal/netdrv`, `internal/service/net_service.go`.
- Per-network VXLAN realize/teardown + systemd unit — `netdrv.EnsureVNINetwork`,
  `VNINetworkNames(id)`, `net_service.realizeVXLANNetwork`.
- vSwitches (VLAN-filtering bridges with uplink trunk) + `AddTrunkVlan` / `SetupTapAccess`.
- **Per-org vRouter (NSX-lite)** — `internal/vrouter` + `internal/service/vrouter_service.go`:
  netns **or** LXC runtime, each with its **own FRR + its own nftables instance + its own
  uplink-less internal bridges**, a transit leg on a free physical NIC, SNAT/routing, DHCP,
  and a hard **HOST-SAFETY INVARIANT** (never touch host FRR / host `inet vdxclone` nft /
  mgmt NIC — enforced by `guardMgmt`). This is already Neutron's `qrouter-<id>` namespace model.
- Guards: `guardMgmt` (refuse mgmt NIC), `guardStorageTarget`, `DeleteVSwitch` refuses mgmt bridge.
- Unified `/vfirewall` per-org nftables (bridge `vdxdfw` east-west, per-vRouter `inet vdxfw` N-S).

**The gap** (confirmed by code audit): all of the above is **manual, opt-in, and has no
collision guardrail**, and the shipped defaults **co-locate** every org on one untagged
`vdxbr0`. There is no per-tenant auto-isolation and no structural prevention of two orgs
sharing an L2 segment. This design closes exactly that gap.

## 3. Research basis (how the field does it)

From Neutron/ML2, OVN, Proxmox SDN, Incus/LXD, oVirt, and the Linux VRF-vs-netns analysis
(full notes in session research). Load-bearing lessons adopted:

1. **Centralized, transactional segment-ID allocation** (Neutron ML2 tenant_network_types):
   one authority owns the VNI/VLAN pools and hands out IDs atomically from a DB transaction.
   This is what makes cross-tenant collisions *structurally impossible*. **Highest-value idea.**
2. **VXLAN VNI as the isolation substrate**, not VLANs: 16M IDs, overlapping tenant subnets
   allowed, no dependence on physical-switch VLAN config. VLAN offered only as an explicit
   L2-bridged egress mode.
3. **Per-tenant isolated forwarding domain + default-drop firewall** = the netns vRouter we
   already have (Neutron qrouter / OVN logical datapath).
4. **Proxmox object model Zone→VNet→Subnet** + **pending→Apply with a committed
   running-config**: desired state is data; an explicit Apply reconciles to host state and can
   roll back to a known-good snapshot. Atomic, lockout-safe. Mirrors our vMotion/DB-resilience
   state-machine instincts.
5. **Hard management/data-plane separation**: the admin path stays in a table/iface no tenant
   construct can rewrite (we already have this with host `inet vdxclone` vs per-vRouter tables).
6. **VRF vs netns verdict**: keep **netns** as the per-tenant boundary (already built; free
   overlapping subnets + own conntrack/nft + atomic `ip netns del` teardown). Reserve host-FRR
   **VRF+EVPN Type-5** for the future *multi-host* underlay L3VPN growth path only — pure-VRF on
   a live single host carries a shared-conntrack/nft/lockout tax not worth paying now.

Deliberately simplified away (vs OVN/Neutron): no distributed control plane, no DVR /
gateway-chassis, no ML2 plugin matrix. One allocator, one external-attachment switch.

## 4. The model

A **Tenant Network** (our VNet; one object the user creates) belongs to exactly one org and is
one isolated broadcast domain that materializes as a dedicated Linux bridge. It carries:

- `seg_type` — `vxlan` (default) or `vlan`. Drives which pool allocates the segment id.
- `seg_id` — **auto-allocated** VNI or VLAN tag (user never picks it).
- `cidr`, `gateway`, `dhcp` (+ range/DNS) — the subnet (IPAM-lite; one subnet per network in v1).
- `ext_mode` — how it reaches the outside:
  - **`isolated`** — no external path at all (bridge with no uplink). The safe default.
  - **`routed`** — a per-tenant router leg does SNAT out a transit NIC (Neutron non-DVR model);
    optional floating-IP DNAT later. Implemented via the existing **vRouter** (netns).
  - **`l2bridge`** — the tenant is trunked onto a vSwitch uplink with an allocated VLAN tag
    (direct L2 to the physical network). No router.
  - **`vrouter`** — full NSX-lite FRR (BGP/OSPF/multi-leg), the existing advanced path.
- `state` — `pending | applied | error` + `running_json` (committed snapshot) + `error`.

Per-org **segment pools** with configurable ranges (defaults: VNI 100000–165535 carved into
per-org sub-bands is *not* needed — a single global pool with an `allocated` flag suffices and
is simpler; collisions are prevented by the allocator, not by banding). VLAN pool default
2–4094 minus any reserved/mgmt VLANs.

### Why this satisfies the requirements
- **Easy / UI:** one object + a mode dropdown; everything else is derived and auto-wired.
- **No collisions:** `seg_id` comes from a transactional allocator (unique index + `allocated`
  flag in one DB txn). Two tenants can never get the same VNI/VLAN. Dedicated per-network bridge
  names (`vdxt<netid>` / reuse `VNINetworkNames`) never collide.
- **No lockout:** provisioner only ever creates *new* leaf devices (bridge, vxlan, veth) and
  tenant nft tables; it calls `guardMgmt`/default-route/`main`-table guards and **refuses** any op
  touching the mgmt NIC, the default route, or `main`. External attachment reuses vRouter transit
  (already mgmt-guarded) or a vSwitch uplink (already mgmt-guarded).
- **No cross-tenant impact:** each tenant network's devices are name-scoped and torn down only
  by their own ids; routed/vrouter mode runs in the tenant's own **netns** (own FRR + own nft +
  own conntrack); l2bridge isolation is the allocated VLAN tag. Apply/teardown of org A touches
  only A's devices/tables.

## 5. Data model (migration 44)

```
CREATE TABLE tenant_networks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id      INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        TEXT    NOT NULL,
  seg_type    TEXT    NOT NULL DEFAULT 'vxlan',   -- vxlan|vlan
  seg_id      INTEGER NOT NULL,                   -- allocated VNI or VLAN tag
  bridge      TEXT    NOT NULL DEFAULT '',         -- host bridge device (filled on apply)
  cidr        TEXT    NOT NULL DEFAULT '',
  gateway     TEXT    NOT NULL DEFAULT '',
  dhcp        INTEGER NOT NULL DEFAULT 0,
  dhcp_range  TEXT    NOT NULL DEFAULT '',
  dhcp_dns    TEXT    NOT NULL DEFAULT '',
  ext_mode    TEXT    NOT NULL DEFAULT 'isolated', -- isolated|routed|l2bridge|vrouter
  ext_ref     TEXT    NOT NULL DEFAULT '',         -- transit NIC / uplink vSwitch / vrouter id
  vrouter_id  INTEGER NOT NULL DEFAULT 0,
  state       TEXT    NOT NULL DEFAULT 'pending',  -- pending|applied|error
  running_json TEXT   NOT NULL DEFAULT '',          -- committed snapshot for safe reconcile/rollback
  error       TEXT    NOT NULL DEFAULT '',
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(org_id, name)
);
CREATE INDEX idx_tnet_org ON tenant_networks(org_id);

-- Transactional segment allocator. One row per allocated id; UNIQUE makes a double
-- allocation impossible. Freed on network delete.
CREATE TABLE net_segments (
  seg_type  TEXT    NOT NULL,              -- vxlan|vlan
  seg_id    INTEGER NOT NULL,
  org_id    INTEGER NOT NULL,
  net_id    INTEGER NOT NULL,
  created_at TEXT   NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (seg_type, seg_id)
);
```

Allocator (`AllocSegment(tx, seg_type, org_id, net_id) (int, error)`): `BEGIN IMMEDIATE`;
`SELECT` lowest free id in the configured range not present in `net_segments`; `INSERT` it;
commit. The `PRIMARY KEY(seg_type, seg_id)` turns any race into a constraint error → retry.

## 6. Provisioner (`internal/service/tenantnet_service.go` + `internal/netdrv`)

Pure reconcile from desired row → host state, idempotent, lockout-guarded. Steps per `ext_mode`:

- **isolated:** `netdrv.EnsureBridge(vdxt<id>)` (no uplink). If `seg_type=vxlan`, also create the
  VNI dev enslaved to the bridge (reuse `EnsureVNINetwork`) for future cluster peering. Gateway IP
  (optional) on the bridge; dnsmasq for DHCP. Done — no external path.
- **routed:** ensure/attach a hidden per-org vRouter (netns runtime) and add an internal leg bound
  to this network's bridge + a transit leg (SNAT) on `ext_ref` NIC. Reuses `vrouter_service`
  wholesale. This is the "L3 to external, NAT" path.
- **l2bridge:** attach the network's bridge to the vSwitch named by `ext_ref`; `AddTrunkVlan(uplink,
  seg_id)` and make taps access ports on `seg_id` (reuse `SetupTapAccess`). Direct L2.
- **vrouter:** delegate to the full existing vRouter flow (advanced users).

**Apply discipline:** the editor only writes desired rows (`state=pending`). A single
`ApplyTenantNetwork(p, id)` (and `ApplyAll` at boot) reconciles pending→host, writes
`running_json` on success, and on any error restores the previous `running_json` and sets
`state=error` with the message — never leaving a half-built segment (same rollback shape as
`realizeVXLANNetwork`). Every device op goes through mgmt/default-route guards.

**Teardown** (`DeleteTenantNetwork`): tear down only this id's devices (vRouter leg or vSwitch
trunk entry or bridge/VNI), free the segment row, delete the DB row. Order: detach VMs' note →
remove leg/trunk → `TeardownVNINetwork(id)` / `ip link del vdxt<id>` → free segment. netns teardown
is atomic.

## 7. Default-isolate on org creation

`CreateOrg` provisions one `isolated` tenant network ("default") for the new org, and the VM
start-path default (currently shared `vdxbr0` untagged) changes to **prefer the org's default
tenant-network bridge**. This reverses the co-location default so tenants are isolated *by
default*; an admin must deliberately choose `l2bridge`/shared to co-locate. Lockout-safe: the
default network is `isolated` (no external, no mgmt touch).

## 8. Guardrails (enforced in code, not docs)

- `guardMgmt(iface)` on every external attachment (already exists).
- Refuse any op whose target device == mgmt NIC/bridge, or that would write `main`/table 254 or a
  default route in `main`. (vRouter already forbids host routing writes; add the same assertion to
  the l2bridge path, which only ever calls `AddTrunkVlan` on a non-mgmt uplink.)
- Allocator unique constraint = no cross-tenant seg collision.
- Device-name allowlist on teardown (`vdxt<id>`, `vr<id>-*`, `vdxu*<id>`), never `nomaster` a phys NIC.
- Each routed/vrouter tenant gets its **own netns** → own nft/conntrack (no cross-tenant rule match).

## 9. UI (`/networks` gets a "Tenant Networks" section, or new `/tenant-networks`)

Card list of the org's tenant networks (name, mode badge, seg id, CIDR, state pill). `+ Add`
modal: name, CIDR/gateway, DHCP toggle, **External mode** dropdown (Isolated / Routed-NAT /
L2-bridged / vRouter) with mode-specific fields (transit NIC for routed; vSwitch for l2bridge).
Create → row `pending`; **Apply** button (per-network and "Apply all pending") reconciles and
shows result; status pill reflects `applied|pending|error` with the error text on hover. Admin/
owner gated, CSRF, audited. VM NIC attach dropdown gains the org's tenant-network bridges.

## 10. Phasing (what v1 ships vs later)

**v1 (this pass):** migration 44; transactional allocator; `tenant_networks` CRUD + service;
provisioner for **isolated** and **routed (NAT via netns vRouter)** modes; collision guardrail;
auto-isolated default network on org create; `/tenant-networks` UI + routes + REST; audit; boot
`ApplyAll`. Build/vet/template-check; deploy; Preview release.

**v2 (later, documented):** `l2bridge` mode polish + VLAN pool UI; floating-IP (1:1 DNAT) on
routed mode; per-tenant network ACLs surfaced in `/vfirewall`; IPAM leases view.

**v3 (growth path):** multi-host — host-FRR **VRF + BGP-EVPN Type-5** underlay so a tenant network
spans nodes (anycast gateway, exit nodes, SNAT on a primary exit), reusing the VNI already
allocated per tenant network. This is where VRFs finally earn their place.

## 12. Revision after adversarial Review 1 (SUPERSEDES conflicting text above)

Review 1 found blockers that reshape v1. Resolutions:

- **No segment allocator / no `net_segments` table in v1 (B2/M1/M6 dissolved).** isolated and
  routed modes need no numeric VNI/VLAN pool — isolation is *separate bridges* (isolated) and
  *separate netns legs* (routed). The transactional allocator moves to **v2**, where l2bridge
  (VLAN) and cluster-VXLAN actually need a pool. This removes the tx-across-device-ops hazard
  (M1), the orphaned-segment leak (B2), and the VNI-reuse L2-merge (M6) from v1 entirely.
- **A tenant network OWNS a backing `networks` row (M4).** `tenant_networks.network_id` →
  `networks.id` (mode=`bridge`, `bridge=vdxt<tnet_id>`). VM taps use the existing
  `resolveTapTarget` path **unchanged** — no new tap plumbing, one bridge per segment.
- **Device namespace is tenant-scoped and distinct (M3):** bridge `vdxt<tnet_id>` (NOT
  `VNINetworkNames`, which belongs to the `networks` VXLAN id-space); hidden router keeps its
  `vr<id>-*` devices. No cross-id-space collision.
- **netns `ApplyLegs` idempotency bug is FIXED first (B1):** `backend_netns.go` will skip legs
  whose in-ns iface already exists (mirroring `backend_lxc.go`'s `ifacePresent`) and special-case
  the transit leg. This is a genuine latent bug; fixing it unblocks multi-leg routed on netns.
- **routed integration (M4/M5):** factor a `attachInternalLegToBridge(vrID, bridge, networkID,
  gatewayCIDR, dhcp…)` out of `AttachInternalNetwork` that binds a leg to an EXISTING bridge/row
  (no second bridge). routed Apply ensures the hidden per-org vRouter is `status!='creating'`
  before attaching (no async race); boot `ReensureTenantNetworks()` runs strictly AFTER
  `ReensureVRouters()`.
- **No VM-start default change (M2).** The existing default-org fallback (`manager.go:1660`,
  shared `vdxbr0`) is LEFT ALONE. Default-isolate applies ONLY to **newly created orgs** (a
  "default" isolated tenant network), so no existing VM loses connectivity.
- **Explicit Go teardown, never CASCADE for host effects (B2/M6):** `DeleteTenantNetwork` removes
  the vRouter leg (routed), deletes the backing `networks` row, deletes bridge `vdxt<id>` and
  **verifies it is gone** before success, then deletes the row. (No `DeleteOrg` exists today; when
  added it must iterate this path — noted as a precondition for org deletion.)
- **isolated auto-applies; routed uses explicit Apply (M-e).** isolated touches no external NIC so
  it is safe to realize on create. routed (transit NIC) gets the staged Apply.
- **l2bridge guardrail (deferred to v2, M-b/M-c):** when added, the allocator excludes
  `networks.vlan_id` already in use, and `ext_ref` is refused if its vSwitch bridge == mgmt iface
  (check like `DeleteVSwitch` at vswitch_service.go:313, not just `guardMgmt` name-match).
- **Independent safety fix shipped in v1:** `CreateNetwork` refuses a `bridge`+`vlan_id` already
  used by a *different* org — closes the current cross-tenant L2 co-location gap for
  manually-created port groups, regardless of tenant networks.

### Re-scoped v1 (final)
Migration 44 = `tenant_networks` only (no `net_segments`). netns `ApplyLegs` idempotency fix.
`tenantnet_service.go`: CRUD + provisioner for **isolated** (auto-apply) and **routed** (staged
Apply via refactored leg-attach on the hidden per-org netns vRouter). Explicit teardown.
Default-isolated network for NEW orgs only. `CreateNetwork` cross-org collision guard.
`/tenant-networks` UI + routes + REST + audit. `ReensureTenantNetworks()` after vRouters at boot.
If routed integration proves deeper than estimated during implementation, ship isolated-only and
land routed as a tested follow-up (Review 1's recommended fallback).

## 13. Revision after adversarial Review 2 — FINAL v1 = isolated-only

Review 2 confirmed §12 but found routed is not a cheap reuse and default-isolate was cosmetic
as scoped. Final decisions:

- **v1 is ISOLATED-ONLY.** Routed is deferred to a tested follow-up because the vRouter emits
  **no SNAT** by design (`vrouter.go:155` forces `Uplink=""`/`InternalCIDRs=nil`; `RenderNAT` only
  masquerades when those are set) and there is **no per-leg detach** primitive
  (`ApplyLegs` only adds). Routed therefore needs: (a) netns SNAT (push an nft masquerade in the
  namespace on the transit iface for the internal CIDR), (b) a real leg-detach, (c) a `hidden`
  vRouter flag so the auto-created router is filtered from `/vrouters` and refuses manual delete,
  (d) async wait that treats `status=='error'` + a re-provision repair path. The B1 netns
  idempotency fix (done) is the groundwork. l2bridge + VXLAN + allocator remain v2.
- **Migration 44 DDL (final):** `tenant_networks(id, org_id FK orgs ON DELETE CASCADE, name,
  network_id INTEGER NOT NULL REFERENCES networks(id) /* NO ACTION = RESTRICT */, ext_mode TEXT
  DEFAULT 'isolated', ext_ref TEXT DEFAULT '', vrouter_id INTEGER DEFAULT 0, state TEXT DEFAULT
  'applied', error TEXT DEFAULT '', created_at)`, `UNIQUE(org_id,name)`, indexes on `org_id` and
  `network_id`. No `seg_type`/`seg_id` (no allocator in v1). The RESTRICT FK makes the raw
  `/networks` delete error on a tenant-owned backing row (M-2).
- **Default-isolate is made REAL (M-1):** in `manager.Create`, when `NetworkID==0`, resolve the
  org's default tenant network's backing `networks.id` and use it **iff the org has one**. Existing
  orgs (none) keep `0→vdxbr0` unchanged; new orgs land on their isolated bridge. No global
  start-path change.
- **Teardown guard (M-2):** `DeleteTenantNetwork` refuses while VMs are attached
  (`sessions.network_id`), deletes the `tenant_networks` row first (releases the RESTRICT FK), then
  the backing `networks` row, then `ip link del vdxt<netid>` verified gone, then stops dnsmasq.
- **netns fix (M-3):** uniform `ifacePresent` skip for ALL legs incl idx0 (NO transit special-case),
  with LXC-style stale host-veth + stale in-ns-peer cleanup before rebuild. (Implemented.)
- **Collision guard (M-6):** `CreateNetwork` refuses `bridge`+`vlan_id` where **`vlan_id>0`** is
  already used by a different org (untagged `vlan_id=0` left alone so M2 co-location still works).
  Advisory (internal inserts bypass the service method), documented as such.
- **Boot order (M-7):** `ReensureTenantNetworks()` runs between `ReensureVRouters()` and
  `bootAutostart()` in `worker.go` so isolated bridges exist before autostart VMs attach.
- **Device naming:** bridge `vdxt<networks.id>` (distinct prefix from `VNINetworkNames`).

### Final v1 file plan
`db.go` migration 44; `service/tenantnet_service.go` (model + Create/List/Delete + provisioner +
`ReensureTenantNetworks` + `defaultTenantNetworkFor` + `provisionDefaultForOrg`); `service.go`
CreateOrg hook; `net_service.go` collision guard; `session/manager.go` new-org default bind;
`web/tenantnet_handlers.go` + routes + `templates/tenantnetworks.html` + nav; `worker.go` boot
reensure; optional host dnsmasq helper for isolated DHCP (bound strictly to the tenant bridge).

## 11. Verification

`go build ./...` + `go vet ./internal/...` + template parse-check. Manual: create isolated net →
apply → two VMs on it reach each other, nothing else; create routed net → VM gets DHCP + NATed
egress, cannot see another org's isolated net; delete → devices gone, segment freed; confirm
mgmt/SSH never drops across any apply; confirm org A apply/delete leaves org B devices untouched.
