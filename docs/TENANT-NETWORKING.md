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

---

# v2 — Per-tenant network domain (the user's full vision)

Status: **IMPLEMENTED (v2, vdxd 1.100.0-20261025; migration 45)**. Supersedes the isolated-only
scope where they conflict. v1 (isolated single network per org) shipped in vdxd 1.99.0. v2 makes a
tenant's **whole logical** Networks experience self-service and isolated; the physical layer stays
instance-admin. Built per §24 (final, post-two-reviews): plain-bridge segments + VNI **identity**
allocator (no vxlan device — that + cluster span are v3), per-org-admin `/vrouters`+`/vfirewall`,
netns-only tenant routers with no transit, attach-by-owned-gatewayless-segment, `vrouters.name`
per-org-unique, check-before-apply EW firewall.

## 14. v2 goal and locked decisions

**Goal (user, 2026-10-25):** "If I create a new tenant and go to the network page, I should be
able to use every function under the network page and have it isolated from everyone else."

Reframed: each org is a **virtual network domain** (a VPC). A per-org admin, in their org
context, can create **many** isolated segments, give each a subnet + DHCP, route L3 **between
their own segments** with an internal router, and apply a per-tenant firewall — none of which
can see, collide with, or perturb any other tenant. The **physical layer stays instance-admin**.

**Decisions locked with the user (answered questions, 2026-10-25):**
- **Isolation model = overlay segments.** Each tenant segment = a VXLAN segment with a
  **transactionally-allocated, globally-unique VNI**; a per-tenant netns router is the L3 edge
  *between the tenant's own segments*. (Chosen over "hard namespace per tenant" — no qemu-in-netns
  rework — and it reuses the VXLAN engine + vRouter already built.)
- **Tenant self-serves:** (a) internal segments + subnets + DHCP, (b) internal routers (L3 between
  their own segments), (c) firewall. **NOT external egress** (NAT / floating IPs) — deliberately
  out of v2, which removes the SNAT-edge work entirely. No tenant transit link.
- **Physical layer admin-only (unchanged):** physical NICs, bonds, vSwitch uplinks, mgmt bridge,
  host L3 routing (`/routing`), and **vRouter transit links** (a transit leg attaches a physical
  NIC → stays instance-admin). This is what guarantees "can never get locked out" and
  "can't affect other tenants".

## 15. The authz pivot (the key enabling change)

Today `/vrouters` and `/vfirewall` gate on **instance** `IsAdmin` (`vroutersPage`/`fwPage`
403 on `!p.IsAdmin`); all their reads/writes are *already* org-scoped by `p.OrgID`. v2 changes
those gates to **per-org admin** (`p.atLeast("admin")`), with two carve-outs that remain
instance-only:
- `AddTransitLink` / `UpdateTransitLink` (physical NIC attach) — refuse unless `p.IsAdmin`.
- The physical cards on `/networks` (Bonds, vSwitches, Host interfaces, Topology) — already
  `{{if .P.IsAdmin}}` in the template and `!p.IsAdmin` in `vswitch_service.go`; unchanged.

Result: a per-org admin, switched into their org, sees **only their** segments, routers, and
firewall (org-scoped queries already enforce this), and cannot touch anything physical. An
instance admin still sees everything per currently-selected org, plus the physical plane.

`/routing` (host FRR, `inet vdxclone`) stays instance-admin — it is the host control plane, not
a tenant object.

## 16. Transactional segment allocator (migration 45) — the isolation substrate

```
CREATE TABLE net_segments (
  seg_type   TEXT    NOT NULL,            -- 'vxlan' (v2); 'vlan' reserved for a later L2-bridge mode
  seg_id     INTEGER NOT NULL,            -- the allocated VNI
  org_id     INTEGER NOT NULL,
  net_id     INTEGER NOT NULL,            -- backing networks.id this VNI realizes
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (seg_type, seg_id)
);
CREATE INDEX idx_net_segments_net ON net_segments(net_id);
```

`AllocVNI(orgID, netID) (int, error)`:
1. **Short DB-only critical section** (NO device ops inside — avoids the single-conn-pool
   tx-across-device deadlock, Review-1 M1): pick the lowest free id in `[VNIBase, VNIMax]`
   (default **200000–1048575**, above hand-entered VNIs and the cluster overlay's range) that is
   present in neither `net_segments` nor `networks.vni`; `INSERT` it. The composite PRIMARY KEY
   turns any race into a constraint error → retry the next free id (bounded retries).
2. Return the VNI. **Device realize happens AFTER this returns**, outside any tx.
3. On a later realize failure, the caller **frees** the row (`DELETE FROM net_segments WHERE
   seg_type='vxlan' AND seg_id=?`) as a compensating action — same rollback discipline as
   `realizeVXLANNetwork`.

`FreeVNI(netID)` on segment delete. Allocation is correct under the single-connection pool
(the existing concurrency guard) and additionally race-safe via the unique PK.

## 17. Tenant segment = VXLAN-backed network (evolves tenant_networks, keeps backing-row model)

A tenant **segment** keeps v1's "owns a backing `networks` row" shape (so VM taps use
`resolveTapTarget` unchanged — one bridge per segment), but the backing row is now **mode=vxlan**:

- backing `networks`: `mode='vxlan'`, `org_id`, `cidr`, `gateway`, `vni=AllocVNI(...)`,
  `underlay=<resolved>`, `vxlan_peers=MergePeerCSV("", ClusterPeerUnderlayIPs)` (auto cluster peers),
  `dstport/mtu` defaults.
- bridge = `VNINetworkNames(netid)` = `vdxubr<netid>`; realized by `EnsureVNINetwork(...)` +
  persisted via the `vdx-net-<id>.service` systemd unit (reuse `realizeVXLANNetwork` verbatim).
- `tenant_networks.ext_mode='segment'`, `seg_id` recorded (via `net_segments`, joined for display).
- **Underlay resolver** (`segmentUnderlay()`): cluster underlay NIC if clustered, else the NIC
  carrying the host default route, else the mgmt NIC. The VXLAN device sits *on top of* the NIC
  (transport only) — it never reassigns the NIC's IP or brings it down, so it is lockout-safe even
  when it resolves to the mgmt NIC. On a single host there are **no peers**, so BUM frames have
  nowhere to go and all traffic stays local on the bridge — identical isolation to a plain bridge,
  but with an allocator-owned unique VNI and instant cluster-readiness (the user's explicit choice).

**Isolation between tenants is structural**: distinct VNIs + distinct bridges. It does not depend
on any firewall rule. (The host-global EW `bridge vdxdfw` table only ever emits a rule when *both*
endpoints have a MAC on the *same* org-scoped network, so it cannot create cross-tenant reachability
either — confirmed by the firewall map.)

v1's `ext_mode='isolated'` (plain `vdxt<id>` bridge, no VNI) remains valid for already-created
rows and as an automatic fallback is **not** used — new tenant segments are always `'segment'`
(VXLAN). The default-on-org-create network becomes a `'segment'` too.

## 18. Internal router (L3 between a tenant's own segments) — reuse vRouter, no transit

The vRouter already routes between internal legs with **no SNAT** when it has no transit leg
(`RenderForVRouter` forces `Uplink=""`/`InternalCIDRs=nil`). v2 exposes this to per-org admins:

- A per-org admin creates an **internal-only router** (runtime `netns`) on `/vrouters` (now
  per-org-admin gated). The transit-link action stays instance-admin, so a tenant router is
  internal-only by construction.
- **Attaching an existing segment as a leg** must NOT create a second bridge/row. Factor
  `attachInternalLegToBridge(vrID, bridge, networkID, gatewayCIDR, dhcp, range, dns)` out of
  `AttachInternalNetwork` (the Review-1 M4/M5 refactor, now actually built): it inserts a
  `vrouter_legs` row bound to the segment's existing `bridge`/`network_id`, then `applyAndPush`.
- **Gateway ownership handoff:** a *standalone* segment may carry a host gateway IP on its bridge +
  host dnsmasq. When that segment is attached to a router, the **router leg becomes the gateway**:
  remove the host gateway IP from the bridge and stop host dnsmasq for it; the router leg holds the
  gateway IP (zebra assigns it) and the router's per-leg dnsmasq (`SetDHCP`) serves DHCP with the
  leg IP as gateway. On detach, reverse it. This transition is the main new state-machine in v2 and
  must be idempotent and lockout-neutral (segment bridge, never mgmt).
- Routing *between* the attached segments is then automatic (zebra connected routes); the tenant
  can additionally add static/OSPF/BGP between their own segments via the existing dynamic-routing
  CRUD (all org-scoped, no host effect).

## 19. Per-tenant firewall — reuse `/vfirewall` as-is, just re-gate

`org_firewall` is already one doc per org, compiled to a per-vRouter `inet vdxfw` (default-drop,
isolated netfilter per netns) for N-S and the host `bridge vdxdfw` (default-accept, MAC-matched)
for E-W. v2 only **re-gates `/vfirewall` to per-org admin**; the compiler and enforcement are
unchanged. Cross-tenant isolation is structural (segments), so default-accept EW is safe; a tenant's
rules only ever match their own MACs/segments. No new firewall engine.

## 20. UI / scoping changes

- `/networks`: the **Tenant Networks** card becomes **"Segments"**, ungated from `IsAdmin` to
  per-org admin; "+ Add Segment" modal (name, CIDR, gateway, DHCP). Physical cards stay admin-only.
- `/vrouters`: per-org-admin; in non-instance-admin context the **transit-link UI is hidden** and
  the endpoint refuses. "Attach segment" picks from the org's segments (not a free-form new net).
- `/vfirewall`: per-org-admin (template + handler gate change only).
- Nav: the Network group's L3 Routing stays admin-only; vRouters + vFirewall lose the
  `{{if .P.IsAdmin}}` gate and instead render for `atLeast("admin")` (add a template helper
  `.P.OrgAdmin` since templates currently only have `.P.IsAdmin`).

## 21. Guardrails (v2 additions on top of v1)

- Allocator: `net_segments` PK + range exclusion of in-use `networks.vni` = no VNI collision ever.
- Underlay is transport-only; never reconfigured; mgmt-safe even if it is the mgmt NIC.
- Tenant routers cannot get a transit leg (instance-admin gate on `AddTransitLink`) → no tenant can
  reach a physical NIC or the outside; the host-safety invariant in `internal/vrouter` already
  forbids host-routing writes.
- Gateway handoff only ever touches the segment's own `vdxubr<id>` bridge, never mgmt.
- Every tenant op is `p.OrgID`-scoped and `atLeast("admin")`-gated and audited.

## 22. v2 file plan (to be finalized after the two reviews)

- `db.go`: migration 45 `net_segments`; add `seg_type`/`seg_id` display join (no destructive change
  to `tenant_networks`; `ext_mode='segment'` is a new value, columns already exist).
- `service/segment_alloc.go` (new): `AllocVNI`/`FreeVNI`, range consts, `segmentUnderlay()`.
- `service/tenantnet_service.go`: segment create path (VXLAN-backed) + reensure for `'segment'`.
- `service/vrouter_service.go`: `attachInternalLegToBridge`; per-org-admin gating; transit stays
  `IsAdmin`; gateway-handoff on attach/detach.
- `service/service.go`: default-on-org-create becomes a `'segment'`.
- `web/vrouter_handlers.go` + `fw_handlers.go` + `net_handlers.go` + `server.go`: gate changes.
- `web/templates/{networks,vrouters,vfirewall,head}.html`: Segments card, transit-hide, nav gating,
  `.P.OrgAdmin` helper.
- `worker.go`: reensure order already correct (vRouters → tenant nets → autostart).

## 23. Open risks to stress in the two adversarial reviews

1. **Gateway-ownership handoff** (standalone→routed→standalone): the trickiest new state machine —
   races, idempotency, DHCP continuity, and never touching mgmt.
2. **VXLAN-on-mgmt-NIC underlay on a single host**: correctness/isolation of a peerless VNI; any
   path by which BUM/flood could leak onto the underlay or the mgmt segment.
3. **Per-org-admin exposure of `/vrouters`**: does any existing vRouter endpoint assume instance
   admin for a host-affecting side effect (beyond transit), e.g. a leg that could land on a shared
   bridge or a dynamic-routing knob with host reach? Audit every `vrDo` handler.
4. **Allocator vs single-conn pool**: confirm no device op occurs inside the alloc tx; confirm the
   compensating `FreeVNI` on every realize-failure branch.
5. **`vrouters.name` is globally UNIQUE, not per-org** — two orgs naming a router "core" collides.
   Needs per-org name handling or a scoped default name.
6. **Does making segments VXLAN break v1's shipped isolated nets / the default org?** Migration must
   be additive; existing `'isolated'` rows must keep working; the pre-existing default org must keep
   `0→vdxbr0`.

## 24. FINAL v2 (after two adversarial reviews) — SUPERSEDES §14–23 where they conflict

Both reviews converged. The design is re-scoped to **single-host, plain-bridge segments**; the
VXLAN *device* and cluster-spanning are deferred to v3. Resolutions:

**R1 — Substrate: NO vxlan device in v2. Plain uplink-less bridge (v1's proven `vdxt<id>`/`vdxubr`
path), full stop.** Both reviewers showed a peerless vxlan on a single host is a *regression*:
`EnsureVNINetwork` opens a host-wide **UDP:4789 listener demuxed purely by VNI** (R1-B1) with no
input filter anywhere in the tree; VNIs are sequential/guessable; the underlay resolves to the mgmt
NIC — an external/cross-tenant L2 **injection** surface a plain bridge does not have. And the
allocator is **node-local** while the design auto-peered VNIs cluster-wide (R1-B3) → node A's
tenant-X VNI 200000 would VXLAN-bridge to node B's tenant-Y VNI 200000: catastrophic cross-tenant
L2. **Decision:** segments realize as plain bridges (reuse v1 `provisionIsolated` verbatim). We
**still `AllocVNI` + record `net_segments`** purely as a reserved, globally-unique *identity* for
the future — **no device uses it in v2, no auto-peer.** Cluster-spanning (materialize vxlan +
cluster-wide allocator + segment-row replication + a UDP:4789 cluster-peer-allowlist input filter)
is **v3**, explicitly descoped.

**R2 — Router: NO live gateway handoff.** A segment is created **either** standalone (host gateway
IP on its bridge + host dnsmasq) **or** routed (gatewayless, pure L2). Only a **gatewayless**
segment may be attached to a tenant router (whose leg becomes the sole gateway + dnsmasq — exactly
today's `AttachInternalNetwork`, minus the fresh-bridge creation). Attaching a segment that still
holds a host gateway IP is **refused** ("create it gatewayless, or remove the gateway first"). This
deletes the IP-steal / DHCP-continuity / reensure-race state machine (R1-B5) entirely. Track attach
state in the existing `tenant_networks.vrouter_id` column; `ReensureTenantNetworks` **skips** host
gateway/DHCP for any segment with `vrouter_id!=0`.

**R3 — Authz pivot through ONE choke-point (R2-B4/R1-M5).** Add `requireVRouterAdmin(p)` and
`requireOrgFWAdmin(p)` = `atLeast("admin")` + org-scoped; flip ALL ~30 `!p.IsAdmin` sites in
`vrouter_service.go` + `fw_service.go` + the `vroutersPage`/`fwPage`/`fwDo` handlers to call them.
**Explicit instance-admin exceptions that STAY `IsAdmin`:** `AddTransitLink`, `UpdateTransitLink`
(physical NIC), and `DeleteVRouter` *when a transit leg exists*. Fix `VRouterAvailable` (today
returns false for non-instance-admins → feature looks unavailable). Add a `Principal.OrgAdmin()`
method (templates only have `.P.IsAdmin`).

**R4 — Tenant routers are `netns`-only (R1-M1/R2-B4).** `CreateVRouter` rejects `runtime` in
{`lxc`,`vm`} unless `p.IsAdmin` (lxc = privileged container on the host).

**R5 — Attach-by-owned-segment-only (R1-B7).** `attachInternalLegToBridge(p, vrID, tnetID)` resolves
the segment via `tenant_networks`+`networks` by `(id, org_id=p.OrgID)`; **derives the bridge from
that row**, never from client input; refuses anything not an owned tenant segment (never
`vdxbr0`/a foreign bridge). Otherwise a crafted POST could land a router leg on a shared/foreign L2.

**R6 — `DeleteVRouter` must not destroy attached segments (R1-B4).** For each internal leg, if its
`network_id` is referenced by a `tenant_networks` row → it is an *attached* segment: remove ONLY
the leg + clear `vrouter_id`, never `DeleteNetwork`/`DeleteLink` it (it has its own lifecycle and
may run VMs). Only *owned* internal nets (created by the legacy `AttachInternalNetwork`) get the old
teardown. Refuse the whole delete for a non-instance-admin if a transit leg exists.

**R7 — `vrouters.name` → `UNIQUE(org_id,name)` (R1-B6/R2-B3).** Migration 45 rebuilds `vrouters`
safely under FK-ON (copy legs to a tmp table, drop `vrouter_legs` then `vrouters`, recreate
`vrouters` with `UNIQUE(org_id,name)`, rename, recreate `vrouter_legs` with its FK, restore legs,
drop tmp — no cascade wipe because no child references `vrouters` at the moment it is dropped).
`CreateVRouter` also checks per-org name uniqueness with a friendly error.

**R8 — Raw network-create stays instance-admin (R2-B1).** The free-text-`underlay`/arbitrary-`vni`
VXLAN form and `mode in {vxlan,bridge,vlan}`/`bridge`/`vlan_id` fields of `CreateNetwork` require
`p.IsAdmin`. Per-org admins create networks **only** through the constrained segment path
(forced naming, no free-text underlay/VNI). Template exposes only "+ Add Segment" to `.P.OrgAdmin`;
Port Groups / raw VXLAN / Bonds / vSwitches / Topology stay under `.P.IsAdmin`.

**R9 — Allocator hardening (R1-M3/R2-MINOR-1).** `AllocVNI`: inclusive bounds `[200000,1048575]`;
exclude `networks.vni` **and** `storage_overlays.vni` **and** the cluster-config overlay VNI;
prefer `max+1` over lowest-free to avoid immediate reuse; **free the row only AFTER device teardown**
on delete; the whole alloc is a short DB-only critical section (no device op inside), composite PK
makes a race a constraint error → retry; realize happens after the alloc returns, with a
compensating `FreeVNI` on every realize-failure branch. (In v2 no device is realized from the VNI,
so this is mostly future-proofing, but the free-after-teardown ordering is wired now.)

**R10 — Firewall safety (R1-M2/R1-M4).** `ReplaceBridgeFW` validates/loads the new ruleset **before**
deleting the live table (don't leave every tenant's DFW empty on a transient parse failure).
Validate group MACs against the **org's own VMs** at write time and org-scope the `ip_leases` query
in `buildFWMaps`; add a regression test asserting a foreign MAC in a group yields no host rule (the
cross-tenant EW safety is currently implicit).

**R11 — Topology stays instance-only in v2 (R2-MINOR-3).** The `/networks` topology + host-interface
cards are host-wide and remain `.P.IsAdmin`. A per-org segment/router diagram is a later nicety; the
user's logical functions (segments, routing, firewall) are all delivered without it.

### Final v2 file plan
- `internal/db/db.go`: migration 45 — `net_segments` + safe `vrouters` rebuild to `UNIQUE(org_id,name)`.
- `internal/service/segment_alloc.go` (new): `AllocVNI`/`FreeVNI` + range consts (R9).
- `internal/service/tenantnet_service.go`: VNI alloc on create; gatewayless-segment option;
  `ReensureTenantNetworks` skips host gw/DHCP when `vrouter_id!=0`; `FreeVNI` on delete after teardown.
- `internal/service/vrouter_service.go`: `requireVRouterAdmin`; flip gates (transit + transit-delete
  stay `IsAdmin`); netns-only for tenants; per-org name check; `attachInternalLegToBridge` (owned-only);
  `detachInternalLeg`; `DeleteVRouter` segment-preservation; fix `VRouterAvailable`.
- `internal/service/fw_service.go` + `fw_compile.go` + `net_firewall_service.go`: `requireOrgFWAdmin`;
  MAC/org validation; org-scoped `ip_leases`; atomic `ReplaceBridgeFW`.
- `internal/service/net_service.go`: `CreateNetwork` raw-mode/underlay/vni/vlan fields require `IsAdmin`.
- `internal/service/service.go`: `Principal.OrgAdmin()`; default-on-org-create stays a standalone segment.
- `internal/web/{vrouter_handlers,fw_handlers,net_handlers}.go` + `server.go`: page gates → OrgAdmin;
  routes for attach/detach segment + constrained segment create.
- `internal/web/templates/{networks,vrouters,vfirewall,head}.html`: Segments card + "+ Add Segment"
  (OrgAdmin); hide transit UI for non-IsAdmin; attach-segment picker; nav gates → OrgAdmin.
- `internal/worker/worker.go`: reensure order already correct.

### v2 verification
build + vet + template-check; migration 45 applies (incl. vrouters rebuild preserves legs);
as a per-org **admin** (non-instance-admin), in a tenant org: create two standalone segments → VMs
on each reach peers only within the segment; create a `netns` router → cannot see a transit option;
create two gatewayless segments + attach both → VMs route between them, not to other orgs; firewall
page usable and rules scoped to the org; confirm a per-org admin can NOT reach bonds/vSwitches/raw
VXLAN/host routing/transit, cannot delete a transit-bearing router, and cannot attach a foreign/shared
bridge; confirm mgmt/SSH never drops; confirm org A ops leave org B untouched.

---

# v4 — Tenant vSwitches, VLAN port groups, L2 + L3 out (migration 48, v1.106)

## 25. Model
- **Tenant view.** An instance admin switched into a tenant org is that org's owner (`TenantView`):
  host/physical surfaces hidden and refused; only the org quota and member-password reset stay gated
  on `ProviderAdmin`. Host administration happens from the Default (provider) org.
- **vSwitch = tenant network.** Its bridge `vdxt<network_id>` and backing `networks` row (the
  **untagged** default port group). New VMs land there; `CreateUplink` auto-connects a new uplink to
  the org's default vSwitch if it has none.
- **VLAN port groups** (`tenant_portgroups`): VLAN 2–4094, unique per vSwitch (standalone unique
  indexes), each with its own backing `networks` row (bridge = the vSwitch, `vlan_id` = the PG), so VM
  attach is the normal port-group path (`SetupTapAccess` → access port). The tenant's VLAN numbering is
  private — it never touches another tenant's. `vlan_filtering` is on only while a PG exists.
- **PG kinds:** *standalone* (host gateway on `<bridge>.<vid>` + optional DHCP, local only — never
  routed by the host), *routed* (gatewayless, a netns router leg is its gateway), *L2-out*
  (gatewayless, carried out the uplink; the upstream routes it).

## 26. The uplink port
`uplinkPortVlans(mode, native, pgs)`: PVID = native PG (`native_vlan`, 0 → bridge VLAN 1 = the untagged
PG). **access** uplink = one 802.1q tag on the wire → carries only the native PG. **QinQ / dedicated**
→ also every other PG tagged with its own VID (inner tags survive the S-tag / the dedicated NIC).
`carriedOut()` mirrors this and drives two invariants:
1. A carried PG's host gateway + DHCP are **suspended** (`syncVSwitch` removes the address / stops
   dnsmasq; restored when no longer carried) — the host never answers DHCP on the provider's wire.
2. A carried PG can't be router-gatewayed, and an uplink/native change that would carry a routed PG
   is refused (`checkCarry`) — no second gateway on the upstream L2.
Uplink **disconnect keeps the outer VID** (`unrealizeUplink(..., free=false)`); only `DeleteUplink` /
`DisableTenantEgress` free it (was a bug: reconnect then built `<trunk>.0`).

## 27. Host isolation (closes the standalone-segment gap)
A standalone tenant gateway lives on the host. Before v4 the host (ip_forward=1, forward accept)
would route a tenant VM to the management LAN and expose sshd/the admin UI. Now, for every tenant
bridge and PG interface: `net.ipv4.conf.<dev>.forwarding=0`, `ipv6 disable_ipv6=1`, and the host nft
`table inet vdxtenant` — input: established/related, DHCP (udp 67), ICMP echo to the ingress
interface's own address (`fib daddr . iif type local`), else drop; forward: drop routed traffic in or
out of a tenant interface (br_netfilter-aware: with bridge-nf on, only tenant↔non-tenant crossings).
Tenant dnsmasq runs `port=0` (no host resolver). `applyTenantIsolation()` is the single rebuild point;
it runs after every vSwitch change, at boot, and after host `routing.Apply` (rewriting ip_forward resets
per-iface flags). The guard set lists exact names only — VM taps (also `vdxt…`) are never in it.

## 28. L3 out (netns router)
- `AttachPortGroup`: router leg on a gatewayless, non-carried PG; the leg's host veth end becomes an
  access port of that VLAN (`Leg.VLAN` → `netdrv.SetAccessVlan` in `netnsBackend.ApplyLegs`).
- `AttachUplinkLeg` (one per router): `LegUplink` on a **carried** PG; `cidr` = router's upstream
  address, `upstream_gw` → default static route rendered by `RenderForVRouter` (unless the operator set
  their own default), `snat` → `table ip vdxnat` masquerade. Applied by `vrouter.EdgeApplier`
  (`netnsBackend.ApplyEdge`, which also sets the netns `ip_forward=1` explicitly). `LegUplink` is in the
  firewall External zone. netns-only.
- `DeleteVRouter` releases PG/uplink legs without touching the tenant vSwitch bridge.

## 29. Verification (v1.106.2 on the test host, org "test")
Unit: carry/port-VLAN matrix, leg addressing, SNAT + default-route render, guard render (`nft -c`),
migration 48 on the real driver and on a copy of the live DB, page render (networks/vRouters as
tenant + admin). Live E2E (service layer as the tenant admin, real DB + kernel, full teardown):
vSwitch + standalone PG (vlan_filtering, `<br>.<vid>` gateway + DHCP, per-iface isolation, guard set),
routed PG (no host iface; router leg = VLAN access port), access-uplink VID retention across
disconnect/reconnect, native VLAN → uplink port PVID, gateway suspend/restore, carried-PG refusals,
WAN leg VLAN + SNAT table + netns forwarding, zebra/mgmtd/staticd up in the router's pathspace, leg
address + default route via the upstream inside the netns, no AppArmor FRR denials, guard restored to
its initial set. The netns FRR daemons need `deploy/apparmor/frr.d-vxvisor` on Ubuntu 26.04 (stock
AppArmor only allows the flat `/run/frr/` paths; installed by `install.sh` — see CLAUDE.md).


## 30. UI (v1.107)
A tenant's `/networks` is the admin page's layout, scoped to the org: a **vSwitches** table (bridge,
uplink, VLANs; connect/disconnect, delete), a **Port Groups** table (every port group of every
vSwitch, its role, "Make native", delete; "+ Add port group" picks the vSwitch) and the same
**Topology** map. `/api/topology` returns `tenantTopology` for anyone but an instance admin (an admin
in tenant view included): only the org's vSwitches (by name), port groups, VMs, containers, routers
and uplinks (by the tenant-facing uplink name; link up only when the provider port is) — no host
NICs, bridges, taps, management IPs or LLDP. vRouter legs are merged **per port group**
(`mergeVRouters`, by the leg's `network_id`): a routed port group moves onto its router, the
vSwitch and its other port groups stay; an uplink leg's way out is the vSwitch uplink. The host
map uses the same merge, so a router leg on a tenant port group no longer swallows the whole
vSwitch; legacy dedicated segment / transit bridges still collapse into the router.

## 31. Tenant Egress console: edit in place + the "Add tenant egress" wizard (v1.107)
Everything on `/trunks` is editable (instance admin; `service/trunk_edit.go`):
- **Trunk** (`UpdateTrunk`, `POST /trunks/{id}/edit`): MTU and QinQ capability of a *dedicated* trunk,
  applied live via `EnsureTrunk`. Turning QinQ off first puts the NIC's VLAN offload back to its
  pre-designation state (`RestoreTrunk` with MTU 0) and is refused while a QinQ uplink uses the trunk.
  A shared (management) trunk is never modified — no Edit button.
- **VLAN pool** (`SetVlanPool` upsert, now guarded by `checkPoolRange`): refuses overlap with another
  tenant's pool or in-use tag on the same trunk, and a shrink that leaves out a tag one of the
  tenant's uplinks holds from its current pool.
- **Uplink** (`UpdateUplink` + `SetUplinkConnection`, `POST /trunks/uplink/{id}/edit`): rename, mode,
  trunk, tag (0 = next free from the pool) or dedicated NIC, and which of its tenant's vSwitches it
  connects to (or none). A connected uplink is re-wired live: unrealize → `wireUplink` (tag released
  and re-assigned, realize, `resyncVSwitch`); if the new wiring fails the old one is put back. The
  carry rules (`checkCarry`) are re-checked for the new mode. The page asks before re-wiring a
  connected uplink; a rename alone is instant.

`+ Add tenant egress` (`service/egress_wizard.go` `ProvisionTenantEgress`, `POST /trunks/wizard`) runs
**Tenant → Trunk → VLAN pool → Uplink → vSwitch → Review**. Pools and uplinks belong to a tenant *on a
trunk*, so those come first; the vSwitch is last because it connects to the uplink. Each step reuses
the single-item path (`DesignateTrunk`, `SetVlanPool`, `createUplink` without auto-connect,
`createTenantNetwork` + `connectUplink`), and each completed step pushes an undo (undesignate / old
pool range or delete / delete uplink / delete vSwitch), so a failure at any step leaves the tenant as
it was ("… (the earlier steps were undone)"). Choices: existing trunk or designate one (dedicated or
the shared mgmt uplink); the pool is prefilled from the tenant's existing pool or the first free block
of ten from VLAN 100; a new uplink (auto or explicit tag; QinQ only on a QinQ-capable trunk) or one of
the tenant's unconnected uplinks on that trunk; connect an existing unconnected vSwitch (its default
is preselected), create one (named `default` and made the default when the tenant has none), or
none. A wizard-created vSwitch has no host gateway/DHCP — its untagged port group is carried, so the
provider network serves the subnet (the optional CIDR is shown on the tenant's map). The page checks
each step client-side; the service re-checks everything.

Verified: unit (`egress_edit_test.go`: pool guards, unbound rename/retag + restore on clash, org guard
on connect, wizard success + rollback of pool and uplink), page render (`trunks_render_test.go`), the
wizard and edit modals driven in headless Chromium, and a live E2E on the test host (org "test",
trunk `enp4s0f0`): wizard → bound subinterface in the new bridge, live retag 501→502, refused clash
keeps the live wiring, admin disconnect, trunk MTU edit, wizard rollback, and the DB/devices back
to their exact starting state. The trunk had no carrier, so wire behaviour is untested.

## 32. Networking audit hardening (v1.108, 2026-10-29)

A full audit of host switching, L3 and tenant networking (after the management bond was deleted by
accident from the Networks page) produced these fixes. They are listed by subsystem, with the
invariants later code must keep.

**Input reaches config files only after validation, twice.** The service layer gives a friendly
error. The sink, the function that writes the file or runs the command, refuses anything that
isn't one clean token. Sinks covered:
- the tenant dnsmasq conf (`netdrv.RenderTenantDHCPConf`) and the vRouter dnsmasq conf (`vrouter.DnsmasqConf`);
- FRR and NAT renderers (`internal/routing/validate.go`);
- the vRouter firewall renderer: it fails closed with `DenyAllFirewall`;
- LXC config values (`internal/lxc/validate.go`);
- VXLAN systemd units and `ip` commands.

**Management can't be cut from the UI.**
- `guardIfaceInUse` covers bond delete, team create/edit, vSwitch create and add teaming. It refuses
  management devices, vSwitch uplinks, trunks, dedicated uplinks, vRouter transits, the storage
  NIC, the routing uplink, interfaces with addresses, and stacked devices.
- vSwitch and port-group deletes refuse while anything is on them, including instances in Trash.
- Management detection (`service/mgmt.go`) falls back to the default-route interfaces when the
  listener binds a wildcard address. If still unknown it **fails closed**: set `[server] addr`.
- Host routing refuses a default route off the management NIC or one whose next hop isn't
  connected. It also refuses routes or OSPF networks that would take over the management subnet
  or the admin's own session.
- Routing and vRouter FRR changes are applied first and saved only if the apply succeeds. On
  failure the previous config is re-applied.
- The management netplan file is edited in place (yaml.v3). The admin IP and default route are
  verified before and after, with restore on failure.

**Every vSwitch runs `vlan_filtering=1`**, the netplan-owned management bridge included.
- Every port defaults to VID 1 PVID untagged, so untagged and management traffic is unchanged.
- Guest-tagged frames on a VLAN-0 port group are dropped, as in vSphere.
- The management uplink carries only the VIDs its port groups use.
- Netplan can't persist the setting, so `ReensureVSwitches` re-applies it at boot. It also
  re-creates the NIC teams and `vds*` vSwitches vdxd made, and re-applies a set MTU.
- Boot link-up still brings every non-netplan NIC up so the UI shows carrier. Ports vdxd doesn't
  manage get RA/SLAAC off first.

**Guests and containers.**
- A VM bound to a bridged port group always gets a tap, even when the global mode is `user`.
- A tenant-org VM (org slug ≠ `default`) can never run without a port group or fall back to the
  shared bridge or SLIRP. This is checked at create, rebind and start.
- Containers attach to a port group the org owns (`containers.network_id`, migration 52). They no
  longer take a raw bridge name.
- Static IPs come from the VM's own port group. Uniqueness is per bridge+VLAN.
- Taps follow the bridge MTU, and virtio `host_mtu` advertises it (1450 on VXLAN).
- nft table `inet vdxslirp` drops new QEMU connections to host loopback, except DNS, so a
  user-mode guest can't reach VNC, SPICE, guacd or rustguac via 10.0.2.2. QEMU is matched by its
  `run_as` uid, or by the `vdxqemu` group that vdxd creates when QEMU runs as root.
- VNC passwords are 8 characters from 62 symbols, and now survive live migration.

**Tenants.**
- Subnets are IPv4 only. They must not overlap any host interface subnet or route; tenant-vs-tenant
  overlap is still allowed.
- DHCP needs a gateway. The range must be inside the subnet and exclude the gateway; DNS takes up
  to 4 IPs.
- The default vSwitch can't be deleted, and there is a "Make default" action.
- vSwitches and port groups can be edited. Subnet and gateway are locked while something is attached.
- Migration 49 persists the untagged port group's DHCP settings. Migration 50 adds unique indexes
  for one uplink per vSwitch and one default per org.
- The trunk VLAN allocator skips VIDs the host uses: admin port groups on that uplink, and
  subinterfaces no tenant owns. Admin port groups refuse a VID a tenant holds.
- Trunk names are capped at 10 characters so `<trunk>.<vid>` fits IFNAMSIZ.
- Connect order is: suspend the host gateway, enslave the port down, set VLANs, bring it up.
  Router external interfaces pin what they ride on.
- "Disable tenant egress" is resumable (`teardown_pending`).
- nft bridge table `vdxtenantl2` drops DHCP server replies, IPv6 RAs and BPDUs from untrusted ports
  on tenant bridges. Uplink ports and router-leg veths are trusted.
- Tenant interfaces get `arp_ignore=1` and `arp_announce=2`. The host guard no longer depends on
  br_netfilter.

**Tenant gateways (vRouters outside the default org).**
- BGP neighbors must be on a connected network.
- Every neighbor gets `prefix-list VDX-TENANT-EXPORT out`, limited to the router's downlinks.
- BGP and OSPF networks are limited to the downlinks. EIGRP is off.
- The external interface IP must be inside the carried port group. It must not be the network or
  broadcast address, the upstream gateway, or another leg's address.
- netns FRR logs to syslog, so the AppArmor grant is unchanged.
- `AttachInternalNetwork` is instance-admin only. There is a `DeleteTransitLink` action.
- Removing a downlink the gateway created deletes its port group.
- `ApplyLegs` re-links legs to their bridge and VLAN on every apply.
- Firewall lease maps are scoped to the compiled org.

**VXLAN.**
- Inputs are validated: VNI, port, MTU, names, and peers in one IP family.
- VNIs must be unique host-wide. The local IP must be this host's.
- nft table `inet vdxvxlan` accepts each VNI only from its peers.
- VXLAN port groups get the tenant host isolation unless set to "Host access: routed".

**NIC teams.**
- `EditBond` changes members, mode and hash. Netplan-owned teams are refused, with a pointer to
  the netplan file.
- Mode labels give the vSphere equivalent and say whether the switch needs configuring.
- Per-vSwitch MTU is settable (migration 51).

**Naming (VMware/NSX).**
- Sidebar: Switching, Gateways (Tier-0/Tier-1), Firewall (gateway N-S / distributed E-W), External
  Connectivity (was Tenant Egress), Host Routing.
- Bonds are "NIC teams" and a vSwitch's NIC is its "physical adapter".
- A tenant uplink is an "external network", and a VLAN pool is a "VLAN range".
- A transit link is a "provider link (Tier-0 uplink)", an internal leg is a "downlink", and a
  router's uplink leg is its "external interface".
- DB, Go and kernel names are unchanged.

**vdxd-owned host state added:**
- nft tables `inet vdxslirp`, `inet vdxvxlan` and `bridge vdxtenantl2`;
- system group `vdxqemu`;
- `/etc/vdxclone/vxlan-guard.nft`.

A restart of `nftables.service` flushes these tables. `vdxslirp` self-heals within 30s; the
others come back on the next tenant or routing apply, or a vdxd restart.
