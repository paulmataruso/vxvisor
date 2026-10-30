# VXVisor Fabric — multi-host L2/L3 overlay (design)

Status: DRAFT for review. Nothing here is built.

## 1. What the user asked for

- A **"Deploy fabric" wizard**:
  - The admin picks the hosts, and per host an interface for host-to-host traffic: a dedicated NIC, or "ride over management".
  - Afterwards every host has a vSwitch whose uplink is shown as **"VXVisor Fabric"**, and everything behind it is automatic.
- **Port groups** attach to that vSwitch and get IPs (a gateway and addresses for VMs).
- **A page that says who can talk to whom.** It is a table with dropdowns, e.g. "Host 1 PG 1 can talk to Host 2 PG 2".
- **Both L2 and L3.**

## 2. The model (NSX names in brackets)

| VXVisor | NSX / vSphere | What it is |
|---|---|---|
| Fabric | Overlay transport zone | A set of hosts that share overlay networks |
| Fabric host | Transport node | A host in a fabric; owns one tunnel endpoint |
| TEP | TEP | The host's tunnel IP on the chosen interface |
| Fabric vSwitch | VDS / N-VDS | One logical switch, present on every fabric host, uplink "VXVisor Fabric" |
| Fabric port group | Segment | One network, **created once, present on every fabric host** |
| Distributed gateway | T1 distributed router | The PG's gateway IP, live on every host at once (anycast) |
| Connectivity rules | Gateway / distributed firewall | The "who can talk to whom" table |

### 2.1 Deviation from the request: port groups are fabric-wide, not per-host

The request has a PG on Host 1, a PG on Host 2, and a rule linking them. This design instead creates a PG **once**, and it exists on every fabric host. The reasons:

1. **VMs move.** Live migration and HA restart already exist. A host-scoped PG would be left behind, or would need re-mapping on every move.
2. **"H1 PG1 talks to H2 PG2 at L2" means they are one broadcast domain.** That is the same subnet and the same VNI: one network with two names. Two names invite IP conflicts and two DHCP servers answering.
3. **It is how vDS and NSX segments behave**, which is the target.

The table survives. Its rows are **PG ↔ PG** (fabric-wide PGs). Each row also shows, as information only, which hosts currently run VMs on each PG. A host-local network is still available: it is an ordinary standard vSwitch, outside the fabric.

### 2.2 L2 and L3 semantics

**L2:**
- The same PG on any host is one L2 domain (one VNI). VMs on that PG reach each other at L2 wherever they run. This is always allowed, like a switch.
- An **L2-only PG** (no gateway) is for workloads that bring their own router, DHCP or appliance. It has no L3 and takes no connectivity rules.

**L3:**
- A **routed PG** has a subnet, a gateway IP (default `.1`) and a DHCP range.
- The gateway is anycast: the same IP and MAC exist on every fabric host. A VM's first hop is always its own host.
- Routing happens on the source host (symmetric IRB), so traffic between PGs never hairpins through another host.

**Connectivity table:** traffic between two different PGs is **denied by default**. The table is an allow-list:

| From | To | Direction | Service | On |
|---|---|---|---|---|
| PG ▼ (or "any PG in org") | PG ▼ / "External" | ↔ both ways / → one way (stateful) | Any / ICMP / TCP ports / UDP ports | ✓ |

- A read-only **PG × PG matrix** (✓/✗) gives the at-a-glance view.
- A row's **"External"** target means egress (§5).

## 3. Control plane: BGP EVPN in FRR, with vdxd as the intent controller

**Recommended: BGP EVPN over VXLAN, using the FRR already on every host.**
- It is the standard design (Cumulus, SONiC, Proxmox SDN's EVPN zone).
- It provides:
  - per-VNI flood lists (type-3);
  - MAC and IP learning with ARP suppression (type-2);
  - **MAC mobility**, which handles live migration;
  - symmetric IRB with one L3VNI per VRF, plus subnet routes (type-5).

**Rejected alternative: vdxd programs a static FDB and neighbour table.** That reinvents EVPN inside the controller, depends on vdxd being up for every VM move, and has no standard to test against.

**vdxd's role:**
- The **leader** owns the fabric intent: fabrics, hosts, PGs, VNIs, VRFs, IPAM and rules.
- **Followers** pull a versioned snapshot, the same pattern as `accountsync.go`. Unlike accounts, the snapshot carries **tombstones**, so deletes propagate.
- Fabric writes on a follower are refused, as `guardClusterWrite` does for accounts.
- Each host realizes the intent locally: kernel devices, nft, dnsmasq, and its section of the host `frr.conf`.
- **VNI and L3VNI allocation happen only on the leader.** This is the cluster-safe allocator that TENANT-NETWORKING §24 R1 deferred.

**BGP layout:**
- iBGP full mesh between fabric TEPs, address family `l2vpn evpn`. Clusters are small; a route reflector on the leader is a later option.
- Private ASN, auto-picked and editable.
- TCP-MD5 on every session, keyed from a per-fabric secret derived from `cluster.key`.

**Per-host kernel layout (traditional multi-device, the most proven):**
- Per fabric PG: `vxv<vni>`, a VXLAN device with `nolearning`, `local <TEP>` and dstport 4789. It is enslaved to `vxf<vni>`, a bridge.
- The `networks` row has `mode=fabric` and `bridge=vxf<vni>`, so **the existing VM and container attach path is unchanged**.
- Per org: `vxvrf<org>`, a VRF with its L3VNI device.
- The PG bridge is the SVI. It holds the anycast gateway inside the org's VRF.
- **Lazy realization:** a PG's devices are created on a host only when something there attaches to it. EVPN type-3 routes then add that host to the flood list. This keeps BUM traffic off hosts that don't need it.

## 4. Underlay (the interface between hosts)

The wizard picks one of three options per host:

| Option | TEP IP | MTU | Notes |
|---|---|---|---|
| **Dedicated NIC / bond** (recommended) | Static, or auto from a TEP pool (e.g. `10.250.0.0/24`) | Wizard raises it to 1600 (or 9000) → guests keep 1500 | Must pass `guardIfaceInUse`; never the mgmt or storage NIC |
| **VLAN on an existing uplink** | Same | ≤ parent; parent untouched | Like the shared-trunk rule: never modifies the parent |
| **Ride over management** | The mgmt IP itself | Mgmt is **never** modified → guest MTU 1450 | Easiest; see the security notes |

**MTU handling:**
- The guest MTU is derived (underlay minus 50).
- It is pushed to VMs by DHCP option 26 and by cloud-init `network-config`.

**Preflight**, run before anything is changed:
- A DF ping between every pair of TEPs at the full overlay size.
- FRR version and EVPN support.
- The `vxlan` and `vrf` kernel modules.
- Checks for an existing host BGP instance: its ASN must be reused, otherwise the wizard refuses with a clear message.
- Collisions on UDP 4789 / VNI with legacy VXLAN networks and storage overlays. The allocator excludes their VNIs.

## 5. IPAM, DHCP, gateway, egress

**IPAM:**
- The leader is authoritative.
- VM addresses are **static leases**: MAC → IP, assigned by the leader. They are rendered on every host as `dhcp-host` lines, so whichever host answers gives the same answer.

**DHCP:**
- Each host's dnsmasq binds only to its local PG bridges.
- **DHCP and ARP to the anycast gateway must never cross the tunnel.** A bridge nft rule drops UDP 67/68 between a VXLAN port and the bridge. Otherwise a DISCOVER would flood and get one OFFER per host.
- The anycast gateway MAC is identical on every host and is not advertised.

**Egress ("External" in the table):**
- Distributed SNAT: each host masquerades its local VMs out of its own default route (or a chosen uplink). This is HA by construction, like OpenStack DVR.
- **Inbound** from the LAN to fabric PGs needs route advertisement: BGP to the physical router, ECMP across hosts. This is phase 3.

## 6. Tenancy and permissions

- **Instance admin:** creates fabrics. The fabric is the physical layer: hosts, interfaces, TEPs, ASN, encryption.
- **Org admin:** creates PGs and rules in their own org, on fabrics the provider has enabled for that org.
- **Isolation:**
  - One VRF per org, so orgs never route to each other.
  - Distinct VNIs, so they never share L2.
  - Every query is scoped by `org_id`.
- **Tenant pages** mirror the admin page, org-scoped, per the existing convention.

## 7. Security

**Ingress filters:**
- UDP 4789 is accepted only from fabric TEPs, and only on the TEP interface (extends `inet vdxvxlan`).
- TCP 179 is accepted only from fabric TEPs.
- BGP uses MD5.

**L2 guards on fabric PG bridges:**
- The existing `bridge vdxtenantl2` guards (rogue DHCP, RA and BPDU) apply.
- VMs get port security, MAC and IP anti-spoof, from the IPAM leases. This is phase 2.

**VXLAN is unencrypted and unauthenticated:**
- On a dedicated, isolated network that is acceptable.
- **Over the management LAN**, anyone there who can spoof a TEP's source IP can inject frames into any VNI.
- The option is **"Encrypt fabric traffic" (WireGuard between TEPs)**, which costs about 60 bytes more per packet. It should be the default for "ride over management". Keys are distributed by the leader over the peer API.

## 8. Lifecycle and failure

| Event | Behaviour |
|---|---|
| Leader down | The data plane keeps running (kernel + FRR are local); fabric edits wait for a leader. |
| Host down | BGP withdraws its routes; restarted VMs re-advertise from their new host. |
| vdxd restart | `ReensureFabric` (idempotent), then an FRR reload via `frr-reload.py`, the same path as host routing. |
| Add host | The wizard's "Add host" step: preflight, realize, then every peer updates its BGP neighbour list. |
| Remove host | Refused while any fabric PG on it has VMs, containers or instances in Trash. |
| Delete fabric / PG / VRF | Refused while anything is attached. Tombstones replicate. |
| Live migration | Pre-flight realizes the PG on the destination; EVPN MAC mobility moves the MAC. |

## 9. Data model (new migrations; numbers assigned at build time)

| Table | Columns |
|---|---|
| `fabrics` | id, name, asn, encap, encrypt, mtu_underlay, mtu_guest, version |
| `fabric_hosts` | fabric_id, node, mode (dedicated/vlan/mgmt), iface, vlan, tep_cidr, tep_ip, state |
| `fabric_vrfs` | fabric_id, org_id, l3vni (UNIQUE fabric+org; UNIQUE l3vni) |
| `networks` | Reused: mode=`fabric`, plus fabric_id, vni, l2_only. The existing cidr / gateway / DHCP columns carry the routed-PG fields. |
| `fabric_rules` | id, fabric_id, org_id, src_net, dst_net or `external`, bidir, proto, ports, enabled |

- IPAM reuses the existing lease tables. The leader is authoritative.
- Uniqueness uses standalone partial unique indexes, per CLAUDE.md.

## 10. UI

**Networking → "Fabrics" page:**
- A list of fabrics.
- **+ Deploy fabric** opens the wizard. Its steps:
  1. Name + hosts.
  2. Per-host interface and TEP.
  3. Security (encryption, ASN).
  4. Preflight, with an MTU and connectivity matrix.
  5. Review → Deploy, with undo-on-failure.

**Switching page:**
- Each host shows "Fabric vSwitch `<name>`" with uplink **"VXVisor Fabric"**.
- **+ Add port group** on it creates a fabric PG.

**"Connectivity" page:**
- The allow-list table plus the PG × PG matrix.
- A "Can VM A reach VM B?" checker. It evaluates the policy and the realized state.

**Topology map:**
- The fabric vSwitch is drawn once, spanning hosts.
- PGs show a per-host VM count.

## 11. Phases

1. **Phase 1 — L2 + L3 east-west:**
   - the wizard (all three underlay modes), EVPN, routed and L2-only PGs;
   - the anycast gateway, per-org VRFs, static-lease DHCP;
   - the connectivity allow-list and distributed SNAT egress;
   - nft guards, boot re-ensure, and the topology map.
2. **Phase 2:** WireGuard encryption, port security, the reachability checker, live-migration polish.
3. **Phase 3:** inbound/north-south (BGP to physical routers, edge on `/trunks` uplinks), IPv6, and moving legacy VXLAN networks onto a fabric.

## 12. Testing

- **Unit tests:** renderers (FRR, nft, dnsmasq), the allocator, replication with tombstones, rule compilation, authz.
- **Live tests need two or more nodes.** The nested two-node test cluster (test01/test02) must be re-verified first. The single test host can only exercise preflight and a one-host fabric.

## 13. Adversarial review (2026-10-30): summary

An independent review checked §1–12 against the code and against the FRR, Proxmox SDN and kernel VRF docs. Its main findings:

**Blockers:**
1. **Leader-only allocation with no quorum brings back cross-tenant VNI collisions.**
   - A 2-node election can produce two leaders.
   - A failover inside the 10 s pull window can double-allocate.
   - `accountsync` upserts by integer id, but `networks.id` is a per-node AUTOINCREMENT, so a replicated PG would overwrite an unrelated local PG.
   - `ip_leases ON DELETE CASCADE` means a tombstone silently drops leases.
2. **Leader-authoritative IPAM makes VM create and start depend on the leader.**
3. **Live migration never attaches the destination NIC.** VERIFIED:
   - `ReceiverSpec` / `LaunchReceiver` never set `TapName` or bridge the tap. A normal start does both (`manager.go:1006-1023`).
   - `AdoptMigrated` keeps the source node's local `network_id`.
   - This is an **existing bug**: bridged VMs lose networking after a live migration today.
4. **The L3 layout as drafted won't forward.**
   - It lacks the per-org L3VNI bridge and a unique router MAC per VTEP. FRR requires both.
   - Stamping the anycast MAC on every bridge makes the bridges drop each other's frames ("own address as source"). FRR's recipe is a macvlan carrying the anycast MAC, plus a local FDB entry.
   - §32's forced `vlan_filtering=1` hides traditional SVIs from zebra. Fabric bridges must be exempt.

**Major:**
- **DHCP and SNAT inside VRFs.** dnsmasq can't see VRF traffic without `udp_l3mdev_accept`, and turning that on globally exposes host UDP services to tenants. Distributed SNAT breaks with overlapping tenant CIDRs.
- **FRR clobbering.** Separate writers would wipe each other's `frr.conf`. New BGP neighbours get IPv4 unicast by default, so router-id and update-source must be pinned. The TCP 179 allow-list must keep the existing host-routing neighbours.
- **The host becomes the tenant router.** That reverses §27 and needs guards on SVIs and VRFs.
- **The UDP 4789 allow-list is meaningless over a shared mgmt LAN.** Spoofed UDP needs no handshake, so mgmt mode needs mandatory WireGuard. VERIFIED: the peer API HMAC covers only timestamp and path (`peer.go:33-36`), not the method, body or response.
- **"Mgmt is sacred" is about traffic, not MTU.** A guest L2 loop sprays BUM traffic across mgmt; that needs BUM policers. Mgmt mode also needs a static mgmt IP, and the TEP must never be the VIP. A VLAN on the mgmt uplink must be reserved in the trunk allocator. The design never re-uplinks vSwitch0.
- **Product fit.** Fabric-wide PGs are right. Still needed:
  - a per-PG **host span**;
  - a cluster-aware distributed firewall (`buildFWMaps` is local-only);
  - compiling the table into the existing unified firewall, not adding a third policy engine.
- **Operations.**
  - nft watchdog for every fabric table.
  - Check whether networkd's `ManageForeignRoutes` strips VRF routes on `netplan apply`.
  - Desired-state reconcile instead of imperative undo.
  - A health page.

Full review: the session transcript of 2026-10-30.

## 14. FINAL design (supersedes §2–11 where they conflict)

**Owner decisions (2026-10-30):**
- L3 is **distributed from the start**. The anycast gateway (was D7, phase 2) moves into phase 1; the
  hairpin-through-one-gateway interim is dropped.
- The live-migration NIC bug is **fixed first** (D4a, done in `a452492`, deployed 1.109.2).
- No 2-node cluster for now. Phase 1 is built against unit tests and a single-host netns lab
  (two network namespaces standing in for two hosts). The 2-node live E2E runs when test01/test02 are back.

**D1 — Port groups.**
- Fabric-wide PGs, with a per-PG **host span** (NSX transport-zone membership). The default span is all fabric hosts.
- Realization is eager within the span; no lazy realization.
- The table keeps the owner's dropdowns. PG options read like `Web 10.1.0.0/24 · Host1, Host2`.
- Rules are never host-scoped, because they would silently change meaning after a vMotion or HA restart.

**D2 — The fabric vSwitch** is a new logical switch per fabric. It never touches or re-uplinks vSwitch0 (mgmt).

**D3 — Intent.**
- Every fabric object has a UUID, mapped to local ids on each node.
- Fabric writes are a **unanimous commit**: every live fabric member ACKs, or the write is refused.
- A dead member is removed by an explicit **Evict host** action.
- A node may not coordinate fabric writes until it has synced since boot.
- TEPs and WireGuard public keys travel in authenticated gossip meta.
- Shared secrets (BGP MD5) are derived locally from `cluster.key` and never sent.

**D4 — Phase 0 (prerequisites; also fixes existing problems):**
- **(a) Done (`a452492`).** The live-migration receiver bridges its tap like a normal start. Live and cold adopts map
  `network_id` by port-group identity (org + name + VLAN + VNI + subnet, `qemu.PortGroupRef`): exactly one local
  match or the move is refused, and the guest's address is reserved on the destination. A precheck runs before any
  copy or stream. Fabric PGs will add their UUID to that identity once they exist.
- **(b) Done.** The peer API HMACs the method, path, query, body digest, timestamp and a single-use nonce, and
  MACs its responses; streamed bodies carry a trailer MAC. The admin reverse proxy now signs the user too (it
  was unsigned, so a sniffed header could be replayed as any admin within 30 s).
- **(c)** One composed FRR renderer for host routing plus fabric, with BGP hygiene:
  - IPv4 unicast deactivated for fabric peers;
  - router-id and update-source pinned to the TEP;
  - an immutable ASN, BFD, and `frr-reload.py --test` before applying;
  - the TCP 179 allow-list = TEPs + the configured host neighbours.

**D5 — Phase 1 (smallest viable; delivers wizard → vSwitch → PG → table, with L2 and L3):**
- **Underlay:** a dedicated NIC or bond, or a VLAN on a **non-mgmt** uplink. Preflight runs a DF-ping matrix and checks the FRR version and kernel modules.
- **EVPN L2:** iBGP full mesh, `l2vpn evpn` only, with MD5 and BFD.
- **Port groups:**
  - one bridge per PG with `vlan_filtering=0`, exempted from §32, plus an nft drop of guest-tagged frames;
  - `neigh_suppress`, MAC anti-spoof and BUM policers on taps;
  - the UDP 4789 guard and its nft watchdog.
- **L3 / IPs / table: distributed from the start (NSX DR; was D7).**
  - Per-org VRF + L3VNI (symmetric IRB). A unique router MAC per VTEP.
  - An anycast gateway on every host in a PG's span: the same gateway IP and MAC via macvlan + local FDB, following
    FRR's recipe. Traffic between PGs is routed on the host where the VM runs; there's no hairpin and no single gateway.
  - Per-VRF dnsmasq on each host (`ip vrf exec`) with `dhcp-range …,static`. Leases are allocated by the
    coordinator in the replicated intent and rendered as static host entries, so every host answers identically.
  - Preflight and a watchdog assert `tcp_l3mdev_accept=0` and `udp_l3mdev_accept=0`. The `vdxtenant` input
    guard extends to SVIs and VRFs.
  - The connectivity table is a UI over a **distributed firewall**: the same rules, rendered from intent on every
    host, enforced in each VRF's forward path. The default is deny between PGs and allow within a PG.
  - Egress (SNAT, default route) stays on the org's **netns tenant gateway**, as NSX keeps it on the SR. A VRF's
    default route points at that gateway's leg on a transit PG.
- **Health page:**
  - BGP sessions;
  - VTEPs per VNI;
  - the MAC table;
  - EVPN duplicate-address flags;
  - the DF-ping matrix;
  - UDP 4789 drop counters.
- **Testing:** unit tests plus a single-host netns lab (two namespaces, each with its own FRR, VTEP, bridges and
  VRF). The live 2-node E2E is deferred until a test cluster is available.

**D6 — Phase 1b, "ride over management":**
- Mandatory WireGuard between TEPs:
  - each node generates its key locally;
  - public keys travel in gossip;
  - the guard matches `iifname wg*`;
  - the guest MTU is about 1390;
  - `install.sh` adds `wireguard-tools`.
- Refused on a DHCP-addressed mgmt IP. The TEP is the node's own IP, never the VIP.
- BUM policers are mandatory, and fabric UDP is shaped or DSCP-marked.

**D7 — (merged into phase 1).** Distributed L3 is part of D5 per the owner's decision.

**D8 — Phase 3:**
- Inbound north-south via BGP to physical routers (ECMP).
- An edge on `/trunks` uplinks.
- IPv6.
- Moving legacy VXLAN networks onto a fabric.

**D9 — Operations:**
- Desired-state reconcile per host (`fabric_hosts.state`), with no imperative undo.
- A watchdog for every fabric nft table.
- Verify networkd `ManageForeignRoutes` behaviour.
- Surface `clear evpn dup-addr`.
- TCP MSS clamp on fabric taps.
- VRF table ids allocated per host.
