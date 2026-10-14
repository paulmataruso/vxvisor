# Cluster networking

This document explains how VXVisor turns a set of independent hosts into one
cluster that can **place VMs by load**, give a VM a **browser desktop**, and
**live-migrate a running VM between nodes without dropping its connections**.

All three capabilities rest on one foundation: a shared layer-2 fabric. The
default single-host install uses QEMU user-mode (SLIRP) networking and needs
none of this — a guest gets a private, NAT'd `10.0.2.x` and the host publishes
ports with `hostfwd`. That is fine for one box but cannot carry a routable guest
identity between hosts. Cluster networking replaces it.

## The three layers

### 1. A real L2 edge per node (`network.mode = "bridge"`)

Each VM gets a tap device enslaved to a host bridge (`vdxbr0`) instead of SLIRP.
The guest now has a routable MAC/IP on the bridge. The daemon:

- creates the tap owned by the unprivileged run-as user so a dropped-privilege
  QEMU can open it (`netdrv.SetupTapOwned`),
- allocates a stable IP from the network's CIDR via the `ip_leases` table
  (`netdrv.Store.AllocLease`) and bakes it into the cloud-init **network-config**
  so the guest comes up on a predictable address,
- tears the tap down on stop (the lease is retained so a restart reuses it).

On a flat LAN this is all you need: bridge `vdxbr0` to the physical NIC and every
VM is on the office network.

### 2. A VXLAN overlay across nodes (`network.mode = "overlay"`, `cluster.overlay = true`)

When nodes sit on different subnets, a VXLAN overlay stitches every node's bridge
into **one virtual L2 segment**, so all VMs appear on the same broadcast domain
regardless of physical topology. Per node (`netdrv.EnsureOverlay`):

```
ip link add vdxbr0 type bridge
ip link add vdxvx42 type vxlan id <VNI> dev <underlay NIC> dstport 4789
ip link set vdxvx42 master vdxbr0
ip link set vdxvx42 up
ip addr add <gateway>/<prefix> dev vdxbr0
```

VM↔VM traffic is MAC-in-UDP encapsulated between the nodes' VTEPs on UDP 4789.
This is the same model Proxmox SDN, Nutanix and OpenStack Neutron use. Guest IPs
come from one cluster-wide subnet (`cluster.subnet`), leased by the IPAM table so
no two nodes hand out the same address.

Config:

```toml
[network]
mode = "overlay"

[cluster]
overlay  = true
vni      = 42
underlay = "eth0"          # physical NIC carrying encapsulated traffic
bridge   = "vdxbr0"
subnet   = "10.77.0.0/16"
gateway  = "10.77.0.1"
```

### 3. Membership & placement (gossip, no central coordinator)

Nodes find each other over **mDNS** (zero-config) and/or static **seeds**, then
gossip liveness and live capacity with a SWIM protocol (`hashicorp/memberlist`).
Each node advertises `{cpus, mem_free}` in its gossip metadata; every node folds
the mesh view into its `nodes` table, so the scheduler (`cluster.Schedule`,
most-free-memory) places a new session on the least-loaded node **from any
node's point of view** — there is no master.

```toml
[cluster]
mdns        = true
gossip_port = 7946
seeds       = ["10.0.0.11:7946", "10.0.0.12:7946"]  # optional
```

`StartSession` calls `cluster.PlaceSession`, which records the chosen `node_id`
on the session. On a single host this resolves to the local node.

## How each feature uses the fabric

### Browser desktop (any tab, no plugin)

The `/desktop/{id}` page runs `guacamole-common-js` (vendored under
`/static/guac/`, no CDN) over a WebSocket. The daemon is a server-side client of
**guacd**: `internal/gateway` speaks guacd's wire protocol, performs the
`select → args → connect → ready` handshake, and relays the instruction stream
to the browser.

- With bridge/overlay networking and a guest running **xrdp**, it connects by
  **RDP** to the guest's leased IP — RDP's virtual channels carry clipboard,
  audio, microphone and webcam. (cloud-init can install xrdp automatically; see
  `cloudinit.Config.InstallRDP`.)
- Otherwise it falls back to **VNC** against the loopback QEMU display, which
  always works regardless of guest OS or networking mode.

```toml
[gateway]
enabled   = true
guacd_addr = "127.0.0.1:4822"
protocol   = "rdp"   # falls back to vnc when the guest has no routable lease
```

### Live migration (no disconnect)

`MigrateSession` streams a running VM to another node:

1. the source ships a serialized receiver `qemu.Spec` to the destination over
   SSH; the destination launches `qemu-system-x86_64 ... -incoming tcp:0.0.0.0:<port>`
   (via `vdxd migrate-recv`),
2. the source drives QMP `migrate` (with `auto-converge` + `xbzrle`) and polls
   `query-migrate` to completion,
3. on `completed`, the control plane flips the session's `node_id`.

**The guest keeps its IP** because both nodes are on the same VXLAN L2: when
migration finishes, QEMU emits a gratuitous ARP/RARP for the guest's MAC, the
VTEPs relearn it on the destination, and traffic follows — no visible drop.

Preconditions enforced by `cluster.Migrate` (it refuses rather than corrupt a
disk):

- two distinct, reachable nodes,
- **shared storage** at the same path on both nodes (`cluster.shared_storage`,
  e.g. an NFS/Ceph mount) **or** `block migration` to copy the disk inline.

```toml
[cluster]
shared_storage = "/srv/vdx-shared"   # same mount on every node
migrate_port   = 49200
```

## Verifying the overlay on one host

You can prove the encapsulation model without a second machine using two network
namespaces as stand-in nodes joined by a veth "underlay"; create a VXLAN (same
VNI) in each, enslave to a bridge, assign overlay IPs, and ping across — tcpdump
on the underlay shows the traffic wrapped as `VXLAN, vni 42` on UDP 4789, and the
overlay bridge learns the remote neighbor's MAC (the same relearning that makes
migration seamless). See `scratchpad/overlay-demo.sh` in the build notes.

## What needs real hardware

- **Live migration without disconnect** needs two physical/virtual nodes plus
  shared storage; the orchestration is implemented and the QMP sequence runs, but
  a single host cannot demonstrate the guest surviving the move.
- **RDP device redirection** (audio/mic/webcam) needs a guest running xrdp and a
  routable lease; the VNC fallback is always available.
- **mDNS discovery across nodes** needs more than one node on the segment; the
  gossip layer, join, and capacity replication are unit-tested in-process.
