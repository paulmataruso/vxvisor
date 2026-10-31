# What's left: the 3-node test plan and the backlog (2026-10-31)

The single test host is being retired for a nested **3-node lab on Proxmox**. Everything below
was built and checked with unit tests, netns labs and single-host live E2Es. **Nothing that needs
a second host has been run since the old two-node lab was retired (2026-10-16).** That covers
clustering since then, migration, the fabric and the peer-signing changes. This file is the
checklist for the lab (§2–3) and the list of what isn't built (§4).

## 1. Where things stand

- `dev` holds everything; `main` (Stable) is behind it. Latest Stable release: v1.96.0. Latest
  Preview: v1.109.1-20261030. The next release must be newer than v1.109.1. The last build
  deployed anywhere was 1.111.0-20261030 (phase 1b of the fabric).
- For the lab, build `dev` (INSTALL.md §2) or cut a Preview with `deploy/release.sh` so the nodes
  can also test the in-app updater (§3 step 13).
- Promote to Stable (merge `dev` → `main`, release) only after §3 passes.
- Fixed just before the move (2026-10-31): `install.sh`'s `apt_opt` checked candidates with
  `apt-cache policy | grep -q`, which under `set -o pipefail` reported every package as
  missing. Since 2026-10-17 a fresh install had silently skipped FRR, LXC, ZFS/LVM,
  NFS/CIFS/Ceph/iSCSI, lldpd, nbdkit and wireguard-tools. The lab is the first fresh install
  with the fix, so step 1 checks those packages explicitly.
- Also new in install.sh (2026-10-31): the RustGuac console is built from pinned source and
  configured, so the button works on a fresh host. The section was run on a fresh Ubuntu 26.04
  container:
  - loopback-only listeners;
  - the key accepted from 127.0.0.1 only;
  - every guacd protocol library resolves;
  - a re-run takes seconds and changes nothing.

## 2. The lab

**Proxmox host:** nested virtualization on (`cat /sys/module/kvm_intel/parameters/nested` →
`Y`, or `kvm_amd`). The Proxmox firewall must be off on the lab VMs' NICs, or at least have
`macfilter=0`. Guests of the lab nodes put their own MACs on these wires.

**Node VMs `vx1`, `vx2`, `vx3`:**
- Ubuntu 26.04 server; CPU type `host`; 8 vCPU / 16 GB (4 / 8 minimum).
- Disks: 64 GB OS disk, plus two blank 50 GB disks. One is for a ZFS pool (zvol snapshots) or
  LVM-thin. The other is a Ceph OSD (3 nodes = a real Ceph HCI cluster).

**Service VM `svc`** (small Ubuntu): the NFS/iSCSI/SMB target on the storage net. It is also
the "provider router" on the trunk net (VLAN subinterfaces, tcpdump, later a BGP peer for
fabric phase 3) and the "stranger" on the management LAN for the fabric's spoof tests.

**Proxmox bridges** (only `vmbr0` has an uplink):

| Bridge | NIC in the nodes | Purpose | Notes |
|---|---|---|---|
| `vmbr0` | `ens18` | management LAN | **Static IPs** on every node: a fabric over management refuses DHCP. |
| `vmbr1` | `ens19` | cluster net: gossip 7946, peer API 8767, live migration 49200 | `[cluster] advertise` = this address |
| `vmbr2` | `ens20` | storage net (NFS/iSCSI/CIFS/Ceph) | set as each node's storage interface; `svc` on it too |
| `vmbr3` | `ens21` | fabric dedicated underlay | bridge **MTU 9000**, VM NICs `mtu=1` (inherit); fabric MTU 1550 needs ≥ 1600 |
| `vmbr4` | `ens22` | tenant-egress trunk | **not** VLAN-aware (a VLAN-aware bridge filters tags and breaks QinQ); `svc` on it |

**Install, on every node:**
1. Copy `dist/vdxd` + `deploy/*` to the node.
2. `sudo ./install.sh --ip <mgmt-ip> --mgmt-vswitch`. Save the admin password it prints. The
   RustGuac build adds several minutes to a first install.
3. Restart FRR once (`systemctl restart frr`) so `bfdd` runs. It starts only on FRR's next
   restart.
4. **Don't** use the zero-touch "Join a worker node → install vdxd" bootstrap for lab nodes. It
   copies only the binary and a minimal config, none of install.sh's packages (see §4).

**Cluster config** (`/etc/vdxclone/config.toml`, `[cluster]`, then restart vdxd):
- `enabled = true`.
- `primary = true` on `vx1` only.
- `advertise`, `gossip_bind` = the node's `vmbr1` IP.
- `mgmt_addr` = its static management IP.
- `seeds` = the other two nodes' `vmbr1` IPs with `:7946`.
- `vip = "<free LAN IP>/<len>"`, `vip_iface = "vSwitch0"`.
- Copy `/var/lib/vdxclone/data/cluster.key` from `vx1` to the others **before** their first
  cluster start. The file must be byte-identical everywhere.

## 3. Test plan (in order; each step relies on the previous ones)

1. **Install baseline**, per node:
   - `vdxd`, `frr` (with `bfdd`), `lldpd`, `rustguac` and `rustguac-guacd` are active.
   - `wg`, `vtysh`, `lxc-ls`, `zfs`, `rbd`, `iscsiadm` and `mount.nfs` exist.
   - `/etc/apparmor.d/abstractions/frr.d/vxvisor` is present.
   - `[guac]` is in the config (file mode 0600).
   - The RustGuac button opens a VM's VNC and SPICE console.
   - rustguac answers only on 127.0.0.1:8089, guacd only on 127.0.0.1:4823.
2. **Cluster formation:**
   - Gossip sees 3 members and exactly one leader holds the VIP.
   - A user created on the leader can log in on the followers (account sync).
   - On the VIP: the unified view, a remote VM's details and actions (signed admin proxy), and a
     cross-node console.
   - On a node IP: the standalone view.
3. **Election and failover with 3 nodes.** The election was designed for 2 nodes and has no
   majority quorum (see §4).
   - Power off the leader: a follower promotes after its management probe fails, and the VIP
     moves.
   - Power the old leader back on: no failback.
   - Take only one node's cluster link down (`qm set <id> --net1 …,link_down=1`): the VIP is
     never held twice.
4. **Peer API signing v2:**
   - Normal cluster traffic works.
   - A node on an older binary is refused, as designed. Note what breaks during a rolling
     upgrade (§4).
5. **Shared storage:**
   - Set the storage interface (`ens20`) on each node.
   - NFS, iSCSI and CIFS pools from `svc` mount on all three.
   - Ceph HCI: one OSD per node, then an RBD pool.
6. **Migration:**
   - Live migration on NFS and on RBD, there and back, between every pair of nodes.
   - Cold migration (streamed disk with trailer MAC) and storage move.
   - A bridged VM keeps its network after a live migration. That was the old receiver-tap bug,
     fixed in `a452492` and never run across hosts.
   - The precheck refuses when the destination has no matching port group (none or several).
   - The guest's IP lease is reserved on the destination.
7. **Legacy VXLAN port groups:**
   - Auto-peering across 3 nodes.
   - The `inet vdxvxlan` guard drops UDP 4789 from `svc`.
8. **Fabric on a dedicated underlay** (`ens21`, docs/FABRIC.md §14–15), three hosts:
   - **Deploy and control plane:**
     - The wizard deploys and the DF-ping matrix passes.
     - `vtysh -c 'show bgp l2vpn evpn summary'` shows every session Established, and BFD is
       up.
   - **Forwarding:**
     - VMs on one routed port group on different hosts reach each other.
     - An L2-only port group spans hosts.
     - Traffic between port groups is routed on the VM's own host (traceroute: the first hop is
       the local anycast gateway).
     - The default deny between port groups holds and an allow rule opens it.
     - DHCP static leases are answered on every host.
     - Egress goes through a tenant router on `vx1` for VMs on `vx2` and `vx3`.
   - **Guards:**
     - The bridge guard drops a spoofed MAC/IP, a rogue DHCP server and an RA.
     - BUM floods are policed.
     - VXLAN from a non-TEP is dropped (the guard counters on the page).
   - **Migration:** live-migrate a fabric VM. Its IP and MAC are kept, the EVPN MAC-mobility
     sequence increments, and there's no duplicate-address flag.
   - **Membership changes:**
     - Grow a 2-host fabric to 3; add-host is reverted when its DF check fails.
     - Remove a host.
     - Evict a powered-off host. While it's down and not evicted, writes are refused (the 2PC
       is unanimous).
   - **Recovery:**
     - Catch-up: stop vdxd on `vx3`, change the intent, start it again; it adopts the new
       version within 30 s.
     - Reboot a node: the boot reconcile restores everything.
     - `systemctl restart nftables` flushes the tables; reconcile restores them within 60 s.
     - `netplan apply` on a fabric node: do VRF routes survive (networkd `ManageForeignRoutes`,
       FABRIC.md D9)?
   - **Write the multi-node fabric E2E** while doing this. `internal/service/fabric_e2e_test.go`
     is single-host only.
9. **Fabric over management** (FABRIC.md §16), three hosts on `vmbr0`, everything in step 8
   plus:
   - **Tunnel:**
     - Every pair has a fresh handshake on the hosts table.
     - Tunnel packets show `tos 0x20` (CS1) on `vmbr0`: `tcpdump -v -i vmbr0 udp port 51871`
       on Proxmox.
     - Guests get MTU 1390, checked with a DF ping at full size.
   - **Strangers on the management LAN** (from `svc`):
     - Its UDP to 51871 is dropped.
     - A packet spoofing a TEP source is dropped.
   - **The management interface is never touched.** On all three nodes, its link, addresses
     and routes are identical before, during and after the fabric.
   - **Refusals:**
     - A node whose management address is a DHCP lease.
     - `mgmt_addr` set to the VIP.
     - A management MTU under fabric MTU + 60.
10. **Tenant egress on the wire** (`ens22` as the trunk, `svc` capturing):
    - An access uplink shows its 802.1Q tag in `tcpdump -e`.
    - QinQ shows the 802.1ad outer tag over the tenant's own tags.
    - A carried port group never gets DHCP or an address from the host.
    - An uplink leg SNATs out through `svc`.
    - A shared management-uplink trunk is access-only and leaves management alone.
    - This was never tested with carrier before.
11. **Snapshots on zvol and RBD:** first real run for both (the old host had no ZFS pool, and
    Ceph was off-limits). Cover:
    - snapshot, revert and clone;
    - promote or flatten on purge;
    - immutable locks;
    - policies.

    The qcow2 and LVM paths were tested.
12. **RustGuac in cluster mode:** open the RustGuac console through the VIP for a VM on another
    node. The button redirects to that node's `proxy_addr`, and the `vdx_session` cookie
    belongs to the VIP's host. **Expect this to fail; fix it.**
13. **In-app update across the cluster:** cut a Preview and update the nodes one at a time from
    the Updates page. Record what refuses while versions differ (migration, the fabric 2PC, the
    peer API).
14. **Outside the Proxmox lab** (need the owner present):
    - **Veeam:** a real VBR 13 server (a Windows VM on Proxmox will do), `[ovirt] enabled = true`,
      the checklist in docs/VEEAM-OVIRT-API.md §8. Full backup of an RBD VM is untested.
    - **CBT warm import:** a real vCenter (nested ESXi works) and a throwaway VM the owner picks.
      Per-VM consent; plan in docs/CBT-IMPORT.md.

## 4. Not built yet

**Fabric** (docs/FABRIC.md §14):
- **Phase 3:**
  - north–south routing: BGP to physical routers with ECMP;
  - an edge on the `/trunks` uplinks;
  - IPv6;
  - moving legacy VXLAN networks onto a fabric.
- **Phase 2 leftovers:**
  - the reachability checker;
  - a button for `clear evpn dup-addr`. Duplicate flags are shown; there's no clear action.
- **Not planned yet, but worth deciding:**
  - Encryption on a dedicated underlay. Only the over-management mode encrypts.
  - VRF table ids are the L3VNI, not allocated per host as D9 said. That's fine unless they
    collide with something else.
- The multi-node fabric E2E (step 8).

**Clustering:**
- **Majority-quorum election.** It was built for 2 nodes and doesn't detect a primary that's
  hung but still answers its management probe. With 3+ nodes it should take a majority or a
  witness.
- **No HA restart.** Nothing restarts a dead node's VMs on the survivors. `worker.go` mentions
  an "HA monitor" loop that doesn't exist.
- **Zero-touch join only installs the binary.** "Join a worker node → install vdxd" copies the
  binary and a minimal config, so a joined node lacks every package install.sh brings
  (FRR, wireguard-tools, LXC, storage tools, RustGuac…). It should run install.sh on the node.
- **No rolling upgrade.** The peer API refuses mixed versions (signing v2), so an upgrade is
  all nodes at once. A version window is needed if rolling upgrades matter.

**Smaller items:**
- **Naming leftovers toward NSX:** tenant uplink → "External network", transit → "provider
  link", VLAN pool → "VLAN range".
- **Stale reference:** `deploy/config.toml.tmpl` points at `docs/CLUSTER-NETWORKING.md`, which
  doesn't exist.
- **Re-running install.sh on existing hosts:** in-app updates replace only the binary. A host
  must re-run install.sh once for the AppArmor site file, wireguard-tools, RustGuac and the
  packages the `apt_opt` bug skipped.

## 5. Operational notes to keep in mind while testing

- Restarting `nftables.service` flushes vdxd's tables. The fabric's tables come back with the
  next reconcile (≤ 60 s); for the others, restart vdxd.
- NICs released from a NIC team stay down until vdxd restarts.
- Never test bond or vSwitch changes on a node's management NIC. If a node drops off the
  network, run `sudo netplan apply` at its console.
- A provider router should still filter routes learned from tenants.
