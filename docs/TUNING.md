# VXVisor performance tuning

Every knob we can turn, split into **what VXVisor already does per-VM** (automatic) and
**host-level tuning you apply once per box** (manual — do these on the new host).

Sources: Intel [KVM tuning guide](https://cdrdv2-public.intel.com/686407/kvm-tuning-guide-icx.pdf),
[Rocky Linux KVM tuning](https://docs.rockylinux.org/10/guides/virtualization/kvm_tuning/),
[Red Hat virt tuning — networking](https://docs.redhat.com/en/documentation/Red_Hat_Enterprise_Linux/7/html/virtualization_tuning_and_optimization_guide/sect-virtualization_tuning_optimization_guide-networking-techniques),
[Proxmox aio/iothread benchmark](https://forum.proxmox.com/threads/proxmox-ve-7-2-benchmark-aio-native-io_uring-and-iothreads.116755/),
QEMU commits ([virtio-blk num-queues=vCPUs](https://qemu.googlesource.com/qemu/+/9445e1e15e66c19e42bea942ba810db28052cd05),
[`-cpu host,migratable`](https://qemu.googlesource.com/qemu/+/84f1b92f974fbb19967c5f10ac6c3f4a04fb86dd)).

---

## A. Automatic — applied by VXVisor on every VM (no action needed)

| Area | What we set | Why |
|---|---|---|
| Accel | `-enable-kvm -cpu host -machine q35` | Hardware virt + full host CPU features |
| Disk AIO | dedicated `-object iothread` + `aio=io_uring` (qcow2) / `aio=native,cache=none` (zvol) | Biggest single disk win; io_uring is correct for ZFS/file-backed, native+O_DIRECT for raw block |
| Disk queues | `virtio-blk-pci,num-queues=<vCPUs>` | 1:1 virtqueue↔vCPU → completion IRQ on submitting vCPU (~78k→104k IOPS in QEMU's benchmark) |
| Disk hygiene | `discard=unmap,detect-zeroes=unmap` | Keeps thin qcow2/zvol small |
| Disk backend | **raw ZFS zvol** option (vs qcow2-on-dataset) | Avoids COW-on-COW; fastest on ZFS |
| Net dataplane | tap `vhost=on` | Kernel-side virtio-net; far higher throughput / lower CPU than userspace |
| Net queues | `queues=N` + `mq=on,vectors=2N+2` (N=vCPUs≤8, bridged only) | RX/TX scale across vCPUs |
| GPU | `-vga qxl` | Real KMS/DRM device; fixes GNOME/GDM black screen, renders over VNC+SPICE |
| Input | `qemu-xhci + usb-tablet + usb-kbd` | Absolute pointer + reliable keyboard |
| Entropy/mem | `virtio-rng-pci`, `virtio-balloon-pci` | No boot stall on randomness; host can reclaim RAM |
| Display | VNC always + optional SPICE (qxl+agent) | Choice of console |

**Guest-side follow-ups** (inside the VM, once): for multiqueue net to engage, run
`sudo ethtool -L <iface> combined <N>` (N = vCPUs). virtio-rng/balloon drivers ship in modern kernels.

---

## B. Host-level — do once on the new host (manual)

### 1. tuned profile (easiest big win)
```bash
apt-get install -y tuned
tuned-adm profile virtual-host      # general KVM host
# latency-sensitive / dedicated-core VMs:
# tuned-adm profile cpu-partitioning
```
`virtual-host` sets sane vm.*, scheduler, and I/O defaults. `cpu-partitioning` adds core isolation
(needs a reboot; pairs with pinning below).

### 2. Hugepages (reduce TLB misses)
2 MiB THP is automatic. For predictable 1 GiB pages, reserve at boot:
```
# /etc/default/grub : GRUB_CMDLINE_LINUX
default_hugepagesz=1G hugepagesz=1G hugepages=<N_GiB>
```
`update-grub && reboot`. Then back VM RAM with hugepages (QEMU `-mem-path /dev/hugepages -mem-prealloc`,
or a `memory-backend-file`). Note: `-mem-prealloc` raises start/migration time.
→ *Candidate VXVisor knob: a per-VM "back with hugepages" toggle + `[host] hugepages` config.*

### 3. CPU pinning + NUMA (latency-sensitive guests)
Inspect first: `lscpu`, `numactl --hardware`. Then pin each vCPU 1:1 to a host core, keep a VM's
vCPUs + RAM on one NUMA node, and pin QEMU's emulator threads OFF the vCPU cores:
```
# libvirt-style intent (we'd emit taskset/cgroup cpuset per VM):
vcpu 0->core2, 1->core3, ...   emulator->core0   memory: nodeset=0 strict
```
Reserve host cores (`isolcpus=` / systemd `CPUAffinity=`) so the scheduler leaves VM cores alone.
→ *Candidate VXVisor knob: optional CPU-pinning per VM (taskset the vCPU threads via QMP `query-cpus-fast` tids).*

### 4. ZFS (our default disk pool)
```bash
# cap ARC so it doesn't starve VMs (e.g. 8 GiB):
echo 8589934592 > /sys/module/zfs/parameters/zfs_arc_max
# for VM zvols: volblocksize=16k is a good default; disable atime; lz4 compression on
zfs set compression=lz4 atime=off tank0
```
Prefer **raw zvols** for VM disks (VXVisor supports this) over qcow2-on-dataset.

### 5. Networking (host)
```bash
# vhost module present:
lsmod | grep vhost_net
# bump the physical uplink + bridge queue depth / offloads as needed:
ethtool -L <uplink> combined <ncpus>     # multiqueue on the NIC itself
ethtool -K <uplink> gro on gso on tso on
ip link set <uplink> txqueuelen 10000
```
Use **bridged (tap) networking** for throughput — SLIRP user-mode NAT is convenience-only and slow
(this is why in-guest package installs over user-mode NAT crawl). For the storage network, keep it on
its own NIC (the dedicated storage-interface rule) and consider jumbo frames (`mtu 9000`) end-to-end.

### 6. Swappiness / THP / kernel
```bash
sysctl vm.swappiness=10
echo always > /sys/kernel/mm/transparent_hugepage/enabled
```

---

## C. Expectations by host class
- **This Atom C2758**: fine for servers + LXC + light desktops (LXQt/XFCE). GNOME/llvmpipe is CPU-bound and always sluggish here.
- **The new (faster) host**: apply §B (tuned virtual-host, hugepages, pinning if latency-sensitive, ZFS arc cap, bridged+multiqueue net). With a real GPU, GPU passthrough (`vfio-pci`, already supported in VXVisor) unlocks accelerated desktops.
