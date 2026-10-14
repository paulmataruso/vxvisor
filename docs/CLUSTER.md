# VXVisor clustering & live migration (M7)

## Topology

- **Control node** — runs `vdxd`, the web UI/API, and the SQLite control plane.
  It auto-registers as the `local` node on first start.
- **Worker nodes** — additional hosts that run VMs, driven by the control node
  **over SSH** (key-based). Register them in the UI under *Instance → Cluster*
  (`name`, `host:port`, SSH user). The control node probes `nproc` / `free -b`
  to track health and free capacity; the scheduler places new instances on the
  ready node with the most free memory.

### Worker prerequisites

- Key-based SSH from the control node (no password/`BatchMode=yes`).
- `qemu-system-x86_64`, `qemu-img`, OVMF installed; a `vdx` user in the `kvm`
  group (see privilege separation in the main README).
- The same QEMU **major version** as every other node (6.2 here) — mismatched
  versions break live migration.

## Live migration (M7b)

Live migration requires, and VXVisor refuses to proceed without:

1. **Two distinct, reachable nodes** (source `local` + a remote destination).
2. **Shared storage** — the VM disk must live on a pool both nodes mount
   (an NFS pool), *or* a `blockdev-mirror` disk copy must be arranged. Migrating
   a local-only disk would destroy the guest, so it is blocked.
3. Matching CPU model (`-cpu host` on identical CPUs, or a pinned model).

Sequence (wired in `internal/cluster.Migrate`):

```
dst$  qemu-system-x86_64 ... -incoming tcp:0.0.0.0:49152
src$  (QMP) {"execute":"migrate","arguments":{"uri":"tcp:<dst>:49152"}}
src$  (QMP) poll query-migrate until {"status":"completed"}
```

On a single-host install (no second node / no shared storage), the migrate
action returns a clear precondition error instead of pretending to move the VM.
