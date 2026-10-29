# Snapshots, instant clones and snapshot policies

VXVisor snapshots every disk backend it provisions (qcow2, ZFS zvol, LVM thin and
Ceph RBD). It can make an instant clone of an instance from a snapshot or from its
current state, and it can take snapshots on a schedule with retention and optional
immutability.

| Layer | Code |
|---|---|
| Backend commands | `internal/zfs/snap.go`, `internal/lvm/snap.go`, `internal/ceph/snap.go`, `internal/qemu/snapclone.go` (qcow2 + QMP), `internal/qemu/qga.go` (guest freeze/thaw) |
| Engine | `internal/session/snapshots.go` (take / revert / delete / clone / detach), `internal/session/snaprecords.go` (rows, clone links, `Purge`) |
| Authz, audit, policies | `internal/service/snapshot_service.go`, `internal/service/snapshot_policy.go` |
| Scheduler | `internal/worker/worker.go` (`snapshot-policies` loop, every minute) |
| UI | instance page snapshot card + `m-snap` / `m-clone` modals; `/snapshot-policies` (Storage → Snapshot Policies) |
| REST | `internal/api/snapshots.go` |
| DB | migrations 55 (`snapshot_policies`), 56 (snapshot columns), 57 (`snapshot_clones`) |

## Design

* **One recorded row per snapshot.** The `snapshots` table is the authority. Each
  row records its backend and a backend locator `ref` (`pool/ds@tag`, `vg/lv`,
  `pool/image@tag`, or empty for qcow2, where the tag lives inside the file). VXVisor
  only ever destroys snapshots that have a row, and it destroys them through that
  row's `ref`. A snapshot it didn't create is never touched. In particular, a ZFS
  revert refuses if a newer snapshot isn't one of ours.
* **One disk per instance.** A VM has exactly one data disk (`sessions.disk_path`).
  "All disks" therefore means that disk **plus the UEFI NVRAM**, which is copied to
  `<DiskDir>/<id>.vars.<tag>.fd` with every snapshot. A revert restores the NVRAM,
  and a clone starts from it, so boot entries always match the disk.
* **Per-VM serialization.** Snapshot, revert, delete, clone and purge of an instance
  take its lock. Several locks are always taken in sorted order, so a group run and
  a user action can never deadlock. Purges are additionally serialized, because
  purging an origin can modify a clone's storage. Instances that are mid-storage-move
  are refused.
* **Names are strict.** Every pool, dataset, VG, LV, image and tag name passed to a
  CLI must start with a letter or digit. It is limited to `[A-Za-z0-9._:-]` (no `:`
  for LVM or RBD), so no name can be parsed as an option. No `-r`, `-R` or `--force`
  flag is ever passed on a snapshot or clone path.

## Per-backend mechanics

| | Snapshot | Revert (VM stopped) | Delete | Instant clone | Clone depends on snapshot? |
|---|---|---|---|---|---|
| **qcow2** | Running: QMP `blockdev-snapshot-internal-sync` (disk-only, no pause). Stopped: `qemu-img snapshot -c` | `qemu-img snapshot -a` (other snapshots kept) | QMP `blockdev-snapshot-delete-internal-sync` (HMP `delvm` fallback) or `qemu-img snapshot -d` | Reflink copy + `snapshot -a` + strip history, else `qemu-img convert -l snapshot.name=… -B <base>` | No: independent file |
| **zvol** | `zfs snapshot ds@tag` | `zfs rollback ds@tag` (**no `-r`**), see below | `zfs destroy ds@tag` | `zfs clone ds@tag pool/vdx-<id8>` + wait for the udev node | **Yes** |
| **LVM thin** | `lvcreate -s -n <lv>-<tag> vg/<lv>` (inactive, activation-skip) | Swap, see below (all snapshots kept) | `lvremove -f vg/<lv>-<tag>` | `lvcreate -s -kn -ay -n vdx-<id8> vg/<snap>` | No: thin snapshots are independent |
| **RBD** | `rbd snap create` | `rbd snap rollback` | `rbd snap unprotect` (if protected) + `rbd snap rm` | `rbd snap protect` + `rbd clone` | **Yes** (until flattened) |

### Live qcow2 snapshots replace HMP `savevm`

The old live path used HMP `savevm`, which captures RAM and disk. It is replaced by
the disk-only `blockdev-snapshot-internal-sync` for three reasons:

* `savevm` pauses the guest for the whole RAM dump.
* `savevm` fails on every UEFI VM, because the writable raw pflash NVRAM can't hold
  a snapshot.
* The RAM state was never restorable from the UI anyway: revert is an offline
  `qemu-img snapshot -a`.

Rows written by the old code still delete correctly: `delvm` is the fallback.

### ZFS revert and newer snapshots

`zfs rollback` can only go back to the **most recent** snapshot unless `-r`
destroys the newer ones, and `-r` would also take snapshots that clones depend on.
VXVisor never passes `-r`. Reverting to an older snapshot needs an explicit
"discard newer" confirmation (the UI's confirm dialog, or `discard_newer: true` in
the API).

Before anything is destroyed, every newer snapshot is checked. Each one must be:

* recorded by VXVisor;
* not immutable;
* without dependent clones.

If any check fails, nothing happens. Otherwise the newer snapshots are destroyed one
by one, newest first, and then a plain rollback runs. The UI warns on the Revert
button whenever newer snapshots exist.

To get at an older ZFS state without losing the newer snapshots, make an instant
clone from that snapshot instead.

### LVM thin revert: swap, not `lvconvert --merge`

`lvconvert --merge` consumes the snapshot. On an active origin, it only merges on
the next activation. VXVisor reverts by swapping LVs instead (`lvm.RevertThin`):

1. `ThinCopy snap → <lv>-rv<sfx>` makes a fresh thin LV holding the snapshot's
   data. This is instant and shares blocks with the snapshot.
2. `lvrename <lv> → <lv>-pre<sfx>` keeps the current disk aside.
3. `lvrename <lv>-rv<sfx> → <lv>` puts the reverted disk at the VM's path.
4. `lvremove <lv>-pre<sfx>` removes the pre-revert state.

If any of steps 1–3 fails, the earlier steps are undone, so the VM always has a disk
at `/dev/<vg>/<lv>`. Every snapshot survives, so you can revert again to an older or
a newer snapshot.

### Instant clone

The clone is a new, **stopped** instance in the origin's org and folder. It copies
the origin's hardware profile and gets a fresh identity:

* new instance UUID, name (default `<origin>-clone`) and MAC;
* its own address lease (static IPAM, or DHCP by MAC);
* its own VNC/SPICE ports, which are allocated at start and bound to loopback, as
  for every VM;
* a fresh empty TPM, and its own NVRAM copied from the snapshot.

Passthrough devices are not copied, and start-at-boot is off.

If the origin uses cloud-init, the clone gets a new NoCloud seed. The seed carries
the clone's own instance-id, hostname, MAC and lease, which makes cloud-init:

* regenerate the SSH host keys;
* re-render networking for the new MAC;
* reset the password;
* reset the systemd machine-id once per instance (`bootcmd` with `cloud-init-per instance`);
* lease DHCP by MAC (`dhcp-identifier: mac`), so the clone never collides with the
  origin's machine-id-derived DUID.

Guests without cloud-init, Windows guests for example, keep their in-guest identity
(hostname, SID). Generalise them with sysprep first if that matters.

**From now.** Cloning from the current state first takes a *transient* snapshot,
labelled "clone base".

* **Independent backends (qcow2, LVM):** the transient snapshot is deleted as soon as
  the clone exists.
* **Dependent backends (zvol, RBD):** it stays as the clone's base. It is removed
  automatically once nothing depends on it, for example when the clone is purged.

**qcow2: which copy method, and why.** A backing-file overlay chained onto the
origin's image would be instant. However, it would make the origin's disk the
clone's backing file, so purging the origin would break the clone. Reflink and
convert both produce an **independent** file.

* **Reflink (preferred).** Used on XFS (reflink=1), btrfs, and OpenZFS ≥ 2.2 block
  cloning. `cp --reflink=always` shares every extent, then the copy is reverted to
  the snapshot and stripped of the origin's snapshot list. This is instant.
* **Convert (fallback, e.g. on ext4).** `qemu-img convert -U -l snapshot.name=<tag>
  -O qcow2 -B <base> -F <fmt>` writes a new overlay over the **same read-only base
  image**. It copies only the clusters the VM itself wrote, so the cost is the VM's
  own delta, never the whole disk.
* **Running origin.** Reflink is skipped while the origin is running. A whole-file
  copy could catch refcount/L2 metadata that QEMU is mid-update. Convert reads only
  the snapshot's table, L1/L2 and data clusters. QEMU flushed these when it took the
  snapshot and never rewrites them in place while the snapshot references them.

The clone link (`snapshot_clones`) records the method, `reflink` or `convert`. The
clone lands in the same directory as the origin's disk, which is the same storage
pool.

## Consistency

Each snapshot records its consistency level:

| Level | Meaning |
|---|---|
| `offline` | The instance was stopped, so the disk was at rest. |
| `app` | Running. The guest agent froze every guest filesystem (`guest-fsfreeze-freeze`, which uses VSS on Windows) for the instant of the snapshot. |
| `crash` | Running without a successful freeze, like a power cut at that instant. Journaled filesystems and databases recover from this. |

How a live snapshot works:

* **Freeze.** The guest agent is used when the instance has it enabled. The
  connection is resynchronised with `guest-sync-delimited`, so a stale reply is never
  mistaken for ours. A non-responsive agent fails within about 3 s. A responsive one
  gets up to 30 s.
* **Thaw.** The thaw runs in a `defer` on every path: snapshot error, panic, or a
  freeze that timed out (it may still complete inside the guest). It retries with a
  fresh connection for up to 45 s and verifies that `guest-fsfreeze-status` reads
  `thawed`.
* **Downgrades.** If the freeze or the thaw can't be verified, the snapshot is
  recorded as `crash`. It is never wrongly labelled `app`.
* **Groups.** For a group (one policy run), every guest is frozen **in parallel**,
  then every disk is snapshotted, then all are thawed. The group shares one frozen
  window. This is best-effort consistency across VMs, not a distributed transaction.

## Dependency rules

`snapshot_clones` has one row per clone: `clone_id → origin_id`, the snapshot name,
the backend and the method.

* **`snapshot_id` is set only while the clone shares blocks with that snapshot**
  (zvol, RBD). An `ON DELETE RESTRICT` foreign key backs this up in the database.
* **Deleting a snapshot that clones depend on is refused** with the list of clones:
  `instant clones depend on this snapshot (web-clone): delete those instances first`.
  ZFS and RBD would refuse it anyway. The UI disables the button.
* **Purging an origin never breaks a clone.** Its dependents are made independent
  first:
  * **zvol:** the clone of the newest cloned snapshot is `zfs promote`d. It takes
    ownership of that snapshot and every older one. Their rows are re-homed to it, so
    every other clone's link stays valid. The origin becomes a clone of it, which is
    destroyable. This is instant and copies no data. *Chosen over refusing the purge*
    because it is safe, instant, and matches what an operator expects ("delete the
    golden image, keep the clones"). If the origin was itself a dependent clone, the
    promoted clone inherits that dependency.
  * **RBD:** each dependent clone is `rbd flatten`ed. This copies the shared blocks
    and takes time proportional to the image size. The snapshots and the image are
    removed afterwards.
  * **qcow2 / LVM:** clones were always independent, so there is nothing to do.
* **Moves and migrations.** Storage moves and host migrations are refused while an
  instance has snapshots or is a dependent clone. The snapshots live on its current
  storage and in this node's database.

## Immutability

A policy can be **immutable**, which requires keep-days. Each snapshot it takes gets
`locked_until = taken + keep_days`. This is absolute and never shortened.

Until the lock expires, for **every** caller (instance admins included, UI and API):

* the snapshot can't be deleted;
* it can't be destroyed as a side effect of a ZFS discard-newer revert;
* its instance can't be purged;
* retention never prunes it.

Deleting the policy detaches its snapshots (`policy_id` becomes NULL) but keeps
their locks. A lock that can't be parsed counts as locked.

A revert *to an older* snapshot is allowed on qcow2, LVM and RBD. On those backends
a revert never destroys other snapshots, so the locked recovery point survives.

Immutability is enforced by the control plane. Someone with root on the host can
still destroy the snapshot with the storage CLI. Storage-level holds (`zfs hold`,
RBD protect) are a possible future hardening.

## Snapshot policies

| Field | Values |
|---|---|
| Target | one instance, a folder (recursively, sub-folders included), or every instance of the org |
| Schedule | hourly at `:MM`, daily at `HH:MM`, weekly on a day at `HH:MM` (**host local time**) |
| Retention | keep last N (per instance) and/or keep D days. At least one is required. |
| Immutable | lock each snapshot for its keep-days (requires keep-days) |

How runs and retention behave:

* **Due runs.** The worker checks every minute (`RunDueSnapshotPolicies`). It waits
  2 minutes after daemon start so autostarted guests have their agents up.
* **Missed runs** (host down) catch up **once**, not in a burst. The next run is
  computed from the actual run time.
* **Each run** resolves its targets inside the policy's own org, then takes one group
  snapshot. Each snapshot is named `<policy> YYYY-MM-DD HH:MM` and records the
  policy, a shared group id, its expiry and its lock. The run's status is stored on
  the policy, logged, and audited as `snapshot_policy.run` (system actor).
* **Retention** keeps a snapshot while it is **among the last N of its instance OR at
  most D days old**. A rule set to 0 is off. Only the policy's own snapshots are
  considered; manual snapshots are never pruned. Immutable snapshots and snapshots
  with dependent clones are always kept.
* **Pruning** is the only destructive step. It waits out the same 10-minute boot
  grace as auto-retention, so a stale or restored database can't delete snapshots
  right at start.
* **Run now** runs a policy immediately in the background, without changing its
  schedule. Runs are serialized.
* **Cluster.** Each node has its own database, so a policy acts on that node's
  instances.

### Who can manage policies

| Principal | Can |
|---|---|
| Instance admin (provider org) | list/create/pause/run/delete **every** org's policies; pick the org when creating |
| Org admin / owner (`atLeast("admin")`, incl. an instance admin in tenant view) | the same, **own org only**: every query is scoped by `org_id` |
| Member / viewer | no access to policies. Members can snapshot, revert, delete and clone their org's instances; viewers can only list snapshots |

The tenant page is the same template, org-scoped, without the org column and picker.

## REST (`/api/v1`, API key or session)

| Method & path | Scope | Body |
|---|---|---|
| `GET  /sessions/{id}/snapshots` | read | |
| `POST /sessions/{id}/snapshots` | write | `{"name"}` |
| `POST /sessions/{id}/snapshots/{sid}/revert` | write | `{"discard_newer": bool}` |
| `POST /sessions/{id}/snapshots/{sid}/delete` | write | |
| `POST /sessions/{id}/clone` | write | `{"name", "snapshot_id"}` (0 = from now) |
| `GET  /snapshot-policies` | read | |
| `POST /snapshot-policies` | write | `{"org_id","name","target_kind","target_vm","target_folder","schedule","at_hour","at_minute","weekday","keep_last","keep_days","immutable"}` |
| `POST /snapshot-policies/{id}/enable` | write | `{"enabled": bool}` |
| `POST /snapshot-policies/{id}/run` | write | (202, runs in the background) |
| `POST /snapshot-policies/{id}/delete` | write | |

An immutability or clone-dependency refusal returns **409**.

## Audit

| Action | Logged as |
|---|---|
| Snapshot actions | `snapshot.create`, `snapshot.revert`, `snapshot.delete` |
| Clones | `session.clone` (origin, snapshot, from-now, backend, method, dependent) |
| Policy changes | `snapshot_policy.create`, `.delete`, `.enable`, `.run_now` |
| Scheduled runs | `snapshot_policy.run` (system actor: counts per consistency level, failures, pruned list) |

## Testing

* **Unit tests:**
  * the argv of every zfs/lvm/rbd/qemu-img command, plus refusal of option-looking
    names;
  * QGA freeze/thaw against a fake agent: a stale reply, a hung freeze that is still
    thawed, and no agent at all;
  * the engine: freeze-before-snapshot / thaw-after-all ordering, crash downgrade,
    immutability refusals, clone dependency refusal, ZFS discard-newer validation,
    promote/flatten on purge, transient bases, clone failure cleanup;
  * the scheduler's due logic, retention selection and org scoping;
  * template rendering, including CSRF on every POST form;
  * migrations 55–57 through the real driver.
* **Live tests** (env-gated, built with `CGO_ENABLED=0 go test -c`):
  * `internal/lvm` `TestLiveThinSnapshots` (`VDX_LIVE_LVM=<vg>/<thinpool>`, scratch
    `vdxtest-*` LVs only);
  * `internal/qemu` `TestLiveQcow2SnapshotClone` (`VDX_LIVE_QEMU=<dir>`: qemu-img
    plus a device-less, network-less scratch QEMU for the QMP path).

## Known limits

* ZFS and RBD are unit-tested only; the test host has no ZFS pool, and Ceph was
  deliberately left untouched.
* The reflink fast path is unit-tested only; the live run was on tmpfs/ext4, where
  convert is used.
* A cloned TPM-using guest gets a new, empty TPM. BitLocker and measured-boot guests
  will ask for their recovery key.
* Snapshots are per node and are not replicated.
