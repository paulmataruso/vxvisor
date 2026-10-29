# CBT warm import from vCenter / ESXi

A **warm migration** imports a *running* VMware VM with only a short outage at
the end. VXVisor copies the VM's disks while it runs, then uses VMware **Changed
Block Tracking (CBT)** to copy only what changed since the last pass, on a
schedule. When the operator cuts over, the source powers off, one last small
pass copies the final changes, and the instance is created here through the same
path a cold import uses.

The classic (cold) import is unchanged and stays **strictly read-only** on the
source. Warm migration is opt-in per VM, behind an explicit consent checkbox.

## Consent and what changes on the source

In **Import / Export → Quick Import → Connect & import one VM**, after listing
VMs, the dialog shows **Use CBT (warm migration)**. The box appears only when
VDDK is installed (`Service.VDDKReady`); otherwise the dialog says warm
migration needs VDDK.

Ticking the box is the operator's consent for VXVisor to make these changes, and
only these, to **that one VM**:

| Change | When | Undone |
|---|---|---|
| `ReconfigVM` with `changeTrackingEnabled=true` | at the start, only if CBT was off | turned back off at the end (see below) |
| `CreateSnapshot` named `vxvisor-cbt-<id>-<n>` (no memory, no quiesce) | once per pass | removed right after the pass, and on every failure, cancel, or restart |
| `RemoveSnapshot` (`removeChildren=false`) | after each pass | only on snapshots VXVisor recorded as its own |
| `ShutdownGuest` (VMware Tools) | at cut-over, only if the operator leaves "Shut the guest down" ticked | not undone: the source stays off after cut-over |

Unticked, the import is the read-only path exactly as before (`runVMwareImport`).

### Code boundary

Every mutating vSphere call is in **`internal/vmware/cbt.go`**, and nowhere else:

- `SetChangeTracking`
- `CreateCBTSnapshot`
- `RemoveCBTSnapshot`
- `ShutdownGuestOS`

Each one takes a `vmware.CBTConsent`. That value can only be built with
`NewCBTConsent(moid, importID)`, and each method refuses a zero consent. It acts
only on the VM the consent names, so no other VM can be touched.

Two tests enforce this:

- **`TestReadOnlyDiscipline`** (`internal/vmware/vmware_test.go`) fails the build
  if `Reconfigure`, `CreateSnapshot`, `RemoveSnapshot` or `ShutdownGuest` appears
  in any other file. Every other mutating vSphere operation stays forbidden
  everywhere.
- **`TestCBTMutationsAreConsentGated`** checks that each mutating function takes
  the consent and calls `consent.check()` before its first mutation.

The service stores the consent as `consent=1` on the import row. A job that finds
no consent refuses to connect at all.

### Snapshot rules

- **Our snapshots have a recognizable name.** Each is called
  `vxvisor-cbt-<12 hex of the import id>-<seq>`. The name is unique, enforced by
  the `ux_cbt_snap_name` index.
- **The record is written before the snapshot exists.** The row in
  `vmware_cbt_snapshots` is INSERTed *before* the create call, and the moref is
  added after it. A crash at any point therefore leaves a record that cleanup can
  resolve.
- **Removal is checked three ways.** `RemoveCBTSnapshot` removes a snapshot only
  if all of these hold:
  - its name has the prefix,
  - the moref is in that VM's snapshot tree, and
  - the snapshot there still has exactly the recorded name.

  Anything else returns `ErrNotOurSnapshot`. That happens, for example, if someone
  renamed our snapshot to keep it. The record is then marked abandoned
  (`removed_at=-1`), audited as `vmware.cbt_snapshot_abandoned`, and left alone.
- **Nothing outside our records is ever touched.** Snapshots VXVisor did not
  record are never reverted, committed or removed. VMs with pre-existing snapshots
  are allowed, and those snapshots are left as they are.
- **A record with no moref is resolved by name.** This happens when vdxd died
  during the create call. Cleanup looks for the record's exact unique name in
  that VM's tree:
  - exactly one match: the snapshot is removed;
  - several matches: none is removed, the import retries, and the case is logged;
  - no match, and the record is younger than 15 minutes: the import waits,
    because the create may still be running on vCenter;
  - no match after that: the record is marked never-created.

### CBT is restored the way we found it

`cbt_orig` records the CBT setting **once, before the first change** (−1 =
unknown, 0 = off, 1 = on). `cbt_enabled_by_us` is set *before* the enable call,
so a crash in the middle still restores it.

At the end, whether done, cancelled or error, cleanup turns CBT back **off** only
if all of these are true:

- it was off when we found it,
- we turned it on, and
- the VM still exists.

If CBT was already on, we leave it on: some other product (a backup tool) relies
on it. We never re-enable CBT that someone switched off during the import.
Instead the import fails, because the change history is gone.

The choice is deliberate. Leaving CBT on would cost the source a little I/O for
nothing. Turning it off when it was on would break the operator's backups. So we
put back exactly what we found.

## Flow

1. **Prechecks, before anything on the source changes.**
   - The VM must be importable (no RDM, multi-writer or shared disks).
   - It must have no independent-mode disks, because snapshots skip them.
   - There must be enough free space in image storage: twice the disks'
     capacity, for staging plus the converted copy.
2. **Base copy.** The source keeps running.
   1. Record the CBT state, enable CBT if it is off, and take snapshot S1. The
      snapshot's stun cycle is what activates CBT on a running VM.
   2. Read each disk's change id from S1's `config.hardware`. If one is empty,
      the pass fails and retries.
   3. Create one fresh, sparse raw staging file per disk:
      `<ImageDir>/.vdxcbt-<id>-disk<i>.raw`, truncated to the disk's capacity.
   4. Query the allocated areas with `QueryChangedDiskAreas(changeId="*")`.
   5. Read those areas through `nbdkit vddk … snapshot=<S1> file=<S1's vmdk>`
      over a private unix socket. Four NBD connections run in parallel, in 4 MiB
      chunks, and all-zero chunks are skipped, so staging stays sparse.
   6. `fsync`, then commit the change ids, `state=syncing` and pass 1 in one
      transaction. Remove S1.
3. **Delta passes.** These run every *interval*: 30 minutes by default, 5 minutes
   to 24 hours, set in the dialog. **Sync now** runs one immediately.
   1. Take snapshot Sn.
   2. Check that the disk layout is unchanged (same count, device keys and
      capacities) and that every disk still has a change id. A layout change or a
      CBT reset is fatal.
   3. Query the areas changed since the recorded change id.
   4. Copy them into staging. A chunk that is now all zeros is punched out
      (`FALLOC_FL_PUNCH_HOLE`) or written as zeros, so stale data never survives.
   5. Commit the new change ids, then remove Sn.

   Re-running a pass that a crash interrupted is safe. The old change ids still
   describe staging, so the next query returns a superset of the changes.
4. **Cut-over** (the user clicks **Cut over…** and confirms in a modal).
   1. If the VM is running: one more delta pass, to make the final pass small.
   2. Shut the guest down through VMware Tools, if that was ticked and Tools is
      running. Otherwise the step text asks the operator to power the VM off in
      vCenter.
   3. Poll until the VM is `poweredOff`, for up to 1 hour.
   4. Run the **final pass**, then confirm the VM is still off.
   5. Move to `finishing`. From this point a cancel is refused.
   6. Read the source's shape (CPU, memory, firmware, NICs, MAC) with `GetVM`.
   7. Convert the staging files and create the instance through
      `importDisksToInstance`. This is the tail extracted, unchanged, from the
      cold import: `qemu-img convert` to qcow2 or zvol, register the base image,
      create the instance with the source's shape and MAC.
   8. Clean up with the end state `done`.

   Any failure before the instance exists returns the import to `syncing`, with
   the error shown and staging kept, so the operator can fix the cause and cut
   over again.
5. **Cleanup** (after done, cancel, or error).
   1. Remove every recorded snapshot of ours that is still pending.
   2. Restore CBT, as described above.
   3. Delete the staging files.
   4. Wipe the stored vCenter password and set the terminal state.

   If vCenter can't be reached, cleanup retries every minute and the import stays
   in `cleanup`. A record is only marked removed once its snapshot is confirmed
   gone.

## State machine

```
            ┌──────────── fail (retry after 2 min, ≤5 in a row) ───┐
            ▼                                                      │
 starting ──► base-copy ──────────────────────────► syncing ◄──────┤ delta pass (interval / Sync now)
                                                     │  ▲          │
                                       Cut over…     │  │ any cut-over failure, or a
                                                     ▼  │ restart during cutover/finishing
                                                   cutover ──► finishing ──┐
                                                                           │ instance created
 any non-terminal state ── Cancel / fatal error / 5th failure ──► cleanup ◄┘
                                                                     │
                                         end_state ∈ {done, cancelled, error}
```

| State | Meaning |
|---|---|
| `starting` | base copy queued, or being retried |
| `base-copy` | full copy from the first snapshot |
| `syncing` | base done; delta passes on the interval or on demand |
| `cutover` | pre-pass, waiting for power-off, final pass |
| `finishing` | conversion and instance creation; cannot be cancelled |
| `cleanup` | removing our snapshots, restoring CBT, deleting staging; retried until done |
| `done` / `cancelled` / `error` | terminal; password wiped, staging gone |

### Who drives what

- **Every scheduling fact is in the DB:** state, `next_run_at`, `cancel_req`,
  `fail_count`, change ids, snapshot records and staging paths.
- **`CBTTick` drives every import from that state.** `internal/worker` calls it
  at boot and every 15 s.
- **One job per import at a time.** A job is a goroutine that claims the import
  in memory, so two jobs never act on one import.
- **The races are guarded by conditional `UPDATE`s:**
  - cut-over only moves `syncing` → `cutover` when `cancel_req=0`;
  - `cutover` → `finishing` also requires `cancel_req=0`;
  - cancel is refused once the import is in `finishing` or `cleanup`.
- **vSphere tasks always run to the end.** They run on a non-cancellable context
  (30-minute cap), so a cancel or shutdown still learns whether a snapshot was
  actually created.
- **Errors are classed as fatal or transient.**
  - Fatal goes straight to `cleanup` → `error`. Examples: the VM is gone, CBT
    was switched off, the disk layout changed, or the staging file is missing.
  - Transient errors retry after 2 minutes. The 5th failure in a row ends the
    import in `error` (after cleanup).

### Crash and restart recovery

A restart of vdxd, a host reboot, or a crash at any point leaves the import's
state in the DB. On boot, `CBTTick` acts on it:

| Interrupted during | On restart |
|---|---|
| base copy | starts the base copy over in fresh staging, after removing the leftover snapshot by its record |
| a delta pass | the next pass first removes any recorded leftover snapshot, then reruns with the old change ids (a superset) |
| cutover | goes back to `syncing` with a note to cut over again; the source is never left half-converted |
| finishing | goes to `cleanup` → `done` if the instance was recorded; otherwise back to `syncing` (staging intact) |
| cleanup | continues: removes the recorded snapshots, restores CBT, deletes staging |

At boot, orphan `.vdxcbt-*` staging files that no unfinished import owns are
deleted (`sweepCBTStaging`, called from `SweepImportTemps`).

## Cancel

**Cancel** sets `cancel_req`. A running pass is aborted: in-flight NBD reads are
cut off by stopping nbdkit. Cleanup then runs while still holding the import:

- it removes our snapshots,
- restores CBT,
- deletes staging, and
- ends in `cancelled`.

The source keeps its current power state. If the cut-over had already shut the
guest down, it stays off; VXVisor never powers a source VM on.

## Data model (migrations 53, 54)

- **`vmware_cbt_imports`**: one row per import.
  - vCenter URL, host, user and **sealed password**, plus the TLS-insecure flag
  - moid, VM name, consent
  - `cbt_orig`, `cbt_enabled_by_us`
  - state, end_state, cancel_req, step, last_error, fail_count
  - os_type, target_pool_id, interval_sec, next_run_at, last_sync_at
  - passes, snap_seq, base_bytes, shutdown_guest
  - result image and instance, timestamps
- **`vmware_cbt_disks`**: per disk.
  - device key, index, label, capacity
  - staging path, last committed change id
- **`vmware_cbt_snapshots`**: every snapshot we create or are about to create.
  - name, moref, created_at
  - removed_at: 0 = pending, >0 = removed, −1 = abandoned
- **`vmware_cbt_passes`**: per pass.
  - kind (base, delta or final), bytes, extents, start and finish times
- **Migration 54 adds the indexes**, all standalone `CREATE … INDEX` statements:
  - `ux_cbt_active_vm`: partial unique on `(vc_host, moid)` for non-terminal
    rows, so there is one active warm import per VM;
  - `ux_cbt_snap_name`: unique on the snapshot name;
  - `ix_cbt_snap_pending`: speeds up the lookup of pending snapshots.
  - `TestMigration53And54` opens a fresh DB through the real driver.

## Required vCenter privileges

Grant these on the VM. A role scoped to just the VMs being migrated is best.
The account needs everything the cold VDDK import needs, plus:

| Privilege | Used for |
|---|---|
| Virtual machine → Change Configuration → **Toggle disk change tracking** | enable / restore CBT |
| Virtual machine → Snapshot management → **Create snapshot**, **Remove snapshot** | the per-pass snapshots |
| Virtual machine → Provisioning → **Allow read-only disk access**, **Allow disk access** | `QueryChangedDiskAreas`, VDDK reads |
| Virtual machine → Interaction → **Power off** | VMware Tools guest shutdown (only if used) |

### Password at rest

A warm import runs for hours or days and must survive a restart, including
cleaning up after one. So the vCenter password is stored sealed with the
per-install AES-GCM key: the same key that protects the AD bind password,
`<DataDir>/ad.key` or the cluster key. It is never logged or audited. The column
is wiped when the import reaches a terminal state.

Use a dedicated vCenter account for migrations.

## Audit trail

- **User actions**, via `s.audit` with the user and IP:
  - `vmware.cbt_start` (records the consent)
  - `vmware.cbt_sync_now`
  - `vmware.cbt_cutover`
  - `vmware.cbt_cancel`
- **Background source changes**, via `SysAudit`:
  - `vmware.cbt_enable`
  - `vmware.cbt_snapshot_create`
  - `vmware.cbt_snapshot_remove`
  - `vmware.cbt_snapshot_abandoned`
  - `vmware.cbt_shutdown_guest`
  - `vmware.cbt_restore`
  - `vmware.cbt_base_done`
  - `vmware.cbt_cleanup_incomplete`
  - `vmware.cbt_done`, `vmware.cbt_cancelled`, `vmware.cbt_error`
- **A per-import log** is kept at
  `<DataDir>/import-logs/vmware-<id>.log`, viewable from the **log** link.

## Limitations

- **Snapshots are crash-consistent, not quiesced.** The final pass runs with the
  VM powered off, so the imported disk is clean.
- **A CBT reset fails the import.** That covers CBT switched off, a disk resized
  or added, or vSphere invalidating the change ids. Start a new warm import.
- **Independent-mode disks are refused.** Snapshots skip them.
- **One active warm import per VM.** Different VMs can each have their own
  warm import running at the same time.
- **Staging needs space.** A staging file is as large as the disk (sparse, so
  only allocated data uses space), and the conversion makes a second copy.
- **An interrupted conversion can leave partial output.** A conversion
  interrupted by a vdxd restart in `finishing` may leave a partial qcow2 or an
  unregistered image file. The retry converts again.
- **Single-NIC model.** The instance keeps the first NIC's MAC, as with a cold
  import.

## UI

- **Quick Import dialog.**
  - The **Use CBT (warm migration)** checkbox shows the consent text, the
    required privileges and the sync interval.
  - When it is ticked, running VMs become selectable and the transfer-method
    select is hidden (warm migration always reads through VDDK).
- **Warm migrations card.** Each import has one row showing:
  - the state;
  - the step, or the error;
  - the last sync time and the next one;
  - the bytes changed in each recent pass;
  - the progress of the running job.

  Each row has **Sync now**, **Cut over…** (confirm modal, with the "Shut the
  guest down through VMware Tools" option), **Cancel** (confirm modal), and
  **log**.
- **Routes.** All are admin-only and CSRF-checked:
  - `POST /import/vmware/cbt/{id}/sync`
  - `POST /import/vmware/cbt/{id}/cutover`
  - `POST /import/vmware/cbt/{id}/cancel`

  `GET /api/vmware-import` now also returns `cbt`.

## Tests

| Test | Where | Proves |
|---|---|---|
| `TestReadOnlyDiscipline`, `TestCBTMutationsAreConsentGated` | `internal/vmware` | mutations only in `cbt.go`, each consent-gated |
| `TestCBTConsentRequired`, `TestCBTSnapshotLifecycle`, `TestCBTNeverTouchesOtherVMs`, `TestCBTShutdownGuest` | `internal/vmware` (vcsim) | the real govmomi calls; refusals; a user snapshot survives |
| `TestMigration53And54` | `internal/db` | migrations open on a fresh DB; the unique indexes hold |
| `TestCBTCopyExtentsOverNBD` | `internal/service` | delta-apply over a real NBD client against an NBD server: base, delta with zeroed blocks, out-of-range refusal, cancel |
| `TestCBTCopyLiveNBDKit` (opt-in: `VDX_CBT_LIVE_NBDKIT=1`) | `internal/service` | the same path against a **real nbdkit** (file plugin on a scratch image): socket start-up, size check, sparse base copy, delta with a zeroed region, abort by killing nbdkit |
| `TestCBTWarmImportLifecycle` … `TestCBTOneActiveImportPerVM` | `internal/service` (fake vCenter) | full lifecycle, CBT restore choice, cancel, crash recovery removing only recorded snapshots, interrupted base copy, layout change, retry limit, cut-over failure, CBT switched off, admin-only, one import per VM |
| `TestCBTWarmImportAgainstVCSim` | `internal/service` | end-to-end through the real vSphere calls on vcsim (QueryChangedDiskAreas faked; vcsim lacks it) |
| `TestCBTImportRender` | `internal/web` | the checkbox only with VDDK; modals and CSRF fields present |
