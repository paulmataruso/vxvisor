# Veeam Backup & Replication via an oVirt-compatible API

VXVisor can present itself to **Veeam Backup & Replication** (VBR) as an **oVirt / OLVM
engine**, so VBR's *Veeam Plug-in for oVirt KVM* backs up and restores VXVisor instances
with no Veeam-side changes. The same API works for anything that speaks the oVirt engine
REST API + ovirt-imageio (the oVirt Python SDK backup examples, `ovirt-imageio` client).

It is **off by default** (`[ovirt] enabled = false`), config-only to turn on and off, and
makes no outbound calls.

Code: `internal/ovirtapi` (engine REST + SSO + transfer orchestration),
`internal/imageio` (the `/images/{ticket}` data server), `internal/vmbackup` (the backup data
path: fleecing, checkpoints, NBD exports), `internal/nbd` (NBD client),
`internal/service/ovirt_service.go` (the authz/audit adapter onto VXVisor),
`internal/session/backupapi.go` (backup pins, disk-less VMs), `cmd/vdxd/ovirt.go` (listeners).
Migrations **58** (`ovirt-checkpoints`) and **59** (`ovirt-disks`).

---

## 1. Why the oVirt API

VBR has three ways a KVM platform gets in:

| Route | Who can use it |
|---|---|
| **Veeam Plug-in for oVirt KVM** — VBR talks to an oVirt/OLVM engine's REST API and to ovirt-imageio. | Anyone who implements the API. OpenNebula and Apache CloudStack ship emulators of exactly this, and Veeam documents OpenNebula as a working target. |
| **Veeam Plug-in for Universal Hypervisor API** (VBR 13) | Vendor program; today only VergeOS and Platform9 are listed. Not open to us. |
| Agent-in-guest (Veeam Agent for Linux/Windows) | Works today with no VXVisor changes, but is per-guest, not hypervisor-level. |

So VXVisor emulates the oVirt engine, like OpenNebula's `ovirtapi` and the CloudStack
`cloudstack-ovirtapi` project do.

### Sources

- Veeam plug-in for oVirt KVM user guide (VBR 13):
  `helpcenter.veeam.com/docs/vbr/userguide/` — `ovirt_overview`, `ovirt_system_requirements`,
  `platform_support_olvm_rhv`, `ovirt_permissions`, `ovirt_used_ports`,
  `ovirt_changed_block_tracking`, `ovirt_backup_job_how`, `ovirt_restore_how_entire`,
  `ovirt_restore_how_disk_restore`, `ovirt_workers*`, `ovirt_limitations_rhv`.
- The older stand-alone plug-in guide (`helpcenter.veeam.com/archive/vbrhv/6/userguide/`):
  `used_ports`, `changed_block_tracking`, `backup_job_how`, `restore_how_*`, `permissions`,
  `system_requirements`, `workers*`.
- Veeam KB4208 / KB4345 (plug-in release notes and known issues).
- Universal Hypervisor API: `helpcenter.veeam.com/docs/vbr/userguide/universal_hypervisors.html`;
  Platform9 `docs.platform9.com/private-cloud-director/integrations/veeam-integration-with-pcd`;
  VergeOS `docs.verge.io` Veeam pages.
- OpenNebula: `github.com/OpenNebula/one` `src/ovirtapi/` (Ruby emulator: `app.rb`,
  `controllers/*`), and `docs.opennebula.io/7.4/product/cluster_configuration/backup_system/veeam/`.
- CloudStack: `github.com/weizhouapache/cloudstack-ovirtapi` (Python emulator + imageio proxy).
- oVirt: the API model `ovirt.github.io/ovirt-engine-api-model/4.5/`, the incremental backup
  guide `ovirt.org/develop/incremental-backup-guide/incremental-backup-guide.html`,
  `python-ovirt-engine-sdk4` (`examples/backup_vm.py`, `upload_disk.py`, the SSO code in
  `ovirtsdk4/__init__.py`), `ovirt-imageio` (`docs/images.md`, `docs/random-io.md`,
  the client), and ovirt-engine's `OAuthTokenServlet` / `SsoService` for the SSO shapes.

### What the research established

- **Supported engines**: RHV-M 4.5.0+ (RHV 4.4 SP1) and OLVM 4.5.4+. We report engine version
  **4.5.6** and host VDSM **4.50.5.1** (VBR refuses VDSM older than 4.50.3.5 for worker deployment).
- **Account**: VBR's engine account must have **SuperUser**. It creates and deletes VMs and
  disks, so there is no meaningful "read-only" Veeam account.
- **Ports** (Veeam's tables): engine REST **443**; imageio on the host **54322**; imageio proxy
  on the engine **54323**; workers → backup server **10006**; backup server → workers **19000**;
  workers → repository per the repository's own ports.
- **Backup = oVirt incremental backup API**: `POST /vms/{id}/backups` (optionally
  `from_checkpoint_id`), poll until `ready`, one `imagetransfers` download per disk **tied to the
  backup** (`backup.id`), reading extents (`context=zero` for a full, `context=dirty` for an
  incremental), then `.../backups/{id}/finalize`. Checkpoints are kept between jobs; VBR asks
  for the VM's checkpoints and removes old ones.
- **Downloads are always inside a backup.** OpenNebula refuses a transfer without `backup.id`,
  and Veeam works against it. We do the same.
- **CBT**: only for QCOW2 disks. RAW disks get a full read every run (Veeam then dedups
  against the repository). This matches what VXVisor can do (§7).
- **Snapshots**: the docs say the plug-in "takes a snapshot" per session and deletes it after.
  OpenNebula answers snapshot create/delete with a record that goes `locked` → `ok` and does
  nothing else; Veeam is satisfied. We do the same (§5).
- **Restore of an entire VM**: VBR (to the original location) powers off and **removes the
  original VM**, creates a VM from the stored OVF (`initialization.configuration`, type `ovf`),
  creates empty disks, a worker writes the backup into each disk through an **upload** image
  transfer, the disks are attached, the NICs are wired to vNIC profiles. **Disk restore**
  detaches and removes the original disks, then creates/uploads/attaches new ones.
- **Workers** are Linux VMs VBR deploys **into the cluster** through the same API (1 vCPU + 1 GB
  per concurrent task) and powers on/off per session; VBR 12.3+ also deploys a **backup appliance**
  VM (Rocky 8.10, 6 vCPU, 6 GB, 100 GB per OpenNebula's docs). The worker's network settings are
  given in VBR (DHCP or static); cloud-init `custom_script` user-data is how the emulators pass
  it in. Workers fetch package updates from the internet unless that is disabled in VBR.
- **OpenNebula's operating notes** (useful here too): the address added in VBR must match the
  engine's public address/certificate; an untrusted-certificate prompt is expected; the
  appliance has no guest contextualisation (use DHCP or a static IP); avoid spaces in VM names;
  a "Switched to proxy URL" warning on uploads is harmless; host names given to workers must
  resolve.

### What the research could NOT confirm

Stated plainly; each is either handled defensively or called out as a risk in §9.

1. **Exact call order and every field VBR reads.** No Veeam traffic capture was available. The
   endpoint set is the union of what the two working emulators implement plus what the oVirt SDK
   backup/upload examples use. A field VBR needs that neither emulator serves would surface as a
   job error.
2. **Auth method.** The SDK uses the SSO password grant then Bearer; some tools use HTTP Basic.
   Both are implemented. Whether VBR sends `Prefer: persistent-auth`/`Filter: true` and expects
   any specific behaviour from them is unknown; both headers are accepted and ignored.
3. **XML vs JSON.** The SDK sends `Accept: application/xml` + `Version: 4`; OpenNebula serves
   JSON by default. We serve XML when asked and JSON otherwise.
4. **Version / product checks.** OpenNebula reports product `0.0.0` and still works, which
   suggests VBR does not gate on the engine version; we report 4.5.6 anyway.
5. **Snapshot use.** Whether VBR ever *reads* through a snapshot (rather than the backup) could
   not be confirmed; nothing in either emulator supports that, so it is not offered.
6. **How the worker's OS disk is provisioned** (an upload of a Veeam image, which format, or a
   template) was not visible in any source. If VBR uploads a **qcow2 container** into a
   `format=cow` transfer, the upload is refused with a clear 400 (see §9, "RawOnly").
7. **OVF `BiosType` numbering.** Real oVirt 4.5 numbers it 1–4 with 0 = cluster default; the
   emulators use 0–3 (0 i440fx SeaBIOS … 3 q35 Secure Boot). We follow the emulators; a
   VXVisor → VXVisor restore doesn't depend on it (see §6).
8. **JSON fault shape** and the **SSO `exp` unit**: we send oVirt's XML fault
   (`<fault><reason/><detail/></fault>`) and its JSON mirror, and `exp` in milliseconds as the
   engine does; the SDK accepts both, VBR's handling is unverified.
9. **`format=cow` on upload transfers**: OpenNebula echoes the format and writes guest data; we
   do the same (§5).

---

## 2. Object mapping

All oVirt ids are stable UUIDs. Ids VXVisor already has are used directly; the rest are
UUIDv5 names under a fixed namespace (`6f1d9a3e-2c4b-5e7a-9d1f-0a8b7c6d5e4f`), so they survive
restarts with nothing stored.

| oVirt | VXVisor | Notes |
|---|---|---|
| Data center, cluster | this host | One of each. `node_name` is the name. |
| Host | this host | CPU/memory/OS/QEMU version from `/proc` and `qemu-system-x86_64 --version`; `address` = `public_host`. |
| Storage domain | storage pool | Pool 0 = `paths.disk_dir`. File-backed pools (dir, NFS, CIFS, ZFS dataset) are upload targets; LVM/RBD are listed but not upload targets (§7). Size/free via `statfs`. |
| VM | instance (`sessions`) | id = instance UUID. Local node only; Trash is hidden. All orgs (instance admin). |
| Disk | the instance's single disk | id = a UUIDv5 of the VM id, unless the disk was created through the API (`ovirt_disks`). `format` cow for qcow2, raw for zvol/LVM/RBD. |
| Disk attachment | the instance ↔ its disk | Exactly one per VM. Bus virtio / virtio_scsi / sata. |
| Network, vNIC profile | port group (`networks`) | One profile per network; id = UUIDv5 of the network id. NetID 0 = **`vxvisor-nat`** (SLIRP user-net). Tenant port groups are named `<org-slug>/<name>`. |
| NIC | the instance's one NIC | MAC, model (virtio/e1000/rtl8139), profile; reported devices carry guest-agent IPs. |
| Checkpoint | persistent qcow2 dirty bitmap `vdxckpt-<id>` + `ovirt_checkpoints` row | Parent chain kept; an inconsistent bitmap is reported as an invalid checkpoint. |
| Backup | an NBD export (fleecing or qemu-nbd) | In memory; ends on finalize, failure or 2 h idle. |
| Image transfer | an imageio ticket over that export | In memory. |
| Snapshot | a record only | "Active VM" + whatever the client created; no disk state. |
| Job, tag | empty lists | Present because clients follow the links. |

---

## 3. Endpoint subset

Prefix `/ovirt-engine/api` (a `/v4` prefix is accepted too). XML or JSON per `Accept`.
Lists honour `search=name=…` / `id=…`, `max`, and `follow=` for the links VBR follows.

| Area | Endpoints |
|---|---|
| SSO | `POST/GET /ovirt-engine/sso/oauth/token` (password grant), `/ovirt-engine/services/sso-logout`, `/sso/oauth/revoke`; HTTP Basic on any API call. |
| CA | `GET /ovirt-engine/services/pki-resource?resource=ca-certificate` |
| Root | `GET /` (product info, summary, `special_objects`, authenticated user) |
| Inventory | `datacenters`, `clusters` (+ `/networks`), `hosts` (+ `/statistics`), `storagedomains` (+ `/disks`), `networks`, `vnicprofiles`, `tags`, `jobs` |
| VMs | `GET/POST /vms`, `GET/PUT/DELETE /vms/{id}` (`detach_only`), `start`, `stop`, `shutdown`, `poweroff`, `reboot` |
| VM children | `diskattachments` (GET/POST/DELETE), `disks` (legacy), `nics` (GET/POST/PUT), `reporteddevices`, `snapshots` (GET/POST/DELETE), `backups`, `checkpoints`, `tags` |
| Disks | `GET/POST /disks`, `GET/PUT/DELETE /disks/{id}`, `POST /storagedomains/{id}/disks` |
| Backups | `POST /vms/{id}/backups` (`from_checkpoint_id`, disks), `GET …/backups/{id}`, `…/disks` (with `backup_mode` full/incremental), `POST …/finalize` |
| Checkpoints | `GET /vms/{id}/checkpoints[/{id}]`, `DELETE` (refused while a backup runs) |
| Transfers | `GET/POST /imagetransfers` (download with `backup.id`, or upload to a disk), `GET /imagetransfers/{id}`, `finalize`, `cancel`; `extend`/`pause`/`resume` accepted as no-ops. Both `transfer_url` (imageio listener) and `proxy_url` (API listener) are returned. |
| imageio | `OPTIONS/GET/PUT/PATCH /images/{ticket}`, `GET /images/{ticket}/extents?context=zero|dirty`, `GET /info` — on both listeners. |

Everything else answers a proper oVirt `404` fault.

---

## 4. Backup data path (`internal/vmbackup`)

**Running VM — pull mode, as libvirt does it.** In one QMP `transaction`:
a scratch qcow2 *fleecing* node (under `work_dir`) whose backing is the live disk node, a
`blockdev-backup sync=none` copy-before-write job into it, and — for qcow2 — the new
checkpoint's persistent bitmap `vdxckpt-<new>`. The fleecing node is the disk frozen at that
instant while the guest keeps running. For an incremental, the base checkpoint's bitmap is
merged into a disabled temporary bitmap in the same transaction. The node is exported
read-only by QEMU's own NBD server on a **unix socket** (never TCP), with
`qemu:dirty-bitmap:` for the increment. On finalize the export, job and fleecing node are
removed; on failure the new checkpoint's bitmap is removed too, so the chain stays truthful.

**Stopped VM.** `qemu-nbd --read-only` on the image (`--bitmap` for an incremental). qemu-nbd
holds the image lock, and the VM is **pinned** (below), so it can't start mid-backup.

**Checkpoints.** One persistent enabled bitmap per checkpoint. Each records every write since
its own checkpoint, so "incremental since C" is exactly bitmap C — no chain merges. A bitmap
QEMU couldn't flush cleanly (killed process) comes back `in-use`/`inconsistent`; the API
reports that checkpoint as invalid and refuses an incremental from it (`400 … a full backup is
required`), which makes VBR fall back to a full. A backup start also drops `vdxckpt-` bitmaps
the database doesn't know (from a backup that never finalized).

**Uploads (restore).** `qemu-nbd` writable on the target image (`-f qcow2` or raw), same
imageio front end.

**imageio server (`internal/imageio`).** Range GETs, PUT at `Content-Range`, `PATCH` zero and
flush, `extents` (zero = `base:allocation`; dirty = the bitmap context merged with allocation),
up to 4 NBD connections per ticket. Each request is relayed to the NBD export; nothing is
buffered to disk.

**Backup pins (`session.PinBackup`).** While a backup or upload holds a VM: no Start (if
stopped), Delete, Purge, Resize, Snapshot/Revert, storage move, or cluster migration. Anything
that rewrites the disk's history also drops its checkpoints (revert, storage move, resize,
disk replacement), so the next backup is a full.

**Crash recovery.** On start, `RecoverBackups` removes fleecing nodes / exports / jobs left in
running QEMUs, kills orphaned qemu-nbd, and sweeps `work_dir`.

---

## 5. Restore and workers

- **`POST /vms`** creates a **disk-less** instance (`CreateBare`) from either the OVF
  (`initialization.configuration`, type ovf) or plain fields; explicit fields win. CPU = the
  topology product, memory in MiB, firmware from `bios.type`, OS type, machine type.
  `initialization.custom_script` becomes **raw cloud-init user-data** (NoCloud seed).
  Duplicate live names are refused. Quota is checked against the target org.
- The OVF we hand out carries a `vxvisor:Instance` element (org, firmware, Secure Boot,
  machine, buses, NIC model, VGA, guest agent, TPM, port group, MAC), so a **VXVisor → VXVisor
  restore is exact**. A restore onto the **same install** lands in the org it was backed up
  from. The org is trusted only when the OVF's `vxvisor:engine` matches this install's engine
  id (derived from the per-install CA): org numbers are local, so a backup restored onto
  another VXVisor host must not land in whichever tenant there shares the number. Restores
  from another install, and OVFs from other platforms (standard oVirt fields only), land in
  the provider org.
- **`POST /disks`** creates an empty `ovirt-<id>.qcow2` on a file-backed pool (512-aligned,
  refused unless ≥ 1 GiB stays free) as a **staged** disk; an upload writes it; attaching it
  to a stopped disk-less VM makes it that VM's disk. Detaching (qcow2 only) turns it back into
  a staged disk.
- A NIC is bound to a vNIC profile (= port group) of the **same org** (or `vxvisor-nat`).
- **Purpose.** VMs created through the API are tagged `worker` (no OVF) or `restore` (OVF).
  Deleting a **worker** purges it; deleting anything else — including the original VM VBR
  removes during an in-place restore — moves it to **Trash**, like a UI delete, so an in-place
  restore is recoverable until Trash is emptied.

Networking for workers: VBR reaches workers inbound (19000) and workers reach the engine
(443/54322), the backup server (10006) and the repository. **Put workers on a bridged
provider port group** that routes to the management network and the Veeam server — not
`vxvisor-nat` (SLIRP has no inbound path) and not a tenant network (tenant networks are
isolated from the host by design).

---

## 6. Security model

- **Listeners.** Two TLS listeners, both bound to **one specific IP** — by default the IP of
  `[server] addr` (the management IP): the engine on `:443`, imageio on `:54322`. A wildcard or
  hostname bind is refused at startup. The admin UI listener is unchanged; VNC/QMP/SPICE stay on
  loopback; NBD exports are unix sockets under `work_dir` (mode 0700), never TCP.
- **TLS.** A per-install CA (`<data_dir>/ovirt-ca.{crt,key}`) and a server certificate it issues
  (`ovirt-tls.{crt,key}`, SANs = `public_host`, the listen IPs), created on first start, stored
  like the other per-install secrets (`internal/secrets`; private keys 0600). The CA is published at the
  oVirt `pki-resource` URL so VBR can show and pin it. TLS 1.2+.
- **Authentication.** vdxd's own local users (`auth.Authenticate`, including its per-username
  failed-login throttle, which is shared with the web login). **Only enabled instance admins**
  are accepted; anyone else gets the same "denied" answer as a bad password. Every request
  re-checks (`Bind`) that the user still exists, is enabled and is still an admin, so disabling
  or demoting a user cuts off live tokens at once. SSO tokens: 12 h lifetime, 1 h idle. Basic
  credentials are cached for 1 minute (hashed) to avoid a bcrypt per request. AD/OIDC users
  can't use this API (no password grant for them).
- **Authorization.** The API acts as an instance admin across all orgs, through the service
  layer (`OvirtBackend`), with every existing guard: quota, org-scoped port groups,
  disk-in-use, backup pins.
- **Tickets.** Random (UUIDv4, 122 bits), one per transfer, scoped to **one disk and one
  direction**, expire on inactivity (default 60 s, client-settable) and in any case after 24 h,
  and are revoked the moment the transfer finalizes or is cancelled (then 403). A ticket is the
  only credential on `/images/` — exactly oVirt's model — which is why both listeners are TLS
  and bound to the management IP.
- **Audit.** Every mutation is in the audit log with the user and client IP:
  `ovirt.login` / `login_denied` / `login_failed`, `ovirt.vm.create` / `delete`,
  `ovirt.disk.create` / `delete` / `attach` / `detach`, `ovirt.nic.model`,
  `ovirt.backup.start` / `start_failed` / `finalize` / `abandoned`,
  `ovirt.checkpoint.remove`, `ovirt.snapshot.record` / `remove`,
  `ovirt.transfer.start` / `start_failed` / `finalize` / `cancel` / `timeout`, plus the
  normal start/stop/network-change entries of the service layer.
- **No outbound calls.** The API only answers; it never contacts Veeam or anything else.

### Proposed: a "backup operator" role (not implemented)

A dedicated role (users that may use this API but not the web UI or host operations) is the
natural next step: a `backup_operator` flag on `users` (migration 60 was reserved for it and is
**unused**), accepted by `Login`/`Bind` instead of `IsAdmin`, refused by the web login. It was
left out because VBR needs SuperUser-equivalent rights on VMs anyway — it creates, powers off
and **deletes** VMs and disks during restores — so the role would mainly keep the Veeam
account out of the UI and host operations (networking, storage, users). Worth doing before
giving the Veeam account to a different team than the VXVisor admins.

---

## 7. Supported and not supported

| | Status | Why |
|---|---|---|
| Full backup, running VM | ✅ qcow2, zvol, LVM | QMP fleecing works on any QEMU node. |
| Full backup, stopped VM | ✅ qcow2, zvol, LVM; RBD untested | qemu-nbd on the image; RBD needs QEMU's rbd block module, which the host already has if it runs RBD VMs. |
| Incremental (CBT) | ✅ **qcow2 only** | Persistent dirty bitmaps live in the qcow2. **zvol / LVM / RBD = full every time** (raw has nowhere to store a bitmap that survives a restart). Same as oVirt itself and as Veeam documents. |
| Restore (entire VM, disk restore) | ✅ onto file-backed pools | Staged disks are qcow2 files created by `qemu-img`. Restoring onto zvol/LVM/RBD needs a block-volume create path — not done. |
| Multiple disks per VM | ❌ | A VXVisor instance has exactly one disk. A multi-disk restore attaches the first disk and refuses the rest. |
| Detach (disk restore of an existing VM) | qcow2 only | Detaching a zvol/LVM/RBD disk would need block-volume ownership tracking. |
| Plain disk download (no backup) | ❌ | Unsafe point in time; VBR doesn't need it (§1). |
| Snapshots | records only | VBR's snapshot is bookkeeping; the backup itself provides the point in time. |
| Application-consistent backup | ❌ | No guest freeze yet (VBR doesn't offer it for oVirt either). |
| Instant recovery, replicas | ❌ | Not part of the oVirt plug-in for KVM targets. |
| VMs on other cluster nodes | not listed | One engine per host; add each VXVisor host to VBR separately. |
| Containers (LXC) | ❌ | Not VMs. |
| AD / OIDC users | ❌ | Password grant only against local users. |
| IPv6 | n/a | Veeam's plug-in doesn't support it. |

---

## 8. Configuration and operations

```toml
[ovirt]
enabled = true
# listen = "<mgmt-ip>:443"            # default: [server] addr's IP, port 443 (must be a specific IP)
# imageio_listen = "<mgmt-ip>:54322"  # default: the listen IP, port 54322
# public_host = "vxhost.example.lan"  # the name VBR uses; in the cert and transfer URLs. Default: listen IP
# product_name = ""                   # engine product name shown to clients
# work_dir = ""                       # default <data_dir>/backup-work; ≤ 52 bytes (NBD socket paths)
```

- Restart vdxd after changing it. **Rollback:** `enabled = false` (or delete the block) and
  restart — the listeners are gone; the tables from migrations 58/59 stay and are harmless.
  Checkpoint bitmaps stay inside qcow2 images; they cost a little write tracking and are
  removed by the next backup start or `qemu-img bitmap --remove`.
- `work_dir` must be on local disk with room for **guest writes made during a backup** (the
  fleecing image grows by what the guest overwrites while VBR reads).
- Firewall: allow 443 and 54322 to the management IP from the Veeam server, its proxies and the
  workers.
- Host tools: `qemu-img` and `qemu-nbd` (`qemu-utils`, already a hard requirement of
  `deploy/install.sh`).

### Adding VXVisor to Veeam

1. Enable `[ovirt]`, restart vdxd, check the log line
   `oVirt-compatible backup API listening on …`.
2. In VBR: *Backup Infrastructure → Managed Servers → Add → Virtualization Platforms → oVirt KVM*
   (*Oracle Linux Virtualization Manager / Red Hat Virtualization* in older releases). Address =
   `public_host`, port 443, credentials = a VXVisor **instance admin** (user name with or
   without `@internal`). Accept the certificate (issued by "VXVisor backup API CA").
3. Add a worker: pick the host, a **bridged provider port group** (§5), DHCP or a static IP;
   test it. Disable online updates for the worker if it has no internet access.
4. Create a backup job with VXVisor VMs, run it twice (full, then incremental), restore one VM
   to a new name, then restore one in place.

---

## 9. Testing

- **Unit** (`go test ./internal/...`): golden XML/JSON shapes for every inventory/VM/disk/NIC/
  checkpoint/snapshot/fault response (`internal/ovirtapi/testdata`, regenerate with
  `go test ./internal/ovirtapi -run TestGoldenShapes -update`), SSO + Basic + token expiry,
  restore from an OVF, the worker lifecycle, backup/transfer refusals; imageio ranges, PUT/PATCH,
  extents, dirty merge, ticket lifecycle and the RawOnly guard; the NBD client against
  qemu-nbd semantics; config address rules; the per-install CA; migrations 58/59 on a fresh DB;
  the service adapter (admin-only login, `Bind` cutting off a disabled user, pools, port groups,
  staged disks, pins, worker purge vs Trash).
- **Data path on a real QEMU** (`internal/vmbackup`, `VDX_HOST_QEMU=1`): full + incremental of a
  running VM with guest writes during the backup, the same on a stopped disk, a failed backup's
  checkpoint rollback, a writable upload export, imageio on top. Build with
  `CGO_ENABLED=0 go test -c ./internal/vmbackup`, run the binary on a VM host.
- **Conformance with the real clients** (`internal/ovirtapi/host_test.go`, `VDX_HOST_OVIRT=1`):
  runs `testdata/sdk_conformance.py` with **ovirt-engine-sdk-python 4.6** and **ovirt-imageio 2.5**
  (in a venv; `VDX_SDK_PYTHON`, `VDX_SDK_SCRIPT`) against the API over TLS on loopback and a
  scratch QEMU: SSO, inventory, snapshot record, full backup with guest writes during it,
  incremental downloaded onto the full as a backing file and compared with `qemu-img compare`,
  an invalid checkpoint refused, checkpoint removal, an incremental of the stopped VM, a restore
  (disk create + upload + VM from the OVF + attach + NIC + start) compared byte-for-byte with the
  source, and a worker VM with `custom_script`. Passed on QEMU 10.2 / Python 3.14.
- **Not yet done: a real VBR.** See the checklist in §8 ("Adding VXVisor to Veeam"). Watch the
  vdxd log and the audit log for refused calls; a 404 fault on a path this table doesn't list,
  or a 400 from the RawOnly guard, is the first thing to look for.

### Known risks

- **Untested against real VBR** — §1 lists what couldn't be confirmed. The most likely gaps are
  a field VBR reads that neither emulator serves, and how VBR provisions the worker's disk.
- **RawOnly**: an upload transfer whose first write is a qcow2 header is refused (400) rather
  than written as guest data (which would produce an unbootable disk). If VBR really uploads
  qcow2 containers for its worker image, container uploads must be added (stage the file, then
  `qemu-img convert`).
- **In-place restore** sends the original VM to Trash; its disk stays on the pool until Trash
  is emptied — size the pool for it.
- **Basic auth with a wrong password** trips the per-username login throttle, which also
  briefly blocks that user's web login.
