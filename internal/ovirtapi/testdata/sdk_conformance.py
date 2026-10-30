#!/usr/bin/env python3
"""
oVirt Python SDK + ovirt-imageio client conformance run against the VXVisor
engine API. Driven by TestHostSDKConformance (internal/ovirtapi/host_test.go),
which serves the API on loopback over TLS in front of a scratch QEMU and
exposes hooks: /write (a guest write via qemu-io), /stop (QEMU quits cleanly),
/compare?path= and /compare-disk?id= (qemu-img compare with the VM's disk).

Every step uses the SDK the way backup software does; any deviation raises.
"""

import argparse
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

import ovirtsdk4 as sdk
import ovirtsdk4.types as types
from ovirt_imageio import client

BLANK = "00000000-0000-0000-0000-000000000000"
MiB = 1 << 20


def step(msg):
    print("==> " + msg, flush=True)


def hook(base, endpoint, **params):
    url = base + endpoint + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, data=b"", method="POST")
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read().decode()


def wait(get, ok, what, timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        v = get()
        if ok(v):
            return v
        if time.monotonic() > deadline:
            raise RuntimeError("timed out waiting for " + what)
        time.sleep(0.3)


def expect(cond, msg):
    if not cond:
        raise AssertionError(msg)


def wait_transfer(ts):
    deadline = time.monotonic() + 120
    while True:
        try:
            t = ts.get()
        except sdk.NotFoundError:
            return
        if t.phase == types.ImageTransferPhase.FINISHED_SUCCESS:
            return
        if t.phase == types.ImageTransferPhase.FINISHED_FAILURE:
            raise RuntimeError("transfer failed")
        if time.monotonic() > deadline:
            raise RuntimeError("transfer did not finish (phase %s)" % t.phase)
        time.sleep(0.3)


def start_backup(vm_service, disk_id, from_cp, desc):
    backups = vm_service.backups_service()
    b = backups.add(types.Backup(disks=[types.Disk(id=disk_id)], from_checkpoint_id=from_cp,
                                 description=desc))
    bs = backups.backup_service(b.id)
    b = wait(bs.get, lambda x: x.phase == types.BackupPhase.READY, "backup ready")
    disks = bs.disks_service().list()
    expect(len(disks) == 1 and disks[0].id == disk_id, "backup disks %r" % disks)
    mode = types.DiskBackupMode.INCREMENTAL if from_cp else types.DiskBackupMode.FULL
    expect(disks[0].backup_mode == mode, "backup_mode %s, want %s" % (disks[0].backup_mode, mode))
    expect(b.to_checkpoint_id, "backup has no to_checkpoint_id")
    if from_cp:
        expect(b.from_checkpoint_id == from_cp, "from_checkpoint_id %s" % b.from_checkpoint_id)
    return b, bs


def download(conn, backup, disk_id, out, ca, backing=None):
    its = conn.system_service().image_transfers_service()
    t = its.add(types.ImageTransfer(disk=types.Disk(id=disk_id), backup=types.Backup(id=backup.id),
                                    direction=types.ImageTransferDirection.DOWNLOAD,
                                    format=types.DiskFormat.RAW, inactivity_timeout=120))
    ts = its.image_transfer_service(t.id)
    t = wait(ts.get, lambda x: x.phase == types.ImageTransferPhase.TRANSFERRING, "transfer")
    expect(t.transfer_url and t.proxy_url, "transfer urls missing")
    client.download(t.transfer_url, out, ca, fmt="qcow2", incremental=backing is not None,
                    proxy_url=t.proxy_url, backing_file=backing,
                    backing_format="qcow2" if backing else None)
    ts.finalize()
    wait_transfer(ts)


def finish_backup(bs):
    bs.finalize()
    b = wait(bs.get, lambda x: x.phase in (types.BackupPhase.SUCCEEDED, types.BackupPhase.FAILED),
             "backup finalize")
    expect(b.phase == types.BackupPhase.SUCCEEDED, "backup phase %s" % b.phase)
    return b


def raw_bytes(path, work, off, n):
    raw = os.path.join(work, "check.raw")
    subprocess.run(["qemu-img", "convert", "-O", "raw", path, raw], check=True)
    with open(raw, "rb") as f:
        f.seek(off)
        data = f.read(n)
    os.unlink(raw)
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--hook", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    w = a.work

    step("connect (SSO password grant)")
    conn = sdk.Connection(url=a.engine + "/ovirt-engine/api", username="admin@internal",
                          password="secret", ca_file=a.ca)
    conn.test(raise_exception=True)
    system = conn.system_service()
    api = system.get()
    expect(api.product_info.version.major == 4, "product version %r" % api.product_info.version)
    print("    product:", api.product_info.name, api.product_info.version.full_version)

    step("inventory")
    dcs = system.data_centers_service().list()
    clusters = system.clusters_service().list()
    hosts = system.hosts_service().list()
    sds = system.storage_domains_service().list()
    nets = system.networks_service().list()
    profiles = system.vnic_profiles_service().list()
    expect(len(dcs) == 1 and len(clusters) == 1 and len(hosts) == 1, "one dc/cluster/host")
    expect(hosts[0].status == types.HostStatus.UP, "host status %s" % hosts[0].status)
    expect(clusters[0].version.major == 4 and clusters[0].version.minor == 7, "cluster level")
    sd = next(s for s in sds if s.name == "default")
    expect(sd.type == types.StorageDomainType.DATA, "storage domain type %s" % sd.type)
    lan = next(p for p in profiles if p.name == "lan")
    expect(any(n.name == "lan" and n.vlan and n.vlan.id == 20 for n in nets), "network vlan")
    dc_sds = system.data_centers_service().data_center_service(dcs[0].id).storage_domains_service().list()
    expect(any(s.id == sd.id and s.status == types.StorageDomainStatus.ACTIVE for s in dc_sds),
           "attached storage domain")

    vms = system.vms_service()
    found = vms.list(search="name=web01")
    expect(len(found) == 1, "search name=web01 -> %d" % len(found))
    vm = found[0]
    expect(vm.status == types.VmStatus.UP, "vm status %s" % vm.status)
    vm_service = vms.vm_service(vm.id)
    atts = vm_service.disk_attachments_service().list()
    expect(len(atts) == 1, "attachments %d" % len(atts))
    disk = system.disks_service().disk_service(atts[0].disk.id).get()
    expect(disk.backup == types.DiskBackup.INCREMENTAL, "disk backup %s" % disk.backup)
    expect(disk.format == types.DiskFormat.COW, "disk format %s" % disk.format)
    expect(disk.provisioned_size == 64 * MiB, "disk size %d" % disk.provisioned_size)
    nics = vm_service.nics_service().list()
    expect(len(nics) == 1 and nics[0].vnic_profile.id == lan.id, "nic profile")
    full_vm = vm_service.get(all_content=True, follow="disk_attachments.disk,nics.reporteddevices")
    ovf = full_vm.initialization.configuration.data
    expect("ovf:Envelope" in ovf, "OVF missing")
    expect(full_vm.disk_attachments[0].disk.id == disk.id, "followed disk")
    expect(full_vm.nics[0].reported_devices[0].ips[0].address, "reported IP")

    step("snapshot record")
    snaps = vm_service.snapshots_service()
    sn = snaps.add(types.Snapshot(description="pre-backup", persist_memorystate=False))
    expect(len(snaps.list()) == 2, "snapshots list")
    snaps.snapshot_service(sn.id).remove()

    step("full backup of the running VM, guest writing during it")
    hook(a.hook, "/write", pattern="0x11", offset=0, length=MiB)
    b1, bs1 = start_backup(vm_service, disk.id, None, "full")
    hook(a.hook, "/write", pattern="0x22", offset=MiB, length=MiB)  # after the point in time
    full = os.path.join(w, "full.qcow2")
    download(conn, b1, disk.id, full, a.ca)
    b1 = finish_backup(bs1)
    cp1 = b1.to_checkpoint_id
    expect(raw_bytes(full, w, 0, 4) == b"\x11" * 4, "full backup content")
    expect(raw_bytes(full, w, MiB, 4) == b"\x00" * 4, "full backup includes a later write")

    step("incremental backup of the running VM")
    hook(a.hook, "/write", pattern="0x33", offset=4 * MiB, length=64 * 1024)
    b2, bs2 = start_backup(vm_service, disk.id, cp1, "incremental")
    inc = os.path.join(w, "inc1.qcow2")
    download(conn, b2, disk.id, inc, a.ca, backing=full)
    b2 = finish_backup(bs2)
    cp2 = b2.to_checkpoint_id
    hook(a.hook, "/compare", path=inc)  # full + incremental == the disk now
    cps = vm_service.checkpoints_service().list()
    expect([c.id for c in cps] == [cp1, cp2], "checkpoints %r" % [c.id for c in cps])
    expect(cps[1].parent_id == cp1, "checkpoint parent")

    step("an unknown base checkpoint is refused")
    try:
        start_backup(vm_service, disk.id, "00000000-0000-4000-8000-00000000dead", "bad")
        raise AssertionError("bogus checkpoint accepted")
    except sdk.Error as e:
        expect(e.code == 400, "bogus checkpoint -> %s" % e.code)

    step("checkpoint removal")
    vm_service.checkpoints_service().checkpoint_service(cp1).remove()
    expect([c.id for c in vm_service.checkpoints_service().list()] == [cp2], "after removal")

    step("incremental backup of the stopped VM (qemu-nbd)")
    hook(a.hook, "/write", pattern="0x44", offset=8 * MiB, length=64 * 1024)
    hook(a.hook, "/stop")
    expect(vm_service.get().status == types.VmStatus.DOWN, "vm not down")
    b3, bs3 = start_backup(vm_service, disk.id, cp2, "stopped incremental")
    inc2 = os.path.join(w, "inc2.qcow2")
    download(conn, b3, disk.id, inc2, a.ca, backing=inc)
    finish_backup(bs3)
    hook(a.hook, "/compare", path=inc2)

    step("restore: staged disk + upload")
    disks = system.disks_service()
    nd = disks.add(types.Disk(name="web01-restored-disk", format=types.DiskFormat.COW,
                              provisioned_size=disk.provisioned_size, backup=types.DiskBackup.INCREMENTAL,
                              storage_domains=[types.StorageDomain(id=sd.id)]))
    nds = disks.disk_service(nd.id)
    wait(nds.get, lambda d: d.status == types.DiskStatus.OK, "disk ok")
    its = system.image_transfers_service()
    t = its.add(types.ImageTransfer(disk=types.Disk(id=nd.id), direction=types.ImageTransferDirection.UPLOAD,
                                    format=types.DiskFormat.RAW, inactivity_timeout=120))
    ts = its.image_transfer_service(t.id)
    t = wait(ts.get, lambda x: x.phase == types.ImageTransferPhase.TRANSFERRING, "upload transfer")
    client.upload(inc2, t.transfer_url, a.ca, proxy_url=t.proxy_url)
    ts.finalize()
    wait_transfer(ts)
    hook(a.hook, "/compare-disk", id=nd.id)

    step("restore: VM from the backed-up OVF, attach, NIC, start")
    nv = vms.add(types.Vm(name="web01-restored", cluster=types.Cluster(id=clusters[0].id),
                          template=types.Template(id=BLANK),
                          initialization=types.Initialization(configuration=types.Configuration(
                              type=types.ConfigurationType.OVF, data=ovf))))
    nvs = vms.vm_service(nv.id)
    nvs.disk_attachments_service().add(types.DiskAttachment(disk=types.Disk(id=nd.id), bootable=True,
                                                            active=True,
                                                            interface=types.DiskInterface.VIRTIO_SCSI))
    nvs.nics_service().add(types.Nic(name="nic1", vnic_profile=types.VnicProfile(id=lan.id)))
    nvs.start()
    expect(nvs.get().status == types.VmStatus.UP, "restored vm not up")
    hook(a.hook, "/compare-disk", id=nd.id)
    nvs.stop()
    nvs.remove()

    step("backup worker: VM with cloud-init, created and removed")
    wv = vms.add(types.Vm(name="veeam-worker-conformance", cluster=types.Cluster(id=clusters[0].id),
                          template=types.Template(id=BLANK), memory=2 << 30,
                          cpu=types.Cpu(topology=types.CpuTopology(sockets=2, cores=1, threads=1)),
                          bios=types.Bios(type=types.BiosType.Q35_OVMF),
                          os=types.OperatingSystem(type="other_linux"),
                          initialization=types.Initialization(
                              custom_script="#cloud-config\nruncmd:\n  - echo conformance-worker\n")))
    vms.vm_service(wv.id).remove()

    conn.close()
    step("all conformance steps passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # report and fail
        print("FAILED: %s: %s" % (type(e).__name__, e), file=sys.stderr, flush=True)
        raise
