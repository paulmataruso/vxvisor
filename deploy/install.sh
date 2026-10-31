#!/usr/bin/env bash
# VDXClone host installer.
#   sudo ./install.sh [--ip <bind-ip>] [--no-admin] [--dir <staging-dir>]
#                     [--mgmt-vswitch [--mgmt-vswitch-name NAME] | --no-vswitch] [--no-tune] [--hugepages PCT]
#
# Installs the vdxd binary, runtime dependencies, a dedicated run-as user,
# a systemd unit, and a host config. Idempotent: safe to re-run (it upgrades
# the binary and leaves an existing /etc/vdxclone/config.toml untouched).
#
# It can also convert the management interface into a default vSwitch bridge
# (ESXi-style) so VMs can share the uplink. That step is SAFE BY DESIGN: it
# clones the NIC MAC, preserves the exact addressing, and arms an automatic
# rollback so a failed apply can never leave the host unreachable.
set -euo pipefail

# ---- args ----------------------------------------------------------------
BIND_IP=""
MAKE_ADMIN=1
SETUP_VSW="ask"       # ask (prompt if interactive) | yes | no
VSW_NAME="vSwitch0"
TUNE_HOST=1           # apply safe host performance tuning (--no-tune to skip)
HUGEPAGES_PCT=0       # reserve this %% of RAM as 2 MiB hugepages (--hugepages N)
GET_VIRTIO_WIN=1      # download the virtio-win driver ISO (--no-virtio-win to skip)
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --ip)                BIND_IP="$2"; shift 2 ;;
    --no-admin)          MAKE_ADMIN=0; shift ;;
    --dir)               SRC_DIR="$2"; shift 2 ;;
    --mgmt-vswitch)      SETUP_VSW=yes; shift ;;
    --mgmt-vswitch-name) VSW_NAME="$2"; SETUP_VSW=yes; shift 2 ;;
    --no-vswitch)        SETUP_VSW=no; shift ;;
    --no-tune)           TUNE_HOST=0; shift ;;
    --hugepages)         HUGEPAGES_PCT="$2"; shift 2 ;;
    --no-virtio-win)     GET_VIRTIO_WIN=0; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

die(){ echo "ERROR: $*" >&2; exit 1; }
say(){ echo -e "\n\033[1;36m==>\033[0m $*"; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"

# ---- preflight -----------------------------------------------------------
say "Preflight checks"
[ "$(uname -m)" = "x86_64" ] || die "host is $(uname -m); an amd64 (x86_64) host is required"
if [ ! -e /dev/kvm ]; then
  echo "  WARNING: /dev/kvm is missing — guests will run without KVM (very slow)."
  echo "           On bare metal enable VT-x/AMD-V in BIOS; on a cloud VM enable nested virt."
else
  echo "  /dev/kvm present"
fi
VIRT=$(grep -Ec '(vmx|svm)' /proc/cpuinfo || true)
echo "  virtualization-capable CPUs: ${VIRT}"
[ -f "$SRC_DIR/vdxd" ] || die "vdxd binary not found next to this script ($SRC_DIR/vdxd)"

if [ -z "$BIND_IP" ]; then
  BIND_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '!f{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); f=1; break}}')
  [ -n "$BIND_IP" ] || die "could not auto-detect an IP; pass --ip <addr>"
  echo "  auto-detected bind IP: $BIND_IP  (override with --ip)"
else
  echo "  bind IP: $BIND_IP"
fi

# ---- dependencies --------------------------------------------------------
say "Installing runtime dependencies (apt)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# apt_opt installs whatever of the given packages actually have an install
# candidate on this release. A package with NO candidate on this Ubuntu/Debian
# (name differs or doesn't exist here) is skipped with a warning — that is the
# only tolerated miss. But a package that HAS a candidate and then FAILS to
# install is a hard error: silently swallowing it (the old `|| true`) is exactly
# how a UI feature ends up dead on a host with no trace. Every tool the UI can
# drive must really be installed, so we fail loudly instead.
#
# Under `set -o pipefail` never pipe a command into something that stops reading
# early (`grep -q`, `head`, `awk …exit`): the writer dies of SIGPIPE and the
# pipeline fails even on a match. apt-cache flushes per line, so the old
# `apt-cache policy | grep -q` called EVERY package "no install candidate" and
# skipped them all.
apt_opt(){
  local want="$*" have=() miss=() p c
  for p in $want; do
    c=$(apt-cache policy "$p" 2>/dev/null | sed -n 's/^ *Candidate: *//p')
    if [ -n "$c" ] && [ "$c" != "(none)" ]; then have+=("$p"); else miss+=("$p"); fi
  done
  [ ${#miss[@]} -gt 0 ] && echo "  (skipped — no install candidate on this release: ${miss[*]})"
  if [ ${#have[@]} -gt 0 ]; then
    apt-get install -y -qq "${have[@]}" || die "failed to install: ${have[*]}"
  fi
  return 0
}

# Core hypervisor + guest plumbing (hard requirement — fail if these won't install):
#   qemu-system-x86  hypervisor            qemu-utils   qemu-img + qemu-nbd (backup API exports)
#   ovmf             UEFI/SecureBoot firmware (Win11/Server 2025, q35)
#   swtpm(+tools)    software TPM 2.0 (UEFI SecureBoot guests)
#   genisoimage      cloud-init NoCloud seed + ISO handling
#   iproute2         bridges / taps / bonds    nftables  routing firewall table
#   chrony           host NTP client (log/VM time sync — see below)
#   zstd gzip        backup compressors        ethtool   NIC multiqueue tuning
#   python3          frr-reload.py + helpers   curl ca-certificates  downloads
say "Core packages"
apt-get install -y -qq \
  qemu-system-x86 qemu-utils ovmf swtpm swtpm-tools genisoimage \
  iproute2 nftables chrony zstd gzip ethtool python3 curl ca-certificates \
  || die "failed to install core packages"

# Storage backends (best-effort — only the ones a deployment uses need to work):
#   lvm2 + thin-provisioning-tools  LVM-thin pools
#   zfsutils-linux                  ZFS pools / datasets / zvols
#   nfs-common cifs-utils ceph-common open-iscsi  shared storage (NFS/CIFS/Ceph/iSCSI)
#   ceph                            hyperconverged Ceph server (mon/mgr/osd/ceph-volume)
#                                   — the nodes BECOME the Ceph cluster; VM disks on RBD.
#                                   No ceph unit is enabled here; the cluster is created on
#                                   demand from the UI (which enables ceph-mon@/ceph-mgr@/OSDs).
# Snapshots / instant clones / snapshot policies (docs/SNAPSHOTS.md) use only these
# same tools: qemu-img (qemu-utils), zfs, lvcreate/lvrename/lvremove (lvm2), rbd
# (ceph-common), cp --reflink + udevadm (base system) — nothing extra to install.
# App-consistent snapshots need qemu-guest-agent INSIDE the guest (cloud-init
# installs it when the instance has the guest agent enabled), not on the host.
say "Storage backend tools (LVM / ZFS / NFS / CIFS / Ceph / iSCSI / Ceph HCI)"
apt_opt mdadm xfsprogs e2fsprogs
apt_opt lvm2 thin-provisioning-tools zfsutils-linux \
  nfs-common cifs-utils ceph-common open-iscsi ceph

# VMware import — fastest transport (VDDK over NBD). nbdkit + its VDDK plugin are
# the apt-installable wrapper; the VDDK library itself is proprietary (Broadcom,
# not redistributable) and is supplied by the operator via a libdir set in the UI.
# Without these the import still works over the NFC and datastore-direct transports.
say "VMware import VDDK transport wrapper (nbdkit; VDDK library is operator-supplied)"
apt_opt nbdkit nbdkit-plugin-vddk

# SPICE display modules: on newer Ubuntu, SPICE/QXL support for qemu is split into
# a separate module package. Install it if present so display=spice works.
apt_opt qemu-system-modules-spice

# LXC system containers (the Containers feature). lxc/lxc-utils provide the
# lxc-create/start/stop/info/attach CLIs vdxd drives; lxc-templates ships the
# "download" template; debootstrap builds Debian/Ubuntu rootfs; dnsmasq-base +
# the lxc-net service bring up the default lxcbr0 NAT bridge; uidmap/rsync are
# used by the template tooling. Without these the Containers page is disabled.
say "Container runtime (LXC)"
apt_opt lxc lxc-templates lxcfs debootstrap dnsmasq-base bridge-utils uidmap rsync
# Bring up the default NAT bridge + the lxc autostart service if installed.
systemctl enable --now lxc-net >/dev/null 2>&1 || true
systemctl enable --now lxc     >/dev/null 2>&1 || true

# Routing stack: FRR provides OSPF / BGP / static routing that vdxd drives via
# /usr/lib/frr/frr-reload.py; frr-pythontools ships that reloader. Installed here
# so routing "just works" on a fresh host (configured + enabled further below).
say "Routing stack (FRR: OSPF / BGP / static)"
apt_opt frr frr-pythontools

# wireguard-tools: `wg` for the VXVisor Fabric's "over management" underlay
# (docs/FABRIC.md §16): each host's TEP rides an encrypted WireGuard tunnel
# between the hosts' management addresses. The wireguard module is in the stock
# kernel; nothing is enabled here (vdxd creates vxfwg0 only for such a fabric).
say "WireGuard tools (fabric over management)"
apt_opt wireguard-tools

# lldpd: link-layer discovery. Receives BOTH LLDP and Cisco CDP so the network
# topology diagram can show the upstream switch each uplink is wired to (switch
# name, port, VLAN, mgmt IP). Enabled now; the diagram reads `lldpctl`.
say "Link-layer discovery (lldpd: LLDP + CDP neighbors)"
apt_opt lldpd
if command -v lldpd >/dev/null 2>&1; then
  # Enable CDP + LLDP reception/advertisement on all ports.
  if [ -d /etc/lldpd.d ]; then
    printf 'configure lldp portidsubtype ifname\nconfigure system interface pattern *\n' >/etc/lldpd.d/vdxd.conf 2>/dev/null || true
  fi
  systemctl enable --now lldpd >/dev/null 2>&1 || true
fi

# Disk & RAID health. smartmontools (smartctl) + pciutils (lspci) back the
# "Disk status" card and drive-failure toasts — hard requirement, the UI reads
# them directly.
say "Disk health tools (smartmontools, pciutils)"
apt-get install -y -qq smartmontools pciutils || die "failed to install smartmontools/pciutils"

# Hardware-RAID controller CLIs. Disks behind a RAID controller never appear to
# the kernel (lsblk shows only the virtual disk), so per-drive SMART/health needs
# the vendor CLI plus smartctl's -d passthrough. These live in VENDOR repos, not
# the Ubuntu archive, so this whole step is BEST-EFFORT: a flaky/unavailable
# vendor repo must never brick a host install. We only touch a vendor's repo when
# that controller is actually on the PCI bus. Proprietary CLIs with no apt repo
# (Dell perccli, Broadcom storcli, Adaptec arcconf) install only when the operator
# supplies a .deb URL via the matching *_DEB_URL env var.
install_raid_tools(){
  command -v lspci >/dev/null 2>&1 || return 0
  local pci; pci="$(lspci 2>/dev/null)"
  local keyring=/usr/share/keyrings updated=0
  install -d "$keyring" 2>/dev/null || true
  _try_deb_url(){ # $1=name $2=url
    [ -n "$2" ] || return 0
    say "Installing $1 from operator-supplied URL"
    local t; t="$(mktemp --suffix=.deb)"
    if curl -fsSL "$2" -o "$t"; then apt-get install -y -qq "$t" || echo "  WARN: $1 package failed to install"; else echo "  WARN: could not download $1 from $2"; fi
    rm -f "$t"
  }
  _install_megacli(){
    # megacli ships only in the community hwraid repo, and its newest (focal) build
    # hard-links the EOL libncurses.so.5. Rather than trust that repo's Release
    # signature (a rotated key) or install a conflicting old libncurses5 system-wide,
    # we lay down the package's files plus just the two legacy .so's beside the
    # binary — its wrapper sets LD_LIBRARY_PATH=/usr/lib/megacli, so nothing else on
    # the host sees them. Package from the hwraid pool, libs from the official Ubuntu
    # archive. All best-effort.
    local base=https://hwraid.le-vert.net/ubuntu deb t f idx lib
    deb="$(curl -fsSL "$base/dists/focal/main/binary-amd64/Packages" 2>/dev/null | awk '/^Package: megacli$/{p=1} p&&/^Filename:/&&!f{print $2; f=1}')"
    [ -n "$deb" ] || return 1
    t="$(mktemp -d)"
    curl -fsSL "$base/$deb" -o "$t/megacli.deb" || { rm -rf "$t"; return 1; }
    dpkg-deb -x "$t/megacli.deb" "$t/mc" || { rm -rf "$t"; return 1; }
    idx="$(curl -fsSL http://archive.ubuntu.com/ubuntu/pool/universe/n/ncurses/ 2>/dev/null)"
    for lib in libncurses5 libtinfo5; do
      f="$(echo "$idx" | grep -oE "${lib}_[^\"]+_amd64.deb" | sort -V | tail -1)"
      [ -n "$f" ] && curl -fsSL "http://archive.ubuntu.com/ubuntu/pool/universe/n/ncurses/$f" -o "$t/$lib.deb" \
        && dpkg-deb -x "$t/$lib.deb" "$t/nc" || true
    done
    rm -rf /usr/lib/megacli
    cp -a "$t/mc/usr/lib/megacli" /usr/lib/megacli
    find "$t/nc" \( -name 'libncurses.so.5*' -o -name 'libtinfo.so.5*' \) -exec cp -a {} /usr/lib/megacli/ \; 2>/dev/null
    install -m0755 "$t/mc/usr/sbin/megacli" /usr/sbin/megacli
    rm -rf "$t"
    megacli -v >/dev/null 2>&1
  }
  # --- Broadcom/LSI MegaRAID = Dell PERC / Lenovo / Supermicro ---
  if grep -qiE 'megaraid|\bPERC\b|LSI.*(RAID|SAS)|Broadcom.*(RAID|SAS)|Avago' <<<"$pci"; then
    if ! command -v megacli >/dev/null 2>&1 && ! command -v storcli >/dev/null 2>&1 && ! command -v perccli >/dev/null 2>&1; then
      say "MegaRAID/PERC controller detected — installing megacli"
      _install_megacli || echo "  WARN: could not install megacli (controller still detected; UI shows an install hint)"
    fi
    # Broadcom storcli / Dell perccli are self-contained (no legacy libs) and are
    # the modern replacement — install them when the operator supplies a .deb URL.
    _try_deb_url perccli "${PERCCLI_DEB_URL:-}"
    _try_deb_url storcli "${STORCLI_DEB_URL:-}"
  fi
  # --- HPE Smart Array (ssacli via HPE Management Component Pack) ---
  if grep -qiE 'smart array|hewlett.?packard.*(array|raid)' <<<"$pci"; then
    if ! command -v ssacli >/dev/null 2>&1; then
      say "HPE Smart Array detected — adding HPE MCP repo for ssacli"
      local cn; cn="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-focal}")"
      if curl -fsSL https://downloads.linux.hpe.com/SDR/hpePublicKey2048_key1.pub 2>/dev/null \
           | gpg --dearmor -o "$keyring/hpe-mcp.gpg" 2>/dev/null; then
        echo "deb [signed-by=$keyring/hpe-mcp.gpg] https://downloads.linux.hpe.com/SDR/repo/mcp $cn/current non-free" \
          >/etc/apt/sources.list.d/hpe-mcp.list
        apt-get update -qq || true; updated=1
        apt-get install -y -qq ssacli || echo "  WARN: ssacli not installable for codename '$cn' (check the HPE MCP channel for your ProLiant generation)"
      else
        echo "  WARN: could not fetch the HPE signing key — skipping ssacli"
      fi
    fi
  fi
  # --- Adaptec / Microchip (arcconf — no apt repo; operator-supplied only) ---
  if grep -qiE 'adaptec|microsemi|pmc.?sierra' <<<"$pci"; then
    command -v arcconf >/dev/null 2>&1 || _try_deb_url arcconf "${ARCCONF_DEB_URL:-}"
  fi
  [ "$updated" = 1 ] && apt-get update -qq || true
  return 0
}
install_raid_tools

# ---- time sync (chrony/NTP) ----------------------------------------------
# Accurate host time is critical: log correlation, TLS, Kerberos/AD joins, and
# backup/snapshot timestamps all depend on it, and KVM guests inherit the host
# clock (kvm-clock) at boot. Enable chrony so the host disciplines itself to NTP;
# guests then stay correct via kvm-clock + their own in-guest time sync (Linux:
# systemd-timesyncd/chrony; Windows: w32time, kept honest by the qemu guest agent).
if command -v chronyd >/dev/null 2>&1; then
  say "Enabling host time sync (chrony/NTP)"
  # systemd-timesyncd and chrony conflict; prefer chrony.
  systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
  systemctl enable --now chrony >/dev/null 2>&1 || systemctl enable --now chronyd >/dev/null 2>&1 || true
  timedatectl set-ntp true >/dev/null 2>&1 || true
  echo "  chrony active: $(chronyc -n tracking 2>/dev/null | awk -F': ' '/Stratum/{print "stratum "$2}' | head -1 || echo 'starting')"
fi

# ---- routing stack (FRR) -------------------------------------------------
# vdxd writes /etc/frr/frr.conf and reloads via /usr/lib/frr/frr-reload.py, but
# FRR ships with every routing daemon DISABLED. Turn on the ones vdxd drives
# (ospfd/bgpd/eigrpd/staticd, plus bfdd for the VXVisor Fabric's BFD on its
# EVPN sessions) in /etc/frr/daemons, then enable the service. We never touch
# frr.conf here — that file is owned by vdxd.
if [ -f /etc/frr/daemons ]; then
  say "Enabling FRR routing daemons (ospfd, bgpd, eigrpd, staticd, bfdd)"
  for d in ospfd bgpd eigrpd staticd bfdd; do
    if grep -q "^${d}=" /etc/frr/daemons; then
      sed -i "s/^${d}=.*/${d}=yes/" /etc/frr/daemons
    else
      echo "${d}=yes" >>/etc/frr/daemons
    fi
  done
  systemctl enable --now frr >/dev/null 2>&1 || true
  echo "  frr: $(systemctl is-active frr 2>/dev/null || echo inactive)"
  # A running FRR picks up a newly enabled daemon only on restart (watchfrr
  # can't add one live). We don't restart it here — that would drop live
  # routing sessions. Until then the VXVisor Fabric runs without BFD (it only
  # renders BFD when bfdd is running); BGP timers still detect a dead peer.
  if systemctl is-active --quiet frr && ! pgrep -x bfdd >/dev/null; then
    echo "  note: bfdd is enabled but starts at FRR's next restart"
  fi
fi

# netns vRouters run each router's FRR in a pathspace (`-N <id>`), which puts its
# pid/vty/zserv sockets in /run/frr/<id>/ and config in /etc/frr/<id>/. The stock
# AppArmor abstraction (recent Ubuntu, e.g. 26.04) only allows the flat /run/frr/ paths, so the
# confined staticd/bgpd/ospfd die at start. Add the same grants one directory down
# via the abstraction's frr.d/ hook and reload every profile that includes it.
if [ -f /etc/apparmor.d/abstractions/frr ]; then
  say "Allowing netns vRouter FRR pathspaces in AppArmor"
  [ -f "$SRC_DIR/apparmor/frr.d-vxvisor" ] || die "missing $SRC_DIR/apparmor/frr.d-vxvisor"
  install -D -o root -g root -m 0644 "$SRC_DIR/apparmor/frr.d-vxvisor" /etc/apparmor.d/abstractions/frr.d/vxvisor
  if command -v apparmor_parser >/dev/null 2>&1 && [ -d /sys/kernel/security/apparmor ]; then
    for f in $(grep -ls 'abstractions/frr>' /etc/apparmor.d/*); do
      apparmor_parser -r "$f" || die "apparmor_parser failed to reload $f"
    done
  fi
fi

# ---- run-as user ---------------------------------------------------------
say "Creating run-as user 'vdx'"
if ! id vdx >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin vdx
  echo "  created system user vdx"
else
  echo "  user vdx already exists"
fi
# Needs /dev/kvm access.
getent group kvm >/dev/null && usermod -aG kvm vdx || true

# ---- directories ---------------------------------------------------------
say "Creating data directories under /var/lib/vdxclone"
install -d -o vdx -g vdx -m 0750 \
  /var/lib/vdxclone \
  /var/lib/vdxclone/data \
  /var/lib/vdxclone/images \
  /var/lib/vdxclone/disks \
  /var/lib/vdxclone/isos \
  /var/lib/vdxclone/backups
# The unit's TMPDIR (on disk, not tmpfs) — must exist or every tool vdxd runs
# that honors TMPDIR fails to create its temp files.
install -d -o root -g root -m 0700 /var/lib/vdxclone/tmp

# ---- virtio-win driver ISO ----------------------------------------------
# Windows VMs default to virtio devices (fastest), and the Windows installer
# needs the virtio drivers (viostor/NetKVM/qxl) to see a virtio disk/NIC. Fetch
# the official stable ISO once so it's present and auto-mounted on every Windows
# VM. Non-fatal: a failed/absent download just means Windows users pull it later.
VIRTIO_WIN_ISO=/var/lib/vdxclone/isos/virtio-win.iso
VIRTIO_WIN_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
if [ "$GET_VIRTIO_WIN" = 1 ]; then
  if [ -f "$VIRTIO_WIN_ISO" ]; then
    say "virtio-win driver ISO already present"
  else
    say "Downloading the virtio-win driver ISO (for Windows guests; ~700 MB)"
    tmp="${VIRTIO_WIN_ISO}.part"
    if curl -fL --retry 3 -o "$tmp" "$VIRTIO_WIN_URL"; then
      mv -f "$tmp" "$VIRTIO_WIN_ISO"
      chown vdx:vdx "$VIRTIO_WIN_ISO" 2>/dev/null || true
      echo "  saved $VIRTIO_WIN_ISO — it auto-mounts on every Windows VM"
    else
      rm -f "$tmp"
      echo "  WARNING: download failed — pull it later from the ISO library:"
      echo "           $VIRTIO_WIN_URL  (save as virtio-win.iso)"
    fi
  fi
fi

# ---- binary --------------------------------------------------------------
say "Installing binary -> /usr/local/bin/vdxd"
install -o root -g root -m 0755 "$SRC_DIR/vdxd" /usr/local/bin/vdxd
/usr/local/bin/vdxd version

# ---- config --------------------------------------------------------------
say "Installing config -> /etc/vdxclone/config.toml"
install -d -o root -g root -m 0755 /etc/vdxclone
if [ -f /etc/vdxclone/config.toml ]; then
  echo "  config already exists — leaving it untouched"
else
  sed "s/__BIND_IP__/${BIND_IP}/g" "$SRC_DIR/config.toml.tmpl" > /etc/vdxclone/config.toml
  chmod 0644 /etc/vdxclone/config.toml
  echo "  wrote config bound to ${BIND_IP} (admin :8766)"
fi

# ---- RustGuac console (rustguac + guacd) ---------------------------------
# The console page's "RustGuac" button (browser SSH/RDP/VNC/SPICE) is vdxd
# fronting a local rustguac (github.com/sol1/rustguac) and its own guacd.
# Upstream's packages target Debian 13, so both are built here from pinned
# sources into /opt/rustguac (build tree on disk under /var/lib/vdxclone/tmp,
# Ubuntu's own cargo). rustguac listens on 127.0.0.1:8089 and its guacd on
# 127.0.0.1:4823 — loopback only, always: the only way in is vdxd's
# cookie-gated proxy on <bind-ip>:8769, so a browser needs a vdxd session. vdxd
# mints sessions with an admin API key that rustguac accepts only from
# 127.0.0.1. A re-run rebuilds only when the pinned versions change and never
# replaces a [guac] section vdxd already has. Not installed: rustguac's
# web-browser sessions (Xvnc + Chromium) and its encrypted RDP drive — vdxd
# uses neither.
RUSTGUAC_REPO="https://github.com/sol1/rustguac.git"
RUSTGUAC_TAG="v1.13.4"
RUSTGUAC_COMMIT="82aca33d1aedf9e141ec04b2cb15883ff625dc1c"
GUACD_REPO="https://github.com/apache/guacamole-server.git"
GUACD_COMMIT="6719b20d09b767d30915c5e1c626a7a72fc75a59"   # the commit rustguac pins
RG=/opt/rustguac
RG_PROXY_PORT=8769   # not 8767: that's the cluster peer API

install_rustguac(){
  say "RustGuac console (rustguac + guacd from source — a first install takes several minutes)"
  apt_opt autoconf automake libtool pkg-config make gcc g++ git \
    libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libssh2-1-dev libssl-dev \
    libvncserver-dev libpango1.0-dev libpulse-dev libavcodec-dev libavformat-dev \
    libavutil-dev libswscale-dev libtelnet-dev libwebsockets-dev freerdp3-dev \
    libspice-client-glib-2.0-dev uuid-dev cargo rustc
  id rustguac >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$RG" --shell /usr/sbin/nologin rustguac

  local stamp="$RG/.vxvisor-build" want="$RUSTGUAC_COMMIT $GUACD_COMMIT"
  if [ -x "$RG/bin/rustguac" ] && [ -x "$RG/sbin/guacd" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$want" ]; then
    echo "  rustguac $RUSTGUAC_TAG already built"
  else
    local b=/var/lib/vdxclone/tmp/rustguac-build p
    rm -rf "$b"; install -d -m 0700 "$b"
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$RUSTGUAC_TAG" "$RUSTGUAC_REPO" "$b/rustguac" 2>/dev/null || die "can't fetch rustguac $RUSTGUAC_TAG"
    [ "$(git -C "$b/rustguac" rev-parse HEAD)" = "$RUSTGUAC_COMMIT" ] || die "rustguac $RUSTGUAC_TAG isn't the pinned commit $RUSTGUAC_COMMIT"
    git init -q "$b/guacd"
    git -C "$b/guacd" fetch -q --depth 1 "$GUACD_REPO" "$GUACD_COMMIT" || die "can't fetch guacamole-server $GUACD_COMMIT"
    git -C "$b/guacd" checkout -q FETCH_HEAD
    # rustguac's guacd patches, as its own installer applies them (one that
    # doesn't apply to this commit is already in it).
    for p in "$b/rustguac/patches/"*.patch; do
      [ -f "$p" ] || continue
      if git -C "$b/guacd" apply --check "$p" 2>/dev/null; then git -C "$b/guacd" apply --whitespace=nowarn "$p"; else echo "  guacd patch $(basename "$p"): already in this commit"; fi
    done
    echo "  building guacd (log: $b/guacd.log)"
    (cd "$b/guacd" && autoreconf -fi && ./configure --prefix="$RG" --with-ssh --with-vnc --with-rdp --with-spice \
        --without-telnet --disable-kubernetes --disable-guaclog --disable-guacclip --disable-static \
      && make -j"$(nproc)" && make install) >"$b/guacd.log" 2>&1 \
      || { tail -n 30 "$b/guacd.log"; die "guacd build failed (log: $b/guacd.log)"; }
    echo "  building rustguac (log: $b/cargo.log)"
    (cd "$b/rustguac" && CARGO_HOME="$b/cargo" cargo build --release --locked) >"$b/cargo.log" 2>&1 \
      || { tail -n 30 "$b/cargo.log"; die "rustguac build failed (log: $b/cargo.log)"; }
    systemctl stop rustguac rustguac-guacd 2>/dev/null || true
    install -d "$RG/bin"
    install -m 0755 "$b/rustguac/target/release/rustguac" "$RG/bin/rustguac"
    rm -rf "$RG/static"; cp -r "$b/rustguac/static" "$RG/static"
    echo "$want" >"$stamp"
    rm -rf "$b"
  fi

  install -d -o rustguac -g rustguac "$RG/data" "$RG/recordings"
  if [ ! -f "$RG/config.toml" ]; then
    cat >"$RG/config.toml" <<EOF
listen_addr = "127.0.0.1:8089"
guacd_addr = "127.0.0.1:4823"
recording_path = "$RG/recordings"
static_path = "$RG/static"
db_path = "$RG/data/rustguac.db"
session_pending_timeout_secs = 60
xvnc_path = "Xvnc"
chromium_path = "chromium"
display_range_start = 100
display_range_end = 199
EOF
  fi
  sed -i -E 's|^listen_addr *=.*|listen_addr = "127.0.0.1:8089"|; s|^guacd_addr *=.*|guacd_addr = "127.0.0.1:4823"|' "$RG/config.toml"
  echo "$RG/lib" >/etc/ld.so.conf.d/rustguac.conf
  ldconfig
  cat >/etc/systemd/system/rustguac-guacd.service <<EOF
[Unit]
Description=Guacamole proxy daemon (guacd) for rustguac
After=network.target

[Service]
Type=simple
User=rustguac
ExecStart=$RG/sbin/guacd -b 127.0.0.1 -l 4823 -L info -f
Restart=on-failure
RestartSec=5
Environment=LD_LIBRARY_PATH=$RG/lib

[Install]
WantedBy=multi-user.target
EOF
  cat >/etc/systemd/system/rustguac.service <<EOF
[Unit]
Description=rustguac web session proxy
After=network.target rustguac-guacd.service
Requires=rustguac-guacd.service

[Service]
Type=simple
User=rustguac
WorkingDirectory=$RG
ExecStart=$RG/bin/rustguac --config $RG/config.toml serve
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable rustguac-guacd rustguac >/dev/null 2>&1 || die "can't enable the rustguac services"
  systemctl restart rustguac-guacd rustguac || die "rustguac didn't start (journalctl -u rustguac -u rustguac-guacd)"
  local i
  for i in $(seq 1 30); do [ -n "$(ss -Hltn 'sport = :8089')" ] && break; sleep 1; done
  [ -n "$(ss -Hltn 'sport = :8089')" ] || die "rustguac isn't listening on 127.0.0.1:8089 (journalctl -u rustguac)"
  echo "  rustguac: $(systemctl is-active rustguac), guacd: $(systemctl is-active rustguac-guacd)"

  local cfg=/etc/vdxclone/config.toml
  if grep -q '^\[guac\]' "$cfg"; then
    echo "  vdxd's [guac] section already exists — leaving it untouched"
    return 0
  fi
  local rg=(runuser -u rustguac -- "$RG/bin/rustguac" --config "$RG/config.toml") out key
  if "${rg[@]}" list-admins 2>/dev/null | grep -w vdxd >/dev/null; then
    out=$("${rg[@]}" rotate-key --name vdxd) || die "can't rotate rustguac's vdxd API key"
  else
    out=$("${rg[@]}" add-admin --name vdxd --allowed-ips 127.0.0.1/32) || die "can't create rustguac's vdxd admin"
  fi
  key=$(printf '%s\n' "$out" | sed -n -E 's/^(New )?API Key: *//p')
  [ -n "$key" ] || die "rustguac printed no API key"
  chmod 0600 "$cfg"   # it now holds a secret
  cat >>"$cfg" <<EOF

[guac]
# RustGuac console (set up by install.sh): vdxd mints sessions on the loopback
# rustguac with this key and proxies browsers to it on proxy_addr.
enabled    = true
upstream   = "127.0.0.1:8089"
api_key    = "$key"
proxy_addr = "$BIND_IP:$RG_PROXY_PORT"
EOF
  echo "  RustGuac console on: browser proxy ${BIND_IP}:${RG_PROXY_PORT}"
}
install_rustguac

# ---- default vSwitch (bridge the management interface) -------------------
# Converts the mgmt NIC into a bridge (vSwitch0) so VMs can ride the uplink,
# the same way ESXi puts the mgmt interface on vSwitch0. Rock-solid rules:
#   * NEVER lose mgmt access: back up netplan, arm a timed auto-rollback BEFORE
#     applying, keep the new config only after the mgmt IP is confirmed on the
#     bridge — otherwise restore the backup automatically.
#   * Preserve identity: clone the NIC MAC (DHCP keeps the same lease) and
#     reproduce the exact addressing (DHCP stays DHCP, static stays static).
#   * Idempotent + conservative: skip if already bridged/enslaved, if the NIC
#     can't be found, or if the host isn't netplan-managed.
setup_mgmt_vswitch(){
  command -v netplan >/dev/null 2>&1 || { echo "  netplan not found — skipping vSwitch setup (configure the bridge manually)"; return 0; }

  # The mgmt NIC is whichever interface actually carries the bind IP.
  local IF MAC
  IF=$(ip -o -4 addr show 2>/dev/null | awk -v ip="$BIND_IP" '{split($4,a,"/"); if(a[1]==ip) print $2}' | sed -n 1p)
  [ -n "$IF" ] || { echo "  could not find the interface carrying $BIND_IP — skipping vSwitch setup"; return 0; }

  if [ -d "/sys/class/net/$IF/bridge" ]; then
    echo "  $IF is already a bridge — leaving management networking untouched"; return 0
  fi
  if [ -e "/sys/class/net/$IF/master" ]; then
    echo "  $IF is already enslaved to $(basename "$(readlink -f /sys/class/net/$IF/master)") — skipping"; return 0
  fi
  if ip -o link show "$VSW_NAME" >/dev/null 2>&1; then
    echo "  $VSW_NAME already exists — skipping vSwitch setup"; return 0
  fi

  MAC=$(cat "/sys/class/net/$IF/address" 2>/dev/null || true)
  [ -n "$MAC" ] || { echo "  could not read MAC of $IF — skipping vSwitch setup"; return 0; }

  # DHCP vs static: a kernel-assigned DHCP lease is flagged "dynamic".
  local IS_DHCP=0
  ip -o -4 addr show dev "$IF" 2>/dev/null | grep -w dynamic >/dev/null && IS_DHCP=1

  say "Converting $IF into default vSwitch '$VSW_NAME' (mgmt IP $BIND_IP, DHCP=$IS_DHCP)"

  # Build the bridge body: DHCP mirrors DHCP; static reproduces addrs/gw/DNS so
  # the mgmt IP is identical no matter what the DHCP server does at apply time.
  local BODY=""
  if [ "$IS_DHCP" = 1 ]; then
    BODY=$'      dhcp4: yes\n      dhcp6: no'
  else
    local A4 A6 GW4 GW6 DNS NSLINE="" i
    A4=$(ip -o -4 addr show dev "$IF" | awk '{print $4}')
    A6=$(ip -o -6 addr show dev "$IF" scope global | awk '{print $4}')
    GW4=$(ip -o -4 route show default dev "$IF" 2>/dev/null | awk 'NR==1{print $3}')
    GW6=$(ip -o -6 route show default dev "$IF" 2>/dev/null | awk 'NR==1{print $3}')
    DNS=$(resolvectl dns "$IF" 2>/dev/null | awk '{for(i=2;i<=NF;i++)print $i}')
    [ -z "$DNS" ] && DNS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null)
    [ -z "$DNS" ] && DNS=$'1.1.1.1\n8.8.8.8'
    BODY=$'      dhcp4: no\n      dhcp6: no\n      addresses:'
    for i in $A4 $A6; do BODY+=$'\n        - '"$i"; done
    if [ -n "$GW4" ] || [ -n "$GW6" ]; then
      BODY+=$'\n      routes:'
      [ -n "$GW4" ] && BODY+=$'\n        - {to: default, via: '"$GW4"'}'
      [ -n "$GW6" ] && BODY+=$'\n        - {to: "::/0", via: '"$GW6"'}'
    fi
    for i in $DNS; do NSLINE+=$'\n          - '"$i"; done
    BODY+=$'\n      nameservers:\n        addresses:'"$NSLINE"
  fi

  local CFG=/etc/netplan/90-vdx-vswitch0.yaml
  local BK=/var/lib/vdxclone/netplan-backup.$(date +%s)
  mkdir -p "$BK"; cp /etc/netplan/*.yaml "$BK"/ 2>/dev/null || true
  echo "  backed up current netplan -> $BK"

  cat > "$CFG" <<YAML
# Managed by VXVisor installer — default management vSwitch.
network:
  version: 2
  renderer: networkd
  ethernets:
    $IF:
      dhcp4: no
      dhcp6: no
  bridges:
    $VSW_NAME:
      interfaces: [$IF]
      macaddress: "$MAC"
$BODY
      parameters:
        stp: false
        forward-delay: 0
YAML
  chmod 600 "$CFG"

  # Arm the auto-rollback BEFORE applying: if the mgmt IP is not confirmed on
  # the bridge within the window, the sentinel is never created and this
  # detached job restores the backup and re-applies — so a bad apply self-heals
  # even if this script's SSH session drops.
  rm -f /run/vdx-netok
  setsid bash -c "sleep 150; [ -f /run/vdx-netok ] && exit 0; rm -f '$CFG'; cp '$BK'/*.yaml /etc/netplan/ 2>/dev/null; netplan apply" \
    </dev/null >/var/log/vdx-net-rollback.log 2>&1 &
  local WD=$!
  echo "  armed auto-rollback (pid $WD, 150s) — mgmt access cannot be lost"

  if ! netplan generate 2>/var/log/vdx-net-apply.log; then
    echo "  netplan generate FAILED — restoring backup"; kill "$WD" 2>/dev/null || true
    rm -f "$CFG"; cp "$BK"/*.yaml /etc/netplan/ 2>/dev/null || true; netplan apply || true
    return 0
  fi
  netplan apply >>/var/log/vdx-net-apply.log 2>&1 || true

  # Confirm the mgmt IP landed on the bridge (the only success that matters).
  local ok=0 i
  for i in $(seq 1 30); do
    if ip -o addr show dev "$VSW_NAME" 2>/dev/null | grep -w "$BIND_IP" >/dev/null; then ok=1; break; fi
    sleep 2
  done

  if [ "$ok" = 1 ]; then
    touch /run/vdx-netok           # disarm the rollback
    kill "$WD" 2>/dev/null || true
    echo "  SUCCESS: $BIND_IP is now on $VSW_NAME (uplink $IF). Default vSwitch is live."
  else
    echo "  mgmt IP did not appear on $VSW_NAME — rolling back now (host stays reachable)"
    kill "$WD" 2>/dev/null || true
    rm -f "$CFG"; cp "$BK"/*.yaml /etc/netplan/ 2>/dev/null || true; netplan apply || true
    echo "  rolled back to the original networking. Review /var/log/vdx-net-apply.log"
  fi
}

say "Default management vSwitch"
if [ "$SETUP_VSW" = ask ]; then
  if [ -t 0 ]; then
    echo "  A default vSwitch bridges the management NIC so VMs can use its uplink."
    echo "  It is safe: MAC + addressing are preserved and a failed apply auto-reverts."
    read -r -p "  Create a default vSwitch on the management interface now? [y/N] " _a || _a=n
    case "${_a:-n}" in y|Y|yes|YES) SETUP_VSW=yes ;; *) SETUP_VSW=no ;; esac
  else
    echo "  non-interactive run — skipping (pass --mgmt-vswitch to enable, --no-vswitch to silence)"
    SETUP_VSW=no
  fi
fi
if [ "$SETUP_VSW" = yes ]; then setup_mgmt_vswitch; else echo "  skipped"; fi

# ---- host performance tuning --------------------------------------------
# Safe, reversible host knobs so a DEFAULT install runs VMs fast out of the box
# (the per-VM QEMU tuning is always on; this is the host side of docs/TUNING.md §B).
if [ "$TUNE_HOST" = 1 ]; then
  say "Applying host performance tuning (skip with --no-tune)"

  # 1) tuned 'virtual-host' profile: KVM-host scheduler/VM sysctls + THP=always.
  if apt-get install -y -qq tuned >/dev/null 2>&1 && command -v tuned-adm >/dev/null 2>&1; then
    systemctl enable --now tuned >/dev/null 2>&1 || true
    if tuned-adm profile virtual-host >/dev/null 2>&1; then
      echo "  tuned profile: virtual-host"
    else
      echo "  tuned installed (could not switch profile — check 'tuned-adm active')"
    fi
  else
    echo "  tuned unavailable — applying a sysctl/THP fallback instead"
    echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
  fi

  # 2) Persisted sysctls: light swapping, generous connection backlog for VM nets.
  cat > /etc/sysctl.d/99-vdxclone.conf <<'SYSCTL'
# VXVisor host tuning (safe defaults; remove this file to revert)
vm.swappiness = 10
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 16384
SYSCTL
  sysctl -q --system >/dev/null 2>&1 || true
  echo "  sysctls: vm.swappiness=10 + larger net backlog (/etc/sysctl.d/99-vdxclone.conf)"

  # 3) vhost-net kernel module (in-kernel virtio-net dataplane), loaded + persisted.
  modprobe vhost_net 2>/dev/null || true
  echo "vhost_net" > /etc/modules-load.d/vdxclone.conf
  if lsmod | grep '^vhost_net' >/dev/null; then echo "  vhost_net: loaded"; else echo "  vhost_net: not available on this kernel"; fi

  # 4) THP = always (belt-and-suspenders; tuned usually sets this too).
  if [ -w /sys/kernel/mm/transparent_hugepage/enabled ]; then
    echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
  fi
  echo "  NOTE: for latency-sensitive guests also see docs/TUNING.md §B (hugepages, CPU pinning, ZFS ARC cap)."
fi

# ---- hugepage pool (opt-in: --hugepages <pct of RAM>) --------------------
# Reserve a 2 MiB hugepage pool so the per-VM "Back RAM with hugepages" toggle
# actually engages. Done at install so it lands before memory fragments; also
# persisted so it survives reboot. 2 MiB pages (not 1 GiB) need no bootloader
# change. Reserving pins that RAM away from normal use, so it is OPT-IN.
if [ "${HUGEPAGES_PCT:-0}" -gt 0 ] 2>/dev/null; then
  if [ "$HUGEPAGES_PCT" -ge 90 ]; then die "--hugepages must be < 90 (percent of RAM); got $HUGEPAGES_PCT"; fi
  say "Reserving ${HUGEPAGES_PCT}% of RAM as 2 MiB hugepages"
  MEMKB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
  HPSZKB=$(awk '/^Hugepagesize:/{print $2}' /proc/meminfo); [ -n "$HPSZKB" ] || HPSZKB=2048
  PAGES=$(( MEMKB * HUGEPAGES_PCT / 100 / HPSZKB ))
  if [ "$PAGES" -lt 1 ]; then
    echo "  computed 0 pages — nothing to reserve"
  else
    sysctl -q -w vm.nr_hugepages="$PAGES" >/dev/null 2>&1 || true
    GOT=$(awk '/^HugePages_Total:/{print $2}' /proc/meminfo)
    echo "vm.nr_hugepages = $PAGES" > /etc/sysctl.d/99-vdxclone-hugepages.conf
    # Ensure the hugetlbfs mount exists (memfd-hugetlb doesn't need it, but having
    # /dev/hugepages present keeps other tooling happy). systemd usually mounts it.
    [ -d /dev/hugepages ] || { mkdir -p /dev/hugepages; mount -t hugetlbfs none /dev/hugepages 2>/dev/null || true; }
    HPMB=$(( GOT * HPSZKB / 1024 ))
    echo "  reserved ${GOT}/${PAGES} pages (~${HPMB} MiB); persisted to /etc/sysctl.d/99-vdxclone-hugepages.conf"
    if [ "$GOT" -lt "$PAGES" ]; then
      echo "  WARNING: got fewer pages than asked (memory already fragmented). They fill in fully on next boot (reserved early), or reboot now."
    fi
    echo "  per-VM 'Back RAM with hugepages' will now engage for guests that fit the pool."
  fi
fi

# ---- systemd -------------------------------------------------------------
say "Installing systemd unit"
install -o root -g root -m 0644 "$SRC_DIR/vdxd.service" /etc/systemd/system/vdxd.service
# Shutdown hook: gracefully powers down guest VMs at host poweroff/reboot (its
# ExecStop does NOT fire on a plain `systemctl restart vdxd`, so a control-plane
# restart leaves guests running for re-adoption).
install -o root -g root -m 0644 "$SRC_DIR/vdxd-shutdown.service" /etc/systemd/system/vdxd-shutdown.service
systemctl daemon-reload
systemctl enable vdxd >/dev/null 2>&1 || true
systemctl enable --now vdxd-shutdown >/dev/null 2>&1 || true

# ---- first admin ---------------------------------------------------------
if [ "$MAKE_ADMIN" = 1 ] && [ ! -f /var/lib/vdxclone/.admin-created ]; then
  say "Creating first admin user"
  ADMIN_PW=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)
  # 'user add' runs DB migrations on open; prompt() reads piped stdin here.
  if echo "$ADMIN_PW" | VDX_CONFIG=/etc/vdxclone/config.toml /usr/local/bin/vdxd user add admin --admin; then
    touch /var/lib/vdxclone/.admin-created
    echo "  admin username: admin"
    echo "  admin password: ${ADMIN_PW}"
    echo "  >>> SAVE THIS PASSWORD — it is not stored anywhere else. <<<"
  else
    echo "  admin creation skipped/failed (maybe already exists)"
  fi
fi

# ---- start ---------------------------------------------------------------
say "Starting vdxd"
systemctl restart vdxd
sleep 2
systemctl --no-pager --full status vdxd | head -n 8 || true

cat <<EOF

================================================================
VXVisor installed.

  Admin UI :  http://${BIND_IP}:8766     (sign in as 'admin')
  RustGuac :  the console page's RustGuac button (proxy ${BIND_IP}:${RG_PROXY_PORT})

Next steps:
  1. Pull a base image:
       sudo VDX_CONFIG=/etc/vdxclone/config.toml vdxd image pull ubuntu-24.04
  2. Log in to the admin UI and create a VM; open its console from the
     Instances page.

Logs:   journalctl -u vdxd -f
Config: /etc/vdxclone/config.toml
================================================================
EOF
