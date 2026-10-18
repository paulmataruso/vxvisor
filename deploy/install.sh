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
BUILD_GUACD=1         # build+install guacd (with RDP) from source (--no-guacd to skip)
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
    --no-guacd)          BUILD_GUACD=0; shift ;;
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
  BIND_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
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
apt_opt(){
  local want="$*" have=() miss=() p
  for p in $want; do
    if apt-cache policy "$p" 2>/dev/null | grep -q 'Candidate: [^(]'; then have+=("$p"); else miss+=("$p"); fi
  done
  [ ${#miss[@]} -gt 0 ] && echo "  (skipped — no install candidate on this release: ${miss[*]})"
  if [ ${#have[@]} -gt 0 ]; then
    apt-get install -y -qq "${have[@]}" || die "failed to install: ${have[*]}"
  fi
  return 0
}

# Core hypervisor + guest plumbing (hard requirement — fail if these won't install):
#   qemu-system-x86  hypervisor            qemu-utils   qemu-img
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
say "Storage backend tools (LVM / ZFS / NFS / CIFS / Ceph / iSCSI)"
apt_opt lvm2 thin-provisioning-tools zfsutils-linux \
  nfs-common cifs-utils ceph-common open-iscsi

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

# guacd (browser-desktop gateway) is NOT in the Ubuntu archive on current
# releases, and even where it is, it lacks the FreeRDP-3 RDP plugin we need. Build
# it from source (VNC + RDP) unless --no-guacd was given.
if [ "$BUILD_GUACD" = 1 ]; then
  if command -v guacd >/dev/null 2>&1 && [ -e /usr/local/lib/libguac-client-rdp.so ]; then
    echo "  guacd already present with RDP: $(guacd -v 2>&1 | head -1)"
  else
    say "Building guacd (with RDP) from source — this takes a few minutes"
    if [ -x "$SRC_DIR/guacd-from-source.sh" ]; then
      bash "$SRC_DIR/guacd-from-source.sh" || echo "  WARNING: guacd build failed — browser desktops will be unavailable until it is fixed"
    else
      echo "  NOTE: guacd-from-source.sh not found beside install.sh — run it manually for browser desktops."
    fi
  fi
else
  echo "  (--no-guacd) skipping guacd build; browser desktops need: sudo ./guacd-from-source.sh"
fi

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
# (ospfd/bgpd/eigrpd/staticd) in /etc/frr/daemons, then enable the service. We
# never touch frr.conf here — that file is owned by vdxd.
if [ -f /etc/frr/daemons ]; then
  say "Enabling FRR routing daemons (ospfd, bgpd, eigrpd, staticd)"
  for d in ospfd bgpd eigrpd staticd; do
    if grep -q "^${d}=" /etc/frr/daemons; then
      sed -i "s/^${d}=.*/${d}=yes/" /etc/frr/daemons
    else
      echo "${d}=yes" >>/etc/frr/daemons
    fi
  done
  systemctl enable --now frr >/dev/null 2>&1 || true
  echo "  frr: $(systemctl is-active frr 2>/dev/null || echo inactive)"
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
  echo "  wrote config bound to ${BIND_IP} (admin :8766, public :8768)"
fi

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
  IF=$(ip -o -4 addr show 2>/dev/null | awk -v ip="$BIND_IP" '{split($4,a,"/"); if(a[1]==ip) print $2}' | head -1)
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
  ip -o -4 addr show dev "$IF" 2>/dev/null | grep -qw dynamic && IS_DHCP=1

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
    GW4=$(ip -o -4 route show default dev "$IF" 2>/dev/null | awk '{print $3; exit}')
    GW6=$(ip -o -6 route show default dev "$IF" 2>/dev/null | awk '{print $3; exit}')
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
    if ip -o addr show dev "$VSW_NAME" 2>/dev/null | grep -qw "$BIND_IP"; then ok=1; break; fi
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
  if lsmod | grep -q '^vhost_net'; then echo "  vhost_net: loaded"; else echo "  vhost_net: not available on this kernel"; fi

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
VDXClone installed.

  Admin UI :  http://${BIND_IP}:8766     (sign in as 'admin')
  Portal   :  http://${BIND_IP}:8768     (My Desktops)

Next steps:
  1. Pull a base image:
       sudo VDX_CONFIG=/etc/vdxclone/config.toml vdxd image pull ubuntu-24.04
  2. Log in to the admin UI, create a VM, and open its desktop.
  3. For internet exposure, bind [public] to loopback and front it with
     Caddy/nginx (TLS) — see docs/VDI-GATEWAY.md.

Logs:   journalctl -u vdxd -f
Config: /etc/vdxclone/config.toml
================================================================
EOF
