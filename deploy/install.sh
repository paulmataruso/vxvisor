#!/usr/bin/env bash
# VDXClone host installer.
#   sudo ./install.sh [--ip <bind-ip>] [--no-admin] [--dir <staging-dir>]
#
# Installs the vdxd binary, runtime dependencies, a dedicated run-as user,
# a systemd unit, and a host config. Idempotent: safe to re-run (it upgrades
# the binary and leaves an existing /etc/vdxclone/config.toml untouched).
set -euo pipefail

# ---- args ----------------------------------------------------------------
BIND_IP=""
MAKE_ADMIN=1
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ $# -gt 0 ]; do
  case "$1" in
    --ip)       BIND_IP="$2"; shift 2 ;;
    --no-admin) MAKE_ADMIN=0; shift ;;
    --dir)      SRC_DIR="$2"; shift 2 ;;
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
# qemu-system-x86: hypervisor; qemu-utils: qemu-img; genisoimage: cloud-init
# seed + ISO handling; iproute2: bridges/taps.
apt-get install -y -qq \
  qemu-system-x86 qemu-utils genisoimage iproute2
# guacd (browser-desktop gateway) is NOT in the Ubuntu archive on newer releases.
# Install it separately with guacd-from-source.sh. Warn if it is missing.
if command -v guacd >/dev/null 2>&1; then
  echo "  guacd: $(guacd -v 2>&1 | head -1)"
else
  echo "  NOTE: guacd not found — the browser-desktop gateway needs it."
  echo "        Run:  sudo ./guacd-from-source.sh   (builds + installs a loopback guacd)"
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

# ---- systemd -------------------------------------------------------------
say "Installing systemd unit"
install -o root -g root -m 0644 "$SRC_DIR/vdxd.service" /etc/systemd/system/vdxd.service
systemctl daemon-reload
systemctl enable vdxd >/dev/null 2>&1 || true

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
