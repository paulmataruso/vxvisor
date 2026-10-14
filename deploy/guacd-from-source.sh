#!/usr/bin/env bash
# Build + install Apache guacamole-server (guacd) from source and run it as a
# loopback-only systemd service. Needed because guacd is not in the Ubuntu
# archive on recent releases. VNC is always built; RDP is built only if FreeRDP
# dev headers are available.
set -euo pipefail
GUAC_VER="${GUAC_VER:-1.5.5}"
SRC="https://archive.apache.org/dist/guacamole/${GUAC_VER}/source/guacamole-server-${GUAC_VER}.tar.gz"
WORK="$(mktemp -d)"
die(){ echo "ERROR: $*" >&2; exit 1; }
say(){ echo -e "\n\033[1;36m==>\033[0m $*"; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"

say "Installing build dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Core build + protocol/codec libs. libvncserver-dev => VNC support (what the
# single-host gateway uses). Optional RDP if FreeRDP headers exist.
PKGS="build-essential autoconf automake libtool-bin pkg-config \
  libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev \
  libvncserver-dev libwebsockets-dev libpulse-dev libssh2-1-dev libtelnet-dev \
  libwebp-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev wget"
RDP_FLAG="--disable-rdp"
if apt-cache policy freerdp3-dev 2>/dev/null | grep -q 'Candidate: [0-9]'; then
  PKGS="$PKGS freerdp3-dev"; RDP_FLAG=""        # configure auto-enables RDP
elif apt-cache policy freerdp2-dev 2>/dev/null | grep -q 'Candidate: [0-9]'; then
  PKGS="$PKGS freerdp2-dev"; RDP_FLAG=""
fi
apt-get install -y -qq $PKGS

say "Fetching guacamole-server ${GUAC_VER}"
cd "$WORK"
wget -q "$SRC" -O guac.tar.gz || die "download failed: $SRC"
tar xzf guac.tar.gz
cd "guacamole-server-${GUAC_VER}"

# Newer GCC (Ubuntu 26.04) turns guac's warnings into errors via -Werror;
# relax it so 1.5.5 compiles. CFLAGS is applied last, so -Wno-error wins.
GUAC_CFLAGS="-Wno-error -Wno-discarded-qualifiers"
say "Configuring (RDP: ${RDP_FLAG:-enabled})"
./configure --prefix=/usr/local --with-systemd-dir=/etc/systemd/system $RDP_FLAG \
  CFLAGS="$GUAC_CFLAGS" || die "configure failed"
echo "--- protocol summary ---"; grep -iE 'vnc|rdp|ssh|telnet' config.log | grep -iE 'yes|no' | tail -8 || true

say "Building (guacd + libguac + VNC plugin only)"
# The guacenc/guaclog tools use an old FFmpeg API removed in Ubuntu 26.04's
# FFmpeg 7 and are not needed for the live gateway. Build just the pieces the
# browser-desktop gateway uses: libguac, the common lib, the VNC protocol
# plugin, and guacd itself.
for d in src/libguac src/common src/common-ssh src/pulse src/protocols/vnc src/guacd; do
  [ -d "$d" ] || die "missing source dir $d"
  make -C "$d" -j"$(nproc)" CFLAGS="$GUAC_CFLAGS" || die "build failed in $d"
done
say "Installing"
for d in src/libguac src/common src/common-ssh src/pulse src/protocols/vnc src/guacd; do
  make -C "$d" install || die "install failed in $d"
done
ldconfig

say "Creating guacd system user + loopback systemd unit"
id guacd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin guacd
# Prefer the unit shipped beside this script; fall back to a minimal inline one.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$HERE/guacd.service" ]; then
  install -m 0644 "$HERE/guacd.service" /etc/systemd/system/guacd.service
else
  cat > /etc/systemd/system/guacd.service <<UNIT
[Unit]
Description=Apache Guacamole proxy daemon (guacd)
After=network.target
[Service]
Type=simple
User=guacd
Group=guacd
ExecStart=/usr/local/sbin/guacd -b 127.0.0.1 -L info -f
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
fi
systemctl daemon-reload
systemctl enable --now guacd
sleep 1
say "Result"
/usr/local/sbin/guacd -v 2>&1 | head -2 || true
systemctl --no-pager --full status guacd | head -n 6 || true
ss -ltnp 2>/dev/null | grep 4822 || echo "  (guacd not yet listening on 4822 — check: journalctl -u guacd)"
rm -rf "$WORK"
