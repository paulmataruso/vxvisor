#!/usr/bin/env bash
# Build + install Apache guacamole-server (guacd) from source and run it as a
# loopback-only systemd service. Needed because guacd is not in the Ubuntu
# archive on recent releases. VNC is always built; RDP is built only if FreeRDP
# dev headers are available.
set -euo pipefail
# 1.6.0+ is required for FreeRDP 3 (what current Ubuntu ships); older guacd only
# builds RDP against FreeRDP 2.
GUAC_VER="${GUAC_VER:-1.6.0}"
SRC="https://archive.apache.org/dist/guacamole/${GUAC_VER}/source/guacamole-server-${GUAC_VER}.tar.gz"
WORK="$(mktemp -d)"
die(){ echo "ERROR: $*" >&2; exit 1; }
say(){ echo -e "\n\033[1;36m==>\033[0m $*"; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"

say "Installing build dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# FreeRDP >= 3.31 ships a fatal RDP crash for guacd: gdi_init_ex() dereferences a
# NULL brush cache for a normal client (FreeRDP issue #13342), segfaulting every
# RDP session before it connects. It is absent in <= 3.30. If the archive's
# candidate FreeRDP 3 is affected, pin the newest available FreeRDP 3 below 3.31
# and hold it, so the RDP plugin we build links a working library.
freerdp_guard(){
  local cand older pkgs
  cand=$(apt-cache policy libfreerdp3-3 2>/dev/null | awk '/Candidate:/{print $2}')
  [ -n "$cand" ] && [ "$cand" != "(none)" ] || return 0
  if dpkg --compare-versions "$cand" ge "3.31"; then
    older=$(apt-cache madison libfreerdp3-3 2>/dev/null | awk -F'|' '{gsub(/ /,"",$2);print $2}' \
            | while read -r v; do dpkg --compare-versions "$v" lt "3.31" 2>/dev/null && echo "$v"; done \
            | sort -V | tail -1)
    if [ -n "$older" ]; then
      pkgs="libfreerdp3-3 libfreerdp-client3-3 libwinpr3-3 freerdp3-dev libwinpr3-dev"
      say "FreeRDP candidate $cand has the >=3.31 RDP crash; pinning $older"
      # shellcheck disable=SC2046
      apt-get install -y --allow-downgrades $(for p in $pkgs; do echo "$p=$older"; done) 2>/dev/null \
        && apt-mark hold $pkgs >/dev/null 2>&1 \
        && echo "  pinned + held FreeRDP at $older" \
        || echo "  WARN: could not pin FreeRDP to $older; RDP may crash on >=3.31"
    else
      echo "  WARN: no FreeRDP 3 < 3.31 available; RDP may crash (see FreeRDP #13342)"
    fi
  fi
}
freerdp_guard
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
# Detect FreeRDP AND capture its include flags (freerdp + winpr). Without the
# winpr headers on the include path, guac's configure feature-probes (which
# #include <freerdp/freerdp.h>) fail to compile and SILENTLY report "no" — so the
# RDP plugin falls back to FreeRDP-2 struct layouts that no longer exist in
# FreeRDP 3.x and the build fails. Feeding these flags lets configure detect the
# real API (FREERDP_HAS_CONTEXT, HAVE_SETTERS_GETTERS, etc.) correctly. guac's
# configure auto-detects/enables RDP when FreeRDP is present (it ignores
# --disable-rdp), so we decide the rdp-plugin build from pkg-config presence.
RDP_OK=0; FRDP_CFLAGS=""
if pkg-config --exists freerdp3 2>/dev/null; then
  RDP_OK=1; FRDP_CFLAGS="$(pkg-config --cflags freerdp3 winpr3 2>/dev/null)"
elif pkg-config --exists freerdp2 2>/dev/null; then
  RDP_OK=1; FRDP_CFLAGS="$(pkg-config --cflags freerdp2 winpr2 2>/dev/null)"
fi
# -Wno-deprecated-declarations is REQUIRED: guac's configure runs its FreeRDP
# feature-probes under -Werror, and FreeRDP 3.3x headers emit many deprecation
# warnings → every probe fails → guac silently falls back to removed FreeRDP-2
# APIs and the RDP plugin won't build. Suppressing deprecations lets the probes
# (and the build) succeed against the real FreeRDP-3 API.
GUAC_CFLAGS="-Wno-error -Wno-discarded-qualifiers -Wno-deprecated-declarations $FRDP_CFLAGS"
say "Configuring (RDP: $([ "$RDP_OK" = 1 ] && echo enabled || echo disabled))"
./configure --prefix=/usr/local --with-systemd-dir=/etc/systemd/system \
  CPPFLAGS="$FRDP_CFLAGS" CFLAGS="$GUAC_CFLAGS" || die "configure failed"
echo "--- protocol summary ---"; grep -iE 'vnc|rdp|ssh|telnet' config.log | grep -iE 'yes|no' | tail -8 || true

say "Building (guacd + libguac + VNC/RDP plugins)"
# The guacenc/guaclog tools use an old FFmpeg API removed in Ubuntu 26.04's
# FFmpeg 7 and are not needed for the live gateway. Build just the pieces the
# browser-desktop gateway uses: libguac, the common libs, the protocol plugins
# (VNC always; RDP when FreeRDP was found), and guacd itself.
DIRS="src/libguac src/common src/common-ssh src/pulse src/protocols/vnc"
if [ "$RDP_OK" = 1 ] && [ -d "src/protocols/rdp" ]; then
  DIRS="$DIRS src/protocols/rdp"
fi
DIRS="$DIRS src/guacd"
for d in $DIRS; do
  [ -d "$d" ] || die "missing source dir $d"
  make -C "$d" -j"$(nproc)" CFLAGS="$GUAC_CFLAGS" || die "build failed in $d"
done
say "Installing"
for d in $DIRS; do
  make -C "$d" install || die "install failed in $d"
done
ldconfig
echo "--- installed protocol plugins ---"; ls /usr/local/lib/libguac-client-*.so 2>/dev/null || true

say "Creating guacd system user + loopback systemd unit"
id guacd >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin guacd
# FreeRDP needs a writable HOME for its cert/credential store, or RDP (NLA)
# silently fails. The guacd user has no real home → give it one.
install -d -o guacd -g guacd -m 0750 /var/lib/guacd
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
Environment=HOME=/var/lib/guacd
WorkingDirectory=/var/lib/guacd
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
