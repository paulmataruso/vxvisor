#!/usr/bin/env bash
# Publish a VXVisor GitHub release that the in-app updater can consume.
#
# Builds the server (vdxd) and both desktop clients at one version, writes a
# SHA256SUMS manifest, and creates a GitHub release with all of them attached.
# The running server's Update page reads this release (api.github.com/.../releases/
# latest), verifies downloads against SHA256SUMS, swaps vdxd, refreshes the
# bundled client binaries, and restarts. Desktop clients then self-update from
# their server.
#
# Asset-name contract (do not change without updating the readers):
#   vdxd-<ver>-linux-amd64                     <- platform.findAsset("vdxd")
#   vxconsole-<ver>-linux-amd64                <- clients refresh + /clients/latest
#   vxconsole-<ver>-windows-amd64.exe          <- clients refresh + /clients/latest
#   SHA256SUMS                                 <- platform.FetchSHA256SUMS
#
# Requires: go, docker (for fyne-cross), and the GitHub CLI `gh` (authenticated).
#
# Usage: deploy/release.sh vX.Y.Z-YYYYMMDD [notes-file] [--prerelease] [--target <branch>]
#   --prerelease        mark the release as a GitHub pre-release (the "Preview"
#                       channel the Update page can track) — build these from dev.
#   --target <branch>   git ref the tag is cut from (default: current branch;
#                       use main for stable, dev for preview).
set -euo pipefail
cd "$(dirname "$0")/.."

VER="${1:?usage: deploy/release.sh vX.Y.Z-YYYYMMDD [notes-file] [--prerelease] [--target <branch>]}"
shift
NOTES=""
PRERELEASE=""
TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prerelease) PRERELEASE="--prerelease" ;;
    --target) TARGET="$2"; shift ;;
    *) NOTES="$1" ;;
  esac
  shift
done
OUT=dist/release
rm -rf "$OUT"; mkdir -p "$OUT"

echo ">> building vdxd $VER"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$VER" -o "$OUT/vdxd-$VER-linux-amd64" ./cmd/vdxd

echo ">> building desktop clients $VER"
( cd desktop && ./build.sh "$VER" )
cp "desktop/staging/vxconsole-$VER-linux-amd64"        "$OUT/"
cp "desktop/staging/vxconsole-$VER-windows-amd64.exe"  "$OUT/"

echo ">> writing SHA256SUMS"
( cd "$OUT" && sha256sum vdxd-"$VER"-linux-amd64 vxconsole-"$VER"-* > SHA256SUMS && cat SHA256SUMS )

echo ">> creating GitHub release $VER"
notes_arg=(--generate-notes)
[ -n "$NOTES" ] && notes_arg=(--notes-file "$NOTES")
extra=()
[ -n "$PRERELEASE" ] && extra+=(--prerelease)
[ -n "$TARGET" ] && extra+=(--target "$TARGET")
gh release create "$VER" \
  "$OUT/vdxd-$VER-linux-amd64" \
  "$OUT/vxconsole-$VER-linux-amd64" \
  "$OUT/vxconsole-$VER-windows-amd64.exe" \
  "$OUT/SHA256SUMS" \
  --title "$VER" "${notes_arg[@]}" "${extra[@]}"

echo ">> done: https://github.com/paulmataruso/vxvisor/releases/tag/$VER"
