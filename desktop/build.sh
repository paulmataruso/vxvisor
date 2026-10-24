#!/usr/bin/env bash
# Build the VXVisor Console (Wails) desktop client for Linux AND Windows, both
# cross-compiled on this Linux host. Produces raw binaries under ./staging named
# by platform — the same asset contract the Fyne client used, so the server's
# /clients download + in-app update keep working unchanged:
#   vxconsole-<ver>-linux-amd64
#   vxconsole-<ver>-windows-amd64.exe
#
# Requires (build host only): wails CLI, libgtk-3-dev + libwebkit2gtk-4.1-dev
# (Linux target), gcc-mingw-w64-x86-64 (Windows target).
#
# Usage: ./build.sh [version]   e.g. ./build.sh v1.0.0
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-dev-$(date +%Y%m%d)}"
export PATH="$PATH:$(go env GOPATH)/bin"
LD="-X main.version=${VERSION}"

echo ">> Building linux/amd64 ..."
wails build -s -clean -tags webkit2_41 -ldflags "$LD" -o vxconsole

echo ">> Building windows/amd64 ..."
CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1 \
  wails build -s -platform windows/amd64 -ldflags "$LD" -o vxconsole.exe

mkdir -p staging
cp build/bin/vxconsole     "staging/vxconsole-${VERSION}-linux-amd64"
cp build/bin/vxconsole.exe "staging/vxconsole-${VERSION}-windows-amd64.exe"

echo
echo "Done. Artifacts:"
ls -lh staging/
