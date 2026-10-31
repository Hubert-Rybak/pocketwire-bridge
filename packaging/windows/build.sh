#!/bin/sh
# Builds the Windows installer for one architecture with makensis (runs on Linux and macOS).
#   packaging/windows/build.sh <version> <arch> <dir> <out dir>
# <dir> holds pocketwire.exe (command line) and PocketwireBridge.exe (built with
# --features gui: the tray app, no console window). Output: <out>/pocketwire-setup-windows-<arch>.exe
set -eu
version=${1:?version}; arch=${2:?arch: amd64 or arm64}; src=${3:?dir with the two exes}; out=${4:?out dir}
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$src" && pwd)
mkdir -p "$out"; out=$(cd "$out" && pwd)
for f in pocketwire.exe PocketwireBridge.exe; do
  [ -f "$src/$f" ] || { echo "missing $src/$f" >&2; exit 1; }
done
cd "$here"
makensis -V2 -DVERSION="$version" -DARCH="$arch" -DSRC="$src" -DOUT="$out/pocketwire-setup-windows-$arch.exe" installer.nsi
