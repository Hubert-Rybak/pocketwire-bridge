#!/bin/sh
# Builds "Pocketwire Bridge.app" (menu bar icon, universal arm64 + x86_64) and zips it.
# Runs on a Mac: lipo, sips, iconutil and codesign come with Xcode's command line tools.
#   packaging/macos/build-app.sh <version> <out dir>        (run from the repository root)
# Output: <out>/Pocketwire-Bridge-macos.zip, and its SHA-256 on stdout.
set -eu
version=${1:?version}; out=${2:?out dir}
[ "$(uname -s)" = Darwin ] || { echo "build-app.sh runs on macOS only" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$out"; out=$(cd "$out" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
app="$tmp/Pocketwire Bridge.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

# --features gui: opened from Finder (no arguments) it starts the menu bar app; with any
# argument it is the command line tool.
export MACOSX_DEPLOYMENT_TARGET=11.0
for t in aarch64-apple-darwin x86_64-apple-darwin; do
  (cd "$root" && cargo build --release --locked --features gui --target "$t" >&2)
done
lipo -create -output "$app/Contents/MacOS/pocketwire" \
  "$root/target/aarch64-apple-darwin/release/pocketwire" "$root/target/x86_64-apple-darwin/release/pocketwire"

iconset="$tmp/Pocketwire.iconset"; mkdir -p "$iconset"
src="$root/assets/icon-512.png"
for s in 16 32 128 256; do
  sips -z $s $s "$src" --out "$iconset/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); sips -z $d $d "$src" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/Pocketwire.icns"

sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"

# Ad-hoc signature (no Apple Developer ID): Apple silicon needs one to run at all. The app is
# not notarized, so Gatekeeper asks the user to allow it once.
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"

zip="$out/Pocketwire-Bridge-macos.zip"
rm -f "$zip"
(cd "$tmp" && ditto -c -k --sequesterRsrc --keepParent "Pocketwire Bridge.app" "$zip")
shasum -a 256 "$zip" | cut -d' ' -f1
