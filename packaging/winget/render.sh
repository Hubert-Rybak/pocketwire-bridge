#!/bin/sh
# Writes the winget manifests for one release, in winget-pkgs' layout:
#   render.sh <version> <sha256 amd64 installer> <sha256 arm64 installer> <out dir>
# Output: <out>/manifests/p/Pocketwire/Bridge/<version>/Pocketwire.Bridge*.yaml
set -eu
version=${1:?version}; amd64=${2:?sha256 amd64}; arm64=${3:?sha256 arm64}; out=${4:?out dir}
echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' || { echo "bad version" >&2; exit 1; }
for sha in "$amd64" "$arm64"; do
  case "$sha" in *[!0-9a-fA-F]*|"") echo "bad sha256" >&2; exit 1;; esac
  [ ${#sha} -eq 64 ] || { echo "bad sha256" >&2; exit 1; }
done
here=$(cd "$(dirname "$0")" && pwd)
dir="$out/manifests/p/Pocketwire/Bridge/$version"
mkdir -p "$dir"
up() { echo "$1" | tr 'a-f' 'A-F'; }
for t in "$here"/*.yaml.tmpl; do
  sed -e "s/@VERSION@/$version/g" -e "s/@SHA_AMD64@/$(up "$amd64")/g" -e "s/@SHA_ARM64@/$(up "$arm64")/g" \
      -e "s/@DATE@/$(date -u +%Y-%m-%d)/g" "$t" > "$dir/$(basename "$t" .tmpl)"
done
echo "$dir"
