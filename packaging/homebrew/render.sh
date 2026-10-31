#!/bin/sh
# Writes the cask or the formula for one release:
#   render.sh cask <version> <sha256 of Pocketwire-Bridge-macos.zip> > Casks/pocketwire-bridge.rb
#   render.sh formula <version> <sha256 of the source tarball>      > Formula/pocketwire.rb
set -eu
kind=${1:?cask or formula}; version=${2:?version}; sha=${3:?sha256}
case "$kind" in
  cask) tmpl=pocketwire-bridge.rb.tmpl ;;
  formula) tmpl=pocketwire.rb.tmpl ;;
  *) echo "cask or formula" >&2; exit 1 ;;
esac
echo "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' || { echo "bad version" >&2; exit 1; }
case "$sha" in *[!0-9a-f]*|"") echo "bad sha256" >&2; exit 1;; esac
[ ${#sha} -eq 64 ] || { echo "bad sha256" >&2; exit 1; }
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha/g" "$(dirname "$0")/$tmpl"
