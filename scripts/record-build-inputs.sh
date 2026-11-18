#!/usr/bin/env bash
#
# Record which build inputs a candidate was built from, as its line of
# native-libs/candidates/BUILD-INPUTS: the sha256 of the `sha256sum` listing of
# native/upstream.json, native/build.sh and native/toolchain.sh, taken from the
# package root.  tests/native.rkt checks every line against the current files.
#
# Usage: scripts/record-build-inputs.sh linux|darwin
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  linux) lib=linux/libsecp256k1.so ;;
  darwin) lib=darwin/libsecp256k1.dylib ;;
  *) echo "usage: $0 linux|darwin" >&2; exit 2 ;;
esac

if command -v sha256sum >/dev/null; then sum=sha256sum; else sum="shasum -a 256"; fi
inputs="$(cd "$ROOT" && $sum native/upstream.json native/build.sh native/toolchain.sh \
  | $sum | cut -d' ' -f1)"

record="$ROOT/native-libs/candidates/BUILD-INPUTS"
touch "$record"
{ grep -v "  $lib\$" "$record" || true; echo "$inputs  $lib"; } | sort -k2 > "$record.new"
mv "$record.new" "$record"
echo "$inputs  $lib"
