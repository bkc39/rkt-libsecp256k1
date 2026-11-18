#!/usr/bin/env bash
#
# Compile libsecp256k1 from an unpacked upstream release into one shared library.
# The Nix `native` derivation and scripts/build-so.sh both run this, so every
# shipped library comes from the same compile line.
#
# Usage: native/build.sh <unpacked-source-dir> <output-library>
#   CC selects the compiler (default cc).
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <unpacked-source-dir> <output-library>" >&2
  exit 2
fi

src="$(cd "$1" && pwd)"
out="$2"
cc="${CC:-cc}"

cflags=(
  -O2 -fPIC -fvisibility=hidden
  -DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_KB=86 -DENABLE_MODULE_RECOVERY=1
  -ffile-prefix-map="$src"=secp256k1
  -I"$src/include" -I"$src/src"
)

objects="$(mktemp -d)"
trap 'rm -rf "$objects"' EXIT

for unit in secp256k1 precomputed_ecmult precomputed_ecmult_gen; do
  "$cc" -c "${cflags[@]}" -o "$objects/$unit.o" "$src/src/$unit.c"
done

"$cc" -fPIC -shared -o "$out" \
  "$objects/secp256k1.o" "$objects/precomputed_ecmult.o" "$objects/precomputed_ecmult_gen.o"
