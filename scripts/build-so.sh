#!/usr/bin/env bash
#
# Build the prebuilt libsecp256k1 the package installs from, and stage it as
# native-libs/candidates/<platform>/, and record its build inputs in
# native-libs/candidates/BUILD-INPUTS (scripts/record-build-inputs.sh).  The
# source is the release pinned in native/upstream.json, the compile line is
# native/build.sh, and every platform parameter is in native/toolchain.sh.
#
# linux:  x86_64, inside manylinux2014 (glibc 2.17), so the library needs only
#         GLIBC <= 2.17 and nothing beyond libc.  Needs docker.
# darwin: the host's cc (Apple silicon), install name @rpath, ad-hoc signed.
#
# Usage: scripts/build-so.sh [linux|darwin]    (default: the host's OS)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../native/toolchain.sh
. "$ROOT/native/toolchain.sh"

pin() {
  sed -n "s/^ *\"$1\": *\"\([^\"]*\)\".*/\1/p" "$ROOT/native/upstream.json"
}

platform="${1:-}"
if [[ -z "$platform" ]]; then
  case "$(uname -s)" in
    Linux) platform=linux ;;
    Darwin) platform=darwin ;;
    *) echo "error: unsupported OS '$(uname -s)'; pass linux|darwin" >&2; exit 1 ;;
  esac
fi

case "$platform" in
  linux) lib=libsecp256k1.so ;;
  darwin) lib=libsecp256k1.dylib ;;
  *) echo "error: unknown platform '$platform' (expected linux|darwin)" >&2; exit 1 ;;
esac

version="$(pin version)"
url="$(pin url)"
sha256="$(pin sha256)"
if [[ -z "$version" || -z "$url" || -z "$sha256" ]]; then
  echo "error: native/upstream.json lacks version, url or sha256" >&2
  exit 1
fi

dest="$ROOT/native-libs/candidates/$platform"
mkdir -p "$dest"

fetch_and_build='
  set -euo pipefail
  work="$(mktemp -d)"
  trap "rm -rf \"$work\"" EXIT
  curl --proto "=https" --tlsv1.2 -sSfL -o "$work/src.tar.gz" "$URL"
  if command -v sha256sum >/dev/null; then sum=sha256sum; else sum="shasum -a 256"; fi
  echo "$SHA256  $work/src.tar.gz" | $sum -c -
  mkdir "$work/src"
  tar xzf "$work/src.tar.gz" -C "$work/src" --strip-components 1
  bash "$BUILD" "$work/src" "$work/$LIB"
  cp "$work/$LIB" "$OUT/$LIB"
'

echo ">> libsecp256k1 $version ($url)"
if [[ "$platform" == linux ]]; then
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e HOME=/tmp -e CC="$LINUX_CC" \
    -e URL="$url" -e SHA256="$sha256" -e LIB="$lib" \
    -e BUILD=/src/native/build.sh -e OUT=/out \
    -v "$ROOT:/src:ro" \
    -v "$dest:/out" \
    "$MANYLINUX_IMAGE@$MANYLINUX_DIGEST" bash -c "$fetch_and_build"
else
  export MACOSX_DEPLOYMENT_TARGET="$DARWIN_DEPLOYMENT_TARGET"
  URL="$url" SHA256="$sha256" LIB="$lib" BUILD="$ROOT/native/build.sh" OUT="$dest" \
    CC="$DARWIN_CC" bash -c "$fetch_and_build"
  darwin_finish "$dest/$lib"
fi

echo ">> staged $dest/$lib"
if command -v sha256sum >/dev/null; then sum=sha256sum; else sum="shasum -a 256"; fi
(cd "$ROOT/native-libs/candidates" && $sum "$platform/$lib")
echo ">> build inputs (native-libs/candidates/BUILD-INPUTS)"
"$ROOT/scripts/record-build-inputs.sh" "$platform"

echo ">> dynamic dependencies"
if [[ "$platform" == darwin ]]; then
  otool -L "$dest/$lib"
else
  objdump -p "$dest/$lib" | grep -E 'NEEDED|SONAME' || true
  glibc="$(objdump -T "$dest/$lib" | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V -u | tail -1)"
  echo "max glibc: $glibc"
fi
