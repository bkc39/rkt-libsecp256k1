# The prebuilt libsecp256k1

The package compiles nothing at install.  Its pre-installer
(`private/install.rkt`) copies a prebuilt library from `candidates/` into this
directory, where the loader (`private/locate.rkt`) finds it:

| platform (`system-library-subpath`) | committed file |
|---|---|
| `x86_64-linux` | `candidates/linux/libsecp256k1.so` |
| `aarch64-macosx` | `candidates/darwin/libsecp256k1.dylib` |

Every other platform, `aarch64-linux`, `x86_64-macosx` and Windows among them,
gets no bundled library and uses a system libsecp256k1 or the file named by
`LIBSECP256K1_LIBRARY`.  When `LIBSECP256K1_NATIVE_LIB_PATH` names a directory
whose `lib/` holds the library (the Nix build and dev shell set it to the
`native` derivation), the pre-installer copies that one instead, after checking
that it loads and exports every required symbol when installing for the host's
own platform.

`candidates/SHA256SUMS` records the sha256 of every committed candidate, and
`candidates/BUILD-INPUTS` the build inputs each was built from: the sha256 of
the `sha256sum` listing of `native/upstream.json`, `native/build.sh` and
`native/toolchain.sh`, taken from the package root.  `tests/native.rkt` fails
when a shipped platform has no candidate or no line in either file, when a
file differs from its sha256, or when a recorded build-inputs hash is not the
current one.  `LICENSE.libsecp256k1` is upstream's `COPYING`, the MIT notice
the binaries are distributed under.

## How a candidate is built

`native/upstream.json` pins the upstream release: version, tarball URL and
sha256.  `native/build.sh <source-dir> <output>` is the one compile line:
`src/secp256k1.c`, `src/precomputed_ecmult.c` and
`src/precomputed_ecmult_gen.c` at `-O2 -fPIC -fvisibility=hidden` with
`-DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_KB=86 -DENABLE_MODULE_RECOVERY=1`,
linked `-shared`.  `native/toolchain.sh` holds the rest: the manylinux image
digest, the compilers, the macOS deployment target, and the darwin install
name and ad-hoc signature.  The flake's `native` package and
`scripts/build-so.sh` both run `native/build.sh`.

```sh
scripts/build-so.sh linux    # docker: manylinux2014 (glibc 2.17), pinned by digest
scripts/build-so.sh darwin   # on an Apple-silicon Mac: cc, install name @rpath, ad-hoc codesign
```

Each downloads the pinned tarball, checks its sha256, builds, stages the result
in `candidates/<platform>/`, writes its `BUILD-INPUTS` line
(`scripts/record-build-inputs.sh <platform>`) and prints its sha256 and dynamic
dependencies.  The linux build is reproducible: the same inputs give the same
bytes, and CI rebuilds it and fails if it differs from the committed file.  It
must need only `libc.so.6` and no glibc symbol version above 2.17; CI checks
both and loads it under glibc 2.17.  CI rebuilds the darwin candidate as well
and, until two macOS builds are known to agree, only warns when the bytes
differ.

## Updating upstream, the compile line or the toolchain

A change to any of `native/upstream.json`, `native/build.sh` or
`native/toolchain.sh` rebuilds every candidate; `tests/native.rkt` fails until
each one's `BUILD-INPUTS` line is current.

1. Edit the input.  For a new release: version, URL, and the sha256 of the
   release tarball (download it and check it against the release); then the
   version the README and the manual name, which `tests/native.rkt` compares
   with the pin.
2. `scripts/build-so.sh linux`, then `cd native-libs/candidates &&
   sha256sum linux/libsecp256k1.so` and replace that line of `SHA256SUMS`.
3. If upstream's `COPYING` changed, copy it to `LICENSE.libsecp256k1` and
   update its hash in `tests/native.rkt`.
4. Push.  CI's `Build libsecp256k1 (darwin)` job uploads the darwin build as
   the artifact `libsecp256k1-darwin`.  Commit it as
   `candidates/darwin/libsecp256k1.dylib` (mode 755), replace its line of
   `SHA256SUMS` (`shasum -a 256 darwin/libsecp256k1.dylib`), and run
   `scripts/record-build-inputs.sh darwin` from the same commit (or build it on
   a Mac with `scripts/build-so.sh darwin`).
5. Bump `version` in `info.rkt`.
