# The prebuilt libsecp256k1

The package compiles nothing at install.  Its pre-installer
(`private/install.rkt`) copies a prebuilt library from `candidates/` into this
directory, where the loader (`private/locate.rkt`) finds it:

| platform (`system-library-subpath`) | committed file |
|---|---|
| `x86_64-linux` | `candidates/linux/libsecp256k1.so` |
| `aarch64-macosx` | `candidates/darwin/libsecp256k1.dylib` |

Any other platform gets no bundled library and uses a system libsecp256k1 or
the file named by `LIBSECP256K1_LIBRARY`.  When `LIBSECP256K1_NATIVE_LIB_PATH`
names a directory whose `lib/` holds the library (the Nix build and dev shell
set it to the `native` derivation), the pre-installer copies that one instead.

`candidates/SHA256SUMS` records the sha256 of every committed candidate;
`tests/native.rkt` checks the files against it.  `LICENSE.libsecp256k1` is
upstream's `COPYING`, the MIT notice the binaries are distributed under.

## How a candidate is built

`native/upstream.json` pins the upstream release: version, tarball URL and
sha256.  `native/build.sh <source-dir> <output>` is the one compile line:
`src/secp256k1.c`, `src/precomputed_ecmult.c` and
`src/precomputed_ecmult_gen.c` at `-O2 -fPIC -fvisibility=hidden` with
`-DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_KB=86 -DENABLE_MODULE_RECOVERY=1`,
linked `-shared`.  The flake's `native` package and `scripts/build-so.sh` both
run it.

```sh
scripts/build-so.sh linux    # docker: manylinux2014 (glibc 2.17), pinned by digest
scripts/build-so.sh darwin   # on an Apple-silicon Mac: cc, install name @rpath, ad-hoc codesign
```

Each downloads the pinned tarball, checks its sha256, builds, stages the result
in `candidates/<platform>/` and prints its sha256 and dynamic dependencies.
The linux build is reproducible: the same pin and script give the same bytes,
and CI rebuilds it and fails if it differs from the committed file.  It must
need only `libc.so.6` and no glibc symbol version above 2.17; CI checks both
and loads it under glibc 2.17.

## Updating upstream

1. Edit `native/upstream.json`: version, URL, and the sha256 of the release
   tarball (download it and check it against the release).
2. Update the expected values in `tests/native.rkt`.
3. `scripts/build-so.sh linux`, then `cd native-libs/candidates &&
   sha256sum linux/libsecp256k1.so` and replace that line of `SHA256SUMS`.
4. If upstream's `COPYING` changed, copy it to `LICENSE.libsecp256k1` and
   update its hash in `tests/native.rkt`.
5. Push.  CI's `Build libsecp256k1 (darwin)` job uploads the darwin build as
   the artifact `libsecp256k1-darwin`; commit it as
   `candidates/darwin/libsecp256k1.dylib` and add its line to `SHA256SUMS`
   (`shasum -a 256 darwin/libsecp256k1.dylib`).
6. Bump `version` in `info.rkt`.
