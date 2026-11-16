# libsecp256k1

FFI bindings for Racket to Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1): secret and public
keys on the secp256k1 curve, deterministic ECDSA signatures (RFC 6979,
low-S), public key recovery, and key tweaks.

This package binds the C library.  It is unrelated to the pure-Racket
`secp256k1` package on the catalog.

```racket
(require libsecp256k1 file/sha1)

(define key (generate-secret-key))
(define digest (sha256-bytes #"hello"))
(define sig (ecdsa-sign-recoverable digest key))
(ecdsa-verify sig digest (secret-key->public-key key))       ; #t
(equal? (ecdsa-recover sig digest) (secret-key->public-key key))  ; #t
```

The manual is `scribblings/libsecp256k1.scrbl` (`raco docs libsecp256k1`
once installed); `examples/` holds runnable scripts.

## Install

```
raco pkg install libsecp256k1
```

Installing compiles the bundled C library (libsecp256k1 0.8.0 with the
recovery module) into the package's own directory, so it needs a C compiler
at install time: `gcc` or `cc` on Linux and macOS, or whatever `CC`
names.  It takes a few seconds and happens again only when the vendored
source or the build flags change.  To rebuild by hand, run
`raco setup libsecp256k1`.

Without a compiler, the package falls back to a system libsecp256k1, 0.2 or
later, built with the recovery module.  If neither works, `raco
setup` reports the error, the package stays installed, and every call that
needs the library raises `exn:fail:libsecp256k1:load`.
`(libsecp256k1-origin)` says which library was loaded: `'bundled`,
`'system` or `'environment`.

`LIBSECP256K1_LIBRARY` overrides the choice when the library is loaded: a
path loads that file only, and `system` skips the bundled copy.

`raco exe` and `raco distribute` carry the built library along, since it is
a runtime path of the package; build it before making an executable.

## Vendored source

`native/secp256k1/` is the subset of the upstream v0.8.0 release tarball the
build needs (56 files, byte-identical), with `MANIFEST.rktd` recording the
tarball's sha256 and each file's.  `tests/vendor.rkt` recomputes them.  To
update, download the release tarball, check its hash against the release,
then:

```
racket native/vendor.rkt secp256k1-X.Y.Z.tar.gz X.Y.Z
```

and bump `version` in `info.rkt`.  Never edit the vendored files by hand.

## Development

```
nix develop                                   # Racket, a C compiler, cast, a system libsecp256k1
raco test -x -p libsecp256k1                  # tests, vectors, examples
racket examples/00-keys.rkt
raco setup --check-pkg-deps --unused-pkg-deps --pkgs libsecp256k1
nix build -L                                  # hermetic build and tests
```

The dev shell links this checkout into its own Racket user scope, which runs
the pre-installer.  The gates CI runs are in `.racket-dev.rktd`; see
`AGENTS.md` for the rules.  The cast differential (`tests/cast.rkt`) and the
system-library tests (`tests/load.rkt`) run when `LIBSECP256K1_CAST` and
`LIBSECP256K1_TEST_SYSTEM_LIB` are set, as the dev shell does.

## Licences

- This package: `Apache-2.0 OR MIT` (`LICENSE-APACHE`, `LICENSE-MIT`).
- `native/secp256k1/`: MIT, see `native/secp256k1/COPYING`.
- Test vectors: tiny-secp256k1 (MIT) and trezor-crypto (MIT), and
  Wycheproof (Apache-2.0); see `tests/vectors/README`.
