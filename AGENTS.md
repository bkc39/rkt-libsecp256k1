# AGENTS.md

Guidance for agents working in this repository.

## What this is

`libsecp256k1`: FFI bindings to Bitcoin Core's libsecp256k1 C library for
Racket — secret and public keys, deterministic ECDSA, public key recovery and
key tweaks.  One package, one collection (`libsecp256k1`), one manual
(`scribblings/libsecp256k1.scrbl`).  The first consumer is web3.rkt (local
signing).  It is unrelated to the pure-Racket `secp256k1` package.

| path | holds |
|---|---|
| `info.rkt` | package metadata, `pre-install-collection` |
| `main.rkt` | the public module: `contract-out` over `private/*` and the exception structs; contracts and nothing else |
| `private/exn.rkt` | the exception structs; `racket/base` only |
| `private/scalar.rkt` | `secp256k1-order`, integer/32-byte conversions, `define/snapshot` |
| `private/contracts.rkt` | the opaque contracts and `opaque->` |
| `private/locate.rkt` | `bundled-platforms`, candidate libraries, `required-symbols`, `open-candidate`, `locate-library`; shared by the loader and the pre-installer |
| `private/ffi.rkt` | the load attempt, the context, the callbacks, one callout per C symbol (`define-secp`), `libsecp256k1-origin` |
| `private/keys.rkt` | `secret-key` and `public-key` and their operations (unchecked) |
| `private/ecdsa.rkt` | signature structs and operations (unchecked) |
| `private/install.rkt` | the pre-installer, which copies the platform's prebuilt library into `native-libs/`; never requires `main.rkt`, `private/ffi.rkt`, `private/keys.rkt` or `private/ecdsa.rkt` |
| `native/upstream.json` | the pinned upstream release: version, tarball URL, sha256; read by `flake.nix` and `scripts/build-so.sh` |
| `native/build.sh` | the one compile line, `native/build.sh <source-dir> <output>` |
| `scripts/build-so.sh` | builds a portable candidate: `linux` in manylinux2014 (docker), `darwin` on a Mac |
| `native-libs/candidates/` | the committed prebuilt libraries, `<platform>/libsecp256k1.{so,dylib}`, and their `SHA256SUMS` |
| `native-libs/LICENSE.libsecp256k1` | upstream's `COPYING`, the MIT notice the binaries ship under |
| `native-libs/BUILDING.md` | how the candidates are built and updated |
| `native-libs/libsecp256k1.*` | the staged library the loader opens, git-ignored |
| `examples/` | numbered scripts (`NN-topic.rkt`) for reading and for the REPL; their output in `examples/transcripts/` |
| `scribblings/recorded.rkt` | the manual's examples with their recorded results |
| `tests/helpers/` | shared test code, not run as tests |
| `tests/vectors/` | known-answer vectors; sources, commits, hashes and licences in its `README` |

There is no public raw-FFI module.  Tests require `libsecp256k1/private/ffi`
directly.

## Commands

Work inside the dev shell; it pins Racket, foundry's `cast` and a system
libsecp256k1, builds the flake's `native` package (the pinned release compiled
by `native/build.sh`), stages it in `native-libs/` and links this checkout.

```bash
nix develop -c raco test -x -p libsecp256k1    # tests, vectors, every example
nix develop -c racket examples/00-keys.rkt
nix develop -c raco setup --check-pkg-deps --unused-pkg-deps --pkgs libsecp256k1   # build, docs, deps
nix flake check -L                             # hermetic build and tests
scripts/build-so.sh linux                      # rebuild the linux candidate (docker)
```

The gates are in `.racket-dev.rktd`.

## Rules

- Every public binding has a contract in `main.rkt`, an entry in
  `scribblings/libsecp256k1.scrbl` and a test.  API documentation lives in
  the manual, not in comments.
- The manual is terse and shows Racket only.  It never mentions Nix.
- No upstream C source or header is committed (`tests/native.rkt` checks
  it); the source is the release tarball pinned in `native/upstream.json`.
- Every shipped library comes from `native/build.sh`; a change to the compile
  line rebuilds and recommits every candidate and its `SHA256SUMS` line.
- No argument value in any printed form, error message, contract violation,
  arity error or keyword error: a violation names what was expected and the
  kind and length of what was given, never the value.  Every export that
  takes an argument is wrapped with `opaque->` in `main.rkt`;
  `tests/contracts.rkt` probes each one.
- Every export that takes a caller's byte string copies it on entry
  (`define/snapshot`) and works only on the copy, so another thread mutating
  the buffer cannot split a Racket check from the C call;
  `tests/snapshots.rkt` checks each export.
- Errors a caller can meet are `exn:fail:libsecp256k1` or a subtype, or a
  contract violation.  Parsers take untrusted bytes and raise only their
  documented exception.
- Macros use `syntax-parse` (`define-syntax-parse-rule`), never
  `define-syntax-rule`.  Conversions are named `a->b`.  Constructors are
  `(type-name ...)`, not `(make-type-name ...)`.
- No native resource needs a `with-...` macro: every C object is a Racket
  byte string, and the one context per module instance is never destroyed (a
  custodian could free it under an instance shared between namespaces).
  There is no exposed alloc/free pair, no `malloc`, no finalizer.
- Every callout runs atomically (`call-as-atomic`): a callback that raises
  after a thread swap would return to a stale foreign context.
- Every user-visible feature has an example.  A new example takes the next
  number, gets a row in `examples/README.md` and a transcript, and is
  compared with it by `tests/examples.rkt`.  Examples use only `section`,
  `show` and `show-error`.
- Manual examples live in `scribblings/recorded.rkt` with their printed
  results, so the manual builds without a usable C library;
  `tests/docs.rkt` checks every recorded result against the library.
- Each review finding that is fixed gets a test that fails without the fix.
- `master` must always build: the package catalog follows it.  Bump
  `version` in `info.rkt` on API changes.

## Installing and loading

The pre-installer (`private/install.rkt`) copies a library into
`native-libs/`: the one under `LIBSECP256K1_NATIVE_LIB_PATH/lib/` when that is
set (Nix), else the committed candidate for the platform (`bundled-platforms`:
`x86_64-linux`, `aarch64-macosx`), else it keeps a library already staged.
With none it prints what to do.  It never raises, so `raco setup` succeeds and
the package and its manual install anywhere; it replaces the staged file by a
rename, and only when the bytes differ.

At load time the order is the bundled library, then a system libsecp256k1 (0.2
or later, with the recovery module).  `LIBSECP256K1_LIBRARY` overrides the
choice: a path loads that file only (a relative path is relative to the current
directory), and `system` skips the bundled copy.  System candidates are sonames
resolved by the OS loader (Linux, BSD) or absolute paths built from explicit
directories (macOS, Windows), never the current directory.

`raco exe` and `raco distribute` carry the staged library along, since it is a
runtime path of the package.

## Native library

`native-libs/BUILDING.md` has the build and the update procedure.  In short:
edit the pin in `native/upstream.json`, run `scripts/build-so.sh linux`,
replace the linux line of `native-libs/candidates/SHA256SUMS`, update the
expected pin in `tests/native.rkt`, push, and commit the darwin build CI
uploads (`libsecp256k1-darwin`) with its `SHA256SUMS` line.  The linux
candidate is reproducible and CI fails if a fresh build differs from it; it
needs only `libc.so.6` and glibc 2.17.  Until a darwin candidate is committed,
`tests/native.rkt` prints a `SKIPPED` line for it and the macOS CI lane
installs the darwin build of the same run.

## Tests that need tools

`tests/cast.rkt` (a differential against foundry's `cast`) runs when
`LIBSECP256K1_CAST` names a `cast` binary; the system-library tests in
`tests/load.rkt` run when `LIBSECP256K1_TEST_SYSTEM_LIB` names a system
libsecp256k1.  Each prints a `SKIPPED` line otherwise.  The dev shell and
`nix flake check` set both; the CI Racket lanes set `LIBSECP256K1_CAST`, and
the system-library tests run in the `nix flake check` lane and the Ubuntu
stable lane (the distribution's package).
