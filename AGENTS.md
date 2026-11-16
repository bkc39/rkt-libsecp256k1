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
| `private/scalar.rkt` | `secp256k1-order` and integer/32-byte conversions |
| `private/contracts.rkt` | the opaque contracts and `opaque->` |
| `private/locate.rkt` | candidate libraries, `required-symbols`, `open-candidate`, `locate-library`; shared by the loader and the pre-installer |
| `private/ffi.rkt` | the load attempt, the context, the callbacks, one callout per C symbol (`define-secp`), `libsecp256k1-origin` |
| `private/keys.rkt` | `secret-key` and `public-key` and their operations (unchecked) |
| `private/ecdsa.rkt` | signature structs and operations (unchecked) |
| `private/install.rkt` | the pre-installer, which builds the C library; never requires `main.rkt`, `private/ffi.rkt`, `private/keys.rkt` or `private/ecdsa.rkt` |
| `native/secp256k1/` | the vendored upstream subset, byte-identical to the release tarball, with `COPYING` and `MANIFEST.rktd` |
| `native/vendor.rkt` | maintainer tool: release tarball to `native/secp256k1/` and `MANIFEST.rktd` |
| `native/build/` | build output, git-ignored |
| `examples/` | numbered scripts (`NN-topic.rkt`) for reading and for the REPL; their output in `examples/transcripts/` |
| `scribblings/recorded.rkt` | the manual's examples with their recorded results |
| `tests/helpers/` | shared test code, not run as tests |
| `tests/vectors/` | known-answer vectors; sources, commits, hashes and licences in its `README` |

There is no public raw-FFI module.  Tests require `libsecp256k1/private/ffi`
directly.

## Commands

Work inside the dev shell; it pins Racket, a C compiler, foundry's `cast`
and a system libsecp256k1, and links this checkout (the link's setup runs
the pre-installer, which compiles the bundled library).

```bash
nix develop -c raco test -x -p libsecp256k1    # tests, vectors, every example
nix develop -c racket examples/00-keys.rkt
nix develop -c raco setup --check-pkg-deps --unused-pkg-deps --pkgs libsecp256k1   # build, docs, deps
nix flake check -L                             # hermetic build and tests
```

The gates are in `.racket-dev.rktd`.

## Rules

- Every public binding has a contract in `main.rkt`, an entry in
  `scribblings/libsecp256k1.scrbl` and a test.  API documentation lives in
  the manual, not in comments.
- The manual is terse and shows Racket only.  It never mentions Nix.
- Never edit `native/secp256k1/`.  Update it only with
  `racket native/vendor.rkt <tarball> <version>`, then bump `version` in
  `info.rkt`; `tests/vendor.rkt` recomputes every hash.
- No argument value in any printed form, error message, contract violation,
  arity error or keyword error: a violation names what was expected and the
  kind and length of what was given, never the value.  Every export that
  takes an argument is wrapped with `opaque->` in `main.rkt`;
  `tests/contracts.rkt` probes each one.
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

The pre-installer (`private/install.rkt`) compiles `native/secp256k1/` into
`native/build/<platform>/` with the flags in its build table, and writes a
stamp of the vendored version, manifest hash and table; a matching stamp
skips the build.  A failed build deletes any stale library and stamp, then
falls back to a system libsecp256k1 (0.2 or later, with the recovery
module); if neither works it prints why and what to do, and `raco setup`
still succeeds so the package and its manual install.

`LIBSECP256K1_LIBRARY` overrides the choice at load time: a path loads that
file only, and `system` skips the bundled copy.  System candidates are
sonames resolved by the OS loader (Linux, BSD) or absolute paths built from
explicit directories (macOS, Windows), never the current directory.

`raco exe` and `raco distribute` carry the built library along, since it is
a runtime path of the package.

## Vendored source

`native/secp256k1/` is the subset of the upstream v0.8.0 release tarball the
build needs, byte-identical, with `MANIFEST.rktd` recording the tarball's
sha256 and each file's.  `tests/vendor.rkt` recomputes them.  To update,
download the release tarball, check its hash against the release, then run
`racket native/vendor.rkt secp256k1-X.Y.Z.tar.gz X.Y.Z` and bump `version` in
`info.rkt`.

## Tests that need tools

`tests/cast.rkt` (a differential against foundry's `cast`) runs when
`LIBSECP256K1_CAST` names a `cast` binary; the system-library tests in
`tests/load.rkt` run when `LIBSECP256K1_TEST_SYSTEM_LIB` names a system
libsecp256k1.  Each prints a `SKIPPED` line otherwise.  The dev shell and
`nix flake check` set both; the CI Racket lanes set `LIBSECP256K1_CAST`, and
the system-library tests run in the `nix flake check` lane.
