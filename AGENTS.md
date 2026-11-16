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
| `private/contracts.rkt` | `secp256k1-order`, the named flat contracts, the opaque contracts and `opaque->` |
| `private/locate.rkt` | candidate libraries, `required-symbols`, `open-candidate`; shared by the loader and the pre-installer |
| `private/ffi.rkt` | the load attempt, the per-place context, the callbacks, one raw callout per C symbol, `libsecp256k1-origin` |
| `private/keys.rkt` | `secret-key` and `public-key` and their operations (unchecked) |
| `private/ecdsa.rkt` | signature structs and operations (unchecked) |
| `private/install.rkt` | the pre-installer, which builds the C library; never requires `main.rkt`, `private/ffi.rkt`, `private/keys.rkt` or `private/ecdsa.rkt` |
| `native/secp256k1/` | the vendored upstream subset, byte-identical to the release tarball, with `COPYING` and `MANIFEST.rktd` |
| `native/vendor.rkt` | maintainer tool: release tarball to `native/secp256k1/` and `MANIFEST.rktd` |
| `native/build/` | build output, git-ignored |
| `examples/` | numbered scripts (`NN-topic.rkt`) for reading and for the REPL |
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
nix build -L                                   # hermetic build and tests
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
- No secret key, secret-key bytes or tweak in any printed form, error
  message, contract violation or arity error.  Every procedure that can
  receive secret material is wrapped with `opaque->`.
- Errors a caller can meet are `exn:fail:libsecp256k1` or a subtype, or a
  contract violation.  Parsers take untrusted bytes and raise only their
  documented exception.
- Macros use `syntax-parse` (`define-syntax-parse-rule`), never
  `define-syntax-rule`.  Conversions are named `a->b`.  Constructors are
  `(type-name ...)`, not `(make-type-name ...)`.
- Native resources go through a `with-...` macro; there is no exposed
  alloc/free pair, no `malloc`, no finalizer.
- Every user-visible feature has an example.  A new example takes the next
  number, gets a row in `examples/README.md`, and is run by
  `tests/examples.rkt`.  Every manual example is repeated in
  `tests/docs.rkt`.
- Each review finding that is fixed gets a test that fails without the fix.
- `master` must always build: the package catalog follows it.  Bump
  `version` in `info.rkt` on API changes.
