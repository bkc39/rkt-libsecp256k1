# libsecp256k1

FFI bindings for Racket to Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1): secret and public
keys on the secp256k1 curve, deterministic ECDSA signatures (RFC 6979,
low-S), public key recovery and key tweaks.  The package ships a prebuilt
libsecp256k1 0.8.0 for x86_64 Linux (glibc 2.17 or later) and Apple-silicon
macOS, so installing compiles nothing; elsewhere it uses a system libsecp256k1
0.2 or later with the recovery module, or the file named by
`LIBSECP256K1_LIBRARY`.  It is unrelated to the pure-Racket `secp256k1`
package.

```
raco pkg install libsecp256k1
```

```racket
(require libsecp256k1)
(define key (generate-secret-key))
(define digest (sha256-bytes #"hello"))
(define sig (ecdsa-sign-recoverable digest key))
(equal? (ecdsa-recover sig digest) (secret-key->public-key key))  ; #t
```

The manual is `raco docs libsecp256k1`; `examples/` holds runnable scripts.

Maintainers: `native-libs/BUILDING.md` says how the prebuilt libraries are
built and updated.

Licence: `Apache-2.0 OR MIT`.  The prebuilt libraries in
`native-libs/candidates/` are compiled, unmodified, from the upstream
libsecp256k1 release and are distributed under its MIT licence, whose notice is
`native-libs/LICENSE.libsecp256k1`.
