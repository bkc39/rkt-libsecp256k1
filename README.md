# libsecp256k1

FFI bindings for Racket to Bitcoin Core's
[libsecp256k1](https://github.com/bitcoin-core/secp256k1): secret and public
keys on the secp256k1 curve, deterministic ECDSA signatures (RFC 6979,
low-S), public key recovery and key tweaks.  Installing compiles the bundled
C library, so it needs a C compiler; without one the package uses a system
libsecp256k1 0.2 or later.  It is unrelated to the pure-Racket `secp256k1`
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

Licence: `Apache-2.0 OR MIT`; the bundled libsecp256k1 source is MIT.
