# Examples

Numbered scripts, meant to be read top to bottom and then poked at.  Every
input is fixed (keys 1, 2 and n − 1, digests of fixed messages) except one
generated key, which is only ever tested with a predicate.

```
racket examples/00-keys.rkt                         # run it
racket -i -e '(enter! "examples/00-keys.rkt")'      # run it, then stay in its REPL
```

In the REPL every name the script defines (`one`, `g`, `sig`, `rsig`, ...)
is bound.  `(show expr)` prints an expression and its value; `(show-error
expr)` prints the exception it raises.

| script | shows |
|---|---|
| `00-keys.rkt` | which C library is loaded, secret keys from bytes and back, how they print, generated keys, invalid secret keys (zero, the order, a wrong length), public keys in both forms, parsing them, equality, invalid public keys (prefix 05, hybrid 06, an x that is not on the curve) |
| `01-sign-verify.rkt` | digests with `sha256-bytes`, signing, determinism, verifying against the wrong digest and the wrong key, r and s as integers, low-S, a high-S twin that fails until normalized |
| `02-recover.rkt` | recoverable signing, r, s and the recovery id, recovering the signer, another digest recovering another key, an id that recovers nothing, a recoverable signature verifying as a plain one |
| `03-encodings.rkt` | compact bytes and back, with and without a recovery id, DER bytes and back, malformed DER and out-of-range compact signatures |
| `04-tweaks.rkt` | tweaking a secret key and its public key in step, the zero tweak, negation, sums of public keys, sums that are the point at infinity |

`tests/examples.rkt` runs every script.
