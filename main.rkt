#lang racket/base

(require (only-in racket/contract any/c contract-out or/c)
         "private/contracts.rkt"
         "private/ecdsa.rkt"
         "private/exn.rkt"
         (only-in "private/ffi.rkt" libsecp256k1-origin)
         "private/keys.rkt"
         (only-in "private/scalar.rkt" secp256k1-order))

(provide
 (struct-out exn:fail:libsecp256k1)
 (struct-out exn:fail:libsecp256k1:load)
 (struct-out exn:fail:libsecp256k1:key)
 (struct-out exn:fail:libsecp256k1:signature)
 (struct-out exn:fail:libsecp256k1:illegal-argument)
 (struct-out exn:fail:libsecp256k1:internal)
 secp256k1-order
 compact-bytes/c
 der-bytes/c
 digest/c
 public-key-bytes/c
 recovery-id/c
 scalar/c
 secret-bytes/c
 secret-key/c
 (contract-out
  [libsecp256k1-origin (opaque-> (or/c 'bundled 'system 'environment))]

  [secret-key? (opaque-> any/c boolean?)]
  [generate-secret-key (opaque-> secret-key?)]
  [bytes->secret-key (opaque-> secret-bytes/c secret-key?)]
  [integer->secret-key (opaque-> exact-integer/c secret-key?)]
  [secret-key->bytes (opaque-> secret-key/c secret-bytes/c)]
  [secret-key->integer (opaque-> secret-key/c secret-integer/c)]
  [secret-key->public-key (opaque-> secret-key/c public-key/c)]
  [secret-key-tweak-add (opaque-> secret-key/c secret-bytes/c secret-key?)]
  [secret-key-negate (opaque-> secret-key/c secret-key?)]

  [public-key? (opaque-> any/c boolean?)]
  [bytes->public-key (opaque-> public-key-bytes/c public-key/c)]
  [public-key->bytes (opaque-> public-key/c [#:compressed? any/c] public-key-bytes/c)]
  [public-key-tweak-add (opaque-> public-key/c secret-bytes/c public-key/c)]
  [public-key-negate (opaque-> public-key/c public-key/c)]
  [public-key-combine (opaque-> public-key/c #:rest public-key/c public-key/c)]

  [ecdsa-signature? (opaque-> any/c boolean?)]
  [ecdsa-signature (opaque-> scalar/c scalar/c ecdsa-signature/c)]
  [ecdsa-signature-r (opaque-> ecdsa-signature/c scalar/c)]
  [ecdsa-signature-s (opaque-> ecdsa-signature/c scalar/c)]
  [ecdsa-recoverable-signature? (opaque-> any/c boolean?)]
  [ecdsa-recoverable-signature
   (opaque-> scalar/c scalar/c recovery-id/c ecdsa-recoverable-signature/c)]
  [ecdsa-recoverable-signature-id (opaque-> ecdsa-recoverable-signature/c recovery-id/c)]
  [ecdsa-sign (opaque-> digest/c secret-key/c ecdsa-signature/c)]
  [ecdsa-sign-recoverable (opaque-> digest/c secret-key/c ecdsa-recoverable-signature/c)]
  [ecdsa-verify (opaque-> ecdsa-signature/c digest/c public-key/c boolean?)]
  [ecdsa-recover (opaque-> ecdsa-recoverable-signature/c digest/c (or/c public-key? #f))]
  [ecdsa-signature-low-s? (opaque-> ecdsa-signature/c boolean?)]
  [ecdsa-signature-normalize (opaque-> ecdsa-signature/c ecdsa-signature/c)]
  [ecdsa-signature->compact (opaque-> ecdsa-signature/c compact-bytes/c)]
  [compact->ecdsa-signature (opaque-> compact-bytes/c ecdsa-signature/c)]
  [compact->ecdsa-recoverable-signature
   (opaque-> compact-bytes/c recovery-id/c ecdsa-recoverable-signature/c)]
  [ecdsa-signature->der (opaque-> ecdsa-signature/c der-bytes/c)]
  [der->ecdsa-signature (opaque-> byte-string/c ecdsa-signature/c)]))
