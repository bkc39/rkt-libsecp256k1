#lang racket/base

(require (only-in racket/contract
                  ->
                  ->*
                  any/c
                  contract-out
                  or/c)
         "private/contracts.rkt"
         "private/ecdsa.rkt"
         "private/exn.rkt"
         (only-in "private/ffi.rkt" libsecp256k1-origin)
         "private/keys.rkt")

(provide
 (struct-out exn:fail:libsecp256k1)
 (struct-out exn:fail:libsecp256k1:load)
 (struct-out exn:fail:libsecp256k1:key)
 (struct-out exn:fail:libsecp256k1:signature)
 (struct-out exn:fail:libsecp256k1:illegal-argument)
 (struct-out exn:fail:libsecp256k1:internal)
 secp256k1-order
 digest/c
 secret-bytes/c
 secret-key/c
 public-key-bytes/c
 compact-bytes/c
 recovery-id/c
 scalar/c
 (contract-out
  [libsecp256k1-origin (-> (or/c 'bundled 'system 'environment))]

  [secret-key? (-> any/c boolean?)]
  [generate-secret-key (-> secret-key?)]
  [bytes->secret-key (opaque-> secret-bytes/c secret-key?)]
  [secret-key->bytes (opaque-> secret-key/c bytes?)]
  [secret-key->public-key (opaque-> secret-key/c public-key?)]
  [secret-key-tweak-add (opaque-> secret-key/c secret-bytes/c secret-key?)]
  [secret-key-negate (opaque-> secret-key/c secret-key?)]

  [public-key? (-> any/c boolean?)]
  [bytes->public-key (-> public-key-bytes/c public-key?)]
  [public-key->bytes (->* (public-key?) (#:compressed? any/c) bytes?)]
  [public-key-tweak-add (opaque-> public-key? secret-bytes/c public-key?)]
  [public-key-negate (-> public-key? public-key?)]
  [public-key-combine (-> public-key? public-key? ... public-key?)]

  [ecdsa-signature? (-> any/c boolean?)]
  [ecdsa-signature (-> scalar/c scalar/c ecdsa-signature?)]
  [ecdsa-signature-r (-> ecdsa-signature? scalar/c)]
  [ecdsa-signature-s (-> ecdsa-signature? scalar/c)]
  [ecdsa-recoverable-signature? (-> any/c boolean?)]
  [ecdsa-recoverable-signature
   (-> scalar/c scalar/c recovery-id/c ecdsa-recoverable-signature?)]
  [ecdsa-recoverable-signature-recovery-id
   (-> ecdsa-recoverable-signature? recovery-id/c)]
  [ecdsa-sign (opaque-> digest/c secret-key/c ecdsa-signature?)]
  [ecdsa-sign-recoverable (opaque-> digest/c secret-key/c ecdsa-recoverable-signature?)]
  [ecdsa-verify (-> ecdsa-signature? digest/c public-key? boolean?)]
  [ecdsa-recover (-> ecdsa-recoverable-signature? digest/c (or/c public-key? #f))]
  [ecdsa-signature-low-s? (-> ecdsa-signature? boolean?)]
  [ecdsa-signature-normalize (-> ecdsa-signature? ecdsa-signature?)]
  [ecdsa-signature->compact (-> ecdsa-signature? compact-bytes/c)]
  [compact->ecdsa-signature
   (->* (compact-bytes/c) (#:recovery-id (or/c #f recovery-id/c)) ecdsa-signature?)]
  [ecdsa-signature->der (-> ecdsa-signature? bytes?)]
  [der->ecdsa-signature (-> bytes? ecdsa-signature?)]))
