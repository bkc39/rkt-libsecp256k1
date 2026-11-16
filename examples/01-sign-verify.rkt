#lang racket/base

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (integer->secret-key 1))
(define two (integer->secret-key 2))
(define one-public (secret-key->public-key one))

(section "a digest")

(define digest (sha256-bytes #"Satoshi Nakamoto"))
(show (bytes->hex-string digest))

(section "signing")

(define sig (ecdsa-sign digest one))
(show sig)

(section "the same key and digest give the same signature")

(show (equal? sig (ecdsa-sign digest one)))
(show (equal? sig (ecdsa-sign digest two)))

(section "verifying")

(show (ecdsa-verify sig digest one-public))
(show (ecdsa-verify sig (sha256-bytes #"Satoshi Nakamoto!") one-public))
(show (ecdsa-verify sig digest (secret-key->public-key two)))

(section "r and s are integers below the curve order")

(show (ecdsa-signature-r sig))
(show (ecdsa-signature-s sig))
(show secp256k1-order)

(section "signatures are low-S")

(show (ecdsa-signature-low-s? sig))

(section "a high-S twin")

(define high (ecdsa-signature (ecdsa-signature-r sig) (- secp256k1-order (ecdsa-signature-s sig))))
(show (ecdsa-signature-low-s? high))
(show (ecdsa-verify high digest one-public))
(show (ecdsa-signature-normalize high))
(show (ecdsa-verify (ecdsa-signature-normalize high) digest one-public))

(section "mistakes")

(show-error (ecdsa-sign digest))
(show-error (ecdsa-sign one digest))
(show-error (ecdsa-sign (bytes->hex-string digest) one))
