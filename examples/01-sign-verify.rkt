#lang racket/base

;; 01: signing and verifying.
;;
;; ECDSA signs a 32-byte digest; the caller hashes the message.  The nonce is
;; derived from the key and the digest (RFC 6979), so signing is deterministic.
;;
;;   racket examples/01-sign-verify.rkt
;;   racket -i -e '(enter! "examples/01-sign-verify.rkt")'   ; then keep typing

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
(define two (bytes->secret-key (bytes-append (make-bytes 31 0) #"\2")))
(define one-public (secret-key->public-key one))
(define two-public (secret-key->public-key two))

(section "a digest")

(define message #"Satoshi Nakamoto")
(define digest (sha256-bytes message))
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
(show (ecdsa-verify sig digest two-public))

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
