#lang racket/base

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (integer->secret-key 1))
(define digest (sha256-bytes #"Satoshi Nakamoto"))
(define sig (ecdsa-sign digest one))
(define rsig (ecdsa-sign-recoverable digest one))

(section "compact")

(define compact (ecdsa-signature->compact sig))
(show (bytes->hex-string compact))
(show (equal? (compact->ecdsa-signature compact) sig))

(section "compact with a recovery id")

(define rcompact (ecdsa-signature->compact rsig))
(show (bytes->hex-string rcompact))
(show (compact->ecdsa-recoverable-signature rcompact (ecdsa-recoverable-signature-id rsig)))
(show (equal? (compact->ecdsa-recoverable-signature rcompact
                                                    (ecdsa-recoverable-signature-id rsig))
              rsig))

(section "DER")

(define der (ecdsa-signature->der sig))
(show (bytes->hex-string der))
(show (bytes-length der))
(show (equal? (der->ecdsa-signature der) sig))

(section "malformed encodings")

(show-error (der->ecdsa-signature (bytes-append der #"\0")))
(show-error (der->ecdsa-signature (subbytes der 0 40)))
(show-error (der->ecdsa-signature (hex-string->bytes "3006020181020101")))
(show-error (compact->ecdsa-signature (make-bytes 64 255)))
(show-error (compact->ecdsa-recoverable-signature compact 4))
