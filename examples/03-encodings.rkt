#lang racket/base

;; 03: signature encodings.
;;
;; Compact is r || s, 64 bytes; a recovery id travels separately.  DER is
;; the variable-length ASN.1 form, at most 72 bytes, parsed strictly.
;;
;;   racket examples/03-encodings.rkt
;;   racket -i -e '(enter! "examples/03-encodings.rkt")'   ; then keep typing

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
(define digest (sha256-bytes #"Satoshi Nakamoto"))
(define sig (ecdsa-sign digest one))
(define rsig (ecdsa-sign-recoverable digest one))

(section "compact")

(define compact (ecdsa-signature->compact sig))
(show (bytes->hex-string compact))
(show (compact->ecdsa-signature compact))
(show (equal? (compact->ecdsa-signature compact) sig))

(section "compact with a recovery id")

(define id (ecdsa-recoverable-signature-recovery-id rsig))
(show (compact->ecdsa-signature (ecdsa-signature->compact rsig) #:recovery-id id))
(show (equal? (compact->ecdsa-signature (ecdsa-signature->compact rsig) #:recovery-id id) rsig))

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
