#lang racket/base

;; 02: public key recovery.
;;
;; A recoverable signature carries a recovery id that picks the signer's
;; public key out of the candidates the signature and digest allow.
;;
;;   racket examples/02-recover.rkt
;;   racket -i -e '(enter! "examples/02-recover.rkt")'   ; then keep typing

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
(define one-public (secret-key->public-key one))
(define digest (sha256-bytes #"Satoshi Nakamoto"))

(section "signing with a recovery id")

(define rsig (ecdsa-sign-recoverable digest one))
(show rsig)
(show (ecdsa-signature-r rsig))
(show (ecdsa-signature-s rsig))
(show (ecdsa-recoverable-signature-recovery-id rsig))
(show (equal? (ecdsa-signature-r rsig) (ecdsa-signature-r (ecdsa-sign digest one))))

(section "recovering the signer")

(show (ecdsa-recover rsig digest))
(show (equal? (ecdsa-recover rsig digest) one-public))

(section "another digest recovers another key")

(show (ecdsa-recover rsig (sha256-bytes #"Hal Finney")))
(show (equal? (ecdsa-recover rsig (sha256-bytes #"Hal Finney")) one-public))

(section "an id that recovers nothing")

(define id-2
  (ecdsa-recoverable-signature (ecdsa-signature-r rsig) (ecdsa-signature-s rsig) 2))
(show (ecdsa-recover id-2 digest))

(section "a recoverable signature is also a plain one")

(show (ecdsa-signature? rsig))
(show (ecdsa-verify rsig digest one-public))
