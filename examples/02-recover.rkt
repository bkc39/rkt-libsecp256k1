#lang racket/base

(require libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (integer->secret-key 1))
(define one-public (secret-key->public-key one))
(define digest (sha256-bytes #"Satoshi Nakamoto"))

(section "signing with a recovery id")

(define rsig (ecdsa-sign-recoverable digest one))
(show rsig)
(show (ecdsa-signature-r rsig))
(show (ecdsa-signature-s rsig))
(show (ecdsa-recoverable-signature-id rsig))
(show (equal? (ecdsa-signature-r rsig) (ecdsa-signature-r (ecdsa-sign digest one))))

(section "recovering the signer")

(show (ecdsa-recover rsig digest))
(show (equal? (ecdsa-recover rsig digest) one-public))

(section "another digest recovers another key")

(show (ecdsa-recover rsig (sha256-bytes #"Hal Finney")))
(show (equal? (ecdsa-recover rsig (sha256-bytes #"Hal Finney")) one-public))

(section "an id that recovers nothing")

(show (ecdsa-recover (ecdsa-recoverable-signature (ecdsa-signature-r rsig)
                                                  (ecdsa-signature-s rsig)
                                                  2)
                     digest))

(section "a recoverable signature is also a plain one")

(show (ecdsa-signature? rsig))
(show (ecdsa-verify rsig digest one-public))
