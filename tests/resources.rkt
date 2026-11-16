#lang racket/base

(module+ test
  (require rackunit
           libsecp256k1
           "helpers/bounded.rkt"
           "helpers/util.rkt")

  (test-case "100,000 signs, verifies and parses run in bounded memory"
    (define key (bytes->secret-key (integer->bytes32 77)))
    (define pk (secret-key->public-key key))
    (define outcome
      (call-bounded
       (lambda ()
         (for/sum ([i (in-range 100000)])
           (define digest (integer->bytes32 i))
           (define sig (ecdsa-sign digest key))
           (define parsed (der->ecdsa-signature (ecdsa-signature->der sig)))
           (if (ecdsa-verify parsed digest pk) 1 0)))
       #:seconds 90 #:megabytes 64))
    (check-equal? outcome '(ok 100000))))
