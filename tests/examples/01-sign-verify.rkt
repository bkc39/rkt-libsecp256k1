#lang racket/base

(module+ test
  (require (only-in file/sha1 bytes->hex-string)
           (only-in racket/contract exn:fail:contract:blame?)
           (only-in racket/port with-output-to-string)
           (only-in racket/string string-split)
           rackunit
           libsecp256k1
           "../../examples/01-sign-verify.rkt"
           (only-in "../helpers/util.rkt" example-key-integer raised?))

  (define one (integer->secret-key 1))
  (define two (integer->secret-key 2))
  (define one-public (secret-key->public-key one))
  (define message "Satoshi Nakamoto")
  (define sig (sign-message one message))

  (define (high-s-twin sig)
    (ecdsa-signature (ecdsa-signature-r sig) (- secp256k1-order (ecdsa-signature-s sig))))

  (test-case "run prints the public key and signature, which verifies for its message only"
    (check-equal? (string-split (with-output-to-string
                                  (lambda () (run (integer->secret-key example-key-integer))))
                                "\n")
                  (list (string-append "public key: 02"
                                       "4a321ddaaf494e410cfde06e140b7d605a9f3f7015978330585db24062bfab70")
                        (string-append "signature:  "
                                       "a3972ac78ab90b6a703c622ce49ef32c3dfee67ccd746f182bc338e822044eaf"
                                       "1d95fdd881ff606339e5b5d731fd6545ecc2d81858beb8bff40ed983bdf6a75f")
                        "verifies \"hello\":  #t"
                        "verifies \"hello!\": #f")))

  (test-case "the digest is the SHA-256 of the message"
    (check-equal? (bytes->hex-string (message->digest message))
                  "a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e"))

  (test-case "key 1 signs the message with the RFC 6979 signature"
    (check-equal? (ecdsa-signature-r sig)
                  #x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8)
    (check-equal? (ecdsa-signature-s sig)
                  #x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5))

  (test-case "the same key and message give the same signature; another key another"
    (check-equal? (sign-message one message) sig)
    (check-not-equal? (sign-message two message) sig))

  (test-case "a signature verifies for its message and key only"
    (check-true (verify-message sig message one-public))
    (check-false (verify-message sig (string-append message "!") one-public))
    (check-false (verify-message sig message (secret-key->public-key two))))

  (test-case "signatures are low-S, and a high-S twin verifies only once normalized"
    (define high (high-s-twin sig))
    (check-true (ecdsa-signature-low-s? sig))
    (check-false (ecdsa-signature-low-s? high))
    (check-false (verify-message high message one-public))
    (check-equal? (ecdsa-signature-normalize high) sig)
    (check-true (verify-message (ecdsa-signature-normalize high) message one-public)))

  (test-case "a missing argument, swapped arguments and a hex digest are contract violations"
    (define digest (message->digest message))
    (check-exn (raised? exn:fail:contract:blame? #rx"expected: 2 arguments\n  given: 1 argument")
               (lambda () (ecdsa-sign digest)))
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: a 32-byte digest\n  given: a secret key")
               (lambda () (ecdsa-sign one digest)))
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: a 32-byte digest\n  given: a string of length 64\n")
               (lambda () (ecdsa-sign (bytes->hex-string digest) one)))))
