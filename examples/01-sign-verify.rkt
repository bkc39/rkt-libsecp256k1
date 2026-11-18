#lang racket/base

(require file/sha1
         libsecp256k1)

(define (message->digest message)
  (sha256-bytes (string->bytes/utf-8 message)))

(define (sign-message key message)
  (ecdsa-sign (message->digest message) key))

(define (verify-message sig message public)
  (ecdsa-verify sig (message->digest message) public))

(module+ main
  (define key (generate-secret-key))
  (define public (secret-key->public-key key))
  (define sig (sign-message key "hello"))
  (printf "public key: ~a\n" (bytes->hex-string (public-key->bytes public)))
  (printf "signature:  ~a\n" (bytes->hex-string (ecdsa-signature->compact sig)))
  (printf "verifies \"hello\":  ~a\n" (verify-message sig "hello" public))
  (printf "verifies \"hello!\": ~a\n" (verify-message sig "hello!" public)))

(module+ test
  (require (only-in racket/contract exn:fail:contract:blame?)
           rackunit)

  (define ((raised? predicate pattern) e)
    (and (predicate e) (regexp-match? pattern (exn-message e))))

  (define one (integer->secret-key 1))
  (define two (integer->secret-key 2))
  (define one-public (secret-key->public-key one))
  (define message "Satoshi Nakamoto")
  (define sig (sign-message one message))

  (define (high-s-twin sig)
    (ecdsa-signature (ecdsa-signature-r sig) (- secp256k1-order (ecdsa-signature-s sig))))

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
