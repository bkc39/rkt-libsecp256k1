#lang racket/base

(require file/sha1
         libsecp256k1)

(provide message->digest
         public-key->hex
         run
         sign-message
         signature->hex
         verify-message)

(define (message->digest message)
  (sha256-bytes (string->bytes/utf-8 message)))

(define (sign-message key message)
  (ecdsa-sign (message->digest message) key))

(define (verify-message sig message public)
  (ecdsa-verify sig (message->digest message) public))

(define (public-key->hex key)
  (bytes->hex-string (public-key->bytes key)))

(define (signature->hex sig)
  (bytes->hex-string (ecdsa-signature->compact sig)))

(define (run key)
  (define public (secret-key->public-key key))
  (define sig (sign-message key "hello"))
  (printf "public key: ~a\n" (public-key->hex public))
  (printf "signature:  ~a\n" (signature->hex sig))
  (printf "verifies \"hello\":  ~a\n" (verify-message sig "hello" public))
  (printf "verifies \"hello!\": ~a\n" (verify-message sig "hello!" public)))

(module+ main
  (run (generate-secret-key)))
