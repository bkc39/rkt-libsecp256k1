#lang racket/base

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(section "secret keys from integers and bytes")

(define one (integer->secret-key 1))
(define minus-one (integer->secret-key (- secp256k1-order 1)))
(show one)
(show (format "~a" (list one minus-one)))
(show (secret-key->integer minus-one))
(show (bytes->hex-string (secret-key->bytes one)))
(show (secret-key->integer (bytes->secret-key (secret-key->bytes minus-one))))

(section "secret keys are equal only to themselves")

(show (equal? one (integer->secret-key 1)))
(show (equal? (secret-key->bytes one) (secret-key->bytes (integer->secret-key 1))))

(section "generated keys")

(show (secret-key? (generate-secret-key)))

(section "invalid secret keys")

(show-error (integer->secret-key 0))
(show-error (integer->secret-key secp256k1-order))
(show-error (bytes->secret-key (make-bytes 32 0)))
(show-error (bytes->secret-key (make-bytes 31 1)))

(section "public keys")

(define g (secret-key->public-key one))
(show g)
(show (bytes->hex-string (public-key->bytes g #:compressed? #f)))
(show (secret-key->public-key minus-one))

(section "parsing public keys")

(define g-uncompressed (public-key->bytes g #:compressed? #f))
(show (bytes->public-key g-uncompressed))
(show (equal? (bytes->public-key (public-key->bytes g)) (bytes->public-key g-uncompressed)))

(section "invalid public keys")

(show-error (bytes->public-key (bytes-append #"\5" (subbytes g-uncompressed 1))))
(show-error (bytes->public-key (bytes-append #"\6" (subbytes g-uncompressed 1))))
(show-error (bytes->public-key (bytes-append #"\2" (make-bytes 31 0) #"\5")))
(show-error (bytes->public-key (subbytes g-uncompressed 0 64)))
