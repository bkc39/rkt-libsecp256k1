#lang racket/base

;; 00: keys.
;;
;; A secret key is 32 bytes whose big-endian value is in [1, n).  Its public
;; key is a point on the curve, written in 33 or 65 bytes.
;;
;;   racket examples/00-keys.rkt
;;   racket -i -e '(enter! "examples/00-keys.rkt")'   ; then keep typing

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(section "the C library")

(show (libsecp256k1-origin))

(section "secret keys from bytes")

(define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
(show one)
(show (bytes->hex-string (secret-key->bytes one)))

(define minus-one
  (bytes->secret-key
   (hex-string->bytes "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")))
(show (secret-key? minus-one))
(show (format "~a" (list one minus-one)))

(section "generated keys")

(define fresh (generate-secret-key))
(show (secret-key? fresh))
(show (equal? one (bytes->secret-key (secret-key->bytes one))))

(section "invalid secret keys")

(show-error (bytes->secret-key (make-bytes 32 0)))
(show-error (bytes->secret-key (make-bytes 31 1)))
(show-error
 (bytes->secret-key
  (hex-string->bytes "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")))

(section "public keys")

(define g (secret-key->public-key one))
(show g)
(show (bytes->hex-string (public-key->bytes g)))
(show (bytes->hex-string (public-key->bytes g #:compressed? #f)))
(show (secret-key->public-key minus-one))

(section "parsing public keys")

(define g-compressed (public-key->bytes g))
(define g-uncompressed (public-key->bytes g #:compressed? #f))
(show (bytes->public-key g-uncompressed))
(show (equal? (bytes->public-key g-compressed) (bytes->public-key g-uncompressed)))

(section "invalid public keys")

(show-error (bytes->public-key (bytes-append #"\5" (subbytes g-uncompressed 1))))
(show-error (bytes->public-key (bytes-append #"\6" (subbytes g-uncompressed 1))))
(show-error (bytes->public-key (bytes-append #"\2" (make-bytes 31 0) #"\5")))
