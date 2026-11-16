#lang racket/base

(require file/sha1
         libsecp256k1
         "common.rkt")

(provide (all-defined-out))

(define one (integer->secret-key 1))
(define two (integer->secret-key 2))
(define g (secret-key->public-key one))
(define tweak (sha256-bytes #"child 0"))

(section "tweaking a secret key and its public key agree")

(define child (secret-key-tweak-add one tweak))
(show child)
(show (secret-key->public-key child))
(show (equal? (secret-key->public-key child) (public-key-tweak-add g tweak)))

(section "a zero tweak changes nothing")

(define zero (make-bytes 32 0))
(show (equal? (public-key-tweak-add g zero) g))
(show (equal? (secret-key->public-key (secret-key-tweak-add one zero)) g))

(section "negation")

(show (public-key-negate g))
(show (equal? (secret-key->public-key (secret-key-negate one)) (public-key-negate g)))
(show (equal? (public-key-negate (public-key-negate g)) g))

(section "sums of public keys")

(show (bytes->hex-string (public-key->bytes (public-key-combine g g))))
(show (equal? (public-key-combine g g) (secret-key->public-key two)))
(show (equal? (public-key-combine g (secret-key->public-key two))
              (public-key-tweak-add g (secret-key->bytes two))))

(section "sums that are the point at infinity")

(show-error (public-key-combine g (public-key-negate g)))
(show-error (secret-key-tweak-add one (secret-key->bytes (secret-key-negate one))))
(show-error (public-key-tweak-add g (make-bytes 32 255)))
