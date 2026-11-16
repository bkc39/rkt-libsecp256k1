#lang racket/base

(provide bytes->public-key
         bytes->secret-key
         generate-secret-key
         public-key-combine
         public-key-internal
         public-key-negate
         public-key-tweak-add
         public-key->bytes
         public-key?
         internal->public-key
         secret-key-bytes
         secret-key-negate
         secret-key-tweak-add
         secret-key->bytes
         secret-key->public-key
         secret-key?)

(struct secret-key (bytes))

(struct public-key (compressed internal))

(define (generate-secret-key) (error 'unimplemented))
(define (bytes->secret-key _bs) (error 'unimplemented))
(define (secret-key->bytes _key) (error 'unimplemented))
(define (internal->public-key _internal) (error 'unimplemented))
(define (secret-key->public-key _key) (error 'unimplemented))
(define (secret-key-tweak-add _key _tweak) (error 'unimplemented))
(define (secret-key-negate _key) (error 'unimplemented))
(define (bytes->public-key _bs) (error 'unimplemented))
(define (public-key->bytes _key #:compressed? [_compressed? #t]) (error 'unimplemented))
(define (public-key-tweak-add _key _tweak) (error 'unimplemented))
(define (public-key-negate _key) (error 'unimplemented))
(define (public-key-combine _key . _keys) (error 'unimplemented))
