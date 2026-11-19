#lang racket/base

(require (only-in file/sha1 bytes->hex-string)
         (only-in racket/random crypto-random-bytes)
         "exn.rkt"
         "ffi.rkt"
         "scalar.rkt")

(provide bytes->public-key
         bytes->secret-key
         generate-secret-key
         integer->secret-key
         internal->public-key
         public-key-combine
         public-key-internal
         public-key-negate
         public-key-tweak-add
         public-key->bytes
         public-key?
         secret-key-bytes
         secret-key-negate
         secret-key-tweak-add
         secret-key->bytes
         secret-key->integer
         secret-key->public-key
         secret-key?)

(struct secret-key (bytes)
  #:property prop:custom-write
  (lambda (_key out _mode)
    (fprintf out "#<secret-key>")))

;; compressed is the canonical form: equal? and hashing compare it, and the 64-byte internal
;; form is not specified to be canonical.
(struct public-key (compressed internal)
  #:property prop:custom-write
  (lambda (key out _mode)
    (fprintf out "#<public-key ~a>" (bytes->hex-string (public-key-compressed key))))
  #:methods gen:equal+hash
  [(define (equal-proc a b _recur)
     (equal? (public-key-compressed a) (public-key-compressed b)))
   (define (hash-proc key recur)
     (recur (public-key-compressed key)))
   (define (hash2-proc key recur)
     (recur (public-key-compressed key)))])

(define (key-error who fmt . args)
  (apply raise-libsecp256k1 exn:fail:libsecp256k1:key who fmt args))

(define (generate-secret-key)
  (define bs (crypto-random-bytes 32))
  (if (secp256k1_ec_seckey_verify 'generate-secret-key bs)
      (secret-key bs)
      (generate-secret-key)))

(define/snapshot (bytes->secret-key bs) #:snapshot (bs)
  (if (secp256k1_ec_seckey_verify 'bytes->secret-key bs)
      (secret-key bs)
      (key-error 'bytes->secret-key
                 "invalid secret key;\n the value is zero or not less than the curve order")))

(define (integer->secret-key v)
  (if (< 0 v secp256k1-order)
      (secret-key (integer->bytes32 v))
      (key-error 'integer->secret-key
                 (string-append "invalid secret key;\n the value is less than 1 or not less than"
                                " the curve order"))))

(define (secret-key->bytes key)
  (bytes-copy (secret-key-bytes key)))

(define (secret-key->integer key)
  (bytes->integer (secret-key-bytes key)))

(define (internal->public-key who internal)
  (public-key (bytes->immutable-bytes
               (secp256k1_ec_pubkey_serialize who internal SECP256K1_EC_COMPRESSED))
              internal))

(define (secret-key->public-key key)
  (internal->public-key 'secret-key->public-key
                        (secp256k1_ec_pubkey_create 'secret-key->public-key
                                                    (secret-key-bytes key))))

(define/snapshot (secret-key-tweak-add key tweak) #:snapshot (tweak)
  (secret-key (secp256k1_ec_seckey_tweak_add 'secret-key-tweak-add (secret-key-bytes key) tweak)))

(define (secret-key-negate key)
  (secret-key (secp256k1_ec_seckey_negate 'secret-key-negate (secret-key-bytes key))))

(define/snapshot (bytes->public-key bs) #:snapshot (bs)
  (cond
    [(not (memv (bytes-ref bs 0) (if (= (bytes-length bs) 33) '(2 3) '(4))))
     (key-error 'bytes->public-key
                "invalid public key;\n expected prefix 02 or 03 for 33 bytes, 04 for 65 bytes")]
    [else
     (internal->public-key 'bytes->public-key
                           (secp256k1_ec_pubkey_parse 'bytes->public-key bs))]))

(define (public-key->bytes key #:compressed? [compressed? #t])
  (if compressed?
      (bytes-copy (public-key-compressed key))
      (secp256k1_ec_pubkey_serialize 'public-key->bytes
                                     (public-key-internal key)
                                     SECP256K1_EC_UNCOMPRESSED)))

(define/snapshot (public-key-tweak-add key tweak) #:snapshot (tweak)
  (internal->public-key 'public-key-tweak-add
                        (secp256k1_ec_pubkey_tweak_add 'public-key-tweak-add
                                                       (public-key-internal key)
                                                       tweak)))

(define (public-key-negate key)
  (internal->public-key 'public-key-negate
                        (secp256k1_ec_pubkey_negate 'public-key-negate (public-key-internal key))))

(define (public-key-combine key . keys)
  (internal->public-key 'public-key-combine
                        (secp256k1_ec_pubkey_combine 'public-key-combine
                                                     (map public-key-internal (cons key keys)))))
