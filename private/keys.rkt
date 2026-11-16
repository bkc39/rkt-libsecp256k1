#lang racket/base

(require (only-in file/sha1 bytes->hex-string)
         (only-in racket/random crypto-random-bytes)
         "exn.rkt"
         "ffi.rkt")

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

(struct secret-key (bytes)
  #:property prop:custom-write
  (lambda (_key out _mode)
    (fprintf out "#<secret-key>")))

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

(define (raise-key-error message)
  (raise (exn:fail:libsecp256k1:key message (current-continuation-marks))))

(define (generate-secret-key)
  (define bs (crypto-random-bytes 32))
  (if (secp256k1_ec_seckey_verify bs)
      (secret-key bs)
      (generate-secret-key)))

(define (bytes->secret-key bs)
  (unless (secp256k1_ec_seckey_verify bs)
    (raise-key-error (string-append "bytes->secret-key: invalid secret key;\n"
                                    " the value is zero or not less than the curve order")))
  (secret-key (bytes-copy bs)))

(define (secret-key->bytes key)
  (bytes-copy (secret-key-bytes key)))

(define (internal->public-key internal)
  (public-key (bytes->immutable-bytes
               (secp256k1_ec_pubkey_serialize internal SECP256K1_EC_COMPRESSED))
              internal))

(define (secret-key->public-key key)
  (internal->public-key (secp256k1_ec_pubkey_create (secret-key-bytes key))))

(define (secret-key-tweak-add key tweak)
  (define sum (secp256k1_ec_seckey_tweak_add (bytes-copy (secret-key-bytes key)) tweak))
  (unless sum
    (raise-key-error (string-append "secret-key-tweak-add: invalid tweak;\n"
                                    " the tweak is not less than the curve order, or the sum"
                                    " is zero")))
  (secret-key sum))

(define (secret-key-negate key)
  (secret-key (secp256k1_ec_seckey_negate (bytes-copy (secret-key-bytes key)))))

(define (prefix-hex b)
  (string-append "#x" (if (< b 16) "0" "") (number->string b 16)))

(define (bytes->public-key bs)
  (define prefix (bytes-ref bs 0))
  (define prefix-ok?
    (if (= (bytes-length bs) 33)
        (memv prefix '(2 3))
        (= prefix 4)))
  (define internal (and prefix-ok? (secp256k1_ec_pubkey_parse bs)))
  (cond
    [(not prefix-ok?)
     (raise-key-error (string-append "bytes->public-key: invalid public key;\n"
                                     " expected prefix 02 or 03 for 33 bytes, 04 for 65 bytes\n"
                                     "  prefix: " (prefix-hex prefix)))]
    [(not internal)
     (raise-key-error (string-append "bytes->public-key: invalid public key;\n"
                                     " the bytes do not encode a point on the curve"))]
    [else (internal->public-key internal)]))

(define (public-key->bytes key #:compressed? [compressed? #t])
  (if compressed?
      (bytes-copy (public-key-compressed key))
      (secp256k1_ec_pubkey_serialize (public-key-internal key) SECP256K1_EC_UNCOMPRESSED)))

(define (public-key-tweak-add key tweak)
  (define sum (secp256k1_ec_pubkey_tweak_add (bytes-copy (public-key-internal key)) tweak))
  (unless sum
    (raise-key-error (string-append "public-key-tweak-add: invalid tweak;\n"
                                    " the tweak is not less than the curve order, or the sum"
                                    " is the point at infinity")))
  (internal->public-key sum))

(define (public-key-negate key)
  (internal->public-key (secp256k1_ec_pubkey_negate (bytes-copy (public-key-internal key)))))

(define (public-key-combine key . keys)
  (define sum (secp256k1_ec_pubkey_combine (map public-key-internal (cons key keys))))
  (unless sum
    (raise-key-error "public-key-combine: the sum is the point at infinity"))
  (internal->public-key sum))
