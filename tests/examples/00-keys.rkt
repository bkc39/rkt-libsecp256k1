#lang racket/base

(module+ test
  (require (only-in file/sha1 hex-string->bytes)
           (only-in racket/contract exn:fail:contract:blame?)
           (only-in racket/port with-output-to-string)
           (only-in racket/string string-split)
           rackunit
           libsecp256k1
           "../../examples/00-keys.rkt"
           (only-in "../helpers/util.rkt" example-key-integer raised?))

  (define one (integer->secret-key 1))
  (define minus-one (integer->secret-key (- secp256k1-order 1)))
  (define g-x "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  (define g-y "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
  (define g-uncompressed (hex-string->bytes (string-append "04" g-x g-y)))
  (define example-x "4a321ddaaf494e410cfde06e140b7d605a9f3f7015978330585db24062bfab70")
  (define example-y "2a4708c3092f0b1d7c1d6a1c6d6869813efcb1aa0d9d6097b44c0efd073a9dc2")

  (test-case "run prints the public key both ways and that the stored key restores it"
    (check-equal? (string-split (with-output-to-string
                                  (lambda () (run (integer->secret-key example-key-integer))))
                                "\n")
                  (list (string-append "public key:   02" example-x)
                        (string-append "uncompressed: 04" example-x example-y)
                        "restored key has the same public key: #t")))

  (test-case "a secret key prints without its value"
    (check-equal? (format "~a ~s" (list one minus-one) one)
                  "(#<secret-key> #<secret-key>) #<secret-key>"))

  (test-case "secret keys are equal only to themselves, so compare their bytes"
    (check-false (equal? one (integer->secret-key 1)))
    (check-equal? (secret-key->hex one) (secret-key->hex (integer->secret-key 1))))

  (test-case "a secret key is its 32-byte big-endian value and survives a hex round trip"
    (check-equal? (secret-key->hex one) (string-append (make-string 63 #\0) "1"))
    (check-equal? (secret-key->integer (hex->secret-key (secret-key->hex minus-one)))
                  (- secp256k1-order 1)))

  (test-case "a generated key is a secret key"
    (check-pred secret-key? (generate-secret-key)))

  (test-case "the public key of 1 is the generator, compressed or not"
    (define g (secret-key->public-key one))
    (check-equal? (public-key->hex g) (string-append "02" g-x))
    (check-equal? (public-key->hex g #:compressed? #f) (string-append "04" g-x g-y))
    (check-equal? (hex->public-key (public-key->hex g #:compressed? #f)) g))

  (test-case "the public key of n - 1 is the generator's negation"
    (check-equal? (public-key->hex (secret-key->public-key minus-one)) (string-append "03" g-x)))

  (test-case "a secret key outside [1, n) is rejected"
    (define out-of-range #rx"invalid secret key;\n the value is less than 1 or not less than")
    (check-exn (raised? exn:fail:libsecp256k1:key? out-of-range)
               (lambda () (integer->secret-key 0)))
    (check-exn (raised? exn:fail:libsecp256k1:key? out-of-range)
               (lambda () (integer->secret-key secp256k1-order)))
    (check-exn (raised? exn:fail:libsecp256k1:key? #rx"the value is zero or not less than")
               (lambda () (hex->secret-key (make-string 64 #\0)))))

  (test-case "stored hex that is not 64 hex digits is rejected without showing it"
    (define stored (secret-key->hex minus-one))
    (for ([bad (in-list (list (string-append stored "\n")
                              (string-append " " stored)
                              (substring stored 0 63)
                              (string-append (substring stored 0 63) "g")
                              (string->bytes/utf-8 stored)))])
      (check-exn (lambda (e)
                   (and (exn:fail:libsecp256k1:key? e)
                        (equal? (exn-message e) "hex->secret-key: expected 64 hex digits")))
                 (lambda () (hex->secret-key bad))))
    (check-equal? (secret-key->integer (hex->secret-key (string-upcase stored)))
                  (- secp256k1-order 1)))

  (test-case "31 bytes are not a secret key, and the error does not show them"
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: 32 bytes\n  given: a byte string of length 31")
               (lambda () (bytes->secret-key (make-bytes 31 1)))))

  (test-case "public key bytes with a bad prefix, off the curve or of a bad length are rejected"
    (define bad-prefix #rx"invalid public key;\n expected prefix 02 or 03 for 33 bytes, 04 for 65")
    (check-exn (raised? exn:fail:libsecp256k1:key? bad-prefix)
               (lambda () (bytes->public-key (bytes-append #"\5" (subbytes g-uncompressed 1)))))
    (check-exn (raised? exn:fail:libsecp256k1:key? bad-prefix)
               (lambda () (bytes->public-key (bytes-append #"\6" (subbytes g-uncompressed 1)))))
    (check-exn (raised? exn:fail:libsecp256k1:key? #rx"do not encode a point on the curve$")
               (lambda () (bytes->public-key (bytes-append #"\2" (make-bytes 31 0) #"\5"))))
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: 33 or 65 bytes\n  given: a byte string of length 64")
               (lambda () (bytes->public-key (subbytes g-uncompressed 0 64))))))
