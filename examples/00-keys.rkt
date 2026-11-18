#lang racket/base

(require file/sha1
         libsecp256k1)

(define (secret-key->hex key)
  (bytes->hex-string (secret-key->bytes key)))

(define (hex->secret-key hex)
  (bytes->secret-key (hex-string->bytes hex)))

(define (public-key->hex key #:compressed? [compressed? #t])
  (bytes->hex-string (public-key->bytes key #:compressed? compressed?)))

(define (hex->public-key hex)
  (bytes->public-key (hex-string->bytes hex)))

(module+ main
  (define key (generate-secret-key))
  (define public (secret-key->public-key key))
  (define restored (hex->secret-key (secret-key->hex key)))
  (printf "secret key:   ~a\n" key)
  (printf "public key:   ~a\n" (public-key->hex public))
  (printf "uncompressed: ~a\n" (public-key->hex public #:compressed? #f))
  (printf "restored key has the same public key: ~a\n"
          (equal? (secret-key->public-key restored) public)))

(module+ test
  (require (only-in racket/contract exn:fail:contract:blame?)
           rackunit)

  (define ((raised? predicate pattern) e)
    (and (predicate e) (regexp-match? pattern (exn-message e))))

  (define one (integer->secret-key 1))
  (define minus-one (integer->secret-key (- secp256k1-order 1)))
  (define g-x "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  (define g-y "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
  (define g-uncompressed (hex-string->bytes (string-append "04" g-x g-y)))

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
