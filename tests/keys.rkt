#lang racket/base

(module+ test
  (require racket/list
           rackunit
           libsecp256k1
           "helpers/util.rkt")

  (define (key-of v) (bytes->secret-key (integer->bytes32 v)))
  (define (pub-of v) (secret-key->public-key (key-of v)))

  (test-seeded "secret-key->bytes inverts bytes->secret-key" #:seed (11 12 13 14 15 16) rng
    (for ([bs (in-list (secret-samples rng 500))])
      (check-equal? (secret-key->bytes (bytes->secret-key bs)) bs)))

  (define (edge-biased rng)
    (case (random 6 rng)
      [(0) (integer->bytes32 (+ n (- (random 5 rng) 2)))]
      [(1) (integer->bytes32 (random 3 rng))]
      [(2) (make-bytes 32 255)]
      [(3) (integer->bytes32 (list-ref edge-integers (random (length edge-integers) rng)))]
      [else (random-bytes rng 32)]))

  (test-seeded "bytes->secret-key accepts exactly the values in (0, n)" #:seed (21 22 23 24 25 26) rng
    (for ([_ (in-range 2000)])
      (define bs (edge-biased rng))
      (define v (bytes->integer bs))
      (with-check-info (['bytes (hex bs)])
        (if (< 0 v n)
            (check-pred secret-key? (bytes->secret-key bs))
            (check-exn exn:fail:libsecp256k1:key? (lambda () (bytes->secret-key bs)))))))

  (test-case "invalid secret keys raise the documented message"
    (check-exn (regexp (regexp-quote (string-append
                                      "bytes->secret-key: invalid secret key;\n"
                                      " the value is zero or not less than the curve order")))
               (lambda () (bytes->secret-key (integer->bytes32 n)))))

  (test-case "generated secret keys are valid and distinct"
    (define keys (for/list ([_ (in-range 200)]) (generate-secret-key)))
    (check-true (andmap secret-key? keys))
    (define scalars (map (lambda (k) (bytes->integer (secret-key->bytes k))) keys))
    (check-true (for/and ([v (in-list scalars)]) (< 0 v n)))
    (check-equal? (length (remove-duplicates scalars)) 200))

  (struct known-key (secret compressed uncompressed))

  (define g-x "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
  (define g-y "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

  (define known-keys
    (list
     (known-key 1 (string-append "02" g-x) (string-append "04" g-x g-y))
     (known-key (- n 1) (string-append "03" g-x) #f)
     (known-key 2 "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" #f)
     (known-key 3 "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" #f)
     (known-key #xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
                #f
                (string-append
                 "04"
                 "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"
                 "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"))))

  (test-case "known secret keys give their published public keys"
    (for ([k (in-list known-keys)])
      (define pk (pub-of (known-key-secret k)))
      (with-check-info (['secret (known-key-secret k)])
        (when (known-key-compressed k)
          (check-equal? (hex (public-key->bytes pk)) (known-key-compressed k)))
        (when (known-key-uncompressed k)
          (check-equal? (hex (public-key->bytes pk #:compressed? #f))
                        (known-key-uncompressed k))))))

  (test-seeded "public keys round-trip through both encodings" #:seed (31 32 33 34 35 36) rng
    (for ([bs (in-list (secret-samples rng 200))])
      (define pk (secret-key->public-key (bytes->secret-key bs)))
      (define compressed (public-key->bytes pk))
      (define uncompressed (public-key->bytes pk #:compressed? #f))
      (check-equal? (bytes->public-key compressed) pk)
      (check-equal? (bytes->public-key uncompressed) pk)
      (check-equal? (public-key->bytes (bytes->public-key compressed)) compressed)
      (check-equal? (public-key->bytes (bytes->public-key uncompressed) #:compressed? #f)
                    uncompressed)))

  (test-case "both parses of a point are equal? with equal hash codes; other points are not"
    (define pk (pub-of 5))
    (define a (bytes->public-key (public-key->bytes pk)))
    (define b (bytes->public-key (public-key->bytes pk #:compressed? #f)))
    (check-equal? a b)
    (check-equal? (equal-hash-code a) (equal-hash-code b))
    (check-equal? (equal-secondary-hash-code a) (equal-secondary-hash-code b))
    (check-not-equal? a (pub-of 6))
    (check-equal? (hash-ref (hash a 'found) b) 'found))

  (test-case "a public key prints its compressed hex"
    (define pk (pub-of 2))
    (define expected (string-append "#<public-key " (hex (public-key->bytes pk)) ">"))
    (check-equal? (format "~a" pk) expected)
    (check-equal? (format "~s" pk) expected)
    (check-equal? (format "~v" pk) expected))

  (test-case "public-key->bytes returns fresh bytes"
    (define pk (pub-of 9))
    (define before (public-key->bytes pk))
    (bytes-fill! (public-key->bytes pk) 0)
    (bytes-fill! (public-key->bytes pk #:compressed? #f) 0)
    (check-equal? (public-key->bytes pk) before)
    (check-false (immutable? (public-key->bytes pk))))

  (define (field-bytes v) (integer->bytes32 v))

  (define g-uncompressed (unhex (string-append "04" g-x g-y)))

  (define (with-prefix prefix bs)
    (bytes-append (bytes prefix) (subbytes bs 1)))

  (struct bad-public-key (description bytes))

  (define bad-public-keys
    (append
     (for/list ([prefix (in-list '(#x00 #x01 #x05 #x06 #x07 #xff))])
       (bad-public-key (format "prefix ~a on 65 bytes" prefix)
                       (if (memv prefix '(6 7))
                           (with-prefix prefix (bytes-append #"\4" (make-bytes 64 1)))
                           (with-prefix prefix g-uncompressed))))
     (list
      (bad-public-key "prefix 04 on 33 bytes" (bytes-append #"\4" (unhex g-x)))
      (bad-public-key "hybrid 06 encoding of G" (with-prefix 6 g-uncompressed))
      (bad-public-key "hybrid 07 encoding of G" (with-prefix 7 g-uncompressed))
      (bad-public-key "x = 0" (bytes-append #"\2" (field-bytes 0)))
      (bad-public-key "x = p" (bytes-append #"\2" (field-bytes field-prime)))
      (bad-public-key "x > p" (bytes-append #"\3" (field-bytes (+ field-prime 1))))
      (bad-public-key "x with no square root" (bytes-append #"\2" (field-bytes non-residue-x)))
      (bad-public-key "uncompressed x with no square root"
                      (bytes-append #"\4" (field-bytes non-residue-x) (field-bytes 1)))
      (bad-public-key "y not matching x"
                      (bytes-append (subbytes g-uncompressed 0 33)
                                    (field-bytes (+ 1 (bytes->integer (unhex g-y)))))))))

  (test-case "the non-residue x is found by Euler's criterion"
    (check-false (quadratic-residue? (modulo (+ (* non-residue-x non-residue-x non-residue-x) 7)
                                             field-prime)))
    (check-true (quadratic-residue? 4)))

  (for ([b (in-list bad-public-keys)])
    (test-case (format "bytes->public-key rejects ~a" (bad-public-key-description b))
      (check-exn exn:fail:libsecp256k1:key?
                 (lambda () (bytes->public-key (bad-public-key-bytes b))))))

  (test-case "a bad prefix is described without the bytes given"
    (check-exn (lambda (e)
                 (equal? (exn-message e)
                         (string-append "bytes->public-key: invalid public key;\n"
                                        " expected prefix 02 or 03 for 33 bytes, 04 for 65"
                                        " bytes")))
               (lambda () (bytes->public-key (with-prefix 6 g-uncompressed))))
    (check-exn (regexp (regexp-quote
                        (string-append "bytes->public-key: invalid public key;\n"
                                       " the bytes do not encode a point on the curve")))
               (lambda () (bytes->public-key (bytes-append #"\2" (field-bytes 0))))))

  (test-seeded "integer->secret-key and secret-key->integer are inverses on [1, n)"
    #:seed (17 18 19 20 21 22) rng
    (for ([bs (in-list (secret-samples rng 200))])
      (define v (bytes->integer bs))
      (check-equal? (secret-key->integer (integer->secret-key v)) v)
      (check-equal? (secret-key->bytes (integer->secret-key v)) bs)
      (check-equal? (secret-key->integer (bytes->secret-key bs)) v)))

  (test-case "integer->secret-key refuses values outside [1, n) without showing them"
    (for ([v (list 0 -1 n (+ n 1) (- n) (expt 2 256))])
      (check-exn (lambda (e)
                   (and (exn:fail:libsecp256k1:key? e)
                        (equal? (exn-message e)
                                (string-append "integer->secret-key: invalid secret key;\n"
                                               " the value is less than 1 or not less than the"
                                               " curve order"))))
                 (lambda () (integer->secret-key v))
                 (format "~a" v)))))
