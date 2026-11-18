#lang racket/base

(module+ test
  (require (only-in racket/port with-output-to-string)
           (only-in racket/string string-split)
           rackunit
           libsecp256k1
           "../../examples/04-tweaks.rkt"
           (only-in "../helpers/util.rkt" example-key-integer raised?))

  (define one (integer->secret-key 1))
  (define two (integer->secret-key 2))
  (define g (secret-key->public-key one))
  (define zero (make-bytes 32 0))

  (test-case "run prints the parent's and three children's public keys, which match"
    (check-equal? (string-split (with-output-to-string
                                  (lambda () (run (integer->secret-key example-key-integer))))
                                "\n")
                  (list (string-append "parent public key: 02"
                                       "4a321ddaaf494e410cfde06e140b7d605a9f3f7015978330585db24062bfab70")
                        (string-append "child 0 public key: 02"
                                       "fe3c0b902181fc1ab0da7484e94953c7131af43d7281640d0d505c613ff78292")
                        (string-append "child 1 public key: 02"
                                       "65cf917684654f602b935d6b1f2fac434d4fcd661d09f1aa7113b1fd98baec5b")
                        (string-append "child 2 public key: 02"
                                       "466beaf1cd3692be55c723fea6caaa5428d413e2237af0b25bd64cca362b546c")
                        "child secret keys match: #t")))

  (test-case "tweaking a secret key and its public key agree"
    (define tweak (sha256-bytes #"child 0"))
    (define child (secret-key-tweak-add one tweak))
    (check-equal? (public-key->hex (secret-key->public-key child))
                  "032699aa9999676d80f83f2fd1697e1c0673272d45396500c7d7719c8fe5bd489f")
    (check-equal? (secret-key->public-key child) (public-key-tweak-add g tweak)))

  (test-case "a child's secret key has the public key derived from the parent's public key"
    (for ([index (in-range 4)])
      (check-equal? (secret-key->public-key (child-secret-key two index))
                    (child-public-key (secret-key->public-key two) index))))

  (test-case "children with different indices are different keys"
    (check-not-equal? (child-public-key g 0) (child-public-key g 1)))

  (test-case "a zero tweak changes nothing"
    (check-equal? (public-key-tweak-add g zero) g)
    (check-equal? (secret-key->public-key (secret-key-tweak-add one zero)) g))

  (test-case "negating a secret key negates its public key, and negation is an involution"
    (check-equal? (public-key->hex (public-key-negate g))
                  "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    (check-equal? (secret-key->public-key (secret-key-negate one)) (public-key-negate g))
    (check-equal? (public-key-negate (public-key-negate g)) g))

  (test-case "summing public keys adds their secret keys"
    (check-equal? (public-key->hex (public-key-combine g g))
                  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    (check-equal? (public-key-combine g g) (secret-key->public-key two))
    (check-equal? (public-key-combine g (secret-key->public-key two))
                  (public-key-tweak-add g (secret-key->bytes two))))

  (test-case "a sum that is zero or the point at infinity, or a tweak past the order, is rejected"
    (check-exn (raised? exn:fail:libsecp256k1:key? #rx"the sum is the point at infinity$")
               (lambda () (public-key-combine g (public-key-negate g))))
    (check-exn (raised? exn:fail:libsecp256k1:key?
                        #rx"invalid tweak;\n the tweak is not less than the curve order, or")
               (lambda () (secret-key-tweak-add one (secret-key->bytes (secret-key-negate one)))))
    (check-exn (raised? exn:fail:libsecp256k1:key? #rx"or the sum is the point at infinity$")
               (lambda () (public-key-tweak-add g (make-bytes 32 255))))))
