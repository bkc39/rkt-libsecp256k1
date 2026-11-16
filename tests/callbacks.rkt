#lang racket/base

(module+ test
  (require rackunit
           libsecp256k1
           (except-in libsecp256k1/private/ffi libsecp256k1-origin)
           "util.rkt")

  (define key-bytes (integer->bytes32 5))
  (define internal (secp256k1_ec_pubkey_create key-bytes))

  (test-case "an illegal flag raises instead of aborting, and the next call works"
    (check-exn (lambda (e)
                 (and (exn:fail:libsecp256k1:illegal-argument? e)
                      (regexp-match?
                       #rx"^libsecp256k1: illegal argument: .*[(]flags & SECP256K1_FLAGS_TYPE_MASK[)] == SECP256K1_FLAGS_TYPE_COMPRESSION$"
                       (exn-message e))))
               (lambda () (secp256k1_ec_pubkey_serialize internal 0)))
    (check-equal? (bytes-length (secp256k1_ec_pubkey_serialize internal SECP256K1_EC_COMPRESSED))
                  33))

  (test-case "a NULL digest raises an illegal argument naming it"
    (check-exn (lambda (e)
                 (and (exn:fail:libsecp256k1:illegal-argument? e)
                      (regexp-match? #rx"msghash32 != NULL" (exn-message e))))
               (lambda () (secp256k1_ecdsa_sign #f key-bytes)))
    (check-pred bytes? (secp256k1_ecdsa_sign (make-bytes 32 1) key-bytes)))

  (test-case "the error callback raises an internal error with its message"
    (check-exn (lambda (e)
                 (and (exn:fail:libsecp256k1:internal? e)
                      (equal? (exn-message e) "libsecp256k1: internal error: out of tables")))
               (lambda () (error-callback "out of tables" #f)))
    (check-exn #rx"^libsecp256k1: illegal argument: x != NULL$"
               (lambda () (illegal-callback "x != NULL" #f))))

  (test-seeded "the public procedures never trigger the illegal-argument callback"
    #:seed (241 242 243 244 245 246) rng
    (check-not-exn
     (lambda ()
       (with-handlers ([exn:fail:libsecp256k1:key? void]
                       [exn:fail:libsecp256k1:signature? void])
         (for ([_ (in-range 300)])
           (define bs (random-bytes rng 32))
           (define digest (random-digest rng))
           (with-handlers ([exn:fail:libsecp256k1:key? void]
                           [exn:fail:libsecp256k1:signature? void])
             (define key (bytes->secret-key bs))
             (define pk (secret-key->public-key key))
             (define rsig (ecdsa-sign-recoverable digest key))
             (ecdsa-verify rsig digest pk)
             (ecdsa-recover rsig digest)
             (der->ecdsa-signature (ecdsa-signature->der rsig))
             (bytes->public-key (public-key->bytes pk #:compressed? #f))
             (public-key-combine pk (public-key-negate pk)))
           (with-handlers ([exn:fail:libsecp256k1:key? void]
                           [exn:fail:libsecp256k1:signature? void])
             (der->ecdsa-signature (random-bytes rng (random 72 rng)))
             (compact->ecdsa-signature (random-bytes rng 64) #:recovery-id (random 4 rng))
             (bytes->public-key (bytes-append #"\2" bs))
             (secret-key-tweak-add (generate-secret-key) bs))))))))
