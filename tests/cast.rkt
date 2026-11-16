#lang racket/base

(module+ test
  (require racket/port
           racket/string
           racket/system
           rackunit
           libsecp256k1
           "helpers/util.rkt")

  (define (run-cast cast . args)
    (string-trim (with-output-to-string
                   (lambda ()
                     (parameterize ([current-error-port (open-output-nowhere)])
                       (apply system* cast args))))))

  (define cast
    (let ([env (getenv "LIBSECP256K1_CAST")])
      (and env (not (string=? env "")) env)))

  (define (prefixed bs) (string-append "0x" (hex bs)))

  (cond
    [(not cast)
     (displayln "SKIPPED cast differential: LIBSECP256K1_CAST is not set")]
    [else
     (test-seeded "signatures and public keys match foundry's cast" #:seed (231 232 233 234 235 236)
       rng
       (for ([_ (in-range 32)])
         (define secret (random-secret-bytes rng))
         (define digest (random-digest rng))
         (define key (bytes->secret-key secret))
         (define rsig (ecdsa-sign-recoverable digest key))
         (with-check-info (['secret (hex secret)] ['digest (hex digest)])
           (check-equal? (run-cast cast "wallet" "sign" "--no-hash"
                                   "--private-key" (prefixed secret) (prefixed digest))
                         (string-append (prefixed (ecdsa-signature->compact rsig))
                                        (number->string
                                         (+ 27 (ecdsa-recoverable-signature-id rsig))
                                         16)))
           (check-equal? (run-cast cast "wallet" "public-key" "--private-key" (prefixed secret))
                         (prefixed (subbytes (public-key->bytes (secret-key->public-key key)
                                                                #:compressed? #f)
                                             1))))))]))
