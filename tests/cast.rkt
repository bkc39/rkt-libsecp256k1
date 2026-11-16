#lang racket/base

(module+ test
  (require racket/port
           racket/string
           racket/system
           rackunit
           libsecp256k1
           "util.rkt")

  (define (run-cast cast . args)
    (string-trim (with-output-to-string
                   (lambda ()
                     (parameterize ([current-error-port (open-output-nowhere)])
                       (apply system* cast args))))))

  (define (major-version cast)
    (define m (regexp-match #px"(\\d+)\\.\\d+\\.\\d+" (run-cast cast "--version")))
    (and m (string->number (cadr m))))

  (define cast
    (let ([env (getenv "LIBSECP256K1_CAST")]
          [on-path (find-executable-path "cast")])
      (cond
        [(and env (not (string=? env ""))) env]
        [(and on-path (let ([v (major-version on-path)]) (and v (>= v 1)))) on-path]
        [else #f])))

  (define (prefixed bs) (string-append "0x" (hex bs)))

  (cond
    [(not cast)
     (displayln "skipping cast differential: no cast 1.x (set LIBSECP256K1_CAST)")]
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
                                         (+ 27 (ecdsa-recoverable-signature-recovery-id rsig))
                                         16)))
           (check-equal? (run-cast cast "wallet" "public-key" "--private-key" (prefixed secret))
                         (prefixed (subbytes (public-key->bytes (secret-key->public-key key)
                                                                #:compressed? #f)
                                             1))))))]))
