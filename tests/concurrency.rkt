#lang racket/base

(module worker racket/base
  (require (only-in racket/place place-channel-get place-channel-put)
           libsecp256k1
           "util.rkt"
           "vectors.rkt")

  (provide main
           sign-and-verify)

  ;; The first signing vector's compact hex and how many of count random
  ;; signatures verify.
  (define (sign-and-verify seed count)
    (define row (car (signing-rows)))
    (define first-compact
      (hex (ecdsa-signature->compact
            (ecdsa-sign (signing-row-digest row) (bytes->secret-key (signing-row-secret row))))))
    (define rng (apply seeded seed))
    (define verified
      (for/sum ([_ (in-range count)])
        (define key (bytes->secret-key (random-secret-bytes rng)))
        (define digest (random-digest rng))
        (if (ecdsa-verify (ecdsa-sign digest key) digest (secret-key->public-key key)) 1 0)))
    (list first-compact verified))

  (define (main ch)
    (define seed (place-channel-get ch))
    (place-channel-put ch (sign-and-verify seed 500))))

(module+ test
  (require racket/place
           racket/runtime-path
           rackunit
           libsecp256k1
           (only-in libsecp256k1/private/ffi
                    secp256k1_ec_pubkey_create
                    secp256k1_ec_pubkey_serialize)
           (submod ".." worker)
           "util.rkt"
           "vectors.rkt")

  (define-runtime-path this-file "concurrency.rkt")

  (define (run-place seed)
    (define p (dynamic-place `(submod ,this-file worker) 'main))
    (place-channel-put p seed)
    (begin0
      (sync/timeout 60 p)
      (place-kill p)))

  (test-case "four places each load the library and sign the same signatures"
    (define expected (sign-and-verify '(1 2 3 4 5 6) 500))
    (check-equal? (cadr expected) 500)
    (check-equal? (car expected) (hex (signing-row-compact (car (signing-rows)))))
    (define outcomes (for/list ([i (in-range 4)]) (box #f)))
    (define runners
      (for/list ([i (in-range 4)]
                 [outcome (in-list outcomes)])
        (thread (lambda () (set-box! outcome (run-place (list 1 2 3 4 5 (+ 6 i))))))))
    (for-each thread-wait runners)
    (for ([o (in-list (map unbox outcomes))])
      (check-equal? o (list (car expected) 500))))

  (test-case "threads sign and verify while another triggers illegal arguments"
    (define internal (secp256k1_ec_pubkey_create (integer->bytes32 5)))
    (define stop? (box #f))
    (define illegal-count (box 0))
    (define troublemaker
      (thread (lambda ()
                (let loop ()
                  (unless (unbox stop?)
                    (with-handlers ([exn:fail:libsecp256k1:illegal-argument?
                                     (lambda (_) (set-box! illegal-count (add1 (unbox illegal-count))))])
                      (secp256k1_ec_pubkey_serialize internal 0))
                    (sleep 0)
                    (loop))))))
    (define signers
      (for/list ([i (in-range 8)])
        (define key (bytes->secret-key (integer->bytes32 (+ 100 i))))
        (define pk (secret-key->public-key key))
        (define results (box '()))
        (cons results
              (thread (lambda ()
                        (for ([j (in-range 200)])
                          (define digest (integer->bytes32 (+ (* 1000 i) j)))
                          (set-box! results
                                    (cons (ecdsa-verify (ecdsa-sign digest key) digest pk)
                                          (unbox results)))))))))
    (for ([s (in-list signers)])
      (check-not-false (sync/timeout 60 (cdr s))))
    (set-box! stop? #t)
    (check-not-false (sync/timeout 60 troublemaker))
    (check-true (positive? (unbox illegal-count)))
    (for ([s (in-list signers)])
      (check-equal? (length (unbox (car s))) 200)
      (check-true (andmap values (unbox (car s)))))))
