#lang racket/base

(module worker racket/base
  (require (only-in racket/place place-channel-get place-channel-put)
           libsecp256k1
           (only-in libsecp256k1/private/ffi
                    secp256k1_ec_pubkey_create
                    secp256k1_ec_pubkey_serialize)
           "helpers/util.rkt"
           "helpers/vectors.rkt")

  (provide main
           sign-and-verify
           stress
           (struct-out stress-outcome))

  (struct stress-outcome (verified illegal others) #:prefab)

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

  (define (raises-illegal? thunk)
    (with-handlers ([exn:fail:libsecp256k1:illegal-argument? (lambda (_) #t)])
      (thunk)
      #f))

  (define (stress-thread index iterations illegal-every)
    (define key (integer->secret-key (+ 1000 index)))
    (define pk (secret-key->public-key key))
    (define internal (secp256k1_ec_pubkey_create 'stress (integer->bytes32 (+ 2000 index))))
    (define verified (box 0))
    (define illegal (box 0))
    (define others
      (with-handlers ([(lambda (_) #t) (lambda (e) (list (if (exn? e) (exn-message e) e)))])
        (for ([i (in-range iterations)])
          (when (and (zero? (modulo (add1 i) illegal-every))
                     (raises-illegal? (lambda ()
                                        (secp256k1_ec_pubkey_serialize 'stress internal 0))))
            (set-box! illegal (add1 (unbox illegal))))
          (define digest (integer->bytes32 (+ (* 1000000 index) i)))
          (when (ecdsa-verify (ecdsa-sign digest key) digest pk)
            (set-box! verified (add1 (unbox verified)))))
        '()))
    (stress-outcome (unbox verified) (unbox illegal) others))

  (define (stress threads iterations illegal-every)
    (define outcomes (for/list ([_ (in-range threads)]) (box #f)))
    (define workers
      (for/list ([i (in-range threads)]
                 [outcome (in-list outcomes)])
        (thread (lambda ()
                  (set-box! outcome
                            (with-handlers ([(lambda (_) #t)
                                             (lambda (e)
                                               (stress-outcome 0 0 (list (exn-message e))))])
                              (stress-thread i iterations illegal-every)))))))
    (for-each thread-wait workers)
    (map unbox outcomes))

  (define (main ch)
    (define request (place-channel-get ch))
    (place-channel-put ch (if (eq? (car request) 'stress)
                              (apply stress (cdr request))
                              (sign-and-verify (cdr request) 500)))))

(module+ test
  (require racket/place
           racket/runtime-path
           rackunit
           (submod ".." worker)
           "helpers/bounded.rkt"
           "helpers/util.rkt"
           "helpers/vectors.rkt")

  (define-runtime-path this-file "concurrency.rkt")

  (define (run-place request)
    (define p (dynamic-place `(submod ,this-file worker) 'main))
    (place-channel-put p request)
    (begin0
      (sync/timeout 120 p)
      (place-kill p)))

  (define (run-places requests)
    (define outcomes (for/list ([_ (in-list requests)]) (box #f)))
    (define runners
      (for/list ([request (in-list requests)]
                 [outcome (in-list outcomes)])
        (thread (lambda () (set-box! outcome (run-place request))))))
    (for-each thread-wait runners)
    (map unbox outcomes))

  (define threads 4)
  (define iterations 20000)
  (define illegal-every 1000)

  (define expected-stress
    (for/list ([_ (in-range threads)])
      (stress-outcome iterations (quotient iterations illegal-every) '())))

  (test-case "four places each load the library and sign the same signatures"
    (define expected (sign-and-verify '(1 2 3 4 5 6) 500))
    (check-equal? (cadr expected) 500)
    (check-equal? (car expected) (hex (signing-row-compact (car (signing-rows)))))
    (define requests (for/list ([i (in-range 4)]) (list 'sign 1 2 3 4 5 (+ 6 i))))
    (for ([o (in-list (run-places requests))])
      (check-equal? o (list (car expected) 500))))

  (test-case "four threads sign and verify 20,000 times each between illegal-argument raises"
    (check-equal? (call-bounded (lambda () (stress threads iterations illegal-every))
                                #:seconds 240 #:megabytes 512)
                  (list 'ok expected-stress)))

  (test-case "two places each run four such threads at once"
    (check-equal? (run-places (for/list ([_ (in-range 2)])
                                (list 'stress threads iterations illegal-every)))
                  (list expected-stress expected-stress))))
