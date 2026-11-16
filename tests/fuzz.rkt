#lang racket/base

(module+ test
  (require racket/list
           racket/match
           rackunit
           libsecp256k1
           "bounded.rkt"
           "util.rkt"
           "vectors.rkt")

  (define batch-size 1000)

  ;; Runs (check-input input) on every input in bounded batches; the only
  ;; exception allowed out of check-input is `allowed?`.
  (define (fuzz inputs allowed? check-input)
    (for ([batch (in-slice batch-size inputs)])
      (define outcome
        (call-bounded
         (lambda ()
           (for/list ([input (in-list batch)])
             (with-handlers ([allowed? (lambda (_) 'refused)])
               (check-input input))))
         #:seconds 2 #:megabytes 64))
      (match outcome
        [(list 'ok results) (check-equal? (length results) (length batch))]
        [(list 'raised e) (fail (format "raised ~a" (exn-message e)))]
        [other (fail (format "~a" other))])))

  (define (in-slice size xs)
    (let loop ([xs xs] [acc '()])
      (if (null? xs)
          (reverse acc)
          (let-values ([(head tail) (split-at xs (min size (length xs)))])
            (loop tail (cons head acc))))))

  (define (mutate rng der)
    (define bs (bytes-copy der))
    (define len (bytes-length bs))
    (define (at i) (min i (sub1 len)))
    (cond
      [(zero? len) (random-bytes rng (random 8 rng))]
      [else
       (case (random 6 rng)
         [(0) (let ([i (random len rng)])
                (bytes-set! bs i (bitwise-xor (bytes-ref bs i) (arithmetic-shift 1 (random 8 rng))))
                bs)]
         [(1) (bytes-set! bs (random len rng) (random 256 rng)) bs]
         [(2) (subbytes bs 0 (random len rng))]
         [(3) (bytes-append bs (random-bytes rng (add1 (random 4 rng))))]
         [(4) (bytes-set! bs (at (vector-ref #(1 3) (random 2 rng))) (random 256 rng)) bs]
         [else (bytes-set! bs (at (+ 5 (bytes-ref bs (at 3)))) (random 256 rng)) bs])]))

  (define (check-der der)
    (define sig (der->ecdsa-signature der))
    (unless (equal? (ecdsa-signature->der sig) der)
      (error 'check-der "accepted a non-canonical encoding: ~a" (hex der)))
    sig)

  (test-seeded "DER parsing returns a canonical signature or raises :signature"
    #:seed (251 252 253 254 255 256) rng
    (define seeds (map wycheproof-row-der (wycheproof-rows)))
    (define inputs
      (append (for/list ([_ (in-range 10000)])
                (random-bytes rng (random 101 rng)))
              (for/list ([_ (in-range 10000)])
                (mutate rng (list-ref seeds (random (length seeds) rng))))))
    (fuzz inputs exn:fail:libsecp256k1:signature? check-der))

  (test-seeded "public key parsing round-trips or raises :key" #:seed (261 262 263 264 265 266) rng
    (define inputs
      (for/list ([i (in-range 10000)])
        (define bs (random-bytes rng (if (even? i) 33 65)))
        (bytes-set! bs 0 (modulo i 256))
        bs))
    (fuzz inputs exn:fail:libsecp256k1:key?
          (lambda (bs)
            (define pk (bytes->public-key bs))
            (unless (equal? (public-key->bytes pk #:compressed? (= (bytes-length bs) 33)) bs)
              (error 'check-public-key "does not round-trip: ~a" (hex bs))))))

  (test-seeded "compact parsing gives a signature or raises :signature"
    #:seed (271 272 273 274 275 276) rng
    (define inputs
      (for/list ([_ (in-range 10000)])
        (define bs (random-bytes rng 64))
        (when (zero? (random 2 rng))
          (bytes-copy! bs 0 (make-bytes (random 4 rng) 255)))
        (cons bs (list-ref '(#f 0 1 2 3) (random 5 rng)))))
    (fuzz inputs exn:fail:libsecp256k1:signature?
          (lambda (input)
            (compact->ecdsa-signature (car input) #:recovery-id (cdr input)))))

  (test-seeded "verify and recover never raise on random triples" #:seed (281 282 283 284 285 286)
    rng
    (define keys
      (for/list ([_ (in-range 20)])
        (secret-key->public-key (bytes->secret-key (random-secret-bytes rng)))))
    (define inputs
      (for/list ([_ (in-range 5000)])
        (list (modulo (bytes->integer (random-bytes rng 32)) n)
              (modulo (bytes->integer (random-bytes rng 32)) n)
              (random 4 rng)
              (random-digest rng)
              (list-ref keys (random 20 rng)))))
    (fuzz inputs (lambda (_) #f)
          (match-lambda
            [(list r s id digest key)
             (define sig (ecdsa-recoverable-signature r s id))
             (unless (boolean? (ecdsa-verify sig digest key))
               (error 'verify "not a boolean"))
             (define recovered (ecdsa-recover sig digest))
             (unless (or (not recovered) (public-key? recovered))
               (error 'recover "not a key or #f"))]))))
