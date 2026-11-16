#lang racket/base

(require (for-syntax racket/base
                     (only-in racket/path file-name-from-path))
         (only-in file/sha1 bytes->hex-string hex-string->bytes)
         (only-in racket/contract exn:fail:contract:blame?)
         rackunit
         syntax/parse/define
         libsecp256k1)

(provide bytes->integer
         check-blames-here
         edge-integers
         field-prime
         half-order
         hex
         integer->bytes32
         n
         non-residue-x
         quadratic-residue?
         random-bytes
         random-digest
         random-secret-bytes
         secret-samples
         seeded
         test-seeded
         unhex)

(define n secp256k1-order)
(define half-order (quotient (- n 1) 2))
(define field-prime #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)

(define edge-integers
  (list 1 2 (- n 1) (- n 2) (expt 2 128) (expt 2 255) half-order (quotient (+ n 1) 2)))

(define (integer->bytes32 v)
  (define bs (make-bytes 32 0))
  (for ([i (in-range 32)])
    (bytes-set! bs (- 31 i) (bitwise-and (arithmetic-shift v (* -8 i)) 255)))
  bs)

(define (bytes->integer bs)
  (for/fold ([v 0]) ([b (in-bytes bs)])
    (+ (* v 256) b)))

(define (modular-expt b e m)
  (cond
    [(zero? e) 1]
    [(even? e) (modulo (let ([h (modular-expt b (quotient e 2) m)]) (* h h)) m)]
    [else (modulo (* b (modular-expt b (sub1 e) m)) m)]))

;; Euler's criterion, mod the field prime.
(define (quadratic-residue? v)
  (= 1 (modular-expt v (quotient (- field-prime 1) 2) field-prime)))

;; The smallest x for which no point has that x-coordinate.
(define non-residue-x
  (for/first ([x (in-naturals 1)]
              #:unless (quadratic-residue? (modulo (+ (* x x x) 7) field-prime)))
    x))

(define hex bytes->hex-string)
(define unhex hex-string->bytes)

(define (seeded . seed)
  (vector->pseudo-random-generator (list->vector seed)))

(define (random-bytes rng count)
  (define bs (make-bytes count))
  (for ([i (in-range count)])
    (bytes-set! bs i (random 256 rng)))
  bs)

(define (random-digest rng)
  (random-bytes rng 32))

;; Uniform 32 bytes whose value is a valid secret key.
(define (random-secret-bytes rng)
  (define bs (random-bytes rng 32))
  (define v (bytes->integer bs))
  (if (< 0 v n) bs (random-secret-bytes rng)))

;; count uniform secrets, then the edge set.
(define (secret-samples rng count)
  (append (for/list ([_ (in-range count)])
            (random-secret-bytes rng))
          (map integer->bytes32 edge-integers)))

;; A test case with a seeded generator; the seed is printed when a check fails.
(define-syntax-parse-rule (test-seeded name:expr #:seed (seed:expr ...) rng:id body:expr ...+)
  (test-case name
    (define rng (seeded seed ...))
    (with-check-info (['random-seed (list seed ...)])
      body ...)))

(define (blames? file-name e)
  (and (exn:fail:contract:blame? e)
       (regexp-match? (regexp (string-append "blaming: [^\n]*" (regexp-quote file-name)))
                      (exn-message e))))

;; A contract violation blaming the module this form appears in.
(define-syntax-parse-rule (check-blames-here expr)
  #:with file-name
  (datum->syntax #'expr (path->string (file-name-from-path (syntax-source this-syntax))))
  (check-exn (lambda (e) (blames? file-name e))
             (lambda () expr)
             (format "~s" 'expr)))
