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
         environment-with
         example-key-integer
         field-prime
         half-order
         hex
         integer->bytes32
         n
         non-residue-x
         quadratic-residue?
         raised?
         racket-path
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

(define example-key-integer
  #xaf7f91569049b1ae97b7e3b7a6ec06d9f0ad4ac78822f237c7af387ebe486986)

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

(define (quadratic-residue? v)
  (= 1 (modular-expt v (quotient (- field-prime 1) 2) field-prime)))

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

(define (random-secret-bytes rng)
  (define bs (random-bytes rng 32))
  (define v (bytes->integer bs))
  (if (< 0 v n) bs (random-secret-bytes rng)))

(define (secret-samples rng count)
  (append (for/list ([_ (in-range count)])
            (random-secret-bytes rng))
          (map integer->bytes32 edge-integers)))

(define-syntax-parse-rule (test-seeded name:expr #:seed (seed:expr ...) rng:id body:expr ...+)
  (test-case name
    (define rng (seeded seed ...))
    (with-check-info (['random-seed (list seed ...)])
      body ...)))

(define racket-path
  (let ([exe (find-system-path 'exec-file)])
    (if (absolute-path? exe) exe (find-executable-path exe))))

(define (environment-with settings)
  (define env (environment-variables-copy (current-environment-variables)))
  (for ([s (in-list settings)])
    (environment-variables-set! env
                                (string->bytes/utf-8 (car s))
                                (and (cdr s) (string->bytes/utf-8 (cdr s)))))
  env)

(define ((raised? predicate pattern) e)
  (and (predicate e) (regexp-match? pattern (exn-message e))))

(define (blames? file-name e)
  (and (exn:fail:contract:blame? e)
       (regexp-match? (regexp (string-append "blaming: [^\n]*" (regexp-quote file-name)))
                      (exn-message e))))

(define-syntax-parse-rule (check-blames-here expr)
  #:with file-name
  (datum->syntax #'expr (path->string (file-name-from-path (syntax-source this-syntax))))
  (check-exn (lambda (e) (blames? file-name e))
             (lambda () expr)
             (format "~s" 'expr)))
