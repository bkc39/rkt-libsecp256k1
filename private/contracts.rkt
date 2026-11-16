#lang racket/base

(require (only-in racket/contract
                  blame-add-context
                  blame-swap
                  build-compound-type-name
                  coerce-contract
                  contract-name
                  flat-contract-predicate
                  flat-named-contract
                  get/build-late-neg-projection
                  integer-in
                  make-contract
                  make-flat-contract
                  raise-blame-error)
         (only-in racket/list drop-right last)
         "keys.rkt")

(provide compact-bytes/c
         digest/c
         opaque->
         public-key-bytes/c
         recovery-id/c
         scalar/c
         secp256k1-order
         secret-bytes/c
         secret-key/c)

(define secp256k1-order
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

(define (bytes-of-length? v n)
  (and (bytes? v) (= (bytes-length v) n)))

(define digest/c
  (flat-named-contract 'digest/c (lambda (v) (bytes-of-length? v 32))))

(define public-key-bytes/c
  (flat-named-contract 'public-key-bytes/c
                       (lambda (v) (and (bytes? v) (memv (bytes-length v) '(33 65)) #t))))

(define compact-bytes/c
  (flat-named-contract 'compact-bytes/c (lambda (v) (bytes-of-length? v 64))))

(define recovery-id/c (flat-named-contract 'recovery-id/c (integer-in 0 3)))

(define scalar/c (flat-named-contract 'scalar/c (integer-in 0 (- secp256k1-order 1))))

;; The kind of a value, never its content.
(define (describe v)
  (cond
    [(bytes? v) (format "a byte string of length ~a" (bytes-length v))]
    [(string? v) (format "a string of length ~a" (string-length v))]
    [(exact-integer? v) "an exact integer"]
    [(secret-key? v) "a secret key"]
    [(public-key? v) "a public key"]
    [else "a value of another kind"]))

(define opaque-contracts (make-weak-hasheq))

(define (opaque-flat-contract name accepts? expected)
  (define c
    (make-flat-contract
     #:name name
     #:first-order accepts?
     #:late-neg-projection
     (lambda (blame)
       (lambda (v neg)
         (if (accepts? v)
             v
             (raise-blame-error blame #:missing-party neg v
                                '(expected: "~a" given: "~a") expected (describe v)))))))
  (hash-set! opaque-contracts c #t)
  c)

;; Any flat contract, failing without printing the value: a secret passed in
;; the wrong position must not show up in another argument's violation.
(define (opaque-domain c)
  (if (hash-ref opaque-contracts c #f)
      c
      (opaque-flat-contract (contract-name c)
                            (flat-contract-predicate c)
                            (format "~a" (contract-name c)))))

(define secret-bytes/c
  (opaque-flat-contract 'secret-bytes/c (lambda (v) (bytes-of-length? v 32)) "32 bytes"))

(define secret-key/c
  (opaque-flat-contract 'secret-key/c secret-key? "a secret key"))

(define (plural n)
  (if (= n 1) "1 argument" (format "~a arguments" n)))

(define (ordinal i)
  (case i
    [(1) "1st"]
    [(2) "2nd"]
    [(3) "3rd"]
    [else (format "~ath" i)]))

;; Like ->, but an arity or keyword mismatch prints counts and keywords, never
;; the arguments: Racket's own arity errors print every argument.
(define (opaque-> . contracts)
  (define coerced (for/list ([c (in-list contracts)]) (coerce-contract 'opaque-> c)))
  (define doms (map opaque-domain (drop-right coerced 1)))
  (define rng (last coerced))
  (define arity (length doms))
  (make-contract
   #:name (apply build-compound-type-name 'opaque-> (map contract-name coerced))
   #:first-order procedure?
   #:late-neg-projection
   (lambda (blame)
     (define dom-projections
       (for/list ([d (in-list doms)]
                  [i (in-naturals 1)])
         ((get/build-late-neg-projection d)
          (blame-add-context blame (format "the ~a argument of" (ordinal i)) #:swap? #t))))
     (define rng-projection
       ((get/build-late-neg-projection rng) (blame-add-context blame "the range of")))
     (lambda (f neg)
       (procedure-rename
        (make-keyword-procedure
         (lambda (kws _kw-args . args)
           (cond
             [(pair? kws)
              (raise-blame-error (blame-swap blame) #:missing-party neg f
                                 '(expected: "no keyword arguments" given: "keyword #:~a")
                                 (keyword->string (car kws)))]
             [(not (= (length args) arity))
              (raise-blame-error (blame-swap blame) #:missing-party neg f
                                 '(expected: "~a" given: "~a")
                                 (plural arity) (plural (length args)))]
             [else
              (rng-projection
               (apply f (for/list ([p (in-list dom-projections)]
                                   [a (in-list args)])
                          (p a neg)))
               neg)])))
        (object-name f))))))
