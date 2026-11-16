#lang racket/base

(require (for-syntax racket/base
                     syntax/parse)
         (only-in racket/contract
                  blame-add-context
                  blame-swap
                  build-compound-type-name
                  build-flat-contract-property
                  coerce-flat-contract
                  contract-name
                  flat-contract-predicate
                  get/build-late-neg-projection
                  make-contract
                  prop:flat-contract
                  raise-blame-error)
         (only-in racket/string string-join)
         syntax/parse/define
         "ecdsa.rkt"
         "keys.rkt"
         "scalar.rkt")

(provide compact-bytes/c
         der-bytes/c
         digest/c
         ecdsa-recoverable-signature/c
         ecdsa-signature/c
         byte-string/c
         exact-integer/c
         opaque->
         public-key-bytes/c
         public-key/c
         recovery-id/c
         scalar/c
         secret-bytes/c
         secret-integer/c
         secret-key/c)

(define (describe v)
  (cond
    [(bytes? v) (format "a byte string of length ~a" (bytes-length v))]
    [(string? v) (format "a string of length ~a" (string-length v))]
    [(exact-integer? v) "an exact integer"]
    [(secret-key? v) "a secret key"]
    [(public-key? v) "a public key"]
    [(ecdsa-recoverable-signature? v) "a recoverable ECDSA signature"]
    [(ecdsa-signature? v) "an ECDSA signature"]
    [(boolean? v) "a boolean"]
    [(symbol? v) "a symbol"]
    [else "a value of another kind"]))

;; A flat contract whose violation names what it expected and the kind of value it was
;; given, never the value.
(struct opaque-contract (name expected accepts?)
  #:property prop:flat-contract
  (build-flat-contract-property
   #:name (lambda (c) (opaque-contract-name c))
   #:first-order (lambda (c) (opaque-contract-accepts? c))
   #:late-neg-projection
   (lambda (c)
     (define accepts? (opaque-contract-accepts? c))
     (lambda (blame)
       (lambda (v neg)
         (if (accepts? v)
             v
             (raise-blame-error blame #:missing-party neg v
                                '(expected: "~a" given: "~a")
                                (opaque-contract-expected c) (describe v))))))))

(define (opaque v)
  (if (opaque-contract? v)
      v
      (let ([c (coerce-flat-contract 'opaque-> v)])
        (opaque-contract (contract-name c) (format "~a" (contract-name c))
                         (flat-contract-predicate c)))))

(define ((bytes-of-length? . lengths) v)
  (and (bytes? v) (memv (bytes-length v) lengths) #t))

(define digest/c (opaque-contract 'digest/c "a 32-byte digest" (bytes-of-length? 32)))
(define secret-bytes/c (opaque-contract 'secret-bytes/c "32 bytes" (bytes-of-length? 32)))
(define secret-key/c (opaque-contract 'secret-key/c "a secret key" secret-key?))
(define public-key-bytes/c
  (opaque-contract 'public-key-bytes/c "33 or 65 bytes" (bytes-of-length? 33 65)))
(define compact-bytes/c (opaque-contract 'compact-bytes/c "64 bytes" (bytes-of-length? 64)))
(define der-bytes/c
  (opaque-contract 'der-bytes/c "at most 72 bytes"
                   (lambda (v) (and (bytes? v) (<= (bytes-length v) 72)))))
(define recovery-id/c
  (opaque-contract 'recovery-id/c "an integer from 0 to 3"
                   (lambda (v) (and (exact-integer? v) (<= 0 v 3)))))
(define scalar/c
  (opaque-contract 'scalar/c "an integer in [0, n)"
                   (lambda (v) (and (exact-integer? v) (<= 0 v) (< v secp256k1-order)))))
(define secret-integer/c
  (opaque-contract 'exact-positive-integer? "an integer in [1, n)"
                   (lambda (v) (and (exact-integer? v) (< 0 v secp256k1-order)))))
(define exact-integer/c (opaque-contract 'exact-integer? "an exact integer" exact-integer?))
(define byte-string/c (opaque-contract 'bytes? "a byte string" bytes?))
(define public-key/c (opaque-contract 'public-key? "a public key" public-key?))
(define ecdsa-signature/c
  (opaque-contract 'ecdsa-signature? "an ECDSA signature" ecdsa-signature?))
(define ecdsa-recoverable-signature/c
  (opaque-contract 'ecdsa-recoverable-signature? "a recoverable ECDSA signature"
                   ecdsa-recoverable-signature?))

(define (count-text n)
  (if (= n 1) "1 argument" (format "~a arguments" n)))

(define (arity-text arity)
  (cond
    [(exact-integer? arity) (count-text arity)]
    [(arity-at-least? arity) (format "at least ~a" (count-text (arity-at-least-value arity)))]
    [else (string-join (map arity-text arity) " or ")]))

(define (keywords-text kws)
  (if (null? kws)
      "no keyword arguments"
      (string-append (if (null? (cdr kws)) "keyword " "keywords ")
                     (string-join (map (lambda (k) (format "~a" k)) kws) " or "))))

(define (ordinal i)
  (case i
    [(1) "1st"]
    [(2) "2nd"]
    [(3) "3rd"]
    [else (format "~ath" i)]))

(define (make-opaque-arrow doms rest kws rng)
  (define opaque-doms (map opaque doms))
  (define opaque-rest (and rest (opaque rest)))
  (define opaque-kws (for/list ([k (in-list kws)]) (cons (car k) (opaque (cdr k)))))
  (define opaque-rng (opaque rng))
  (define arity (if rest (arity-at-least (length doms)) (length doms)))
  (make-contract
   #:name (apply build-compound-type-name 'opaque->
                 (append (map contract-name opaque-doms)
                         (if rest (list '#:rest (contract-name opaque-rest)) '())
                         (for/list ([k (in-list opaque-kws)])
                           (list (car k) (contract-name (cdr k))))
                         (list (contract-name opaque-rng))))
   #:first-order (lambda (f) (and (procedure? f) (procedure-arity-includes? f (length doms))))
   #:late-neg-projection
   (lambda (blame)
     (define (argument-projection c label)
       ((get/build-late-neg-projection c) (blame-add-context blame label #:swap? #t)))
     (define dom-projections
       (for/list ([d (in-list opaque-doms)]
                  [i (in-naturals 1)])
         (argument-projection d (format "the ~a argument of" (ordinal i)))))
     (define rest-projection
       (and rest (argument-projection opaque-rest "the rest argument of")))
     (define kw-projections
       (for/list ([k (in-list opaque-kws)])
         (cons (car k) (argument-projection (cdr k) (format "the ~a argument of" (car k))))))
     (define rng-projection
       ((get/build-late-neg-projection opaque-rng) (blame-add-context blame "the range of")))
     (lambda (f neg)
       (define (refuse expected given)
         (raise-blame-error (blame-swap blame) #:missing-party neg f
                            '(expected: "~a" given: "~a") expected given))
       (define (project-positional args)
         (let loop ([args args] [ps dom-projections])
           (cond
             [(null? args) '()]
             [(null? ps) (for/list ([a (in-list args)]) (rest-projection a neg))]
             [else (cons ((car ps) (car args) neg) (loop (cdr args) (cdr ps)))])))
       (define (call kws kw-args . args)
         (define unknown (for/first ([k (in-list kws)] #:unless (assq k kw-projections)) k))
         (cond
           [unknown (refuse (keywords-text (map car kw-projections)) (format "keyword ~a" unknown))]
           [(not (arity-includes? arity (length args)))
            (refuse (arity-text (procedure-arity f)) (count-text (length args)))]
           [else
            (rng-projection
             (keyword-apply f
                            kws
                            (for/list ([k (in-list kws)] [v (in-list kw-args)])
                              ((cdr (assq k kw-projections)) v neg))
                            (project-positional args))
             neg)]))
       (procedure-rename (make-keyword-procedure call (lambda args (apply call '() '() args)))
                         (object-name f))))))

(define (arity-includes? arity n)
  (if (arity-at-least? arity) (>= n (arity-at-least-value arity)) (= n arity)))

(begin-for-syntax
  (define-syntax-class positional
    #:description "an argument contract"
    (pattern (~and e:expr (~not (_:keyword . _)) (~not _:keyword))))

  (define-syntax-class optional-keyword
    #:description "an optional keyword argument: [#:keyword contract]"
    (pattern [kw:keyword c:expr])))

(define-syntax-parser opaque->
  [(_ dom:positional ... (~optional (~seq #:rest rest:expr)) kw:optional-keyword ... rng:expr)
   #'(make-opaque-arrow (list dom ...)
                        (~? rest #f)
                        (list (cons 'kw.kw kw.c) ...)
                        rng)])
