#lang racket/base

(require (for-syntax racket/base)
         (only-in ffi/unsafe ffi-lib ffi-obj-ref)
         racket/runtime-path
         "exn.rkt")

(provide bundled-library
         library-file-name
         locate-library
         missing-reason
         missing-symbols
         native-build-dir
         native-library-path
         open-candidate
         required-symbols
         system-candidates
         (struct-out candidate))

(define library-file-name
  (string-append "libsecp256k1" (bytes->string/utf-8 (system-type 'so-suffix))))

(define (native-build-dir root)
  (build-path root "native" "build" (system-library-subpath #f)))

(define (native-library-path root)
  (build-path (native-build-dir root) library-file-name))

(define-runtime-path bundled-library
  (build-path 'up "native" "build" (system-library-subpath #f)
              (string-append "libsecp256k1" (bytes->string/utf-8 (system-type 'so-suffix)))))

(define required-symbols
  '("secp256k1_context_create"
    "secp256k1_context_randomize"
    "secp256k1_context_set_error_callback"
    "secp256k1_context_set_illegal_callback"
    "secp256k1_ec_pubkey_combine"
    "secp256k1_ec_pubkey_create"
    "secp256k1_ec_pubkey_negate"
    "secp256k1_ec_pubkey_parse"
    "secp256k1_ec_pubkey_serialize"
    "secp256k1_ec_pubkey_tweak_add"
    "secp256k1_ec_seckey_negate"
    "secp256k1_ec_seckey_tweak_add"
    "secp256k1_ec_seckey_verify"
    "secp256k1_ecdsa_recover"
    "secp256k1_ecdsa_recoverable_signature_parse_compact"
    "secp256k1_ecdsa_recoverable_signature_serialize_compact"
    "secp256k1_ecdsa_sign"
    "secp256k1_ecdsa_sign_recoverable"
    "secp256k1_ecdsa_signature_parse_compact"
    "secp256k1_ecdsa_signature_parse_der"
    "secp256k1_ecdsa_signature_serialize_compact"
    "secp256k1_ecdsa_signature_serialize_der"
    "secp256k1_ecdsa_verify"
    "secp256k1_selftest"))

;; origin: 'bundled, 'system or 'environment.  open: a thunk returning an
;; ffi-lib or raising.
(struct candidate (origin label open))

(define (missing-symbols lib)
  (for/list ([name (in-list required-symbols)]
             #:unless (with-handlers ([exn:fail? (lambda (_) #f)])
                        (ffi-obj-ref name lib)))
    name))

(define (missing-reason missing)
  (cond
    [(member "secp256k1_ecdsa_recover" missing)
     "lacks secp256k1_ecdsa_recover (built without the recovery module)"]
    [(member "secp256k1_selftest" missing)
     "lacks secp256k1_selftest (older than 0.2.0)"]
    [else (format "lacks ~a" (car missing))]))

;; An ffi-lib with every required symbol, or the line that says why not.
(define (open-candidate c)
  (define lib
    (with-handlers ([exn:fail? (lambda (e) e)])
      ((candidate-open c))))
  (define missing (and (not (exn? lib)) (missing-symbols lib)))
  (cond
    [(exn? lib) (format "~a: ~a: not found" (candidate-origin c) (candidate-label c))]
    [(pair? missing)
     (format "~a: ~a: ~a" (candidate-origin c) (candidate-label c) (missing-reason missing))]
    [else lib]))

(define system-versions '("7" "6" "5" "2" "1" #f))

(define (soname version)
  (define suffix (bytes->string/utf-8 (system-type 'so-suffix)))
  (cond
    [(not version) (string-append "libsecp256k1" suffix)]
    [(eq? (system-type 'os) 'macosx) (format "libsecp256k1.~a~a" version suffix)]
    [else (format "libsecp256k1~a.~a" suffix version)]))

(define system-candidates
  (append
   (for/list ([v (in-list system-versions)])
     (candidate 'system (soname v) (lambda () (ffi-lib "libsecp256k1" (list v)))))
   (if (eq? (system-type 'os) 'windows)
       (list (candidate 'system "secp256k1.dll" (lambda () (ffi-lib "secp256k1"))))
       '())))

(define (path-candidate origin path)
  (candidate origin (path->string path) (lambda () (ffi-lib path))))

(define (bundled-candidate)
  (path-candidate 'bundled bundled-library))

(define (library-candidates setting)
  (cond
    [(and setting (not (string=? setting "")) (not (string=? setting "system")))
     (list (path-candidate 'environment (string->path setting)))]
    [(equal? setting "system") system-candidates]
    [else (cons (bundled-candidate) system-candidates)]))

(define (reason-line c outcome)
  (cond
    [(and (eq? (candidate-origin c) 'bundled) (not (file-exists? bundled-library)))
     (format "bundled: ~a: not built; run raco setup libsecp256k1" (candidate-label c))]
    [else outcome]))

;; (values origin lib #f) for the first usable candidate, or
;; (values #f #f exn) whose message lists every candidate tried.
(define (locate-library setting)
  (let loop ([cs (library-candidates setting)] [reasons '()])
    (cond
      [(null? cs)
       (values #f #f
               (exn:fail:libsecp256k1:load
                (apply string-append "libsecp256k1: no usable libsecp256k1 library"
                       (for/list ([r (in-list (reverse reasons))])
                         (string-append "\n  " r)))
                (current-continuation-marks)))]
      [else
       (define outcome (open-candidate (car cs)))
       (if (string? outcome)
           (loop (cdr cs) (cons (reason-line (car cs) outcome) reasons))
           (values (candidate-origin (car cs)) outcome #f))])))
