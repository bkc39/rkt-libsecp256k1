#lang racket/base

(require (for-syntax racket/base)
         (only-in ffi/unsafe ffi-lib ffi-obj-ref)
         (only-in racket/file delete-directory/files make-temporary-directory)
         (only-in racket/match match)
         (only-in racket/string string-join string-split)
         racket/runtime-path
         (only-in setup/dirs get-lib-search-dirs)
         syntax/parse/define
         "exn.rkt")

(provide bundled-library
         first-line
         library-file-name
         locate-library
         missing-reason
         missing-symbols
         native-build-dir
         native-library-path
         open-candidate
         required-symbols
         system-candidates
         with-temporary-directory
         (struct-out candidate))

(define-syntax-parse-rule (with-temporary-directory dir:id body:expr ...+)
  (let ([dir (make-temporary-directory)])
    (dynamic-wind
     void
     (lambda () body ...)
     (lambda () (delete-directory/files dir #:must-exist? #f)))))

(define so-suffix (bytes->string/utf-8 (system-type 'so-suffix)))

(define library-file-name (string-append "libsecp256k1" so-suffix))

(define-runtime-path native-build-root (build-path 'up "native" "build"))

(define (native-build-dir root)
  (build-path root "native" "build" (system-library-subpath #f)))

(define (native-library-path root)
  (build-path (native-build-dir root) library-file-name))

(define bundled-library
  (simplify-path (build-path native-build-root (system-library-subpath #f) library-file-name)))

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

(struct candidate (origin label open))

(define (missing-symbols lib)
  (for/list ([name (in-list required-symbols)]
             #:unless (ffi-obj-ref name lib (lambda () #f)))
    name))

(define (missing-reason missing)
  (cond
    [(member "secp256k1_ecdsa_recover" missing)
     "lacks secp256k1_ecdsa_recover (built without the recovery module)"]
    [(member "secp256k1_selftest" missing)
     "lacks secp256k1_selftest (older than 0.2.0)"]
    [else (format "lacks ~a" (car missing))]))

(define (first-line message)
  (car (string-split message "\n" #:trim? #f)))

(define (load-error-reason e label)
  (define system-error (regexp-match #rx"\n  system error: ([^\n]*)" (exn-message e)))
  (define reason (if system-error (cadr system-error) (first-line (exn-message e))))
  (define own-prefix (string-append label ": "))
  (if (and (> (string-length reason) (string-length own-prefix))
           (string=? (substring reason 0 (string-length own-prefix)) own-prefix))
      (substring reason (string-length own-prefix))
      reason))

(define (open-candidate c)
  (define label (format "~a: ~a" (candidate-origin c) (candidate-label c)))
  (define-values (lib failure)
    (with-handlers ([exn:fail? (lambda (e) (values #f e))])
      (values ((candidate-open c)) #f)))
  (define missing (if lib (missing-symbols lib) '()))
  (cond
    [failure (values #f (format "~a: ~a" label (load-error-reason failure (candidate-label c))))]
    [(pair? missing) (values #f (format "~a: ~a" label (missing-reason missing)))]
    [else (values lib #f)]))

;; The OS loader resolves a bare soname without the current directory on Linux and the BSDs;
;; ffi-lib's own fallback to the current directory is disarmed by an empty one.
(define (load-soname version)
  (with-temporary-directory empty
    (parameterize ([current-directory empty])
      (ffi-lib "libsecp256k1" (list version)))))

;; dyld and LoadLibrary search the current directory for a bare name, so these systems get
;; absolute paths from an explicit list of directories.
(define (search-path-dirs variable)
  (define value (getenv variable))
  (define separator (if (eq? (system-type) 'windows) ";" ":"))
  (map string->path (filter absolute-path? (if value (string-split value separator) '()))))

(define (explicit-dirs)
  (case (system-type)
    [(macosx)
     (append (get-lib-search-dirs)
             (search-path-dirs "DYLD_LIBRARY_PATH")
             (match (search-path-dirs "DYLD_FALLBACK_LIBRARY_PATH")
               ['() (map string->path '("/usr/local/lib" "/usr/lib"))]
               [dirs dirs]))]
    [else (append (get-lib-search-dirs) (search-path-dirs "PATH"))]))

(define (load-from-dirs name)
  (define dirs (explicit-dirs))
  (define found
    (for/first ([dir (in-list dirs)]
                #:when (file-exists? (build-path dir name)))
      (build-path dir name)))
  (if found
      (ffi-lib found)
      (raise (exn:fail:filesystem
              (format "not found in ~a" (string-join (map path->string dirs) ", "))
              (current-continuation-marks)))))

(define (soname version)
  (cond
    [(not version) library-file-name]
    [(eq? (system-type) 'macosx) (format "libsecp256k1.~a~a" version so-suffix)]
    [else (format "libsecp256k1~a.~a" so-suffix version)]))

(define system-versions '("7" "6" "5" "2" "1" #f))

(define system-candidates
  (case (system-type)
    [(windows)
     (for/list ([name (in-list '("secp256k1.dll" "libsecp256k1.dll"))])
       (candidate 'system name (lambda () (load-from-dirs name))))]
    [(macosx)
     (for/list ([v (in-list system-versions)])
       (candidate 'system (soname v) (lambda () (load-from-dirs (soname v)))))]
    [else
     (for/list ([v (in-list system-versions)])
       (candidate 'system (soname v) (lambda () (load-soname v))))]))

(define (path-candidate origin path)
  (candidate origin (path->string path) (lambda () (ffi-lib path))))

(define (library-candidates setting)
  (cond
    [(member setting '(#f "")) (cons (path-candidate 'bundled bundled-library) system-candidates)]
    [(string=? setting "system") system-candidates]
    [else (list (path-candidate 'environment (string->path setting)))]))

(define (reason-line c reason)
  (if (and (eq? (candidate-origin c) 'bundled) (not (file-exists? bundled-library)))
      (format "bundled: ~a: not built" (candidate-label c))
      reason))

(define (no-library-hint bundled-missing?)
  (string-append
   (if bundled-missing? "run raco setup libsecp256k1, " "")
   "set LIBSECP256K1_LIBRARY to a libsecp256k1 file, or install libsecp256k1 0.2 or later"
   " with the recovery module"))

(define (locate-library setting)
  (define candidates (library-candidates setting))
  (let loop ([cs candidates] [reasons '()])
    (match cs
      ['()
       (define bundled-missing?
         (for/or ([c (in-list candidates)])
           (and (eq? (candidate-origin c) 'bundled) (not (file-exists? bundled-library)))))
       (values #f #f
               (exn:fail:libsecp256k1:load
                (string-join (append '("libsecp256k1: no usable libsecp256k1 library")
                                     (reverse reasons)
                                     (list (no-library-hint bundled-missing?)))
                             "\n  ")
                (current-continuation-marks)))]
      [(cons c rest)
       (define-values (lib reason) (open-candidate c))
       (if lib
           (values (candidate-origin c) lib #f)
           (loop rest (cons (reason-line c reason) reasons)))])))
