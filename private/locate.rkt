#lang racket/base

(require (for-syntax racket/base)
         (only-in ffi/unsafe ffi-lib ffi-obj-ref)
         (only-in file/sha1 bytes->hex-string)
         (only-in racket/file delete-directory/files)
         (only-in racket/match == match)
         (only-in racket/random crypto-random-bytes)
         (only-in racket/string string-join string-prefix? string-split)
         racket/runtime-path
         (only-in setup/dirs get-lib-search-dirs)
         syntax/parse/define
         "exn.rkt")

(provide bundled-library
         bundled-platform
         bundled-platforms
         first-line
         host-platform
         library-file-name
         load-error-reason
         locate-library
         missing-reason
         missing-symbols
         native-libs-dir
         open-candidate
         required-symbols
         system-candidates
         with-temporary-directory
         (struct-out candidate))

(define (make-private-directory)
  (define dir
    (build-path (find-system-path 'temp-dir)
                (string-append "libsecp256k1-" (bytes->hex-string (crypto-random-bytes 16)))))
  (make-directory dir #o700)
  dir)

(define-syntax-parse-rule (with-temporary-directory dir:id body:expr ...+)
  (let ([dir (make-private-directory)])
    (dynamic-wind
     void
     (lambda () body ...)
     (lambda () (delete-directory/files dir #:must-exist? #f)))))

(define so-suffix (bytes->string/utf-8 (system-type 'so-suffix)))

(define library-file-name (string-append "libsecp256k1" so-suffix))

(define-runtime-path bundled-library-path
  (build-path 'up "native-libs"
              (string-append "libsecp256k1" (bytes->string/utf-8 (system-type 'so-suffix)))))

(define bundled-library (simplify-path bundled-library-path))

(define (native-libs-dir root)
  (build-path root "native-libs"))

(define host-platform (path->string (system-library-subpath #f)))

;; (platform candidate-directory file): the platforms a prebuilt library ships for.
(define bundled-platforms
  '(("x86_64-linux" "linux" "libsecp256k1.so")
    ("aarch64-macosx" "darwin" "libsecp256k1.dylib")))

(define (bundled-platform platform)
  (assoc platform bundled-platforms))

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
    [(null? (remove* missing required-symbols)) "not a libsecp256k1 library"]
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
  (match (regexp-match dyld-first-attempt reason)
    [(list _ (== label) why) why]
    [(list _ path why) (format "~a: ~a" path why)]
    [#f (if (string-prefix? reason own-prefix)
            (substring reason (string-length own-prefix))
            reason)]))

(define dyld-first-attempt #rx"^dlopen\\(.*?\\): tried: '([^']*)' \\((.*?)\\)(?:, '|$)")

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

;; ffi-lib tries a suffixed name before the given one unless the version list is empty.
(define (load-file path)
  (if (file-exists? path)
      (ffi-lib path '())
      (raise (exn:fail:filesystem "no such file" (current-continuation-marks)))))

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
      (load-file found)
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
  (candidate origin (path->string path) (lambda () (load-file path))))

(define (library-candidates setting bundled)
  (cond
    [(member setting '(#f "")) (cons (path-candidate 'bundled bundled) system-candidates)]
    [(string=? setting "system") system-candidates]
    [else (list (path-candidate 'environment (path->complete-path (string->path setting))))]))

(define (bundled-missing? c bundled)
  (and (eq? (candidate-origin c) 'bundled) (not (file-exists? bundled))))

(define (shipped-platforms)
  (string-join (map car bundled-platforms) " and "))

(define (reason-line c reason bundled platform)
  (cond
    [(not (bundled-missing? c bundled)) reason]
    [(bundled-platform platform) (format "bundled: ~a: not installed" (candidate-label c))]
    [else (format "bundled: none for ~a (shipped for ~a only)" platform (shipped-platforms))]))

(define (no-library-hint setup?)
  (string-append
   (if setup? "run raco setup libsecp256k1, " "")
   "set LIBSECP256K1_LIBRARY to a libsecp256k1 file, or install libsecp256k1 0.2 or later"
   " with the recovery module"))

(define (locate-library setting
                        #:bundled [bundled bundled-library]
                        #:platform [platform host-platform])
  (define candidates (library-candidates setting bundled))
  (let loop ([cs candidates] [reasons '()])
    (match cs
      ['()
       (define setup?
         (and (bundled-platform platform)
              (for/or ([c (in-list candidates)]) (bundled-missing? c bundled))))
       (values #f #f
               (exn:fail:libsecp256k1:load
                (string-join (append '("libsecp256k1: no usable libsecp256k1 library")
                                     (reverse reasons)
                                     (list (no-library-hint setup?)))
                             "\n  ")
                (current-continuation-marks)))]
      [(cons c rest)
       (define-values (lib reason) (open-candidate c))
       (if lib
           (values (candidate-origin c) lib #f)
           (loop rest (cons (reason-line c reason bundled platform) reasons)))])))
