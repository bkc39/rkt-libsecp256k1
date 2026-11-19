#lang racket/base

(require (only-in ffi/unsafe ffi-lib)
         (only-in racket/file make-directory* make-temporary-file)
         (only-in racket/string string-join)
         (only-in setup/cross-system cross-system-library-subpath cross-system-type)
         "locate.rkt")

(provide pre-installer
         stage-library!
         validate-on-host?)

(define (target-platform)
  (path->string (cross-system-library-subpath #f)))

(define (target-so-suffix)
  (bytes->string/utf-8 (cross-system-type 'so-suffix)))

(define (validate-on-host? platform)
  (equal? platform host-platform))

(define (failure-detail e)
  (define message (exn-message e))
  (define system-error (regexp-match #rx"\n  (system error: [^\n]*)" message))
  (if system-error
      (format "~a (~a)" (first-line message) (cadr system-error))
      (first-line message)))

(define (same-contents? a b)
  (and (file-exists? b)
       (= (file-size a) (file-size b))
       (equal? (call-with-input-file a sha256-bytes) (call-with-input-file b sha256-bytes))))

;; A rename replaces the staged file, so a process that has the old one mapped keeps it intact.
(define (install-file! source dest)
  (unless (same-contents? source dest)
    (define-values (dir _name _dir?) (split-path dest))
    (make-directory* dir)
    (define partial (make-temporary-file "libsecp256k1-~a.partial" #f dir))
    (with-handlers ([exn:fail? (lambda (e)
                                 (when (file-exists? partial)
                                   (delete-file partial))
                                 (raise e))])
      (copy-file source partial #t)
      (file-or-directory-permissions partial #o755)
      (rename-file-or-directory partial dest #t))))

(define (unusable-reason path)
  (define-values (_lib reason)
    (open-candidate (candidate 'LIBSECP256K1_NATIVE_LIB_PATH
                               (path->string path)
                               (lambda () (ffi-lib path '())))))
  reason)

(define (no-library-line platform)
  (string-append
   (format "libsecp256k1: no bundled library for ~a (shipped for ~a only)"
           platform
           (string-join (map car bundled-platforms) " and "))
   "; install libsecp256k1 0.2 or later with the recovery module, or set"
   " LIBSECP256K1_LIBRARY to a libsecp256k1 file"))

(define (stage-library! root
                        #:native-dir [native-dir (getenv "LIBSECP256K1_NATIVE_LIB_PATH")]
                        #:platform [platform (target-platform)]
                        #:so-suffix [so-suffix (target-so-suffix)]
                        #:validate? [validate? (validate-on-host? platform)])
  (define entry (bundled-platform platform))
  (define libs (native-libs-dir root))
  (define file-name (if entry (caddr entry) (string-append "libsecp256k1" so-suffix)))
  (define from-env
    (and native-dir
         (not (equal? native-dir ""))
         (build-path native-dir "lib" file-name)))
  (define env-present? (and from-env (file-exists? from-env)))
  (define env-reason (and env-present? validate? (unusable-reason from-env)))
  (define staged (build-path libs file-name))
  (define-values (origin source)
    (cond
      [(and env-present? (not env-reason)) (values 'environment from-env)]
      [entry (values 'candidate (build-path libs "candidates" (cadr entry) (caddr entry)))]
      [(file-exists? staged) (values 'staged #f)]
      [else (values 'none #f)]))
  (define failure
    (and source
         (with-handlers ([exn:fail? values])
           (install-file! source staged)
           #f)))
  (cond
    [env-reason (printf "libsecp256k1: not installing ~a\n" env-reason)]
    [(and from-env (not env-present?))
     (printf "libsecp256k1: LIBSECP256K1_NATIVE_LIB_PATH has no ~a\n" from-env)]
    [else (void)])
  (cond
    [failure
     (printf "libsecp256k1: could not install ~a as ~a: ~a\n"
             source staged (failure-detail failure))
     'failed]
    [(eq? origin 'none)
     (printf "~a\n" (no-library-line platform))
     'none]
    [else origin]))

(define (pre-installer _collections-top-path this-collection-path [_user-specific? #f])
  (with-handlers ([exn:fail? (lambda (e) (printf "libsecp256k1: ~a\n" (failure-detail e)))])
    (stage-library! this-collection-path))
  (void))
