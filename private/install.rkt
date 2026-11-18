#lang racket/base

(require (only-in racket/file make-directory* make-temporary-file)
         (only-in racket/string string-join)
         "locate.rkt")

(provide pre-installer
         stage-library!)

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
      (rename-file-or-directory partial dest #t))))

(define (no-library-line platform shipped?)
  (string-append
   "libsecp256k1: "
   (if shipped?
       (format "this copy of the package lacks the bundled library for ~a" platform)
       (format "no bundled library for ~a (shipped for ~a only)"
               platform
               (string-join (map car bundled-platforms) " and ")))
   "; install libsecp256k1 0.2 or later with the recovery module, or set"
   " LIBSECP256K1_LIBRARY to a libsecp256k1 file"))

(define (stage-library! root
                        #:native-dir [native-dir (getenv "LIBSECP256K1_NATIVE_LIB_PATH")]
                        #:platform [platform host-platform])
  (define entry (bundled-platform platform))
  (define libs (native-libs-dir root))
  (define from-env
    (and native-dir
         (not (equal? native-dir ""))
         (build-path native-dir "lib" library-file-name)))
  (define candidate (and entry (build-path libs "candidates" (cadr entry) (caddr entry))))
  (define staged (build-path libs (if entry (caddr entry) library-file-name)))
  (define-values (origin source)
    (cond
      [(and from-env (file-exists? from-env)) (values 'environment from-env)]
      [(and candidate (file-exists? candidate)) (values 'candidate candidate)]
      [(file-exists? staged) (values 'staged #f)]
      [else (values 'none #f)]))
  (define failure
    (and source
         (with-handlers ([exn:fail? values])
           (install-file! source staged)
           #f)))
  (when (and from-env (not (eq? origin 'environment)))
    (printf "libsecp256k1: LIBSECP256K1_NATIVE_LIB_PATH has no ~a\n" from-env))
  (cond
    [failure
     (printf "libsecp256k1: could not install the bundled library: ~a\n"
             (first-line (exn-message failure)))
     'failed]
    [(eq? origin 'none)
     (printf "~a\n" (no-library-line platform (and entry #t)))
     'none]
    [else origin]))

(define (pre-installer _collections-top-path this-collection-path [_user-specific? #f])
  (with-handlers ([exn:fail? (lambda (e)
                               (printf "libsecp256k1: ~a\n" (first-line (exn-message e))))])
    (stage-library! this-collection-path))
  (void))
