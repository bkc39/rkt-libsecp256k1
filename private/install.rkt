#lang racket/base

(require (for-syntax racket/base)
         (only-in dynext/compile compile-extension current-extension-compiler-flags)
         (only-in dynext/file append-object-suffix)
         (only-in dynext/link current-use-mzdyn link-extension)
         (only-in file/sha1 bytes->hex-string)
         (only-in racket/file delete-directory/files make-directory* make-temporary-directory)
         syntax/parse/define
         "exn.rkt"
         "locate.rkt")

(provide build-library
         install-native!
         pre-installer
         probe-system
         recipe
         stamp-path
         with-temporary-directory)

(define-syntax-parse-rule (with-temporary-directory dir:id body:expr ...+)
  (let ([dir (make-temporary-directory)])
    (dynamic-wind
     void
     (lambda () body ...)
     (lambda () (delete-directory/files dir #:must-exist? #f)))))

(define sources '("secp256k1.c" "precomputed_ecmult.c" "precomputed_ecmult_gen.c"))

(define defines
  '("-DECMULT_WINDOW_SIZE=15" "-DECMULT_GEN_KB=86" "-DENABLE_MODULE_RECOVERY=1"))

(define (build-flags)
  (append defines
          (if (eq? (system-type 'os) 'windows)
              '("-DSECP256K1_DLL_EXPORT=1")
              '("-fvisibility=hidden"))))

(define (vendored-dir root)
  (build-path root "native" "secp256k1"))

(define (manifest-path root)
  (build-path (vendored-dir root) "MANIFEST.rktd"))

(define (manifest-version root)
  (cadr (assq 'version (call-with-input-file (manifest-path root) read))))

(define (recipe root)
  (list 'recipe
        (manifest-version root)
        (build-flags)
        (bytes->hex-string (call-with-input-file (manifest-path root) sha256-bytes))))

(define (stamp-path root)
  (build-path (native-build-dir root) "recipe.rktd"))

(define (read-stamp root)
  (with-handlers ([exn:fail? (lambda (_) #f)])
    (call-with-input-file (stamp-path root) read)))

(define (write-stamp! root)
  (call-with-output-file (stamp-path root) #:exists 'truncate/replace
    (lambda (out) (write (recipe root) out))))

(define (build-library root out)
  (define-values (out-dir _name _dir?) (split-path out))
  (define src (vendored-dir root))
  (with-temporary-directory tmp
    (define objects
      (for/list ([source (in-list sources)])
        (define object (build-path tmp (append-object-suffix (path-replace-extension source #""))))
        (parameterize ([current-extension-compiler-flags
                        (append (current-extension-compiler-flags) (build-flags))])
          (compile-extension #t
                             (build-path src "src" source)
                             object
                             (list (build-path src "include") (build-path src "src"))))
        object))
    (define partial
      (path-add-extension out (format ".tmp-~a" (random 1000000000))))
    (make-directory* out-dir)
    (parameterize ([current-use-mzdyn #f])
      (link-extension #t objects partial))
    (rename-file-or-directory partial out #t)))

;; The name of the first usable system library, or the lines that say why
;; each candidate is not.
(define (probe-system)
  (let loop ([cs system-candidates] [reasons '()])
    (define outcome (and (pair? cs) (open-candidate (car cs))))
    (cond
      [(null? cs) (reverse reasons)]
      [(string? outcome) (loop (cdr cs) (cons outcome reasons))]
      [else (candidate-label (car cs))])))

(define (first-line message)
  (car (regexp-split #rx"\n" message)))

(define (no-library-error build-error reasons)
  (exn:fail:libsecp256k1:load
   (apply string-append
          "libsecp256k1: could not build the bundled C library and found no usable system"
          " libsecp256k1\n  build: " (first-line (exn-message build-error))
          (append
           (for/list ([r (in-list reasons)])
             (string-append "\n  " r))
           (list "\n  install a C compiler (or set CC) and run raco setup libsecp256k1, or"
                 " install libsecp256k1 0.2 or later built with the recovery module")))
   (current-continuation-marks)))

(define (install-native! root #:build build #:probe probe)
  (define out (native-library-path root))
  (define cached? (and (file-exists? out) (equal? (read-stamp root) (recipe root))))
  (define build-error
    (and (not cached?)
         (with-handlers ([exn:fail? values])
           (build root out)
           #f)))
  (define system (and build-error (probe)))
  (cond
    [cached? 'cached]
    [(not build-error) (write-stamp! root) 'built]
    [(string? system)
     (printf "libsecp256k1: could not build the bundled library (~a); using the system library ~a\n"
             (first-line (exn-message build-error))
             system)
     'system]
    [else (raise (no-library-error build-error system))]))

(define (pre-installer _collections-top-path this-collection-path)
  (void (install-native! this-collection-path #:build build-library #:probe probe-system)))
