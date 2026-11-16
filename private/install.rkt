#lang racket/base

(require (only-in dynext/compile
                  compile-extension
                  current-extension-compiler
                  current-extension-compiler-flags)
         (only-in dynext/file append-object-suffix)
         (only-in dynext/link current-use-mzdyn link-extension)
         (only-in file/sha1 bytes->hex-string)
         (only-in racket/file make-directory* make-temporary-file)
         (only-in racket/list take)
         (only-in racket/string string-join string-split)
         "locate.rkt")

(provide build-library
         install-native!
         pre-installer
         probe-system
         recipe
         stamp-path)

(define build-table
  '((sources "secp256k1.c" "precomputed_ecmult.c" "precomputed_ecmult_gen.c")
    (flags "-DECMULT_WINDOW_SIZE=15" "-DECMULT_GEN_KB=86" "-DENABLE_MODULE_RECOVERY=1")
    (unix-flags "-fvisibility=hidden")
    (windows-flags "-DSECP256K1_DLL_EXPORT=1")))

(define (table-ref key)
  (cdr (assq key build-table)))

(define (build-flags)
  (append (table-ref 'flags)
          (table-ref (if (eq? (system-type) 'windows) 'windows-flags 'unix-flags))))

(define (vendored-dir root)
  (build-path root "native" "secp256k1"))

(define (manifest-path root)
  (build-path (vendored-dir root) "MANIFEST.rktd"))

(define (recipe root)
  (define manifest (manifest-path root))
  (list 'recipe
        (cadr (assq 'version (call-with-input-file manifest read)))
        (bytes->hex-string (call-with-input-file manifest sha256-bytes))
        build-table))

(define (stamp-path root)
  (build-path (native-build-dir root) "recipe.rktd"))

(define (read-stamp root)
  (with-handlers ([exn:fail? (lambda (_) #f)])
    (call-with-input-file (stamp-path root) read)))

(define (write-stamp! root)
  (call-with-output-file (stamp-path root) #:exists 'truncate/replace
    (lambda (out) (write (recipe root) out))))

(define (remove-library! root)
  (for ([p (list (native-library-path root) (stamp-path root))]
        #:when (file-exists? p))
    (delete-file p)))

(define (build-library root out)
  (define-values (out-dir _name _dir?) (split-path out))
  (define src (vendored-dir root))
  (make-directory* out-dir)
  (with-temporary-directory tmp
    (define objects
      (for/list ([source (in-list (table-ref 'sources))])
        (define object (build-path tmp (append-object-suffix (path-replace-extension source #""))))
        (parameterize ([current-extension-compiler-flags
                        (append (current-extension-compiler-flags) (build-flags))])
          (compile-extension #t
                             (build-path src "src" source)
                             object
                             (list (build-path src "include") (build-path src "src"))))
        object))
    (define partial (make-temporary-file "libsecp256k1-~a.partial" #f out-dir))
    (parameterize ([current-use-mzdyn #f])
      (link-extension #t objects partial))
    (rename-file-or-directory partial out #t)))

(define (probe-system)
  (let loop ([cs system-candidates] [reasons '()])
    (cond
      [(null? cs) (values #f (reverse reasons))]
      [else
       (define-values (lib reason) (open-candidate (car cs)))
       (if lib
           (values (candidate-label (car cs)) '())
           (loop (cdr cs) (cons reason reasons)))])))

(define (compiler-error-lines e)
  (define lines (filter (lambda (l) (regexp-match? #px"\\S" l))
                        (string-split (exn-message e) "\n" #:trim? #f)))
  (define errors (filter (lambda (l) (regexp-match? #rx"(?i:error)" l)) lines))
  (define shown (if (null? errors) lines errors))
  (take shown (min 3 (length shown))))

(define (build-failure e compiler)
  (cond
    [(not compiler) (values "no C compiler found" '())]
    [(not (file-exists? compiler)) (values (format "C compiler ~a not found" compiler) '())]
    [else (values (format "~a failed" compiler) (compiler-error-lines e))]))

(define (install-native! root
                         #:build build
                         #:probe probe
                         #:compiler [compiler (current-extension-compiler)])
  (define out (native-library-path root))
  (define cached? (and (file-exists? out) (equal? (read-stamp root) (recipe root))))
  (define build-error
    (and (not cached?)
         (with-handlers ([exn:fail? values])
           (build root out)
           #f)))
  (when build-error
    (remove-library! root))
  (define-values (system reasons)
    (if build-error (probe) (values #f '())))
  (define-values (summary details)
    (if build-error (build-failure build-error compiler) (values #f '())))
  (cond
    [cached? 'cached]
    [(not build-error) (write-stamp! root) 'built]
    [system
     (printf "libsecp256k1: could not build the bundled C library (~a~a);~a\n"
             summary
             (if (pair? details) (string-append ": " (car details)) "")
             (format " using the system library ~a" system))
     'system]
    [else
     (eprintf "~a\n"
              (string-join
               (append (list (string-append "libsecp256k1: could not build the bundled C library"
                                            " and found no usable system libsecp256k1")
                             (string-append "build: " summary))
                       (for/list ([d (in-list details)]) (string-append "  " d))
                       reasons
                       '("install a C compiler (or set CC) and run raco setup libsecp256k1,"
                         "or install libsecp256k1 0.2 or later with the recovery module"))
               "\n  "))
     'none]))

(define (pre-installer _collections-top-path this-collection-path)
  (void (install-native! this-collection-path #:build build-library #:probe probe-system)))
