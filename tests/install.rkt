#lang racket/base

(module+ test
  (require racket/file
           racket/port
           racket/runtime-path
           rackunit
           libsecp256k1
           libsecp256k1/private/install
           libsecp256k1/private/locate)

  (define-runtime-path package-root "..")

  ;; A package root holding only the manifest, the input the recipe reads.
  (define (make-root! dir)
    (define vendored (build-path dir "native" "secp256k1"))
    (make-directory* vendored)
    (copy-file (build-path package-root "native" "secp256k1" "MANIFEST.rktd")
               (build-path vendored "MANIFEST.rktd")))

  (define (stub-build! calls)
    (lambda (_root out)
      (set-box! calls (add1 (unbox calls)))
      (define-values (dir _name _dir?) (split-path out))
      (make-directory* dir)
      (call-with-output-file out #:exists 'truncate/replace
        (lambda (port) (write-string "built" port)))))

  (define (failing-build _root _out)
    (error 'link-extension "can't find an installed linker"))

  (define (no-system) (list "system: libsecp256k1.so.7: not found"))

  (test-case "a library built from the current recipe is not rebuilt"
    (with-temporary-directory root
      (make-root! root)
      (define calls (box 0))
      (check-eq? (install-native! root #:build (stub-build! calls) #:probe no-system) 'built)
      (check-equal? (unbox calls) 1)
      (check-equal? (file->value (stamp-path root)) (recipe root))
      (check-eq? (install-native! root #:build (stub-build! calls) #:probe no-system) 'cached)
      (check-equal? (unbox calls) 1)))

  (test-case "a stale stamp rebuilds and rewrites the stamp"
    (with-temporary-directory root
      (make-root! root)
      (define calls (box 0))
      (install-native! root #:build (stub-build! calls) #:probe no-system)
      (call-with-output-file (stamp-path root) #:exists 'truncate/replace
        (lambda (out) (write '(recipe "0.0.0" () "stale") out)))
      (check-eq? (install-native! root #:build (stub-build! calls) #:probe no-system) 'built)
      (check-equal? (unbox calls) 2)
      (check-equal? (file->value (stamp-path root)) (recipe root))))

  (test-case "a failed build falls back to a usable system library with one line of output"
    (with-temporary-directory root
      (make-root! root)
      (define result (box #f))
      (define out
        (with-output-to-string
          (lambda ()
            (set-box! result (install-native! root
                                              #:build failing-build
                                              #:probe (lambda () "libsecp256k1.so.7"))))))
      (check-eq? (unbox result) 'system)
      (check-equal? out
                    (string-append "libsecp256k1: could not build the bundled library"
                                   " (link-extension: can't find an installed linker);"
                                   " using the system library libsecp256k1.so.7\n"))))

  (test-case "with no build and no system library, installing raises a load error"
    (with-temporary-directory root
      (make-root! root)
      (check-exn (lambda (e)
                   (and (exn:fail:libsecp256k1:load? e)
                        (regexp-match? #rx"can't find an installed linker" (exn-message e))
                        (regexp-match? #rx"libsecp256k1[.]so[.]7: not found" (exn-message e))
                        (regexp-match? #rx"C compiler" (exn-message e))
                        (regexp-match? #rx"recovery module" (exn-message e))))
                 (lambda () (install-native! root #:build failing-build #:probe no-system)))))

  (test-case "a failed rebuild leaves the existing library in place"
    (with-temporary-directory root
      (make-root! root)
      (install-native! root #:build (stub-build! (box 0)) #:probe no-system)
      (delete-file (stamp-path root))
      (with-output-to-string
        (lambda ()
          (install-native! root #:build failing-build #:probe (lambda () "libsecp256k1.so.7"))))
      (check-equal? (file->string (native-library-path root)) "built")))

  (test-case "the temporary directory is deleted on every exit"
    (define kept (box #f))
    (with-temporary-directory dir
      (set-box! kept dir)
      (check-true (directory-exists? dir)))
    (check-false (directory-exists? (unbox kept)))
    (check-exn #rx"escape"
               (lambda ()
                 (with-temporary-directory dir
                   (set-box! kept dir)
                   (error 'escape "now"))))
    (check-false (directory-exists? (unbox kept))))

  (test-case "the installed library's stamp is the current recipe"
    (when (and (not (getenv "LIBSECP256K1_LIBRARY")) (eq? (libsecp256k1-origin) 'bundled))
      (check-equal? (file->value (stamp-path package-root)) (recipe package-root))
      (check-true (file-exists? (native-library-path package-root))))))
