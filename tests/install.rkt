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

  (define compiler-failure
    (string-append "compile-extension: \n"
                   "In file included from src/secp256k1.c:12:\n"
                   "src/util.h:3:10: fatal error: stdint.h: No such file or directory\n"
                   "compilation terminated."))

  (define (failing-build _root _out)
    (error compiler-failure))

  (define (no-system)
    (values #f (list "system: libsecp256k1.so.7: cannot open shared object file")))

  (define (system-found)
    (values "libsecp256k1.so.7" '()))

  (struct install-run (result stdout stderr))

  (define cc (find-executable-path "sh"))

  (define (install root #:build build #:probe probe #:compiler [compiler cc])
    (define result (box #f))
    (define stderr (open-output-string))
    (define stdout
      (with-output-to-string
        (lambda ()
          (parameterize ([current-error-port stderr])
            (set-box! result
                      (install-native! root #:build build #:probe probe #:compiler compiler))))))
    (install-run (unbox result) stdout (get-output-string stderr)))

  (test-case "a library built from the current recipe is not rebuilt"
    (with-temporary-directory root
      (make-root! root)
      (define calls (box 0))
      (check-eq? (install-run-result (install root #:build (stub-build! calls) #:probe no-system))
                 'built)
      (check-equal? (unbox calls) 1)
      (check-equal? (file->value (stamp-path root)) (recipe root))
      (check-eq? (install-run-result (install root #:build (stub-build! calls) #:probe no-system))
                 'cached)
      (check-equal? (unbox calls) 1)))

  (test-case "a stale stamp rebuilds and rewrites the stamp"
    (with-temporary-directory root
      (make-root! root)
      (define calls (box 0))
      (install root #:build (stub-build! calls) #:probe no-system)
      (call-with-output-file (stamp-path root) #:exists 'truncate/replace
        (lambda (out) (write '(recipe "0.0.0" "stale" ()) out)))
      (check-eq? (install-run-result (install root #:build (stub-build! calls) #:probe no-system))
                 'built)
      (check-equal? (unbox calls) 2)
      (check-equal? (file->value (stamp-path root)) (recipe root))))

  (test-case "the recipe covers every build flag of every system"
    (with-temporary-directory root
      (make-root! root)
      (define flags (cadddr (recipe root)))
      (for ([flag (in-list '("-fvisibility=hidden" "-DSECP256K1_DLL_EXPORT=1"
                             "-DENABLE_MODULE_RECOVERY=1" "-DECMULT_WINDOW_SIZE=15"))])
        (check-not-false (for/or ([row (in-list flags)]) (member flag row)) flag))))

  (test-case "a failed build falls back to a system library, naming the compiler and its error"
    (with-temporary-directory root
      (make-root! root)
      (define run (install root #:build failing-build #:probe system-found))
      (check-eq? (install-run-result run) 'system)
      (check-equal? (install-run-stdout run)
                    (format (string-append "libsecp256k1: could not build the bundled C library"
                                           " (~a failed: src/util.h:3:10: fatal error:"
                                           " stdint.h: No such file or directory);"
                                           " using the system library libsecp256k1.so.7\n")
                            cc))))

  (test-case "with no build and no system library, installing reports why and what to do"
    (with-temporary-directory root
      (make-root! root)
      (define run (install root #:build failing-build #:probe no-system))
      (check-eq? (install-run-result run) 'none)
      (check-equal? (install-run-stdout run) "")
      (check-equal?
       (install-run-stderr run)
       (format
        (string-append
         "libsecp256k1: could not build the bundled C library and found no usable system"
         " libsecp256k1\n"
         "  build: ~a failed\n"
         "    src/util.h:3:10: fatal error: stdint.h: No such file or directory\n"
         "  system: libsecp256k1.so.7: cannot open shared object file\n"
         "  install a C compiler (or set CC) and run raco setup libsecp256k1,\n"
         "  or install libsecp256k1 0.2 or later with the recovery module\n")
        cc))))

  (test-case "a compiler that does not exist is named as not found"
    (with-temporary-directory root
      (make-root! root)
      (define run (install root #:build failing-build #:probe no-system
                           #:compiler "/nonexistent/cc"))
      (check-regexp-match #rx"\n  build: C compiler /nonexistent/cc not found\n"
                          (install-run-stderr run))))

  (test-case "without a compiler, the report says no C compiler was found"
    (with-temporary-directory root
      (make-root! root)
      (define run (install root #:build failing-build #:probe no-system #:compiler #f))
      (check-regexp-match #rx"\n  build: no C compiler found\n" (install-run-stderr run))))

  (test-case "a failed rebuild removes the stale library, so the loader cannot pick it"
    (with-temporary-directory root
      (make-root! root)
      (install root #:build (stub-build! (box 0)) #:probe no-system)
      (call-with-output-file (stamp-path root) #:exists 'truncate/replace
        (lambda (out) (write '(recipe "0.0.0" "stale" ()) out)))
      (check-eq? (install-run-result (install root #:build failing-build #:probe system-found))
                 'system)
      (check-false (file-exists? (native-library-path root)))
      (check-false (file-exists? (stamp-path root)))))

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
