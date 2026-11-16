#lang racket/base

(module+ test
  (require racket/file
           racket/port
           racket/system
           rackunit
           libsecp256k1
           libsecp256k1/private/locate
           "helpers/util.rkt"
           "helpers/vectors.rkt")

  (define racket-path
    (let ([exe (find-system-path 'exec-file)])
      (if (absolute-path? exe) exe (find-executable-path exe))))

  (define (run-program program settings #:directory [directory (current-directory)])
    (define env (environment-variables-copy (current-environment-variables)))
    (for ([s (in-list settings)])
      (environment-variables-set! env
                                  (string->bytes/utf-8 (car s))
                                  (and (cdr s) (string->bytes/utf-8 (cdr s)))))
    (define out
      (parameterize ([current-environment-variables env]
                     [current-directory directory])
        (with-output-to-string
          (lambda ()
            (system* racket-path "-l" "racket/base" "-e" (format "~s" program))))))
    (with-handlers ([exn:fail:read? (lambda (_) out)])
      (read (open-input-string out))))

  (define (load-message setting)
    (define-values (origin lib failure) (locate-library setting))
    (and failure (exn-message failure)))

  (test-case "the bundled library is loaded when no override is set"
    (when (and (not (getenv "LIBSECP256K1_LIBRARY")) (file-exists? bundled-library))
      (check-eq? (libsecp256k1-origin) 'bundled)))

  (define missing-library "/nonexistent/libsecp256k1.so")

  (define load-failure-program
    '(begin
       (require libsecp256k1)
       (define (outcome thunk)
         (with-handlers ([exn:fail:libsecp256k1:load? (lambda (e) (list 'load (exn-message e)))]
                         [(lambda (_) #t) (lambda (e) (list 'other (format "~a" e)))])
           (thunk)
           'returned))
       (write (list (outcome (lambda () (libsecp256k1-origin)))
                    (outcome (lambda () (bytes->secret-key (make-bytes 32 1))))
                    (outcome (lambda ()
                               (ecdsa-recover (ecdsa-recoverable-signature 1 1 0)
                                              (make-bytes 32 0))))
                    (outcome (lambda () (ecdsa-signature-r (ecdsa-signature 5 6))))))))

  (test-case "a library that cannot be loaded is reported by every call, not at require"
    (define outcomes
      (run-program load-failure-program (list (cons "LIBSECP256K1_LIBRARY" missing-library))))
    (check-pred list? outcomes)
    (for ([o (in-list (if (list? outcomes) (reverse (cdr (reverse outcomes))) '()))])
      (check-equal? (car o) 'load)
      (check-regexp-match #rx"^libsecp256k1: no usable libsecp256k1 library\n" (cadr o))
      (check-regexp-match (regexp-quote missing-library) (cadr o)))
    (check-equal? (if (list? outcomes) (cadddr outcomes) outcomes) 'returned))

  (test-case "a missing file is reported with the loader's own reason and what to do"
    (check-equal? (load-message missing-library)
                  (string-append
                   "libsecp256k1: no usable libsecp256k1 library\n"
                   "  environment: " missing-library
                   ": cannot open shared object file: No such file or directory\n"
                   "  set LIBSECP256K1_LIBRARY to a libsecp256k1 file, or install libsecp256k1"
                   " 0.2 or later with the recovery module")))

  (test-case "a file that is not a library is reported with the loader's reason"
    (define garbage (make-temporary-file "libsecp256k1-garbage-~a.so"))
    (call-with-output-file garbage #:exists 'truncate (lambda (out) (write-string "garbage" out)))
    (define message (load-message (path->string garbage)))
    (delete-file garbage)
    (define reason-line
      (string-append "\n  environment: " (regexp-quote (path->string garbage)) ": [^\n]+\n"))
    (check-regexp-match (regexp reason-line) message)
    (check-regexp-match #rx"too short|ELF|[Mm]ach-?[Oo]|Win32" message)
    (check-false (regexp-match? #rx"not found|No such file" message) message))

  (test-case "an unbuilt bundled library asks for raco setup first"
    (unless (file-exists? bundled-library)
      (check-regexp-match #rx"\n  bundled: [^\n]*: not built\n" (load-message #f))
      (check-regexp-match #rx"\n  run raco setup libsecp256k1, set LIBSECP256K1_LIBRARY"
                          (load-message #f))))

  (define missing-symbols-program
    '(begin
       (require ffi/unsafe libsecp256k1/private/locate)
       (define missing (missing-symbols (ffi-lib #f)))
       (write (list (and (member "secp256k1_ecdsa_recover" missing) #t)
                    (and (member "secp256k1_selftest" missing) #t)
                    (missing-reason missing)))))

  (test-case "a library without the recovery module is refused with that reason"
    (check-equal? (run-program missing-symbols-program '())
                  '(#t #t "lacks secp256k1_ecdsa_recover (built without the recovery module)"))
    (check-equal? (missing-reason '("secp256k1_selftest"))
                  "lacks secp256k1_selftest (older than 0.2.0)"))

  (define origin-program
    '(begin
       (require libsecp256k1 racket/file racket/string)
       (define origin
         (with-handlers ([exn:fail:libsecp256k1:load? (lambda (_) 'none)])
           (libsecp256k1-origin)))
       (define maps (if (file-exists? "/proc/self/maps") (file->string "/proc/self/maps") ""))
       (write (list origin (string-contains? maps (path->string (current-directory)))))))

  (test-case "system mode never loads a libsecp256k1 planted in the current directory"
    (when (file-exists? bundled-library)
      (define settings (list (cons "LIBSECP256K1_LIBRARY" "system")
                             (cons "LD_LIBRARY_PATH" #f)
                             (cons "DYLD_LIBRARY_PATH" #f)))
      (define empty (make-temporary-directory))
      (define planted (make-temporary-directory))
      (for ([v (in-list '("7" "6" #f))])
        (copy-file bundled-library
                   (build-path planted (if v (format "~a.~a" library-file-name v) library-file-name))))
      (define without (run-program origin-program settings #:directory empty))
      (define with (run-program origin-program settings #:directory planted))
      (delete-directory/files empty)
      (delete-directory/files planted)
      (check-equal? (cadr with) #f)
      (check-equal? (car with) (car without))))

  (define vector-program
    '(begin
       (require libsecp256k1 file/sha1)
       (define one (integer->secret-key 1))
       (define nonce-sig (ecdsa-sign (sha256-bytes #"Satoshi Nakamoto") one))
       (define digest (hex-string->bytes
                       "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456"))
       (define rsig (ecdsa-sign-recoverable digest one))
       (write (list (libsecp256k1-origin)
                    (ecdsa-signature-r nonce-sig)
                    (bytes->hex-string (ecdsa-signature->compact rsig))
                    (ecdsa-recoverable-signature-id rsig)))))

  (define (expected-vector-values)
    (define nonce (nonce-row-nonce (list-ref (nonce-rows) 2)))
    (define row (car (signing-rows)))
    (list (modulo (bytes->integer (subbytes (public-key->bytes
                                             (secret-key->public-key (bytes->secret-key nonce)))
                                            1))
                  n)
          (hex (signing-row-compact row))
          (signing-row-recovery-id row)))

  (define system-library (getenv "LIBSECP256K1_TEST_SYSTEM_LIB"))

  (cond
    [(not system-library)
     (displayln "SKIPPED system-library tests: LIBSECP256K1_TEST_SYSTEM_LIB is not set")]
    [else
     (define-values (system-dir _name _dir?) (split-path system-library))

     (test-case "a library named by LIBSECP256K1_LIBRARY is used, and reproduces the vectors"
       (check-equal? (run-program vector-program
                                  (list (cons "LIBSECP256K1_LIBRARY" system-library)))
                     (cons 'environment (expected-vector-values))))

     (test-case "LIBSECP256K1_LIBRARY=system uses the system library"
       (check-equal? (run-program vector-program
                                  (list (cons "LIBSECP256K1_LIBRARY" "system")
                                        (cons "LD_LIBRARY_PATH" (path->string system-dir))
                                        (cons "DYLD_LIBRARY_PATH" (path->string system-dir))))
                     (cons 'system (expected-vector-values))))

     (test-case "a real system library is preferred to one planted in the current directory"
       (define planted (make-temporary-directory))
       (copy-file bundled-library (build-path planted (format "~a.7" library-file-name)))
       (define outcome
         (run-program origin-program
                      (list (cons "LIBSECP256K1_LIBRARY" "system")
                            (cons "LD_LIBRARY_PATH" (path->string system-dir))
                            (cons "DYLD_LIBRARY_PATH" (path->string system-dir)))
                      #:directory planted))
       (delete-directory/files planted)
       (check-equal? outcome '(system #f)))]))
