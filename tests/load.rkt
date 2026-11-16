#lang racket/base

(module+ test
  (require racket/port
           racket/system
           rackunit
           libsecp256k1
           libsecp256k1/private/locate
           "util.rkt"
           "vectors.rkt")

  (define racket-path
    (let ([exe (find-system-path 'exec-file)])
      (if (absolute-path? exe) exe (find-executable-path exe))))

  ;; The datum a subprocess writes, run with the environment variables
  ;; `settings` added; the variable is read when the library is instantiated.
  (define (run-program program settings)
    (define env (environment-variables-copy (current-environment-variables)))
    (for ([s (in-list settings)])
      (environment-variables-set! env (string->bytes/utf-8 (car s)) (string->bytes/utf-8 (cdr s))))
    (define out
      (parameterize ([current-environment-variables env])
        (with-output-to-string
          (lambda ()
            (system* racket-path "-l" "racket/base" "-e" (format "~s" program))))))
    (with-handlers ([exn:fail:read? (lambda (_) out)])
      (read (open-input-string out))))

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

  (define vector-program
    '(begin
       (require libsecp256k1 file/sha1)
       (define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
       (define nonce-sig (ecdsa-sign (sha256-bytes #"Satoshi Nakamoto") one))
       (define digest (hex-string->bytes
                       "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456"))
       (define rsig (ecdsa-sign-recoverable digest one))
       (write (list (libsecp256k1-origin)
                    (ecdsa-signature-r nonce-sig)
                    (bytes->hex-string (ecdsa-signature->compact rsig))
                    (ecdsa-recoverable-signature-recovery-id rsig)))))

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
     (displayln "skipping system-library tests: LIBSECP256K1_TEST_SYSTEM_LIB is not set")]
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
                     (cons 'system (expected-vector-values))))]))
