#lang racket/base

(module+ test
  (require racket/file
           racket/match
           racket/port
           (only-in racket/string string-prefix?)
           racket/system
           rackunit
           (only-in setup/dirs get-lib-search-dirs)
           libsecp256k1
           libsecp256k1/private/locate
           "helpers/util.rkt"
           "helpers/vectors.rkt")

  (define (run-program program settings #:directory [directory (current-directory)])
    (define out
      (parameterize ([current-environment-variables (environment-with settings)]
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

  (define so-suffix (bytes->string/utf-8 (system-type 'so-suffix)))

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

  (define no-library-hint
    (string-append "  set LIBSECP256K1_LIBRARY to a libsecp256k1 file, or install libsecp256k1"
                   " 0.2 or later with the recovery module"))

  (test-case "a missing file is reported as missing, with what to do"
    (check-equal? (load-message missing-library)
                  (string-append "libsecp256k1: no usable libsecp256k1 library\n"
                                 "  environment: " missing-library ": no such file\n"
                                 no-library-hint)))

  (define (write-garbage! path)
    (call-with-output-file path #:exists 'truncate (lambda (out) (write-string "garbage" out))))

  (test-case "a file that is not a library is reported with the loader's reason"
    (define garbage (make-temporary-file (string-append "libsecp256k1-garbage-~a" so-suffix)))
    (write-garbage! garbage)
    (define message (load-message (path->string garbage)))
    (delete-file garbage)
    (match (regexp-match #rx"^([^\n]*)\n  environment: ([^\n]*)\n([^\n]*)$" message)
      [(list _ head reason hint)
       (check-equal? head "libsecp256k1: no usable libsecp256k1 library")
       (check-equal? hint no-library-hint)
       (define label (string-append (path->string garbage) ": "))
       (check-true (string-prefix? reason label) reason)
       (define loader-reason (substring reason (min (string-length label) (string-length reason))))
       (check-regexp-match #rx"[a-zA-Z]" loader-reason)
       (check-false (regexp-match? #rx"tried:|[Nn]o such file" loader-reason) loader-reason)]
      [_ (fail (format "unexpected message: ~a" message))]))

  (test-case "dyld's list of attempted paths is cut to the first attempt"
    (define (reason system-error label)
      (load-error-reason
       (exn:fail (string-append "ffi-lib: could not load foreign library\n  path: " label
                                "\n  system error: " system-error)
                 (current-continuation-marks))
       label))
    (check-equal? (reason (string-append "dlopen(/x/l.dylib, 0x0006): tried: '/x/l.dylib' (not a"
                                         " mach-o file), '/System/Volumes/Preboot/Cryptexes/OS/x/"
                                         "l.dylib' (no such file), '/x/l.dylib' (not a mach-o file)")
                          "/x/l.dylib")
                  "not a mach-o file")
    (check-equal? (reason (string-append "dlopen(/x/l.dylib, 0x0006): tried: '/x/l.dylib' (mach-o"
                                         " file, but is an incompatible architecture (have 'x86_64',"
                                         " need 'arm64e')), '/y/l.dylib' (no such file)")
                          "/x/l.dylib")
                  "mach-o file, but is an incompatible architecture (have 'x86_64', need 'arm64e')")
    (check-equal? (reason "dlopen(/x/l.dylib, 0x0006): tried: '/d/l.dylib' (not a mach-o file)"
                          "/x/l.dylib")
                  "/d/l.dylib: not a mach-o file")
    (check-equal? (reason "/x/l.so: file too short" "/x/l.so") "file too short"))

  (test-case "an override path is loaded as named, without the platform suffix appended"
    (when (file-exists? bundled-library)
      (define dir (make-temporary-directory))
      (define named (build-path dir "libsecp256k1-copy"))
      (write-garbage! named)
      (copy-file bundled-library (build-path dir (string-append "libsecp256k1-copy" so-suffix)))
      (define-values (origin _lib failure) (locate-library (path->string named)))
      (delete-directory/files dir)
      (check-false origin)
      (check-regexp-match (regexp (string-append "\n  environment: "
                                                 (regexp-quote (path->string named)) ": "))
                          (if failure (exn-message failure) ""))))

  (define override-program
    '(begin
       (require libsecp256k1)
       (write (with-handlers ([exn:fail:libsecp256k1:load? exn-message])
                (libsecp256k1-origin)))))

  (test-case "a relative override is the file in the current directory, never a search"
    (when (file-exists? bundled-library)
      (define elsewhere (make-temporary-directory))
      (define here (make-temporary-directory))
      (copy-file bundled-library (build-path elsewhere library-file-name))
      (define outcome
        (run-program override-program
                     (list (cons "LIBSECP256K1_LIBRARY" library-file-name)
                           (cons "LD_LIBRARY_PATH" (path->string elsewhere))
                           (cons "DYLD_LIBRARY_PATH" (path->string elsewhere)))
                     #:directory here))
      (define-values (_base here-name _dir?) (split-path here))
      (delete-directory/files elsewhere)
      (delete-directory/files here)
      (check-regexp-match (regexp (string-append "\n  environment: /[^\n]*/"
                                                 (regexp-quote (path->string here-name)) "/"
                                                 (regexp-quote library-file-name)
                                                 ": no such file\n"))
                          (if (string? outcome) outcome (format "~s" outcome)))))

  (test-case "probes run in a directory only the user can open"
    (with-temporary-directory dir
      (check-equal? (bitwise-and (file-or-directory-permissions dir 'bits) #o077) 0)))

  (define (missing-bundled-message platform)
    (define-values (_origin _lib failure)
      (locate-library #f #:bundled (string->path missing-library) #:system '() #:platform platform))
    (exn-message failure))

  (test-case "a bundled library missing on a platform that ships one asks for raco setup first"
    (define message (missing-bundled-message "x86_64-linux"))
    (check-regexp-match (regexp (string-append "\n  bundled: " (regexp-quote missing-library)
                                               ": not installed\n"))
                        message)
    (check-regexp-match #rx"\n  run raco setup libsecp256k1, set LIBSECP256K1_LIBRARY[^\n]*$"
                        message))

  (test-case "a natipkg build of Racket is its platform: a missing library asks for raco setup"
    (check-regexp-match #rx"\n  run raco setup libsecp256k1, "
                        (missing-bundled-message "x86_64-linux-natipkg")))

  (test-case "on a platform without a bundled library the error names the platforms that ship one"
    (define message (missing-bundled-message "riscv64-linux"))
    (check-regexp-match (string-append "\n  bundled: none for riscv64-linux"
                                       " [(]shipped for x86_64-linux and aarch64-macosx only[)]\n")
                        message)
    (check-regexp-match (string-append "\n" (regexp-quote no-library-hint) "$") message))

  (define (macos-search-dirs settings)
    (parameterize ([current-environment-variables (environment-with settings)])
      (map path->string (system-search-dirs 'macosx))))

  (define racket-lib-dirs (map path->string (get-lib-search-dirs)))

  (test-case "on macOS a system library is searched for in the DYLD paths, then Homebrew's"
    (check-equal? (macos-search-dirs '(("DYLD_LIBRARY_PATH" . "/a:relative:/b")
                                       ("DYLD_FALLBACK_LIBRARY_PATH" . #f)))
                  (append racket-lib-dirs
                          '("/a" "/b" "/opt/homebrew/lib" "/usr/local/lib" "/usr/lib"))))

  (test-case "on macOS DYLD_FALLBACK_LIBRARY_PATH replaces the default directories"
    (check-equal? (macos-search-dirs '(("DYLD_LIBRARY_PATH" . #f)
                                       ("DYLD_FALLBACK_LIBRARY_PATH" . "/f")))
                  (append racket-lib-dirs '("/f"))))

  (define missing-symbols-program
    '(begin
       (require ffi/unsafe libsecp256k1/private/locate)
       (define missing (missing-symbols (ffi-lib #f)))
       (write (list (and (member "secp256k1_ecdsa_recover" missing) #t)
                    (and (member "secp256k1_selftest" missing) #t)
                    (missing-reason missing)))))

  (test-case "a library with none of the symbols is not a libsecp256k1 library"
    (check-equal? (run-program missing-symbols-program '())
                  '(#t #t "not a libsecp256k1 library")))

  (test-case "a library without the recovery module is refused with that reason"
    (check-equal? (missing-reason '("secp256k1_ecdsa_recover"
                                    "secp256k1_ecdsa_recoverable_signature_parse_compact"))
                  "lacks secp256k1_ecdsa_recover (built without the recovery module)")
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
