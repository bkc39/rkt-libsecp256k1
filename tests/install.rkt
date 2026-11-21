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

  (define (write-file! path text)
    (define-values (dir _name _dir?) (split-path path))
    (make-directory* dir)
    (call-with-output-file path #:exists 'truncate/replace
      (lambda (out) (write-string text out))))

  (define (make-root! root)
    (write-file! (build-path root "native-libs" "candidates" "linux" "libsecp256k1.so")
                 "linux candidate")
    (write-file! (build-path root "native-libs" "candidates" "darwin" "libsecp256k1.dylib")
                 "darwin candidate"))

  (define (staged root name)
    (define path (build-path root "native-libs" name))
    (and (file-exists? path) (file->string path)))

  (struct staging (result output))

  (define (stage root
                 #:platform platform
                 #:native-dir [native-dir #f]
                 #:so-suffix [so-suffix (bytes->string/utf-8 (system-type 'so-suffix))]
                 #:validate? [validate? #f])
    (define result (box #f))
    (define output
      (with-output-to-string
        (lambda ()
          (set-box! result (stage-library! root
                                           #:platform platform
                                           #:native-dir native-dir
                                           #:so-suffix so-suffix
                                           #:validate? validate?)))))
    (staging (unbox result) output))

  (define (native-dir-with! root file-name text)
    (define native (build-path root "native"))
    (write-file! (build-path native "lib" file-name) text)
    native)

  (test-case "on x86_64 Linux the linux candidate is staged, silently"
    (with-temporary-directory root
      (make-root! root)
      (define run (stage root #:platform "x86_64-linux"))
      (check-eq? (staging-result run) 'candidate)
      (check-equal? (staging-output run) "")
      (check-equal? (staged root "libsecp256k1.so") "linux candidate")
      (check-false (staged root "libsecp256k1.dylib"))))

  (test-case "a natipkg build of Racket stages its platform's candidate, silently"
    (with-temporary-directory root
      (make-root! root)
      (define run (stage root #:platform "x86_64-linux-natipkg"))
      (check-eq? (staging-result run) 'candidate)
      (check-equal? (staging-output run) "")
      (check-equal? (staged root "libsecp256k1.so") "linux candidate")))

  (test-case "on Apple-silicon macOS the darwin candidate is staged"
    (with-temporary-directory root
      (make-root! root)
      (check-eq? (staging-result (stage root #:platform "aarch64-macosx")) 'candidate)
      (check-equal? (staged root "libsecp256k1.dylib") "darwin candidate")
      (check-false (staged root "libsecp256k1.so"))))

  (test-case "a platform without a bundled library stages nothing and says what to do"
    (for ([platform (in-list '("aarch64-linux" "x86_64-macosx" "win32\\x86_64"))])
      (with-temporary-directory root
        (make-root! root)
        (define run (stage root #:platform platform))
        (check-eq? (staging-result run) 'none platform)
        (check-equal? (staging-output run)
                      (string-append
                       "libsecp256k1: no bundled library for " platform
                       " (shipped for x86_64-linux and aarch64-macosx only); install libsecp256k1"
                       " 0.2 or later with the recovery module, or set LIBSECP256K1_LIBRARY to a"
                       " libsecp256k1 file\n"))
        (check-equal? (directory-list (build-path root "native-libs"))
                      (list (string->path "candidates"))))))

  (test-case "a shipped platform's missing candidate fails with its path and the system error"
    (with-temporary-directory root
      (write-file! (build-path root "native-libs" "candidates" "linux" "libsecp256k1.so") "linux")
      (define run (stage root #:platform "aarch64-macosx"))
      (check-eq? (staging-result run) 'failed)
      (check-equal? (staging-output run)
                    (format (string-append "libsecp256k1: could not install ~a as ~a: copy-file:"
                                           " cannot open source file (system error: ~a)\n")
                            (build-path root "native-libs" "candidates" "darwin"
                                        "libsecp256k1.dylib")
                            (build-path root "native-libs" "libsecp256k1.dylib")
                            "No such file or directory; errno=2"))))

  (test-case "a read-only source is staged as an ordinary 755 file"
    (with-temporary-directory root
      (make-root! root)
      (define candidate (build-path root "native-libs" "candidates" "linux" "libsecp256k1.so"))
      (file-or-directory-permissions candidate #o444)
      (stage root #:platform "x86_64-linux")
      (check-equal? (file-or-directory-permissions (build-path root "native-libs" "libsecp256k1.so")
                                                   'bits)
                    #o755)))

  (test-case "staging twice leaves the staged file in place"
    (with-temporary-directory root
      (make-root! root)
      (stage root #:platform "x86_64-linux")
      (define path (build-path root "native-libs" "libsecp256k1.so"))
      (define identity (file-or-directory-identity path))
      (check-eq? (staging-result (stage root #:platform "x86_64-linux")) 'candidate)
      (check-equal? (file-or-directory-identity path) identity)
      (check-equal? (staged root "libsecp256k1.so") "linux candidate")))

  (test-case "a changed candidate replaces the staged file"
    (with-temporary-directory root
      (make-root! root)
      (stage root #:platform "x86_64-linux")
      (write-file! (build-path root "native-libs" "candidates" "linux" "libsecp256k1.so") "newer")
      (stage root #:platform "x86_64-linux")
      (check-equal? (staged root "libsecp256k1.so") "newer")
      (check-equal? (length (directory-list (build-path root "native-libs"))) 2)))

  (test-case "a library already staged on a platform without a candidate is kept"
    (with-temporary-directory root
      (write-file! (build-path root "native-libs" library-file-name) "built by hand")
      (check-eq? (staging-result (stage root #:platform "riscv64-linux")) 'staged)
      (check-equal? (staged root library-file-name) "built by hand")))

  (test-case "LIBSECP256K1_NATIVE_LIB_PATH's library is staged in place of the candidate"
    (with-temporary-directory root
      (make-root! root)
      (define native (native-dir-with! root "libsecp256k1.so" "native build"))
      (define run (stage root #:platform "x86_64-linux" #:native-dir native))
      (check-eq? (staging-result run) 'environment)
      (check-equal? (staging-output run) "")
      (check-equal? (staged root "libsecp256k1.so") "native build")))

  (test-case "a LIBSECP256K1_NATIVE_LIB_PATH library that cannot be loaded is not staged"
    (with-temporary-directory root
      (make-root! root)
      (define native (native-dir-with! root "libsecp256k1.so" "native build"))
      (define run (stage root #:platform "x86_64-linux" #:native-dir native #:validate? #t))
      (check-eq? (staging-result run) 'candidate)
      (check-regexp-match (regexp (string-append
                                   "^libsecp256k1: not installing LIBSECP256K1_NATIVE_LIB_PATH: "
                                   (regexp-quote (path->string (build-path native "lib"
                                                                           "libsecp256k1.so")))
                                   ": [^\n]+\n$"))
                          (staging-output run))
      (check-equal? (staged root "libsecp256k1.so") "linux candidate")))

  (define loaded-libc
    (and (file-exists? "/proc/self/maps")
         (call-with-input-file "/proc/self/maps"
           (lambda (in)
             (for/first ([line (in-lines in)]
                         #:when (regexp-match? #rx" /[^ ]*/libc[.]so[.]6$" line))
               (cadr (regexp-match #rx" (/[^ ]*)$" line)))))))

  (cond
    [(not loaded-libc)
     (displayln "SKIPPED loadable non-libsecp256k1 library test: no /proc/self/maps libc")]
    [else
     (test-case "a LIBSECP256K1_NATIVE_LIB_PATH library that is not libsecp256k1 is not staged"
       (with-temporary-directory root
         (make-root! root)
         (define native (build-path root "native"))
         (make-directory* (build-path native "lib"))
         (define link (build-path native "lib" "libsecp256k1.so"))
         ;; A link to the libc this process has mapped, so dlopen returns it, not a second libc.
         (make-file-or-directory-link loaded-libc link)
         (define run (stage root #:platform "x86_64-linux" #:native-dir native #:validate? #t))
         (check-eq? (staging-result run) 'candidate)
         (check-equal? (staging-output run)
                       (format (string-append "libsecp256k1: not installing"
                                              " LIBSECP256K1_NATIVE_LIB_PATH: ~a:"
                                              " not a libsecp256k1 library\n")
                               link))
         (check-equal? (staged root "libsecp256k1.so") "linux candidate")))])

  (define host-library
    (for/first ([path (in-list (list bundled-library
                                     (let ([entry (bundled-platform host-platform)])
                                       (and entry
                                            (build-path package-root "native-libs" "candidates"
                                                        (cadr entry) (caddr entry))))))]
                #:when (and path (file-exists? path)))
      path))

  (cond
    [(not host-library)
     (displayln "SKIPPED usable LIBSECP256K1_NATIVE_LIB_PATH test: no library for this host")]
    [else
     (test-case "a LIBSECP256K1_NATIVE_LIB_PATH library the host loads is checked and staged"
       (with-temporary-directory root
         (define-values (_dir file-name _dir?) (split-path host-library))
         (define native (build-path root "native"))
         (make-directory* (build-path native "lib"))
         (copy-file host-library (build-path native "lib" file-name))
         (define run (stage root #:platform host-platform #:native-dir native #:validate? #t))
         (check-eq? (staging-result run) 'environment)
         (check-equal? (staging-output run) "")
         (check-equal? (file->bytes (build-path root "native-libs" file-name))
                       (file->bytes host-library))))])

  (test-case "only a library for the host's own platform is loaded before it is staged"
    (check-true (validate-on-host? host-platform))
    (check-false (validate-on-host? (string-append "not-" host-platform))))

  (test-case "a platform without a bundled library stages the target's file, not the host's"
    (with-temporary-directory root
      (make-root! root)
      (define native (native-dir-with! root "libsecp256k1.dll" "windows build"))
      (define run (stage root #:platform "win32\\x86_64" #:so-suffix ".dll" #:native-dir native))
      (check-eq? (staging-result run) 'environment)
      (check-equal? (staged root "libsecp256k1.dll") "windows build")
      (check-false (staged root library-file-name))))

  (test-case "a LIBSECP256K1_NATIVE_LIB_PATH without the library falls back to the candidate"
    (with-temporary-directory root
      (make-root! root)
      (define run (stage root #:platform "x86_64-linux" #:native-dir (build-path root "nowhere")))
      (check-eq? (staging-result run) 'candidate)
      (check-regexp-match #rx"^libsecp256k1: LIBSECP256K1_NATIVE_LIB_PATH has no [^\n]*/nowhere/"
                          (staging-output run))))

  (test-case "an empty LIBSECP256K1_NATIVE_LIB_PATH is unset"
    (with-temporary-directory root
      (make-root! root)
      (define run (stage root #:platform "x86_64-linux" #:native-dir ""))
      (check-eq? (staging-result run) 'candidate)
      (check-equal? (staging-output run) "")))

  (test-case "a copy that fails is reported, not raised"
    (with-temporary-directory root
      (make-root! root)
      (write-file! (build-path root "native-libs" "libsecp256k1.so" "occupied") "")
      (define run (stage root #:platform "x86_64-linux"))
      (check-eq? (staging-result run) 'failed)
      (check-equal? (staging-output run)
                    (format (string-append "libsecp256k1: could not install ~a as ~a:"
                                           " rename-file-or-directory: cannot rename file or"
                                           " directory (system error: ~a)\n")
                            (build-path root "native-libs" "candidates" "linux"
                                        "libsecp256k1.so")
                            (build-path root "native-libs" "libsecp256k1.so")
                            "Is a directory; errno=21"))
      (check-equal? (sort (map path->string (directory-list (build-path root "native-libs")))
                          string<?)
                    '("candidates" "libsecp256k1.so"))))

  (test-case "the pre-installer prints an error staging raises, and returns"
    (define env (environment-variables-copy (current-environment-variables)))
    (environment-variables-set! env #"LIBSECP256K1_NATIVE_LIB_PATH" #f)
    (define result (box 'unset))
    (define output
      (parameterize ([current-environment-variables env])
        (with-output-to-string (lambda () (set-box! result (pre-installer "" ""))))))
    (check-equal? (unbox result) (void))
    (check-regexp-match #rx"^libsecp256k1: build-path: contract violation\n$" output))

  (test-case "the installed package's staged library is its source's"
    (define native-dir (getenv "LIBSECP256K1_NATIVE_LIB_PATH"))
    (define entry (bundled-platform host-platform))
    (define source
      (cond
        [native-dir (build-path native-dir "lib" library-file-name)]
        [entry (build-path package-root "native-libs" "candidates" (cadr entry) (caddr entry))]
        [else #f]))
    (when (and source
               (file-exists? source)
               (not (getenv "LIBSECP256K1_LIBRARY"))
               (eq? (libsecp256k1-origin) 'bundled))
      (check-equal? (file->bytes bundled-library) (file->bytes source)))))
