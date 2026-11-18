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

  (define (stage root #:platform platform #:native-dir [native-dir #f])
    (define result (box #f))
    (define output
      (with-output-to-string
        (lambda ()
          (set-box! result (stage-library! root #:platform platform #:native-dir native-dir)))))
    (staging (unbox result) output))

  (test-case "on x86_64 Linux the linux candidate is staged, silently"
    (with-temporary-directory root
      (make-root! root)
      (define run (stage root #:platform "x86_64-linux"))
      (check-eq? (staging-result run) 'candidate)
      (check-equal? (staging-output run) "")
      (check-equal? (staged root "libsecp256k1.so") "linux candidate")
      (check-false (staged root "libsecp256k1.dylib"))))

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

  (test-case "a copy of the package without its platform's candidate says so"
    (with-temporary-directory root
      (write-file! (build-path root "native-libs" "candidates" "linux" "libsecp256k1.so") "linux")
      (define run (stage root #:platform "aarch64-macosx"))
      (check-eq? (staging-result run) 'none)
      (check-regexp-match (string-append "^libsecp256k1: this copy of the package lacks the"
                                         " bundled library for aarch64-macosx; ")
                          (staging-output run))))

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
      (define native (build-path root "native"))
      (write-file! (build-path native "lib" library-file-name) "native build")
      (define run (stage root #:platform "riscv64-linux" #:native-dir native))
      (check-eq? (staging-result run) 'environment)
      (check-equal? (staged root library-file-name) "native build")))

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
      (check-regexp-match #rx"^libsecp256k1: could not install the bundled library: "
                          (staging-output run))
      (check-equal? (sort (map path->string (directory-list (build-path root "native-libs")))
                          string<?)
                    '("candidates" "libsecp256k1.so"))))

  (test-case "the pre-installer reports a failure instead of raising"
    (with-temporary-directory root
      (define output (box #f))
      (check-not-exn (lambda ()
                       (set-box! output (with-output-to-string (lambda () (pre-installer root ""))))))
      (check-regexp-match #rx"^libsecp256k1: " (unbox output))
      (check-not-exn (lambda ()
                       (with-output-to-string
                         (lambda () (pre-installer root (build-path root "missing") #t)))))))

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
