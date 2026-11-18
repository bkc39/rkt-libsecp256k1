#lang racket/base

(module+ test
  (require (only-in ffi/unsafe ffi-lib)
           (only-in file/sha1 bytes->hex-string)
           json
           racket/file
           racket/list
           (only-in racket/path file-name-from-path find-relative-path simple-form-path)
           racket/runtime-path
           racket/string
           rackunit
           libsecp256k1/private/locate)

  (define-runtime-path package-root "..")

  (define candidates-dir (build-path package-root "native-libs" "candidates"))

  (define (file-sha256 path)
    (bytes->hex-string (call-with-input-file path sha256-bytes)))

  (define recorded-sums
    (for/list ([line (in-list (file->lines (build-path candidates-dir "SHA256SUMS")))]
               #:unless (string=? (string-trim line) ""))
      (define parts (string-split line))
      (cons (second parts) (first parts))))

  (define (candidate-files)
    (for*/list ([platform (in-list (directory-list candidates-dir))]
                #:when (directory-exists? (build-path candidates-dir platform))
                [file (in-list (directory-list (build-path candidates-dir platform)))])
      (path->string (build-path platform file))))

  (define (platform-candidate entry)
    (string-append (cadr entry) "/" (caddr entry)))

  (test-case "every committed candidate matches native-libs/candidates/SHA256SUMS"
    (check-not-false (assoc "linux/libsecp256k1.so" recorded-sums))
    (check-equal? (sort (candidate-files) string<?) (sort (map car recorded-sums) string<?))
    (for ([row (in-list recorded-sums)])
      (check-equal? (file-sha256 (build-path candidates-dir (car row))) (cdr row) (car row))))

  (test-case "candidates exist only for the platforms a library ships for"
    (check-equal? (remove* (map platform-candidate bundled-platforms) (candidate-files)) '()))

  (for ([entry (in-list bundled-platforms)]
        #:unless (file-exists? (build-path candidates-dir (platform-candidate entry))))
    (printf "SKIPPED ~a candidate: native-libs/candidates/~a is not committed\n"
            (car entry) (platform-candidate entry)))

  (define (exported-symbols-missing path)
    (missing-symbols (ffi-lib path '())))

  (test-case "the host's candidate exports every required symbol"
    (define entry (bundled-platform host-platform))
    (define path (and entry (build-path candidates-dir (cadr entry) (caddr entry))))
    (when (and path (file-exists? path))
      (check-equal? (exported-symbols-missing path) '())))

  (test-case "the staged bundled library exports every required symbol"
    (when (file-exists? bundled-library)
      (check-equal? (exported-symbols-missing bundled-library) '())))

  (define upstream (call-with-input-file (build-path package-root "native" "upstream.json") read-json))

  (test-case "the pinned upstream source is libsecp256k1 0.8.0's release tarball"
    (check-equal? (hash-ref upstream 'version) "0.8.0")
    (check-equal? (hash-ref upstream 'url)
                  "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.8.0.tar.gz")
    (check-equal? (hash-ref upstream 'sha256)
                  "eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb"))

  (test-case "the shipped binaries carry upstream's MIT notice"
    (define notice (build-path package-root "native-libs" "LICENSE.libsecp256k1"))
    (check-equal? (file-sha256 notice)
                  "a735999c7e5649df6fcda6fb06ab97435851c392b1b93494ae8725f37441632f")
    (check-regexp-match #rx"Permission is hereby granted" (file->string notice)))

  (define (package-files)
    (for/list ([p (in-directory package-root
                                (lambda (dir)
                                  (not (member (path->string (file-name-from-path dir))
                                               '(".git" "compiled" "doc" ".direnv" "result")))))]
               #:when (file-exists? p))
      (path->string (find-relative-path (simple-form-path package-root) (simple-form-path p)))))

  (test-case "the package holds no C source or header"
    (define files (package-files))
    (check-not-false (member "native/build.sh" files))
    (check-equal? (filter (lambda (f) (regexp-match? #rx"[.][ch]$" f)) files) '())))
