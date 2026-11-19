#lang racket/base

(module+ test
  (require (only-in ffi/unsafe ffi-lib)
           (only-in file/sha1 bytes->hex-string)
           json
           racket/file
           racket/list
           (only-in racket/path file-name-from-path find-relative-path simple-form-path)
           (only-in racket/port open-output-nowhere)
           racket/runtime-path
           racket/string
           (only-in racket/system system*)
           rackunit
           libsecp256k1/private/locate)

  (define-runtime-path package-root "..")

  (define candidates-dir (build-path package-root "native-libs" "candidates"))

  (define (file-sha256 path)
    (bytes->hex-string (call-with-input-file path sha256-bytes)))

  (define (read-record name)
    (for/list ([line (in-list (file->lines (build-path candidates-dir name)))]
               #:unless (string=? (string-trim line) ""))
      (define parts (string-split line))
      (cons (second parts) (first parts))))

  (define recorded-sums (read-record "SHA256SUMS"))

  (define recorded-inputs (read-record "BUILD-INPUTS"))

  (define build-inputs
    '("native/upstream.json" "native/build.sh" "native/toolchain.sh" "scripts/build-so.sh"))

  (define inputs-listing
    (for/list ([file (in-list build-inputs)])
      (format "~a  ~a\n" (file-sha256 (build-path package-root file)) file)))

  (define current-inputs
    (bytes->hex-string (sha256-bytes (open-input-string (string-append* inputs-listing)))))

  (define (candidate-files)
    (for*/list ([platform (in-list (directory-list candidates-dir))]
                #:when (directory-exists? (build-path candidates-dir platform))
                [file (in-list (directory-list (build-path candidates-dir platform)))])
      (path->string (build-path platform file))))

  (define (platform-candidate entry)
    (string-append (cadr entry) "/" (caddr entry)))

  (test-case "every platform a library ships for has its candidate, sha256 and build inputs"
    (for ([entry (in-list bundled-platforms)])
      (define file (platform-candidate entry))
      (check-true (file-exists? (build-path candidates-dir file)) file)
      (check-not-false (assoc file recorded-sums) file)
      (check-not-false (assoc file recorded-inputs) file)))

  (test-case "every committed candidate matches native-libs/candidates/SHA256SUMS"
    (check-equal? (sort (candidate-files) string<?) (sort (map car recorded-sums) string<?))
    (for ([row (in-list recorded-sums)])
      (check-equal? (file-sha256 (build-path candidates-dir (car row))) (cdr row) (car row))))

  (test-case "candidates exist only for the platforms a library ships for"
    (check-equal? (remove* (map platform-candidate bundled-platforms) (candidate-files)) '()))

  (test-case "scripts/record-build-inputs.sh hashes the files this test hashes"
    (define script (file->string (build-path package-root "scripts" "record-build-inputs.sh")))
    (check-equal? (map string-split (regexp-match* #px"\nfiles=\\(([^)]*)\\)" script
                                                   #:match-select cadr))
                  (list build-inputs)))

  (test-case "every candidate was built from the current pin, compile line, toolchain and script"
    (check-equal? (sort (map car recorded-inputs) string<?) (sort (map car recorded-sums) string<?))
    (for ([row (in-list recorded-inputs)])
      (check-equal? (cdr row) current-inputs (car row))))

  (define (exported-symbols-missing path)
    (missing-symbols (ffi-lib path '())))

  (test-case "the host's candidate exports every required symbol"
    (define entry (bundled-platform host-platform))
    (when entry
      (check-equal? (exported-symbols-missing (build-path candidates-dir (platform-candidate entry)))
                    '())))

  (test-case "the staged bundled library exports every required symbol"
    (when (file-exists? bundled-library)
      (check-equal? (exported-symbols-missing bundled-library) '())))

  (define upstream (call-with-input-file (build-path package-root "native" "upstream.json") read-json))

  (test-case "the README and the manual name the pinned upstream version"
    (for ([doc (in-list '("README.md" "scribblings/libsecp256k1.scrbl"))])
      (check-equal? (regexp-match* #px"prebuilt\\s+libsecp256k1\\s+([0-9.]+[0-9])"
                                   (file->string (build-path package-root doc))
                                   #:match-select cadr)
                    (list (hash-ref upstream 'version))
                    doc)))

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
    (check-equal? (filter (lambda (f) (regexp-match? #rx"[.][ch]$" f)) files) '()))

  (define git (find-executable-path "git"))

  (define (git-output . args)
    (define out (open-output-string))
    (define ok?
      (parameterize ([current-output-port out]
                     [current-error-port (open-output-nowhere)])
        (apply system* git "-C" (path->string package-root) args)))
    (and ok? (get-output-string out)))

  (cond
    [(not (and git (equal? (git-output "rev-parse" "--show-prefix") "\n")))
     (displayln "SKIPPED checkout attribute test: the package is not the root of a git checkout")]
    [else
     (test-case "no checkout rewrites the line endings of a hashed or recorded file"
       (define files (append build-inputs
                             '("scripts/record-build-inputs.sh"
                               "native-libs/candidates/SHA256SUMS"
                               "native-libs/candidates/BUILD-INPUTS")
                             (map (lambda (f) (string-append "native-libs/candidates/" f))
                                  (map car recorded-sums))))
       (check-equal? (apply git-output "check-attr" "text" "--" files)
                     (string-append* (for/list ([f (in-list files)])
                                       (format "~a: text: unset\n" f)))))]))
