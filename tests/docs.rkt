#lang racket/base

(module+ test
  (require (only-in racket/file delete-directory/files file->string make-temporary-directory)
           racket/list
           racket/match
           racket/port
           racket/runtime-path
           racket/string
           (only-in racket/system process*/ports)
           rackunit
           libsecp256k1
           (only-in "helpers/util.rkt" environment-with racket-path)
           "../scribblings/recorded.rkt")

  (define-runtime-path readme "../README.md")

  (define-namespace-anchor anchor)

  (define (example-namespace)
    (define ns (namespace-anchor->empty-namespace anchor))
    (parameterize ([current-namespace ns])
      (namespace-require 'racket/base)
      (namespace-require 'libsecp256k1)
      (namespace-require 'file/sha1))
    ns)

  (struct recorded (form expected))

  (define (row->recorded row)
    (match row
      [(list form) (recorded form #f)]
      [(list form (list 'error message)) (recorded form (list 'error message))]
      [(list form (? string? printed)) (recorded form printed)]
      [(list form (list (? string? parts) ...)) (recorded form (string-append* parts))]))

  (define (outcome ns form)
    (parameterize ([current-namespace ns])
      (with-handlers ([exn:fail? (lambda (e) (list 'error (exn-message e)))])
        (call-with-values
         (lambda () (eval form))
         (case-lambda
           [() #f]
           [(v) (and (not (void? v)) (with-output-to-string (lambda () (print v))))])))))

  (define-runtime-path scribblings "../scribblings")

  (define use-pattern #px"@(include-section|recorded-examples)\\[\"?([^]\"]+)")

  (define (recorded-uses file)
    (define text (call-with-input-file (build-path scribblings file) port->string))
    (append*
     (for/list ([use (in-list (regexp-match* use-pattern text #:match-select cdr))])
       (match use
         [(list "include-section" included) (recorded-uses included)]
         [(list "recorded-examples" key) (list (string->symbol key))]))))

  (test-case "the manual shows every recorded block once, in the order they are checked here"
    (check-equal? (recorded-uses "libsecp256k1.scrbl")
                  (map car (syntax->datum manual-examples))))

  (define ns (example-namespace))

  (for ([section (in-list (syntax->datum manual-examples))])
    (match-define (cons name rows) section)
    (for ([r (in-list (map row->recorded rows))])
      (test-case (format "manual, ~a: ~s prints its recorded result" name (recorded-form r))
        (check-equal? (outcome ns (recorded-form r)) (recorded-expected r)))))

  (define-runtime-path manual "../scribblings/libsecp256k1.scrbl")

  (define (build-manual dest settings)
    (define err (open-output-string))
    (match-define (list _ _ _ _ control)
      (parameterize ([current-environment-variables (environment-with settings)])
        (process*/ports (open-output-nowhere) (open-input-bytes #"") err
                        racket-path "-l-" "raco" "scribble" "--html"
                        "--dest" (path->string dest) (path->string manual))))
    (define finished (sync/timeout 90 (thread (lambda () (control 'wait)))))
    (cond
      [finished (values (control 'exit-code) (get-output-string err))]
      [else (control 'kill) (values 'timeout (get-output-string err))]))

  (define (manual-text settings)
    (define dest (make-temporary-directory))
    (define-values (status err) (build-manual dest settings))
    (define html (build-path dest "libsecp256k1.html"))
    (define text
      (and (file-exists? html)
           (string-normalize-spaces (regexp-replace* #rx"<[^>]*>" (file->string html) " "))))
    (delete-directory/files dest)
    (values status err text))

  (test-case "the manual builds without a C library and shows the text it shows with one"
    (define-values (live-status live-err live) (manual-text '()))
    (define-values (offline-status offline-err offline)
      (manual-text (list (cons "LIBSECP256K1_LIBRARY" "/nonexistent/libsecp256k1.so"))))
    (check-equal? live-status 0 live-err)
    (check-equal? offline-status 0 offline-err)
    (check-regexp-match #rx"#&lt;secret-key&gt;" offline)
    (check-regexp-match #rx"the value is zero or not less than the curve order" offline)
    (check-equal? offline live))

  (define readme-example
    (match (regexp-match #rx"```racket\n(.*?)```" (call-with-input-file readme port->string))
      [(list _ code) (with-input-from-string code (lambda () (port->list read)))]))

  (test-case "README: the example's commented results are what it returns"
    (define readme-ns (example-namespace))
    (define results
      (for/list ([form (in-list readme-example)])
        (outcome readme-ns form)))
    (check-equal? (filter values results) '("#t"))))
