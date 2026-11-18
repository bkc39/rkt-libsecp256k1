#lang racket/base

(module+ test
  (require racket/list
           racket/match
           racket/port
           racket/runtime-path
           racket/string
           rackunit
           libsecp256k1
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
    (for ([r (in-list (map row->recorded (cdr section)))])
      (test-case (format "manual, ~a: ~s prints its recorded result" (car section) (recorded-form r))
        (check-equal? (outcome ns (recorded-form r)) (recorded-expected r)))))

  (define readme-example
    (match (regexp-match #rx"```racket\n(.*?)```" (call-with-input-file readme port->string))
      [(list _ code) (with-input-from-string code (lambda () (port->list read)))]))

  (test-case "README: the example's commented results are what it returns"
    (define readme-ns (example-namespace))
    (define results
      (for/list ([form (in-list readme-example)])
        (outcome readme-ns form)))
    (check-equal? (filter values results) '("#t"))))
