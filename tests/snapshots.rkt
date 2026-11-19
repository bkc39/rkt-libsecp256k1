#lang racket/base

(module+ test
  (require racket/list
           racket/match
           rackunit
           syntax/modread)

  (define byte-parameters '(bs compact der digest tweak))

  (define (module-forms file)
    (match (with-module-reading-parameterization
             (lambda ()
               (call-with-input-file (collection-file-path file "libsecp256k1" "private") read)))
      [`(module ,_ ,_ (#%module-begin ,forms ...)) forms]
      [`(module ,_ ,_ ,forms ...) forms]))

  (define (exported-definitions forms)
    (define exported
      (append-map (lambda (f)
                    (match f
                      [`(provide ,names ...) (filter symbol? names)]
                      [_ '()]))
                  forms))
    (filter (lambda (f)
              (match f
                [`(,(or 'define 'define/snapshot) (,name ,_ ...) ,_ ...) (memq name exported)]
                [_ #f]))
            forms))

  (define (unsnapshotted-byte-parameters form)
    (define-values (name params copied)
      (match form
        [`(define/snapshot (,name ,params ...) #:snapshot (,copied ...) ,_ ...)
         (values name params copied)]
        [`(define (,name ,params ...) ,_ ...) (values name params '())]))
    (for/list ([p (in-list params)]
               #:when (memq p byte-parameters)
               #:unless (memq p copied))
      (list name p)))

  (test-case "every export taking caller bytes copies them on entry"
    (define definitions
      (append-map (lambda (file) (exported-definitions (module-forms file)))
                  '("keys.rkt" "ecdsa.rkt")))
    (check-true (> (length definitions) 20))
    (check-equal? (append-map unsnapshotted-byte-parameters definitions) '())))
