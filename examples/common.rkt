#lang racket/base

(require (for-syntax racket/base)
         racket/pretty
         racket/string
         syntax/macro-testing
         syntax/parse/define)

(provide show
         show-error
         section)

(define (section title)
  (printf "\n;;;; ~a\n\n" title))

(define echo-columns 100)

(define (echo datum)
  (define lines (string-split (pretty-format datum (- echo-columns 2) #:mode 'write) "\n"))
  (printf "> ~a\n" (string-join lines "\n  ")))

(define-syntax-parse-rule (show e:expr)
  (begin
    (echo 'e)
    (call-with-values
     (lambda () e)
     (lambda vs
       (for ([v (in-list vs)]
             #:unless (void? v))
         (pretty-print v))))))

(define (exn-name e)
  (regexp-replace #rx"^struct:" (symbol->string (vector-ref (struct->vector e) 0)) ""))

(define (print-error e)
  (printf "; ~a\n" (exn-name e))
  (for ([line (in-list (string-split (exn-message e) "\n"))]
        #:unless (regexp-match? #px"^\\p{Cc}+$" line))
    (printf "; ~a\n" (regexp-replace #px": …$" (regexp-replace* #px"\\p{Cc}+" line "…") ""))))

(define (call-and-show-error datum thunk)
  (echo datum)
  (define e (with-handlers ([exn:fail? values]) (thunk) #f))
  (unless e
    (error 'show-error "~s raised no exception" datum))
  (print-error e)
  e)

(define-syntax-parse-rule (show-error e:expr (~optional (~seq #:as id:id)))
  (begin
    (~? (define id (call-and-show-error 'e (lambda () (convert-syntax-error e))))
        (void (call-and-show-error 'e (lambda () (convert-syntax-error e)))))))
