#lang racket/base

(require (for-syntax racket/base
                     racket/string
                     syntax/parse
                     syntax/strip-context
                     "recorded.rkt")
         (only-in scribble/example examples make-base-eval)
         (only-in scribble/manual racketresultfont)
         libsecp256k1)

(provide recorded-examples)

(define secp-eval (make-base-eval '(require libsecp256k1 file/sha1)))

(define live?
  (with-handlers ([exn:fail:libsecp256k1:load? (lambda (_) #f)])
    (and (libsecp256k1-origin) #t)))

(begin-for-syntax
  (define-syntax-class printed
    #:description "a printed result: a string, or a list of strings to join"
    (pattern text:str)
    (pattern (part:str ...)
             #:with text (datum->syntax #'(part ...)
                                        (string-append* (map syntax-e
                                                             (syntax->list #'(part ...)))))))

  (define-syntax-class recorded-row
    #:description "a recorded example: [form], [form printed] or [form (error message)]"
    #:datum-literals (error)
    (pattern [form]
             #:with live #'form
             #:with recorded #'(eval:alts form (eval:results null)))
    (pattern [form (error message:str)]
             #:with live #'(eval:error form)
             #:with recorded #'(eval:alts form (eval:result "" "" message)))
    (pattern [form result:printed]
             #:with live #'form
             #:with recorded #'(eval:alts form (eval:result (racketresultfont result.text)))))

  (define (recorded-rows stx key)
    (syntax-parse (replace-context stx manual-examples)
      [((name:id row ...) ...)
       (for/first ([name (in-list (attribute name))]
                   [rows (in-list (attribute row))]
                   #:when (eq? (syntax-e name) (syntax-e key)))
         rows)])))

(define-syntax (recorded-examples stx)
  (syntax-parse stx
    [(_ key:id)
     #:do [(define rows (recorded-rows stx #'key))]
     #:fail-unless rows "no recorded examples with this name"
     #:with (row:recorded-row ...) rows
     #'(if live?
           (examples #:eval secp-eval row.live ...)
           (examples #:eval secp-eval row.recorded ...))]))
