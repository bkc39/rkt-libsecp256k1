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
             #:with recorded #'(eval:alts form (eval:result (racketresultfont result.text))))))

(define-syntax (recorded-examples stx)
  (syntax-parse stx
    [(_ key:id)
     (syntax-parse (replace-context stx manual-examples)
       [((name:id row:recorded-row ...) ...)
        (define rows
          (for/first ([name (in-list (syntax->list #'(name ...)))]
                      [rows (in-list (syntax->list #'((row ...) ...)))]
                      #:when (eq? (syntax-e name) (syntax-e #'key)))
            rows))
        (unless rows
          (raise-syntax-error #f "no recorded examples with this name" stx #'key))
        (syntax-parse rows
          [(row:recorded-row ...)
           #'(if live?
                 (examples #:eval secp-eval row.live ...)
                 (examples #:eval secp-eval row.recorded ...))])])]))
