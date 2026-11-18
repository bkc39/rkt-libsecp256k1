#lang racket/base

(require (for-syntax racket/base)
         syntax/parse/define)

(provide bytes->integer
         define/snapshot
         half-order
         integer->bytes32
         secp256k1-order)

(define secp256k1-order
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

(define half-order (quotient (- secp256k1-order 1) 2))

(define (integer->bytes32 v)
  (define bs (make-bytes 32 0))
  (for ([i (in-range 32)])
    (bytes-set! bs (- 31 i) (bitwise-and (arithmetic-shift v (* -8 i)) 255)))
  bs)

(define (bytes->integer bs)
  (for/fold ([v 0]) ([b (in-bytes bs)])
    (+ (* v 256) b)))

(define-syntax-parse-rule (define/snapshot (name:id arg:id ...) #:snapshot (copied:id ...+)
                            body:expr ...+)
  (define (name arg ...)
    (let ([copied (bytes-copy copied)] ...)
      body ...)))
