#lang racket/base

(module+ test
  (require rackunit
           "helpers/bounded.rkt")

  (test-case "call-bounded reports results, exceptions, timeouts and memory"
    (check-equal? (call-bounded (lambda () 1)) '(ok 1))
    (check-match (call-bounded (lambda () (error 'x "y"))) (list 'raised (? exn:fail?)))
    (check-equal? (call-bounded (lambda () (let loop () (loop))) #:seconds 0.2) 'timeout)
    (when memory-bound?
      (check-equal? (call-bounded (lambda ()
                                    (let loop ([xs '()])
                                      (loop (cons (make-vector 1024) xs))))
                                  #:seconds 30 #:megabytes 16)
                    'memory))))
