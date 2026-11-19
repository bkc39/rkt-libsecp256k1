#lang racket/base

(require racket/list
         racket/string
         rackunit
         libsecp256k1
         "util.rkt")

(provide check-no-leak
         leak-patterns
         marker
         marker-key
         marker-value
         probe-raise)

(define marker (list->bytes (range #x11 #x31)))
(define marker-key (bytes->secret-key marker))
(define marker-value (bytes->integer marker))

(define (windows s width)
  (for/list ([i (in-range (add1 (- (string-length s) width)))])
    (substring s i (+ i width))))

(define (written-window bs)
  (define s (format "~s" bs))
  (substring s 2 (sub1 (string-length s))))

(define leak-patterns
  (remove-duplicates
   (append (windows (hex marker) 8)
           (windows (string-upcase (hex marker)) 8)
           (for/list ([i (in-range 29)])
             (written-window (subbytes marker i (+ i 4))))
           (windows (number->string marker-value) 10))))

(define (check-no-leak text)
  (with-check-info (['text text])
    (for ([pattern (in-list leak-patterns)])
      (check-false (string-contains? text pattern) pattern))))

(define probe-definitions
  `((define secret ,marker)
    (define secret-value ,marker-value)
    (define secret-hex ,(hex marker))
    (define key (bytes->secret-key secret))
    (define pk (secret-key->public-key (integer->secret-key 3)))
    (define digest (make-bytes 32 9))
    (define sig (ecdsa-sign digest key))
    (define rsig (ecdsa-sign-recoverable digest key))
    (define n ,n)
    (define order-bytes ,(integer->bytes32 n))
    (define zero-sum-tweak ,(integer->bytes32 (- n marker-value)))))

(define-namespace-anchor anchor)

(define probe-namespace
  (let ([ns (namespace-anchor->empty-namespace anchor)])
    (parameterize ([current-namespace ns])
      (namespace-require 'racket/base)
      (namespace-require 'libsecp256k1)
      (for-each eval probe-definitions))
    ns))

(define (probe-raise form)
  (with-handlers ([(lambda (_) #t) values])
    (parameterize ([current-namespace probe-namespace])
      (eval form))
    #f))
