#lang racket/base

(module+ test
  (require racket/port
           racket/pretty
           racket/string
           rackunit
           libsecp256k1
           "helpers/bounded.rkt"
           "helpers/leaks.rkt"
           "helpers/util.rkt")

  (test-case "the leak probe finds the marker"
    (check-true (for/or ([p (in-list leak-patterns)])
                  (string-contains? (format "~s" marker) p)))
    (check-true (for/or ([p (in-list leak-patterns)])
                  (string-contains? (hex marker) p))))

  (test-case "a secret key prints as #<secret-key> in every mode"
    (for ([s (list (format "~a" marker-key)
                   (format "~s" marker-key)
                   (format "~v" marker-key)
                   (format "~e" marker-key)
                   (pretty-format marker-key)
                   (with-output-to-string (lambda () (pretty-print marker-key)))
                   (parameterize ([print-struct #t])
                     (with-output-to-string (lambda () (print marker-key))))
                   ((error-value->string-handler) marker-key 1000))])
      (check-no-leak s)
      (check-regexp-match #rx"^#<secret-key>\n?$" s))
    (check-equal? (format "~a" (list marker-key marker-key)) "(#<secret-key> #<secret-key>)")
    (check-no-leak (format "~s" (struct->vector marker-key))))

  (struct refusal (call))

  (define refusals
    (map refusal
         '((bytes->secret-key order-bytes)
           (bytes->secret-key (make-bytes 32 255))
           (bytes->secret-key (make-bytes 32 0))
           (integer->secret-key (+ secret-value n))
           (integer->secret-key (- secret-value))
           (secret-key-tweak-add key zero-sum-tweak)
           (secret-key-tweak-add key order-bytes)
           (public-key-tweak-add (secret-key->public-key key) zero-sum-tweak))))

  (for ([r (in-list refusals)])
    (test-case (format "~s raises an error showing no secret" (refusal-call r))
      (define e (probe-raise (refusal-call r)))
      (check-pred exn:fail? e)
      (check-no-leak (if (exn? e) (exn-message e) ""))))

  (test-case "secret-key->bytes returns a fresh mutable copy"
    (define a (secret-key->bytes marker-key))
    (define b (secret-key->bytes marker-key))
    (check-equal? a b)
    (check-false (eq? a b))
    (check-false (immutable? a))
    (bytes-fill! a 0)
    (check-equal? (secret-key->bytes marker-key) marker))

  (test-case "bytes->secret-key copies its argument"
    (define bs (bytes-copy marker))
    (define key (bytes->secret-key bs))
    (bytes-fill! bs 7)
    (check-equal? (secret-key->bytes key) marker))

  (test-case "secret keys are equal? only when eq?"
    (define a (bytes->secret-key marker))
    (define b (bytes->secret-key marker))
    (check-false (equal? a b))
    (check-true (equal? a a)))

  (test-case "bytes->secret-key validates the bytes it keeps while another thread rewrites them"
    (define buffer (integer->bytes32 1))
    (define stop? (box #f))
    (define rewriter
      (thread (lambda ()
                (let loop ([b 0])
                  (unless (unbox stop?)
                    (bytes-set! buffer 31 b)
                    (loop (- 1 b)))))))
    (define outcome
      (call-bounded
       (lambda ()
         (for/sum ([_ (in-range 1000000)])
           (define key
             (with-handlers ([exn:fail:libsecp256k1:key? (lambda (_) #f)])
               (bytes->secret-key buffer)))
           (if (and key (zero? (bytes->integer (secret-key->bytes key)))) 1 0)))
       #:seconds 120))
    (set-box! stop? #t)
    (thread-wait rewriter)
    (check-equal? outcome '(ok 0))))
