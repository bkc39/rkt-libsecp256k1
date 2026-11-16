#lang racket/base

(module+ test
  (require racket/list
           racket/port
           racket/pretty
           racket/string
           rackunit
           libsecp256k1
           "util.rkt")

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

  (define (check-no-leak probe)
    (with-check-info (['probe probe])
      (for ([pattern (in-list leak-patterns)])
        (check-false (string-contains? probe pattern) pattern))))

  (define (raised-message thunk)
    (with-handlers ([(lambda (_) #t) (lambda (e) (if (exn? e) (exn-message e) (format "~s" e)))])
      (thunk)
      (fail "no exception was raised")))

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

  (define n-bytes (integer->bytes32 n))
  (define all-ones (make-bytes 32 255))
  (define pk (secret-key->public-key (bytes->secret-key (integer->bytes32 3))))
  (define digest (make-bytes 32 1))
  (define zero-sum-tweak (integer->bytes32 (- n marker-value)))

  (struct probe-call (description thunk))

  (define probe-calls
    (list
     (probe-call "an extra argument" (lambda () (bytes->secret-key marker 1)))
     (probe-call "a keyword" (lambda () (bytes->secret-key marker #:hint 1)))
     (probe-call "31 bytes" (lambda () (bytes->secret-key (subbytes marker 0 31))))
     (probe-call "hex string" (lambda () (bytes->secret-key (hex marker))))
     (probe-call "33 bytes" (lambda () (bytes->secret-key (bytes-append marker #"\0"))))
     (probe-call "an integer" (lambda () (bytes->secret-key marker-value)))
     (probe-call "the order" (lambda () (bytes->secret-key n-bytes)))
     (probe-call "all ones" (lambda () (bytes->secret-key all-ones)))
     (probe-call "sign with raw bytes" (lambda () (ecdsa-sign digest marker)))
     (probe-call "sign with raw bytes, extra" (lambda () (ecdsa-sign digest marker marker)))
     (probe-call "sign with one argument" (lambda () (ecdsa-sign marker)))
     (probe-call "sign-recoverable with raw bytes" (lambda () (ecdsa-sign-recoverable digest marker)))
     (probe-call "sign-recoverable, extra"
                 (lambda () (ecdsa-sign-recoverable digest marker-key marker)))
     (probe-call "sign-recoverable with one argument" (lambda () (ecdsa-sign-recoverable marker)))
     (probe-call "secret tweak, extra"
                 (lambda () (secret-key-tweak-add marker-key marker marker)))
     (probe-call "public tweak, extra" (lambda () (public-key-tweak-add pk marker marker)))
     (probe-call "secret tweak, zero sum"
                 (lambda () (secret-key-tweak-add marker-key zero-sum-tweak)))
     (probe-call "public tweak, infinity"
                 (lambda () (public-key-tweak-add (secret-key->public-key marker-key)
                                                  zero-sum-tweak)))
     (probe-call "a tweak in the public key's position"
                 (lambda () (public-key-tweak-add marker pk)))
     (probe-call "hex secret as a digest" (lambda () (ecdsa-sign (hex marker) marker-key)))
     (probe-call "a 33-byte secret as a digest"
                 (lambda () (ecdsa-sign-recoverable (bytes-append marker #"\0") marker-key)))
     (probe-call "secret-key->bytes of bytes" (lambda () (secret-key->bytes marker)))
     (probe-call "secret-key->bytes, extra" (lambda () (secret-key->bytes marker-key marker)))
     (probe-call "secret-key->public-key, keyword"
                 (lambda () (secret-key->public-key marker-key #:k marker)))))

  (for ([c (in-list probe-calls)])
    (test-case (format "~a: the error shows no secret" (probe-call-description c))
      (check-no-leak (raised-message (probe-call-thunk c)))))

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
    (check-true (equal? a a))))
