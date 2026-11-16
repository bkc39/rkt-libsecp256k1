#lang racket/base

(module+ test
  (require rackunit
           libsecp256k1
           "util.rkt")

  (struct bad-call (procedure description thunk))

  (define key (bytes->secret-key (integer->bytes32 7)))
  (define pk (secret-key->public-key key))
  (define digest (make-bytes 32 9))
  (define sig (ecdsa-sign digest key))
  (define rsig (ecdsa-sign-recoverable digest key))
  (define tweak (integer->bytes32 5))

  (define bad-calls
    (list
     (bad-call 'bytes->secret-key "31 bytes" (lambda () (bytes->secret-key (make-bytes 31 1))))
     (bad-call 'bytes->secret-key "33 bytes" (lambda () (bytes->secret-key (make-bytes 33 1))))
     (bad-call 'bytes->secret-key "a string" (lambda () (bytes->secret-key (make-string 32 #\a))))
     (bad-call 'bytes->secret-key "a public key" (lambda () (bytes->secret-key pk)))
     (bad-call 'bytes->secret-key "a secret key" (lambda () (bytes->secret-key key)))
     (bad-call 'secret-key->bytes "a public key" (lambda () (secret-key->bytes pk)))
     (bad-call 'secret-key->bytes "bytes" (lambda () (secret-key->bytes (secret-key->bytes key))))
     (bad-call 'secret-key->public-key "a public key" (lambda () (secret-key->public-key pk)))
     (bad-call 'secret-key-tweak-add "a public key" (lambda () (secret-key-tweak-add pk tweak)))
     (bad-call 'secret-key-tweak-add "a 31-byte tweak"
               (lambda () (secret-key-tweak-add key (make-bytes 31 1))))
     (bad-call 'secret-key-tweak-add "a string tweak"
               (lambda () (secret-key-tweak-add key (make-string 32 #\a))))
     (bad-call 'secret-key-negate "a public key" (lambda () (secret-key-negate pk)))
     (bad-call 'bytes->public-key "32 bytes" (lambda () (bytes->public-key (make-bytes 32 2))))
     (bad-call 'bytes->public-key "34 bytes" (lambda () (bytes->public-key (make-bytes 34 2))))
     (bad-call 'bytes->public-key "64 bytes" (lambda () (bytes->public-key (make-bytes 64 4))))
     (bad-call 'bytes->public-key "66 bytes" (lambda () (bytes->public-key (make-bytes 66 4))))
     (bad-call 'bytes->public-key "a secret key" (lambda () (bytes->public-key key)))
     (bad-call 'public-key->bytes "a secret key" (lambda () (public-key->bytes key)))
     (bad-call 'public-key->bytes "bytes" (lambda () (public-key->bytes (public-key->bytes pk))))
     (bad-call 'public-key-tweak-add "a secret key" (lambda () (public-key-tweak-add key tweak)))
     (bad-call 'public-key-tweak-add "a 33-byte tweak"
               (lambda () (public-key-tweak-add pk (make-bytes 33 1))))
     (bad-call 'public-key-negate "a secret key" (lambda () (public-key-negate key)))
     (bad-call 'public-key-combine "a secret key first" (lambda () (public-key-combine key pk)))
     (bad-call 'public-key-combine "a secret key second" (lambda () (public-key-combine pk key)))
     (bad-call 'ecdsa-signature "r = n" (lambda () (ecdsa-signature n 1)))
     (bad-call 'ecdsa-signature "r = -1" (lambda () (ecdsa-signature -1 1)))
     (bad-call 'ecdsa-signature "s = n" (lambda () (ecdsa-signature 1 n)))
     (bad-call 'ecdsa-signature "s = -1" (lambda () (ecdsa-signature 1 -1)))
     (bad-call 'ecdsa-signature-r "compact bytes"
               (lambda () (ecdsa-signature-r (ecdsa-signature->compact sig))))
     (bad-call 'ecdsa-signature-s "compact bytes"
               (lambda () (ecdsa-signature-s (ecdsa-signature->compact sig))))
     (bad-call 'ecdsa-recoverable-signature "id 4" (lambda () (ecdsa-recoverable-signature 1 1 4)))
     (bad-call 'ecdsa-recoverable-signature "id -1"
               (lambda () (ecdsa-recoverable-signature 1 1 -1)))
     (bad-call 'ecdsa-recoverable-signature "r = n"
               (lambda () (ecdsa-recoverable-signature n 1 0)))
     (bad-call 'ecdsa-recoverable-signature "s = -1"
               (lambda () (ecdsa-recoverable-signature 1 -1 0)))
     (bad-call 'ecdsa-recoverable-signature-recovery-id "a plain signature"
               (lambda () (ecdsa-recoverable-signature-recovery-id sig)))
     (bad-call 'ecdsa-sign "a 31-byte digest" (lambda () (ecdsa-sign (make-bytes 31 1) key)))
     (bad-call 'ecdsa-sign "a 33-byte digest" (lambda () (ecdsa-sign (make-bytes 33 1) key)))
     (bad-call 'ecdsa-sign "a string digest" (lambda () (ecdsa-sign (make-string 32 #\a) key)))
     (bad-call 'ecdsa-sign "a public key" (lambda () (ecdsa-sign digest pk)))
     (bad-call 'ecdsa-sign "key bytes" (lambda () (ecdsa-sign digest (secret-key->bytes key))))
     (bad-call 'ecdsa-sign-recoverable "a 31-byte digest"
               (lambda () (ecdsa-sign-recoverable (make-bytes 31 1) key)))
     (bad-call 'ecdsa-sign-recoverable "a string digest"
               (lambda () (ecdsa-sign-recoverable (make-string 32 #\a) key)))
     (bad-call 'ecdsa-sign-recoverable "a public key" (lambda () (ecdsa-sign-recoverable digest pk)))
     (bad-call 'ecdsa-verify "compact bytes"
               (lambda () (ecdsa-verify (ecdsa-signature->compact sig) digest pk)))
     (bad-call 'ecdsa-verify "a 31-byte digest" (lambda () (ecdsa-verify sig (make-bytes 31 1) pk)))
     (bad-call 'ecdsa-verify "a 33-byte digest" (lambda () (ecdsa-verify sig (make-bytes 33 1) pk)))
     (bad-call 'ecdsa-verify "a secret key" (lambda () (ecdsa-verify sig digest key)))
     (bad-call 'ecdsa-verify "public key bytes"
               (lambda () (ecdsa-verify sig digest (public-key->bytes pk))))
     (bad-call 'ecdsa-recover "a plain signature" (lambda () (ecdsa-recover sig digest)))
     (bad-call 'ecdsa-recover "a 33-byte digest" (lambda () (ecdsa-recover rsig (make-bytes 33 1))))
     (bad-call 'ecdsa-recover "a string digest"
               (lambda () (ecdsa-recover rsig (make-string 32 #\a))))
     (bad-call 'ecdsa-signature-low-s? "compact bytes"
               (lambda () (ecdsa-signature-low-s? (ecdsa-signature->compact sig))))
     (bad-call 'ecdsa-signature-normalize "compact bytes"
               (lambda () (ecdsa-signature-normalize (ecdsa-signature->compact sig))))
     (bad-call 'ecdsa-signature->compact "DER bytes"
               (lambda () (ecdsa-signature->compact (ecdsa-signature->der sig))))
     (bad-call 'compact->ecdsa-signature "63 bytes"
               (lambda () (compact->ecdsa-signature (make-bytes 63 1))))
     (bad-call 'compact->ecdsa-signature "65 bytes"
               (lambda () (compact->ecdsa-signature (make-bytes 65 1))))
     (bad-call 'compact->ecdsa-signature "recovery id 4"
               (lambda () (compact->ecdsa-signature (make-bytes 64 1) #:recovery-id 4)))
     (bad-call 'compact->ecdsa-signature "recovery id -1"
               (lambda () (compact->ecdsa-signature (make-bytes 64 1) #:recovery-id -1)))
     (bad-call 'ecdsa-signature->der "DER bytes"
               (lambda () (ecdsa-signature->der (ecdsa-signature->der sig))))
     (bad-call 'der->ecdsa-signature "a string"
               (lambda () (der->ecdsa-signature (hex (ecdsa-signature->der sig)))))))

  (define (names-procedure? name e)
    (regexp-match? (regexp (string-append "^" (regexp-quote (symbol->string name)) ": "))
                   (exn-message e)))

  (for ([c (in-list bad-calls)])
    (test-case (format "~a given ~a is a contract violation blaming the caller"
                       (bad-call-procedure c) (bad-call-description c))
      (check-blames-here ((bad-call-thunk c)))
      (check-exn (lambda (e) (names-procedure? (bad-call-procedure c) e))
                 (bad-call-thunk c))))

  (test-case "no FFI-level error reaches the caller"
    (for ([c (in-list bad-calls)])
      (define message
        (with-handlers ([exn:fail? exn-message])
          ((bad-call-thunk c))))
      (check-false (regexp-match? #rx"_bytes|ptr-ref|cpointer|ffi" message) message)))

  (test-case "#:compressed? accepts any value"
    (check-equal? (public-key->bytes pk #:compressed? 'yes) (public-key->bytes pk))
    (check-equal? (bytes-length (public-key->bytes pk #:compressed? #f)) 65))

  (struct opaque-procedure (name procedure arity))

  (define opaque-procedures
    (list (opaque-procedure 'bytes->secret-key bytes->secret-key 1)
          (opaque-procedure 'secret-key->bytes secret-key->bytes 1)
          (opaque-procedure 'secret-key->public-key secret-key->public-key 1)
          (opaque-procedure 'secret-key-tweak-add secret-key-tweak-add 2)
          (opaque-procedure 'secret-key-negate secret-key-negate 1)
          (opaque-procedure 'public-key-tweak-add public-key-tweak-add 2)
          (opaque-procedure 'ecdsa-sign ecdsa-sign 2)
          (opaque-procedure 'ecdsa-sign-recoverable ecdsa-sign-recoverable 2)))

  (define (argument-count n)
    (if (= n 1) "1 argument" (format "~a arguments" n)))

  (test-case "a wrong argument count to a procedure taking secrets blames the caller with counts"
    (for* ([p (in-list opaque-procedures)]
           [count (in-list '(0 1 2 3))]
           #:unless (= count (opaque-procedure-arity p)))
      (define (call) (apply (opaque-procedure-procedure p) (for/list ([_ (in-range count)]) key)))
      (with-check-info (['procedure (opaque-procedure-name p)] ['count count])
        (check-blames-here (call))
        (check-exn (lambda (e)
                     (and (names-procedure? (opaque-procedure-name p) e)
                          (regexp-match?
                           (regexp (string-append
                                    "expected: " (argument-count (opaque-procedure-arity p))
                                    "\n  given: " (argument-count count) "\n"))
                           (exn-message e))))
                   call))))

  (test-case "a keyword to a procedure taking secrets blames the caller and names the keyword"
    (for ([p (in-list opaque-procedures)])
      (define (call)
        (keyword-apply (opaque-procedure-procedure p) '(#:hint) '(1)
                       (for/list ([_ (in-range (opaque-procedure-arity p))]) key)))
      (with-check-info (['procedure (opaque-procedure-name p)])
        (check-blames-here (call))
        (check-exn #rx"expected: no keyword arguments\n  given: keyword #:hint\n" call))))

  (test-seeded "every result satisfies its range contract on random inputs" #:seed (1 2 3 4 5 6) rng
    (for ([_ (in-range 200)])
      (define k (bytes->secret-key (random-secret-bytes rng)))
      (define d (random-digest rng))
      (define t (random-secret-bytes rng))
      (define p (secret-key->public-key k))
      (define s (ecdsa-sign d k))
      (define rs (ecdsa-sign-recoverable d k))
      (check-pred secret-key? (secret-key-negate k))
      (check-pred bytes? (secret-key->bytes k))
      (check-pred secret-key? (secret-key-tweak-add k t))
      (check-pred public-key? (public-key-tweak-add p t))
      (check-pred public-key? (public-key-negate p))
      (check-pred public-key? (public-key-combine p (public-key-tweak-add p t)))
      (check-pred public-key? (bytes->public-key (public-key->bytes p #:compressed? #f)))
      (check-pred ecdsa-recoverable-signature? (ecdsa-signature-normalize rs))
      (check-pred boolean? (ecdsa-verify s d p))
      (check-pred public-key? (ecdsa-recover rs d))
      (check-pred ecdsa-signature? (der->ecdsa-signature (ecdsa-signature->der s)))
      (check-pred ecdsa-signature? (compact->ecdsa-signature (ecdsa-signature->compact s)))
      (check-pred exact-nonnegative-integer? (ecdsa-recoverable-signature-recovery-id rs))
      (check-pred boolean? (ecdsa-signature-low-s? s))))

  (test-case "contracts are exported as named flat contracts"
    (check-true (digest/c (make-bytes 32)))
    (check-false (digest/c (make-bytes 31)))
    (check-true (secret-bytes/c (make-bytes 32)))
    (check-false (secret-bytes/c "x"))
    (check-true (secret-key/c key))
    (check-false (secret-key/c pk))
    (check-true (public-key-bytes/c (make-bytes 65)))
    (check-false (public-key-bytes/c (make-bytes 64)))
    (check-true (compact-bytes/c (make-bytes 64)))
    (check-true (recovery-id/c 3))
    (check-false (recovery-id/c 4))
    (check-true (scalar/c (- n 1)))
    (check-false (scalar/c n))))
