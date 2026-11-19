#lang racket/base

(module+ test
  (require (only-in racket/contract contract-name exn:fail:contract:blame?)
           rackunit
           libsecp256k1
           "helpers/leaks.rkt"
           "helpers/util.rkt")

  (struct violation (call expected given))

  (define violations
    (for/list ([row (in-list
                     '([(bytes->secret-key (subbytes secret 0 31)) "32 bytes"
                        "a byte string of length 31"]
                       [(bytes->secret-key (bytes-append secret #"\0")) "32 bytes"
                        "a byte string of length 33"]
                       [(bytes->secret-key secret-value) "32 bytes" "an exact integer"]
                       [(bytes->secret-key secret-hex) "32 bytes" "a string of length 64"]
                       [(bytes->secret-key key) "32 bytes" "a secret key"]
                       [(bytes->secret-key) "1 argument" "0 arguments"]
                       [(bytes->secret-key secret secret) "1 argument" "2 arguments"]
                       [(bytes->secret-key secret #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(integer->secret-key secret) "an exact integer"
                        "a byte string of length 32"]
                       [(integer->secret-key secret-value secret-value) "1 argument"
                        "2 arguments"]
                       [(integer->secret-key secret-value #:hint secret-value)
                        "no keyword arguments" "keyword #:hint"]
                       [(secret-key->bytes secret) "a secret key" "a byte string of length 32"]
                       [(secret-key->bytes key secret) "1 argument" "2 arguments"]
                       [(secret-key->bytes key #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(secret-key->integer secret-value) "a secret key" "an exact integer"]
                       [(secret-key->integer) "1 argument" "0 arguments"]
                       [(secret-key->integer key #:hint secret-value) "no keyword arguments"
                        "keyword #:hint"]
                       [(secret-key->public-key secret) "a secret key"
                        "a byte string of length 32"]
                       [(secret-key->public-key key secret) "1 argument" "2 arguments"]
                       [(secret-key->public-key key #:k secret) "no keyword arguments"
                        "keyword #:k"]
                       [(secret-key-tweak-add secret secret) "a secret key"
                        "a byte string of length 32"]
                       [(secret-key-tweak-add key (subbytes secret 0 31)) "32 bytes"
                        "a byte string of length 31"]
                       [(secret-key-tweak-add key secret-value) "32 bytes" "an exact integer"]
                       [(secret-key-tweak-add key secret secret) "2 arguments" "3 arguments"]
                       [(secret-key-tweak-add key #:tweak secret) "no keyword arguments"
                        "keyword #:tweak"]
                       [(secret-key-negate secret) "a secret key" "a byte string of length 32"]
                       [(secret-key-negate key secret) "1 argument" "2 arguments"]
                       [(secret-key-negate key #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(secret-key? key secret) "1 argument" "2 arguments"]
                       [(secret-key? key #:hint secret) "no keyword arguments" "keyword #:hint"]
                       [(generate-secret-key secret) "0 arguments" "1 argument"]
                       [(generate-secret-key #:seed secret) "no keyword arguments"
                        "keyword #:seed"]
                       [(libsecp256k1-origin secret) "0 arguments" "1 argument"]
                       [(libsecp256k1-origin #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(public-key? pk secret) "1 argument" "2 arguments"]
                       [(public-key? pk #:hint secret) "no keyword arguments" "keyword #:hint"]
                       [(bytes->public-key secret) "33 or 65 bytes"
                        "a byte string of length 32"]
                       [(bytes->public-key (bytes-append secret secret)) "33 or 65 bytes"
                        "a byte string of length 64"]
                       [(bytes->public-key key) "33 or 65 bytes" "a secret key"]
                       [(bytes->public-key secret-hex) "33 or 65 bytes" "a string of length 64"]
                       [(bytes->public-key) "1 argument" "0 arguments"]
                       [(bytes->public-key (public-key->bytes pk) secret) "1 argument"
                        "2 arguments"]
                       [(bytes->public-key (public-key->bytes pk) #:hint secret)
                        "no keyword arguments" "keyword #:hint"]
                       [(public-key->bytes key) "a public key" "a secret key"]
                       [(public-key->bytes secret) "a public key" "a byte string of length 32"]
                       [(public-key->bytes pk secret) "1 argument" "2 arguments"]
                       [(public-key->bytes pk #:compressed secret) "keyword #:compressed?"
                        "keyword #:compressed"]
                       [(public-key-tweak-add secret pk) "a public key"
                        "a byte string of length 32"]
                       [(public-key-tweak-add pk (bytes-append secret #"\0")) "32 bytes"
                        "a byte string of length 33"]
                       [(public-key-tweak-add pk secret-hex) "32 bytes" "a string of length 64"]
                       [(public-key-tweak-add pk secret secret) "2 arguments" "3 arguments"]
                       [(public-key-tweak-add pk secret #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(public-key-negate key) "a public key" "a secret key"]
                       [(public-key-negate pk secret) "1 argument" "2 arguments"]
                       [(public-key-negate pk #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(public-key-combine key) "a public key" "a secret key"]
                       [(public-key-combine pk secret) "a public key"
                        "a byte string of length 32"]
                       [(public-key-combine) "at least 1 argument" "0 arguments"]
                       [(public-key-combine pk #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-signature? sig secret) "1 argument" "2 arguments"]
                       [(ecdsa-signature? sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-signature secret 1) "an integer in [0, n)"
                        "a byte string of length 32"]
                       [(ecdsa-signature n 1) "an integer in [0, n)" "an exact integer"]
                       [(ecdsa-signature 1 -1) "an integer in [0, n)" "an exact integer"]
                       [(ecdsa-signature secret-value) "2 arguments" "1 argument"]
                       [(ecdsa-signature 1 1 #:r secret-value) "no keyword arguments"
                        "keyword #:r"]
                       [(ecdsa-signature-r secret) "an ECDSA signature"
                        "a byte string of length 32"]
                       [(ecdsa-signature-r sig secret) "1 argument" "2 arguments"]
                       [(ecdsa-signature-r sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-signature-s secret-value) "an ECDSA signature" "an exact integer"]
                       [(ecdsa-signature-s) "1 argument" "0 arguments"]
                       [(ecdsa-signature-s sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-recoverable-signature? rsig secret) "1 argument" "2 arguments"]
                       [(ecdsa-recoverable-signature? rsig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-recoverable-signature 1 1 4) "an integer from 0 to 3"
                        "an exact integer"]
                       [(ecdsa-recoverable-signature secret 1 0) "an integer in [0, n)"
                        "a byte string of length 32"]
                       [(ecdsa-recoverable-signature 1 n 0) "an integer in [0, n)"
                        "an exact integer"]
                       [(ecdsa-recoverable-signature secret-value secret-value) "3 arguments"
                        "2 arguments"]
                       [(ecdsa-recoverable-signature 1 1 0 #:id secret-value)
                        "no keyword arguments" "keyword #:id"]
                       [(ecdsa-recoverable-signature-id sig) "a recoverable ECDSA signature"
                        "an ECDSA signature"]
                       [(ecdsa-recoverable-signature-id rsig secret) "1 argument" "2 arguments"]
                       [(ecdsa-recoverable-signature-id rsig #:hint secret)
                        "no keyword arguments" "keyword #:hint"]
                       [(ecdsa-sign digest secret) "a secret key" "a byte string of length 32"]
                       [(ecdsa-sign digest pk) "a secret key" "a public key"]
                       [(ecdsa-sign secret-hex key) "a 32-byte digest" "a string of length 64"]
                       [(ecdsa-sign (bytes-append secret #"\0") key) "a 32-byte digest"
                        "a byte string of length 33"]
                       [(ecdsa-sign secret) "2 arguments" "1 argument"]
                       [(ecdsa-sign digest key secret) "2 arguments" "3 arguments"]
                       [(ecdsa-sign digest key #:nonce secret) "no keyword arguments"
                        "keyword #:nonce"]
                       [(ecdsa-sign-recoverable digest secret) "a secret key"
                        "a byte string of length 32"]
                       [(ecdsa-sign-recoverable (subbytes secret 0 31) key) "a 32-byte digest"
                        "a byte string of length 31"]
                       [(ecdsa-sign-recoverable secret) "2 arguments" "1 argument"]
                       [(ecdsa-sign-recoverable digest key secret) "2 arguments" "3 arguments"]
                       [(ecdsa-sign-recoverable digest key #:nonce secret)
                        "no keyword arguments" "keyword #:nonce"]
                       [(ecdsa-verify (ecdsa-signature->compact sig) digest pk)
                        "an ECDSA signature" "a byte string of length 64"]
                       [(ecdsa-verify sig (subbytes secret 0 31) pk) "a 32-byte digest"
                        "a byte string of length 31"]
                       [(ecdsa-verify sig digest key) "a public key" "a secret key"]
                       [(ecdsa-verify sig digest (public-key->bytes pk)) "a public key"
                        "a byte string of length 33"]
                       [(ecdsa-verify sig digest) "3 arguments" "2 arguments"]
                       [(ecdsa-verify sig digest pk #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-recover sig digest) "a recoverable ECDSA signature"
                        "an ECDSA signature"]
                       [(ecdsa-recover rsig secret-hex) "a 32-byte digest"
                        "a string of length 64"]
                       [(ecdsa-recover rsig digest secret) "2 arguments" "3 arguments"]
                       [(ecdsa-recover rsig digest #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-signature-low-s? secret) "an ECDSA signature"
                        "a byte string of length 32"]
                       [(ecdsa-signature-low-s? sig secret) "1 argument" "2 arguments"]
                       [(ecdsa-signature-low-s? sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-signature-normalize secret) "an ECDSA signature"
                        "a byte string of length 32"]
                       [(ecdsa-signature-normalize sig secret) "1 argument" "2 arguments"]
                       [(ecdsa-signature-normalize sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(ecdsa-signature->compact (bytes-append secret secret))
                        "an ECDSA signature" "a byte string of length 64"]
                       [(ecdsa-signature->compact sig secret) "1 argument" "2 arguments"]
                       [(ecdsa-signature->compact sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(compact->ecdsa-signature secret) "64 bytes"
                        "a byte string of length 32"]
                       [(compact->ecdsa-signature (bytes-append secret secret #"\0")) "64 bytes"
                        "a byte string of length 65"]
                       [(compact->ecdsa-signature (bytes-append secret secret) 1) "1 argument"
                        "2 arguments"]
                       [(compact->ecdsa-signature (bytes-append secret secret) #:recovery-id 1)
                        "no keyword arguments" "keyword #:recovery-id"]
                       [(compact->ecdsa-recoverable-signature (bytes-append secret secret) 4)
                        "an integer from 0 to 3" "an exact integer"]
                       [(compact->ecdsa-recoverable-signature secret 0) "64 bytes"
                        "a byte string of length 32"]
                       [(compact->ecdsa-recoverable-signature (bytes-append secret secret))
                        "2 arguments" "1 argument"]
                       [(compact->ecdsa-recoverable-signature (bytes-append secret secret) 0
                                                              #:hint secret)
                        "no keyword arguments" "keyword #:hint"]
                       [(ecdsa-signature->der secret) "an ECDSA signature"
                        "a byte string of length 32"]
                       [(ecdsa-signature->der sig secret) "1 argument" "2 arguments"]
                       [(ecdsa-signature->der sig #:hint secret) "no keyword arguments"
                        "keyword #:hint"]
                       [(der->ecdsa-signature secret-hex) "a byte string" "a string of length 64"]
                       [(der->ecdsa-signature secret-value) "a byte string" "an exact integer"]
                       [(der->ecdsa-signature secret secret) "1 argument" "2 arguments"]
                       [(der->ecdsa-signature secret #:strict? secret) "no keyword arguments"
                        "keyword #:strict?"]))])
      (apply violation row)))

  (define (violation-kind v)
    (cond
      [(regexp-match? #rx"keyword" (violation-expected v)) 'keyword]
      [(regexp-match? #rx"argument" (violation-expected v)) 'arity]
      [else 'value]))

  (define (violation-procedure v)
    (car (violation-call v)))

  (for ([v (in-list violations)])
    (test-case (format "~s is a contract violation blaming the caller, showing no value"
                       (violation-call v))
      (define e (probe-raise (violation-call v)))
      (check-pred exn:fail:contract:blame? e)
      (define message (if (exn? e) (exn-message e) ""))
      (check-equal? (car (regexp-split #rx"\n" message))
                    (format "~a: contract violation" (violation-procedure v)))
      (check-regexp-match (regexp-quote (format "\n  expected: ~a\n  given: ~a\n"
                                                (violation-expected v) (violation-given v)))
                          message)
      (check-regexp-match #rx"\n  blaming: top-level\n" message)
      (check-false (regexp-match? #rx"_bytes|ptr-ref|cpointer|ffi" message) message)
      (check-no-leak message)))

  (define procedure-exports
    (let-values ([(variables syntaxes) (module->exports 'libsecp256k1)])
      (for*/list ([phase+names (in-list (append variables syntaxes))]
                  #:when (eqv? (car phase+names) 0)
                  [entry (in-list (cdr phase+names))]
                  #:unless (regexp-match? #rx"^(struct:)?exn|/c$|^secp256k1-order$"
                                          (symbol->string (car entry))))
        (car entry))))

  (define exports-without-checked-values
    '(generate-secret-key libsecp256k1-origin secret-key? public-key? ecdsa-signature?
                          ecdsa-recoverable-signature?))

  (test-case "the table probes every exported procedure for each kind of violation"
    (check-equal? (length procedure-exports) 34)
    (for* ([name (in-list procedure-exports)]
           [kind (in-list '(value arity keyword))]
           #:unless (and (eq? kind 'value) (memq name exports-without-checked-values)))
      (with-check-info (['procedure name] ['kind kind])
        (check-true (for/or ([v (in-list violations)])
                      (and (eq? (violation-procedure v) name) (eq? (violation-kind v) kind)))))))

  (define key (integer->secret-key 7))
  (define pk (secret-key->public-key key))

  (test-case "#:compressed? accepts any value"
    (check-equal? (public-key->bytes pk #:compressed? 'yes) (public-key->bytes pk))
    (check-equal? (bytes-length (public-key->bytes pk #:compressed? #f)) 65))

  (test-seeded "every result satisfies its range contract on random inputs" #:seed (1 2 3 4 5 6) rng
    (for ([_ (in-range 200)])
      (define k (bytes->secret-key (random-secret-bytes rng)))
      (define d (random-digest rng))
      (define t (random-secret-bytes rng))
      (define p (secret-key->public-key k))
      (define s (ecdsa-sign d k))
      (define rs (ecdsa-sign-recoverable d k))
      (check-pred secret-key? (secret-key-negate k))
      (check-pred secret-bytes/c (secret-key->bytes k))
      (check-pred public-key-bytes/c (public-key->bytes p #:compressed? #f))
      (check-pred der-bytes/c (ecdsa-signature->der s))
      (check-true (< 0 (secret-key->integer k) n))
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
      (check-pred exact-nonnegative-integer? (ecdsa-recoverable-signature-id rs))
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
    (check-false (scalar/c n))
    (check-true (der-bytes/c (make-bytes 72)))
    (check-false (der-bytes/c (make-bytes 73)))
    (check-equal? (map contract-name (list digest/c secret-bytes/c der-bytes/c))
                  '(digest/c secret-bytes/c der-bytes/c))
    (check-regexp-match #rx"in: the 1st argument of\n +\\(opaque-> secret-bytes/c secret-key\\?\\)"
                        (with-handlers ([exn:fail:contract:blame? exn-message])
                          (bytes->secret-key (make-bytes 31))))))
