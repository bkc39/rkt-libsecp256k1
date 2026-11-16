#lang racket/base

(module+ test
  (require (only-in racket/contract exn:fail:contract:blame?)
           racket/list
           racket/match
           rackunit
           libsecp256k1
           (only-in libsecp256k1/private/ffi secp256k1_ecdsa_signature_parse_der)
           "helpers/util.rkt"
           "helpers/vectors.rkt")

  (define (random-pair rng)
    (values (bytes->secret-key (random-secret-bytes rng)) (random-digest rng)))

  (test-seeded "a signature verifies under the signer's key" #:seed (41 42 43 44 45 46) rng
    (for ([_ (in-range 500)])
      (define-values (key digest) (random-pair rng))
      (check-true (ecdsa-verify (ecdsa-sign digest key) digest (secret-key->public-key key)))))

  (test-seeded "a wrong digest, key, r or s does not verify" #:seed (51 52 53 54 55 56) rng
    (for ([_ (in-range 100)])
      (define-values (key digest) (random-pair rng))
      (define pk (secret-key->public-key key))
      (define sig (ecdsa-sign digest key))
      (define r (ecdsa-signature-r sig))
      (define s (ecdsa-signature-s sig))
      (check-false (ecdsa-verify sig (random-digest rng) pk))
      (check-false (ecdsa-verify sig digest (secret-key->public-key (generate-secret-key))))
      (for ([r* (list (add1 r) (sub1 r))] #:when (< 0 r* n))
        (check-false (ecdsa-verify (ecdsa-signature r* s) digest pk)))
      (for ([s* (list (add1 s) (sub1 s))] #:when (< 0 s* n))
        (check-false (ecdsa-verify (ecdsa-signature r s*) digest pk)))))

  (test-seeded "signing is deterministic and distinct digests give distinct r"
    #:seed (61 62 63 64 65 66) rng
    (define key (bytes->secret-key (random-secret-bytes rng)))
    (define digests (remove-duplicates (for/list ([_ (in-range 500)]) (random-digest rng))))
    (check-equal? (length digests) 500)
    (define sigs (for/list ([d (in-list digests)]) (ecdsa-sign d key)))
    (for ([d (in-list digests)] [sig (in-list sigs)])
      (check-equal? (ecdsa-sign d key) sig))
    (check-equal? (length (remove-duplicates (map ecdsa-signature-r sigs))) 500))

  (test-seeded "produced signatures are low-S" #:seed (71 72 73 74 75 76) rng
    (for ([_ (in-range 500)])
      (define-values (key digest) (random-pair rng))
      (for ([sig (list (ecdsa-sign digest key) (ecdsa-sign-recoverable digest key))])
        (check-true (<= (ecdsa-signature-s sig) half-order))
        (check-true (ecdsa-signature-low-s? sig)))))

  (test-seeded "a high-S twin does not verify until normalized" #:seed (81 82 83 84 85 86) rng
    (for ([_ (in-range 200)])
      (define-values (key digest) (random-pair rng))
      (define pk (secret-key->public-key key))
      (define sig (ecdsa-sign digest key))
      (define high (ecdsa-signature (ecdsa-signature-r sig) (- n (ecdsa-signature-s sig))))
      (check-false (ecdsa-signature-low-s? high))
      (check-false (ecdsa-verify high digest pk))
      (check-equal? (ecdsa-signature-normalize high) sig)
      (check-true (ecdsa-verify (ecdsa-signature-normalize high) digest pk))))

  (test-case "low-S is s <= (n-1)/2"
    (check-true (ecdsa-signature-low-s? (ecdsa-signature 1 half-order)))
    (check-false (ecdsa-signature-low-s? (ecdsa-signature 1 (add1 half-order))))
    (check-true (ecdsa-signature-low-s? (ecdsa-signature 1 0))))

  (test-seeded "normalize is idempotent, keeps the kind and keeps recovery"
    #:seed (91 92 93 94 95 96) rng
    (for ([_ (in-range 200)])
      (define-values (key digest) (random-pair rng))
      (define rsig (ecdsa-sign-recoverable digest key))
      (define r (ecdsa-signature-r rsig))
      (define s (ecdsa-signature-s rsig))
      (define id (ecdsa-recoverable-signature-id rsig))
      (define high (ecdsa-recoverable-signature r (- n s) (bitwise-xor id 1)))
      (for ([sig (list rsig high (ecdsa-signature r s) (ecdsa-signature r (- n s)))])
        (define once (ecdsa-signature-normalize sig))
        (check-equal? (ecdsa-signature-normalize once) once)
        (check-equal? (ecdsa-recoverable-signature? once) (ecdsa-recoverable-signature? sig)))
      (define normalized (ecdsa-signature-normalize high))
      (check-equal? (ecdsa-recoverable-signature-id normalized) id)
      (check-equal? (ecdsa-signature-normalize rsig) rsig)
      (check-equal? (ecdsa-recover normalized digest) (ecdsa-recover high digest))
      (check-equal? (ecdsa-recover high digest) (secret-key->public-key key))))

  (test-seeded "compact encodings round-trip and are big-endian r || s"
    #:seed (101 102 103 104 105 106) rng
    (for ([_ (in-range 300)])
      (define-values (key digest) (random-pair rng))
      (define sig (ecdsa-sign digest key))
      (define rsig (ecdsa-sign-recoverable digest key))
      (define compact (ecdsa-signature->compact sig))
      (check-equal? compact (bytes-append (integer->bytes32 (ecdsa-signature-r sig))
                                          (integer->bytes32 (ecdsa-signature-s sig))))
      (check-equal? (compact->ecdsa-signature compact) sig)
      (check-equal? (compact->ecdsa-recoverable-signature
                     (ecdsa-signature->compact rsig)
                     (ecdsa-recoverable-signature-id rsig))
                    rsig)
      (define r (random-bytes rng 32))
      (define s (random-bytes rng 32))
      (define bs (bytes-append r s))
      (define in-range? (and (< (bytes->integer r) n) (< (bytes->integer s) n)))
      (if in-range?
          (check-equal? (ecdsa-signature->compact (compact->ecdsa-signature bs)) bs)
          (check-exn exn:fail:libsecp256k1:signature? (lambda () (compact->ecdsa-signature bs))))))

  (test-case "compact signatures with zeros parse, and r or s >= n raise"
    (for ([bs (list (make-bytes 64 0)
                    (bytes-append (make-bytes 32 0) (integer->bytes32 (- n 1)))
                    (bytes-append (integer->bytes32 (- n 1)) (make-bytes 32 0)))])
      (check-equal? (ecdsa-signature->compact (compact->ecdsa-signature bs)) bs)
      (check-equal? (ecdsa-signature->compact (compact->ecdsa-recoverable-signature bs 3)) bs))
    (for ([bs (list (bytes-append (integer->bytes32 n) (integer->bytes32 1))
                    (bytes-append (integer->bytes32 1) (integer->bytes32 n))
                    (make-bytes 64 255))]
          #:when #t
          [id (list #f 0 3)])
      (check-exn (pregexp (string-append "^compact->ecdsa-(recoverable-)?signature: invalid"
                                         " signature;\n r or s is not less than the curve"
                                         " order$"))
                 (lambda ()
                   (if id
                       (compact->ecdsa-recoverable-signature bs id)
                       (compact->ecdsa-signature bs))))))

  (define (check-der-law bs)
    (define sig
      (with-handlers ([exn:fail:libsecp256k1:signature? (lambda (_) #f)])
        (der->ecdsa-signature bs)))
    (when sig
      (check-equal? (ecdsa-signature->der sig) bs (hex bs))))

  (test-seeded "DER parses only canonical encodings" #:seed (111 112 113 114 115 116) rng
    (for ([_ (in-range 2000)])
      (check-der-law (random-bytes rng (random 80 rng))))
    (for ([_ (in-range 500)])
      (define-values (key digest) (random-pair rng))
      (define sig (ecdsa-sign digest key))
      (define der (ecdsa-signature->der sig))
      (check-equal? (der->ecdsa-signature der) sig)
      (check-true (<= (bytes-length der) 72))
      (check-equal? (bytes-ref der 0) #x30)
      (check-der-law der)
      (check-der-law (bytes-append der #"\0"))
      (check-der-law (subbytes der 0 (sub1 (bytes-length der))))))

  (test-case "DER of extreme scalars round-trips"
    (for* ([r (list 0 1 half-order (- n 1))]
           [s (list 0 1 half-order (- n 1))])
      (define sig (ecdsa-signature r s))
      (define der (ecdsa-signature->der sig))
      (check-true (<= (bytes-length der) 72))
      (check-equal? (der->ecdsa-signature der) sig)))

  (test-case "non-canonical DER raises the documented message"
    (check-exn (regexp (regexp-quote
                        (string-append
                         "der->ecdsa-signature: invalid signature;\n"
                         " not strict DER, or r or s is negative or not less than the curve order")))
               (lambda () (der->ecdsa-signature #"\x30\x06\x02\x01\x81\x02\x01\x01"))))

  (test-seeded "a recoverable signature verifies as the plain one" #:seed (121 122 123 124 125 126) rng
    (for ([_ (in-range 200)])
      (define-values (key digest) (random-pair rng))
      (define pk (secret-key->public-key key))
      (define rsig (ecdsa-sign-recoverable digest key))
      (check-true (ecdsa-verify rsig digest pk))
      (check-false (ecdsa-verify rsig (random-digest rng) pk))))

  (test-case "signatures are equal? only when kind and fields match"
    (check-equal? (ecdsa-signature 1 2) (ecdsa-signature 1 2))
    (check-equal? (equal-hash-code (ecdsa-signature 1 2)) (equal-hash-code (ecdsa-signature 1 2)))
    (check-not-equal? (ecdsa-signature 1 2) (ecdsa-recoverable-signature 1 2 0))
    (check-not-equal? (ecdsa-recoverable-signature 1 2 0) (ecdsa-signature 1 2))
    (check-not-equal? (ecdsa-recoverable-signature 1 2 0) (ecdsa-recoverable-signature 1 2 1))
    (check-equal? (ecdsa-recoverable-signature 1 2 1) (ecdsa-recoverable-signature 1 2 1))
    (check-not-equal? (ecdsa-signature 1 2) (ecdsa-signature 2 1)))

  (test-case "signatures print their compact hex"
    (define compact (bytes-append (integer->bytes32 1) (integer->bytes32 2)))
    (check-equal? (format "~a" (ecdsa-signature 1 2))
                  (string-append "#<ecdsa-signature " (hex compact) ">"))
    (check-equal? (format "~s" (ecdsa-recoverable-signature 1 2 3))
                  (string-append "#<ecdsa-recoverable-signature " (hex compact) " id=3>")))

  (define (x-coordinate-mod-n nonce)
    (define pk (secret-key->public-key (bytes->secret-key nonce)))
    (modulo (bytes->integer (subbytes (public-key->bytes pk) 1)) n))

  (for ([row (in-list (nonce-rows))]
        [i (in-naturals 1)])
    (test-case (format "RFC 6979 nonce row ~a gives r = x(kG)" i)
      (define sig (ecdsa-sign (sha256-bytes (nonce-row-message row))
                              (bytes->secret-key (nonce-row-secret row))))
      (check-equal? (ecdsa-signature-r sig) (x-coordinate-mod-n (nonce-row-nonce row)))))

  (test-case "every tiny-secp256k1 signing vector is reproduced and recovers its signer"
    (define rows (signing-rows))
    (check-equal? (length rows) 2020)
    (for ([row (in-list rows)]
          [i (in-naturals)])
      (define key (bytes->secret-key (signing-row-secret row)))
      (define digest (signing-row-digest row))
      (define rsig (ecdsa-sign-recoverable digest key))
      (with-check-info (['row i])
        (check-equal? (ecdsa-signature->compact rsig) (signing-row-compact row))
        (check-equal? (ecdsa-recoverable-signature-id rsig) (signing-row-recovery-id row))
        (check-equal? (ecdsa-signature->compact (ecdsa-sign digest key)) (signing-row-compact row))
        (check-equal? (ecdsa-recover rsig digest) (secret-key->public-key key)))))

  (test-case "Wycheproof: a signature is accepted exactly when the vector is valid"
    (define rows (wycheproof-rows))
    (check-equal? (length rows) 463)
    (define unparsed
      (for/sum ([row (in-list rows)])
        (define key (bytes->public-key (wycheproof-row-public-key row)))
        (define sig
          (with-handlers ([exn:fail:libsecp256k1:signature? (lambda (_) #f)])
            (der->ecdsa-signature (wycheproof-row-der row))))
        (define accepted?
          (and sig (ecdsa-verify sig (sha256-bytes (wycheproof-row-message row)) key)))
        (with-check-info (['tc-id (wycheproof-row-tc-id row)]
                          ['comment (wycheproof-row-comment row)])
          (check-equal? accepted? (wycheproof-row-valid? row)))
        (if sig 0 1)))
    (define upstream-unparsed
      (for/sum ([row (in-list rows)])
        (if (secp256k1_ecdsa_signature_parse_der 'test (wycheproof-row-der row)) 0 1)))
    (check-equal? upstream-unparsed 190)
    (check-equal? unparsed 274))

  (define (tiny-invalid-outcome row)
    (define (attempt thunk)
      (with-handlers ([exn:fail:libsecp256k1:key? (lambda (_) 'key)]
                      [exn:fail:libsecp256k1:signature? (lambda (_) 'signature)]
                      [exn:fail:contract:blame? (lambda (_) 'blame)])
        (thunk)))
    (match row
      [(struct* tiny-invalid-row ([section 'sign] [secret secret] [digest digest]))
       (attempt (lambda () (ecdsa-sign digest (bytes->secret-key secret))))]
      [(struct* tiny-invalid-row ([section 'verify] [public-key q] [digest digest]
                                                    [compact compact]))
       (attempt (lambda ()
                  (define key (bytes->public-key q))
                  (ecdsa-verify (compact->ecdsa-signature compact) digest key)))]
      [(struct* tiny-invalid-row ([section 'recover] [digest digest] [compact compact]
                                                     [recovery-id id]))
       (attempt (lambda ()
                  (ecdsa-recover (compact->ecdsa-recoverable-signature compact (or id 0))
                                 digest)))]))

  (define (expected-tiny-outcome row)
    (match row
      [(struct* tiny-invalid-row ([exception "Expected Private"])) 'key]
      [(struct* tiny-invalid-row ([exception "Expected Point"])) 'key]
      [(struct* tiny-invalid-row ([exception "Expected Hash"])) 'blame]
      [(struct* tiny-invalid-row ([section 'verify] [exception "Expected Signature"])) 'signature]
      [(struct* tiny-invalid-row ([section 'verify] [exception #f])) #f]
      [(struct* tiny-invalid-row ([section 'recover] [compact compact]))
       #:when (or (>= (bytes->integer (subbytes compact 0 32)) n)
                  (>= (bytes->integer (subbytes compact 32 64)) n))
       'signature]
      [(struct* tiny-invalid-row ([section 'recover])) #f]))

  (test-case "tiny-secp256k1 invalid vectors fail at the documented step"
    (define rows (tiny-invalid-rows))
    (check-equal? (length rows) 37)
    (for ([row (in-list rows)])
      (with-check-info (['section (tiny-invalid-row-section row)]
                        ['description (tiny-invalid-row-description row)])
        (check-equal? (tiny-invalid-outcome row) (expected-tiny-outcome row))))))
