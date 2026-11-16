#lang racket/base

(require (only-in file/sha1 hex-string->bytes)
         json
         racket/match
         racket/runtime-path)

(provide nonce-rows
         signing-rows
         tiny-invalid-rows
         vectors-dir
         wycheproof-rows
         (struct-out nonce-row)
         (struct-out signing-row)
         (struct-out tiny-invalid-row)
         (struct-out wycheproof-row))

(define-runtime-path vectors-dir "../vectors")

(struct nonce-row (secret message nonce) #:transparent)
(struct signing-row (secret digest compact recovery-id) #:transparent)
(struct wycheproof-row (tc-id comment public-key message der valid?) #:transparent)
(struct tiny-invalid-row
  (section description exception secret public-key digest compact recovery-id)
  #:transparent)

(define (vector-file . parts)
  (apply build-path vectors-dir parts))

(define (nonce-rows)
  (call-with-input-file (vector-file "rfc6979-nonces.rktd")
    (lambda (in)
      (for/list ([datum (in-port read in)])
        (match datum
          [(list 'nonce-row secret message nonce)
           (nonce-row (hex-string->bytes secret)
                      (string->bytes/utf-8 message)
                      (hex-string->bytes nonce))])))))

(define (tiny-fixture)
  (call-with-input-file (vector-file "tiny-secp256k1" "ecdsa.json") read-json))

(define (signing-rows)
  (for/list ([v (in-list (hash-ref (tiny-fixture) 'valid))])
    (signing-row (hex-string->bytes (hash-ref v 'd))
                 (hex-string->bytes (hash-ref v 'm))
                 (hex-string->bytes (hash-ref v 'signature))
                 (hash-ref v 'recoveryId))))

(define (optional-hex v key)
  (define s (hash-ref v key #f))
  (and s (hex-string->bytes s)))

(define (tiny-invalid-rows)
  (define invalid (hash-ref (tiny-fixture) 'invalid))
  (for*/list ([section (in-list '(sign verify recover))]
              [v (in-list (hash-ref invalid section))])
    (tiny-invalid-row section
                      (hash-ref v 'description)
                      (hash-ref v 'exception #f)
                      (optional-hex v 'd)
                      (optional-hex v 'Q)
                      (optional-hex v 'm)
                      (optional-hex v 'signature)
                      (hash-ref v 'recoveryId #f))))

(define (wycheproof-rows)
  (define fixture
    (call-with-input-file
      (vector-file "wycheproof" "ecdsa_secp256k1_sha256_bitcoin_test.json")
      read-json))
  (for*/list ([group (in-list (hash-ref fixture 'testGroups))]
              [t (in-list (hash-ref group 'tests))])
    (wycheproof-row (hash-ref t 'tcId)
                    (hash-ref t 'comment)
                    (hex-string->bytes (hash-ref (hash-ref group 'publicKey) 'uncompressed))
                    (hex-string->bytes (hash-ref t 'msg))
                    (hex-string->bytes (hash-ref t 'sig))
                    (string=? (hash-ref t 'result) "valid"))))
