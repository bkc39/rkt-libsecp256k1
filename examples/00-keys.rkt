#lang racket/base

(require file/sha1
         libsecp256k1)

(provide hex->public-key
         hex->secret-key
         public-key->hex
         run
         secret-key->hex)

(define (secret-key->hex key)
  (bytes->hex-string (secret-key->bytes key)))

(define (hex->secret-key hex)
  (cond
    [(and (string? hex) (regexp-match? #px"^[0-9a-fA-F]{64}$" hex))
     (bytes->secret-key (hex-string->bytes hex))]
    [else (raise (exn:fail:libsecp256k1:key "hex->secret-key: expected 64 hex digits"
                                            (current-continuation-marks)))]))

(define (public-key->hex key #:compressed? [compressed? #t])
  (bytes->hex-string (public-key->bytes key #:compressed? compressed?)))

(define (hex->public-key hex)
  (bytes->public-key (hex-string->bytes hex)))

(define (run key)
  (define public (secret-key->public-key key))
  (define restored (hex->secret-key (secret-key->hex key)))
  (printf "public key:   ~a\n" (public-key->hex public))
  (printf "uncompressed: ~a\n" (public-key->hex public #:compressed? #f))
  (printf "restored key has the same public key: ~a\n"
          (equal? (secret-key->public-key restored) public)))

(module+ main
  (run (generate-secret-key)))
