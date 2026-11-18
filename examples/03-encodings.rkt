#lang racket/base

(require file/sha1
         libsecp256k1)

(provide compact-hex->signature
         der-hex->signature
         run
         signature->compact-hex
         signature->der-hex)

(define (signature->compact-hex sig)
  (bytes->hex-string (ecdsa-signature->compact sig)))

(define (compact-hex->signature hex)
  (compact->ecdsa-signature (hex-string->bytes hex)))

(define (signature->der-hex sig)
  (bytes->hex-string (ecdsa-signature->der sig)))

(define (der-hex->signature hex)
  (der->ecdsa-signature (hex-string->bytes hex)))

(define (run key)
  (define sig (ecdsa-sign (sha256-bytes #"hello") key))
  (define compact (signature->compact-hex sig))
  (define der (signature->der-hex sig))
  (printf "compact: ~a\n" compact)
  (printf "DER:     ~a\n" der)
  (printf "both parse back: ~a\n"
          (and (equal? (compact-hex->signature compact) sig)
               (equal? (der-hex->signature der) sig))))

(module+ main
  (run (generate-secret-key)))
