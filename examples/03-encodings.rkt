#lang racket/base

(require file/sha1
         libsecp256k1)

(define (signature->hex sig #:der? [der? #f])
  (bytes->hex-string (if der? (ecdsa-signature->der sig) (ecdsa-signature->compact sig))))

(define (hex->signature hex #:der? [der? #f])
  (define bs (hex-string->bytes hex))
  (if der? (der->ecdsa-signature bs) (compact->ecdsa-signature bs)))

(module+ main
  (define key (generate-secret-key))
  (define sig (ecdsa-sign (sha256-bytes #"hello") key))
  (define compact (signature->hex sig))
  (define der (signature->hex sig #:der? #t))
  (printf "public key: ~a\n" (bytes->hex-string (public-key->bytes (secret-key->public-key key))))
  (printf "compact:    ~a\n" compact)
  (printf "DER:        ~a\n" der)
  (printf "both parse back: ~a\n"
          (and (equal? (hex->signature compact) sig)
               (equal? (hex->signature der #:der? #t) sig))))

(module+ test
  (require (only-in racket/contract exn:fail:contract:blame?)
           rackunit)

  (define ((raised? predicate pattern) e)
    (and (predicate e) (regexp-match? pattern (exn-message e))))

  (define one (integer->secret-key 1))
  (define digest (sha256-bytes #"Satoshi Nakamoto"))
  (define sig (ecdsa-sign digest one))
  (define rsig (ecdsa-sign-recoverable digest one))
  (define r-hex "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8")
  (define s-hex "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5")
  (define der (ecdsa-signature->der sig))

  (test-case "compact is r || s, and parses back"
    (check-equal? (signature->hex sig) (string-append r-hex s-hex))
    (check-equal? (hex->signature (signature->hex sig)) sig))

  (test-case "a recoverable signature's compact form leaves out the id"
    (check-equal? (signature->hex rsig) (string-append r-hex s-hex))
    (check-equal? (compact->ecdsa-recoverable-signature (ecdsa-signature->compact rsig)
                                                        (ecdsa-recoverable-signature-id rsig))
                  rsig))

  (test-case "DER is 71 bytes here, and parses back"
    (check-equal? (signature->hex sig #:der? #t)
                  (string-append "3045022100" r-hex "0220" s-hex))
    (check-equal? (bytes-length der) 71)
    (check-equal? (hex->signature (signature->hex sig #:der? #t) #:der? #t) sig))

  (test-case "a trailing byte, a truncation and a negative r are not strict DER"
    (define not-der #rx"invalid signature;\n not strict DER, or r or s is negative or not less")
    (for ([bs (in-list (list (bytes-append der #"\0")
                             (subbytes der 0 40)
                             (hex-string->bytes "3006020181020101")))])
      (check-exn (raised? exn:fail:libsecp256k1:signature? not-der)
                 (lambda () (der->ecdsa-signature bs)))))

  (test-case "compact r and s must be less than the order"
    (check-exn (raised? exn:fail:libsecp256k1:signature?
                        #rx"invalid signature;\n r or s is not less than the curve order")
               (lambda () (hex->signature (make-string 128 #\f)))))

  (test-case "a recovery id of 4 is a contract violation"
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: an integer from 0 to 3\n  given: an exact integer")
               (lambda ()
                 (compact->ecdsa-recoverable-signature (ecdsa-signature->compact sig) 4)))))
