#lang racket/base

(module+ test
  (require (only-in file/sha1 hex-string->bytes)
           (only-in racket/contract exn:fail:contract:blame?)
           (only-in racket/port with-output-to-string)
           (only-in racket/string string-split)
           rackunit
           libsecp256k1
           "../../examples/03-encodings.rkt"
           (only-in "../helpers/util.rkt" example-key-integer raised?))

  (define one (integer->secret-key 1))
  (define digest (sha256-bytes #"Satoshi Nakamoto"))
  (define sig (ecdsa-sign digest one))
  (define rsig (ecdsa-sign-recoverable digest one))
  (define r-hex "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8")
  (define s-hex "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5")
  (define der (ecdsa-signature->der sig))

  (test-case "run prints the compact and DER forms, and both parse back"
    (define example-r "a3972ac78ab90b6a703c622ce49ef32c3dfee67ccd746f182bc338e822044eaf")
    (define example-s "1d95fdd881ff606339e5b5d731fd6545ecc2d81858beb8bff40ed983bdf6a75f")
    (check-equal? (string-split (with-output-to-string
                                  (lambda () (run (integer->secret-key example-key-integer))))
                                "\n")
                  (list (string-append "compact: " example-r example-s)
                        (string-append "DER:     3045022100" example-r "0220" example-s)
                        "both parse back: #t")))

  (test-case "compact is r || s, and parses back"
    (check-equal? (signature->compact-hex sig) (string-append r-hex s-hex))
    (check-equal? (compact-hex->signature (signature->compact-hex sig)) sig))

  (test-case "a recoverable signature's compact form leaves out the id"
    (check-equal? (signature->compact-hex rsig) (string-append r-hex s-hex))
    (check-equal? (compact->ecdsa-recoverable-signature (ecdsa-signature->compact rsig)
                                                        (ecdsa-recoverable-signature-id rsig))
                  rsig))

  (test-case "DER is 71 bytes here, and parses back"
    (check-equal? (signature->der-hex sig) (string-append "3045022100" r-hex "0220" s-hex))
    (check-equal? (bytes-length der) 71)
    (check-equal? (der-hex->signature (signature->der-hex sig)) sig))

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
               (lambda () (compact-hex->signature (make-string 128 #\f)))))

  (test-case "a recovery id of 4 is a contract violation"
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: an integer from 0 to 3\n  given: an exact integer")
               (lambda ()
                 (compact->ecdsa-recoverable-signature (ecdsa-signature->compact sig) 4)))))
