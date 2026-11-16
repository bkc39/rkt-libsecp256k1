#lang racket/base

(module+ test
  (require file/sha1
           rackunit
           libsecp256k1)

  (define one (bytes->secret-key (bytes-append (make-bytes 31 0) #"\1")))
  (define pk (secret-key->public-key one))
  (define digest (sha256-bytes #"Satoshi Nakamoto"))
  (define sig (ecdsa-sign digest one))

  (define sig-hex
    (string-append "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
                   "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"))

  (test-case "README: a generated key signs, verifies and recovers"
    (define key (generate-secret-key))
    (define digest (sha256-bytes #"hello"))
    (define sig (ecdsa-sign-recoverable digest key))
    (check-true (ecdsa-verify sig digest (secret-key->public-key key)))
    (check-true (equal? (ecdsa-recover sig digest) (secret-key->public-key key))))

  (test-case "Secret Keys: a key prints opaquely, and zero is refused"
    (check-equal? (format "~s" one) "#<secret-key>")
    (check-exn (lambda (e)
                 (and (exn:fail:libsecp256k1:key? e)
                      (equal? (exn-message e)
                              (string-append "bytes->secret-key: invalid secret key;\n"
                                             " the value is zero or not less than the curve"
                                             " order"))))
               (lambda () (bytes->secret-key (make-bytes 32 0)))))

  (test-case "Public Keys: key 1 is G in both forms"
    (check-equal? (format "~s" pk)
                  "#<public-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798>")
    (check-equal? (bytes->hex-string (public-key->bytes pk #:compressed? #f))
                  (string-append
                   "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                   "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    (check-true (equal? pk (bytes->public-key (public-key->bytes pk #:compressed? #f)))))

  (test-case "ECDSA: signing \"Satoshi Nakamoto\" with key 1"
    (check-equal? (format "~s" sig) (string-append "#<ecdsa-signature " sig-hex ">"))
    (check-true (ecdsa-verify sig digest pk)))

  (test-case "ECDSA: a high-S twin verifies only after normalizing"
    (define high (ecdsa-signature (ecdsa-signature-r sig)
                                  (- secp256k1-order (ecdsa-signature-s sig))))
    (check-false (ecdsa-verify high digest pk))
    (check-true (equal? (ecdsa-signature-normalize high) sig)))

  (test-case "Encodings: DER"
    (check-equal? (bytes->hex-string (ecdsa-signature->der sig))
                  (string-append
                   "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
                   "02202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"))
    (check-true (equal? (der->ecdsa-signature (ecdsa-signature->der sig)) sig)))

  (test-case "Public Key Recovery: the id and the recovered key"
    (define rsig (ecdsa-sign-recoverable digest one))
    (check-equal? (ecdsa-recoverable-signature-recovery-id rsig) 1)
    (check-true (equal? (ecdsa-recover rsig digest) pk)))

  (test-case "Tweaks: key 1 tweaked by 1 is key 2"
    (define t (bytes-append (make-bytes 31 0) #"\1"))
    (check-equal? (format "~s" (secret-key->public-key (secret-key-tweak-add one t)))
                  "#<public-key 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5>")
    (check-true (equal? (public-key-tweak-add pk t)
                        (secret-key->public-key (secret-key-tweak-add one t))))))
