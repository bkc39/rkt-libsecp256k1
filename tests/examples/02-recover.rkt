#lang racket/base

(module+ test
  (require (only-in file/sha1 bytes->hex-string)
           (only-in racket/port with-output-to-string)
           (only-in racket/string string-split)
           rackunit
           libsecp256k1
           "../../examples/02-recover.rkt"
           (only-in "../helpers/util.rkt" example-key-integer))

  (define one (integer->secret-key 1))
  (define one-public (secret-key->public-key one))
  (define digest (sha256-bytes #"Satoshi Nakamoto"))
  (define rsig (ecdsa-sign-recoverable digest one))
  (define rsv (signature->rsv rsig))

  (define (with-v v)
    (bytes-append (subbytes rsv 0 64) (bytes v)))

  (define (invalid-signature? message)
    (lambda (e)
      (and (exn:fail:libsecp256k1:signature? e) (equal? (exn-message e) message))))

  (test-case "run prints the signer, the signature with v, and the key it recovers"
    (define example-public
      "024a321ddaaf494e410cfde06e140b7d605a9f3f7015978330585db24062bfab70")
    (check-equal? (string-split (with-output-to-string
                                  (lambda () (run (integer->secret-key example-key-integer))))
                                "\n")
                  (list (string-append "public key: " example-public)
                        (string-append "signature:  "
                                       "a3972ac78ab90b6a703c622ce49ef32c3dfee67ccd746f182bc338e822044eaf"
                                       "1d95fdd881ff606339e5b5d731fd6545ecc2d81858beb8bff40ed983bdf6a75f"
                                       "1c")
                        (string-append "recovered:  " example-public)
                        "recovered the signer: #t")))

  (test-case "a recoverable signature is the plain signature with a recovery id"
    (check-equal? (ecdsa-recoverable-signature-id rsig) 1)
    (check-equal? (ecdsa-signature->compact rsig)
                  (ecdsa-signature->compact (ecdsa-sign digest one))))

  (test-case "r || s || v carries the id as v = 27 + id and survives a round trip"
    (check-equal? v-offset 27)
    (check-equal? (bytes-ref rsv 64) (+ v-offset 1))
    (check-equal? (bytes->hex-string rsv)
                  (string-append
                   "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
                   "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
                   "1c"))
    (check-equal? (rsv->signature rsv) rsig)
    (check-equal? (ecdsa-recoverable-signature-id (rsv->signature (with-v v-offset))) 0))

  (test-case "the signature and digest recover the signer"
    (check-equal? (recover-signer rsv digest) one-public))

  (test-case "another digest recovers another key"
    (define other (recover-signer rsv (sha256-bytes #"Hal Finney")))
    (check-equal? (bytes->hex-string (public-key->bytes other))
                  "03e8e636e6e742c3e93580474b327b262e2c4ed2b82c8557418408d76a41281fcf")
    (check-not-equal? other one-public))

  (test-case "an id that selects no point recovers nothing"
    (check-false (ecdsa-recover (compact->ecdsa-recoverable-signature (subbytes rsv 0 64) 2)
                                digest)))

  (test-case "a recoverable signature verifies as a plain one"
    (check-pred ecdsa-signature? rsig)
    (check-true (ecdsa-verify rsig digest one-public)))

  (test-case "v must be 27 or 28, as in Ethereum, and the rsv must be 65 bytes"
    (for ([bad (in-list (list (with-v (- v-offset 1))
                              (with-v (+ v-offset 2))
                              (with-v (+ v-offset 3))
                              (with-v 31)
                              (subbytes rsv 0 64)
                              (bytes-append rsv #"\0")))])
      (check-exn (invalid-signature? "rsv->signature: expected 65 bytes ending in v = 27 or 28")
                 (lambda () (rsv->signature bad)))))

  (test-case "a recovery id of 2 or 3 has no v"
    (for ([id (in-list '(2 3))])
      (check-exn (invalid-signature? "signature->rsv: the recovery id is not 0 or 1")
                 (lambda ()
                   (signature->rsv
                    (compact->ecdsa-recoverable-signature (subbytes rsv 0 64) id)))))))
