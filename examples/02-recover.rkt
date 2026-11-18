#lang racket/base

(require file/sha1
         libsecp256k1)

(define (signature->rsv sig)
  (bytes-append (ecdsa-signature->compact sig)
                (bytes (+ 27 (ecdsa-recoverable-signature-id sig)))))

(define (rsv->signature rsv)
  (compact->ecdsa-recoverable-signature (subbytes rsv 0 64) (- (bytes-ref rsv 64) 27)))

(define (recover-signer rsv digest)
  (ecdsa-recover (rsv->signature rsv) digest))

(module+ main
  (define key (generate-secret-key))
  (define public (secret-key->public-key key))
  (define digest (sha256-bytes #"hello"))
  (define rsv (signature->rsv (ecdsa-sign-recoverable digest key)))
  (define signer (recover-signer rsv digest))
  (printf "public key: ~a\n" (bytes->hex-string (public-key->bytes public)))
  (printf "signature:  ~a\n" (bytes->hex-string rsv))
  (printf "recovered:  ~a\n" (bytes->hex-string (public-key->bytes signer)))
  (printf "recovered the signer: ~a\n" (equal? signer public)))

(module+ test
  (require (only-in racket/contract exn:fail:contract:blame?)
           rackunit)

  (define ((raised? predicate pattern) e)
    (and (predicate e) (regexp-match? pattern (exn-message e))))

  (define one (integer->secret-key 1))
  (define one-public (secret-key->public-key one))
  (define digest (sha256-bytes #"Satoshi Nakamoto"))
  (define rsig (ecdsa-sign-recoverable digest one))
  (define rsv (signature->rsv rsig))

  (test-case "a recoverable signature is the plain signature with a recovery id"
    (check-equal? (ecdsa-recoverable-signature-id rsig) 1)
    (check-equal? (ecdsa-signature->compact rsig)
                  (ecdsa-signature->compact (ecdsa-sign digest one))))

  (test-case "r || s || v carries the id as v = 27 + id and survives a round trip"
    (check-equal? (bytes->hex-string rsv)
                  (string-append
                   "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8"
                   "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
                   "1c"))
    (check-equal? (rsv->signature rsv) rsig))

  (test-case "the signature and digest recover the signer"
    (check-equal? (recover-signer rsv digest) one-public))

  (test-case "another digest recovers another key"
    (define other (recover-signer rsv (sha256-bytes #"Hal Finney")))
    (check-equal? (bytes->hex-string (public-key->bytes other))
                  "03e8e636e6e742c3e93580474b327b262e2c4ed2b82c8557418408d76a41281fcf")
    (check-not-equal? other one-public))

  (test-case "an id that selects no point recovers nothing"
    (check-false (recover-signer (bytes-append (subbytes rsv 0 64) (bytes (+ 27 2))) digest)))

  (test-case "a recoverable signature verifies as a plain one"
    (check-pred ecdsa-signature? rsig)
    (check-true (ecdsa-verify rsig digest one-public)))

  (test-case "a v that is not 27 to 30 is a contract violation"
    (check-exn (raised? exn:fail:contract:blame?
                        #rx"expected: an integer from 0 to 3\n  given: an exact integer")
               (lambda () (rsv->signature (bytes-append (subbytes rsv 0 64) #"\37"))))))
