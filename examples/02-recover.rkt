#lang racket/base

(require file/sha1
         libsecp256k1)

(provide public-key->hex
         recover-signer
         rsv->signature
         run
         signature->rsv
         v-offset)

(define v-offset 27)

(define (signature->rsv sig)
  (define id (ecdsa-recoverable-signature-id sig))
  (cond
    [(<= id 1) (bytes-append (ecdsa-signature->compact sig) (bytes (+ v-offset id)))]
    [else (raise (exn:fail:libsecp256k1:signature
                  "signature->rsv: the recovery id is not 0 or 1"
                  (current-continuation-marks)))]))

(define (rsv->signature rsv)
  (cond
    [(and (= (bytes-length rsv) 65) (<= v-offset (bytes-ref rsv 64) (+ v-offset 1)))
     (compact->ecdsa-recoverable-signature (subbytes rsv 0 64) (- (bytes-ref rsv 64) v-offset))]
    [else (raise (exn:fail:libsecp256k1:signature
                  "rsv->signature: expected 65 bytes ending in v = 27 or 28"
                  (current-continuation-marks)))]))

(define (recover-signer rsv digest)
  (ecdsa-recover (rsv->signature rsv) digest))

(define (public-key->hex key)
  (bytes->hex-string (public-key->bytes key)))

(define (run key)
  (define public (secret-key->public-key key))
  (define digest (sha256-bytes #"hello"))
  (define rsv (signature->rsv (ecdsa-sign-recoverable digest key)))
  (define signer (recover-signer rsv digest))
  (printf "public key: ~a\n" (public-key->hex public))
  (printf "signature:  ~a\n" (bytes->hex-string rsv))
  (printf "recovered:  ~a\n" (public-key->hex signer))
  (printf "recovered the signer: ~a\n" (equal? signer public)))

(module+ main
  (run (generate-secret-key)))
