#lang racket/base

(require (only-in file/sha1 bytes->hex-string)
         "exn.rkt"
         "ffi.rkt"
         "keys.rkt")

(provide compact->ecdsa-signature
         der->ecdsa-signature
         ecdsa-recover
         ecdsa-recoverable-signature
         ecdsa-recoverable-signature-recovery-id
         ecdsa-recoverable-signature?
         ecdsa-sign
         ecdsa-sign-recoverable
         ecdsa-signature
         ecdsa-signature->compact
         ecdsa-signature->der
         ecdsa-signature-low-s?
         ecdsa-signature-normalize
         ecdsa-signature-r
         ecdsa-signature-s
         ecdsa-signature?
         ecdsa-verify)

(define n #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

(define (integer->bytes32 v)
  (define bs (make-bytes 32 0))
  (for ([i (in-range 32)])
    (bytes-set! bs (- 31 i) (bitwise-and (arithmetic-shift v (* -8 i)) 255)))
  bs)

(define (bytes->integer bs)
  (for/fold ([v 0]) ([b (in-bytes bs)])
    (+ (* v 256) b)))

(define (signature-compact sig)
  (bytes-append (integer->bytes32 (ecdsa-signature-r sig))
                (integer->bytes32 (ecdsa-signature-s sig))))

(define (write-signature sig out _mode)
  (if (ecdsa-recoverable-signature? sig)
      (fprintf out "#<ecdsa-recoverable-signature ~a ~a>"
               (bytes->hex-string (signature-compact sig))
               (ecdsa-recoverable-signature-recovery-id sig))
      (fprintf out "#<ecdsa-signature ~a>" (bytes->hex-string (signature-compact sig)))))

(define (signature-fields sig)
  (list (ecdsa-recoverable-signature? sig)
        (ecdsa-signature-r sig)
        (ecdsa-signature-s sig)
        (and (ecdsa-recoverable-signature? sig) (ecdsa-recoverable-signature-recovery-id sig))))

(struct ecdsa-signature (r s)
  #:property prop:custom-write write-signature
  #:methods gen:equal+hash
  [(define (equal-proc a b _recur)
     (equal? (signature-fields a) (signature-fields b)))
   (define (hash-proc sig recur)
     (recur (signature-fields sig)))
   (define (hash2-proc sig recur)
     (recur (signature-fields sig)))])

(struct ecdsa-recoverable-signature ecdsa-signature (recovery-id))

(define (compact->signature compact)
  (ecdsa-signature (bytes->integer (subbytes compact 0 32))
                   (bytes->integer (subbytes compact 32 64))))

(define (signature->internal sig)
  (secp256k1_ecdsa_signature_parse_compact (signature-compact sig)))

(define (raise-signature-error message)
  (raise (exn:fail:libsecp256k1:signature message (current-continuation-marks))))

(define (signing-failed who)
  (raise (exn:fail:libsecp256k1:internal (format "~a: the nonce function failed" who)
                                         (current-continuation-marks))))

(define (ecdsa-sign digest key)
  (define internal (secp256k1_ecdsa_sign digest (secret-key-bytes key)))
  (unless internal
    (signing-failed 'ecdsa-sign))
  (compact->signature (secp256k1_ecdsa_signature_serialize_compact internal)))

(define (ecdsa-sign-recoverable digest key)
  (define internal (secp256k1_ecdsa_sign_recoverable digest (secret-key-bytes key)))
  (unless internal
    (signing-failed 'ecdsa-sign-recoverable))
  (define-values (compact id) (secp256k1_ecdsa_recoverable_signature_serialize_compact internal))
  (ecdsa-recoverable-signature (bytes->integer (subbytes compact 0 32))
                               (bytes->integer (subbytes compact 32 64))
                               id))

(define (ecdsa-verify sig digest key)
  (secp256k1_ecdsa_verify (signature->internal sig) digest (public-key-internal key)))

(define (ecdsa-recover sig digest)
  (define internal
    (secp256k1_ecdsa_recoverable_signature_parse_compact
     (signature-compact sig)
     (ecdsa-recoverable-signature-recovery-id sig)))
  (define recovered (and internal (secp256k1_ecdsa_recover internal digest)))
  (and recovered (internal->public-key recovered)))

(define (ecdsa-signature-low-s? sig)
  (<= (ecdsa-signature-s sig) (quotient (- n 1) 2)))

(define (ecdsa-signature-normalize sig)
  (cond
    [(ecdsa-signature-low-s? sig) sig]
    [(ecdsa-recoverable-signature? sig)
     (ecdsa-recoverable-signature (ecdsa-signature-r sig)
                                  (- n (ecdsa-signature-s sig))
                                  (bitwise-xor (ecdsa-recoverable-signature-recovery-id sig) 1))]
    [else (ecdsa-signature (ecdsa-signature-r sig) (- n (ecdsa-signature-s sig)))]))

(define (ecdsa-signature->compact sig)
  (signature-compact sig))

(define (compact->ecdsa-signature compact #:recovery-id [id #f])
  (define parsed
    (if id
        (secp256k1_ecdsa_recoverable_signature_parse_compact compact id)
        (secp256k1_ecdsa_signature_parse_compact compact)))
  (define r (bytes->integer (subbytes compact 0 32)))
  (define s (bytes->integer (subbytes compact 32 64)))
  (cond
    [(not parsed)
     (raise-signature-error (string-append "compact->ecdsa-signature: invalid signature;\n"
                                           " r or s is not less than the curve order"))]
    [id (ecdsa-recoverable-signature r s id)]
    [else (ecdsa-signature r s)]))

(define (ecdsa-signature->der sig)
  (secp256k1_ecdsa_signature_serialize_der (signature->internal sig)))

(define (der->ecdsa-signature der)
  (define internal (secp256k1_ecdsa_signature_parse_der der))
  (define sig
    (and internal (compact->signature (secp256k1_ecdsa_signature_serialize_compact internal))))
  (cond
    [(and sig (equal? (secp256k1_ecdsa_signature_serialize_der internal) der)) sig]
    [else
     (raise-signature-error
      (string-append "der->ecdsa-signature: invalid signature;\n"
                     " not strict DER, or r or s is negative or not less than the curve order"))]))
