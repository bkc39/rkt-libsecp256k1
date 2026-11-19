#lang racket/base

(require (only-in file/sha1 bytes->hex-string)
         (only-in racket/match match-define)
         "exn.rkt"
         "ffi.rkt"
         "keys.rkt"
         "scalar.rkt")

(provide compact->ecdsa-recoverable-signature
         compact->ecdsa-signature
         der->ecdsa-signature
         ecdsa-recover
         ecdsa-recoverable-signature
         ecdsa-recoverable-signature-id
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

(struct ecdsa-signature (r s)
  #:property prop:custom-write
  (lambda (sig out _mode)
    (fprintf out "#<ecdsa-signature ~a>" (bytes->hex-string (ecdsa-signature->compact sig))))
  #:methods gen:equal+hash
  [(define (equal-proc a b recur)
     (and (recur (ecdsa-signature-r a) (ecdsa-signature-r b))
          (recur (ecdsa-signature-s a) (ecdsa-signature-s b))))
   (define (hash-proc sig recur)
     (recur (list (ecdsa-signature-r sig) (ecdsa-signature-s sig))))
   (define (hash2-proc sig recur)
     (recur (list (ecdsa-signature-r sig) (ecdsa-signature-s sig))))])

(struct ecdsa-recoverable-signature ecdsa-signature (id)
  #:property prop:custom-write
  (lambda (sig out _mode)
    (fprintf out "#<ecdsa-recoverable-signature ~a id=~a>"
             (bytes->hex-string (ecdsa-signature->compact sig))
             (ecdsa-recoverable-signature-id sig)))
  #:methods gen:equal+hash
  [(define (equal-proc a b recur)
     (recur (recoverable-fields a) (recoverable-fields b)))
   (define (hash-proc sig recur)
     (recur (recoverable-fields sig)))
   (define (hash2-proc sig recur)
     (recur (recoverable-fields sig)))])

(define (recoverable-fields sig)
  (list (ecdsa-signature-r sig) (ecdsa-signature-s sig) (ecdsa-recoverable-signature-id sig)))

(define (ecdsa-signature->compact sig)
  (bytes-append (integer->bytes32 (ecdsa-signature-r sig))
                (integer->bytes32 (ecdsa-signature-s sig))))

(define (compact-r compact)
  (bytes->integer (subbytes compact 0 32)))

(define (compact-s compact)
  (bytes->integer (subbytes compact 32 64)))

(define (signature->internal who sig)
  (secp256k1_ecdsa_signature_parse_compact who (ecdsa-signature->compact sig)))

(define (internal->signature who internal)
  (define compact (secp256k1_ecdsa_signature_serialize_compact who internal))
  (ecdsa-signature (compact-r compact) (compact-s compact)))

(define (sign-compact who sign serialize digest key)
  (serialize who (sign who digest (secret-key-bytes key))))

(define/snapshot (ecdsa-sign digest key) #:snapshot (digest)
  (define compact
    (sign-compact 'ecdsa-sign secp256k1_ecdsa_sign secp256k1_ecdsa_signature_serialize_compact
                  digest key))
  (ecdsa-signature (compact-r compact) (compact-s compact)))

(define/snapshot (ecdsa-sign-recoverable digest key) #:snapshot (digest)
  (match-define (cons compact id)
    (sign-compact 'ecdsa-sign-recoverable
                  secp256k1_ecdsa_sign_recoverable
                  secp256k1_ecdsa_recoverable_signature_serialize_compact
                  digest key))
  (ecdsa-recoverable-signature (compact-r compact) (compact-s compact) id))

(define/snapshot (ecdsa-verify sig digest key) #:snapshot (digest)
  (secp256k1_ecdsa_verify 'ecdsa-verify
                          (signature->internal 'ecdsa-verify sig)
                          digest
                          (public-key-internal key)))

(define/snapshot (ecdsa-recover sig digest) #:snapshot (digest)
  (define internal
    (secp256k1_ecdsa_recoverable_signature_parse_compact 'ecdsa-recover
                                                         (ecdsa-signature->compact sig)
                                                         (ecdsa-recoverable-signature-id sig)))
  (define recovered (secp256k1_ecdsa_recover 'ecdsa-recover internal digest))
  (and recovered (internal->public-key 'ecdsa-recover recovered)))

(define (ecdsa-signature-low-s? sig)
  (<= (ecdsa-signature-s sig) half-order))

(define (ecdsa-signature-normalize sig)
  (define r (ecdsa-signature-r sig))
  (define high-s (- secp256k1-order (ecdsa-signature-s sig)))
  (cond
    [(ecdsa-signature-low-s? sig) sig]
    [(ecdsa-recoverable-signature? sig)
     (ecdsa-recoverable-signature r high-s (bitwise-xor (ecdsa-recoverable-signature-id sig) 1))]
    [else (ecdsa-signature r high-s)]))

(define/snapshot (compact->ecdsa-signature compact) #:snapshot (compact)
  (secp256k1_ecdsa_signature_parse_compact 'compact->ecdsa-signature compact)
  (ecdsa-signature (compact-r compact) (compact-s compact)))

(define/snapshot (compact->ecdsa-recoverable-signature compact id) #:snapshot (compact)
  (secp256k1_ecdsa_recoverable_signature_parse_compact 'compact->ecdsa-recoverable-signature
                                                       compact id)
  (ecdsa-recoverable-signature (compact-r compact) (compact-s compact) id))

(define (ecdsa-signature->der sig)
  (secp256k1_ecdsa_signature_serialize_der 'ecdsa-signature->der
                                           (signature->internal 'ecdsa-signature->der sig)))

(define/snapshot (der->ecdsa-signature der) #:snapshot (der)
  (define internal (secp256k1_ecdsa_signature_parse_der 'der->ecdsa-signature der))
  (cond
    [(and internal
          (equal? (secp256k1_ecdsa_signature_serialize_der 'der->ecdsa-signature internal) der))
     (internal->signature 'der->ecdsa-signature internal)]
    [else
     (raise-libsecp256k1 exn:fail:libsecp256k1:signature 'der->ecdsa-signature
                         (string-append "invalid signature;\n not strict DER, or r or s is"
                                        " negative or not less than the curve order"))]))
