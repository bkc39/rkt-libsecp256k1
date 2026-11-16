#lang racket/base

(require (for-syntax racket/base
                     syntax/parse)
         ffi/unsafe
         (only-in ffi/unsafe/atomic call-as-atomic)
         (only-in racket/random crypto-random-bytes)
         syntax/parse/define
         "exn.rkt"
         "locate.rkt")

(provide error-callback
         illegal-callback
         libsecp256k1-origin
         raise-libsecp256k1
         secp256k1_ec_pubkey_combine
         secp256k1_ec_pubkey_create
         secp256k1_ec_pubkey_negate
         secp256k1_ec_pubkey_parse
         secp256k1_ec_pubkey_serialize
         secp256k1_ec_pubkey_tweak_add
         secp256k1_ec_seckey_negate
         secp256k1_ec_seckey_tweak_add
         secp256k1_ec_seckey_verify
         secp256k1_ecdsa_recover
         secp256k1_ecdsa_recoverable_signature_parse_compact
         secp256k1_ecdsa_recoverable_signature_serialize_compact
         secp256k1_ecdsa_sign
         secp256k1_ecdsa_sign_recoverable
         secp256k1_ecdsa_signature_parse_compact
         secp256k1_ecdsa_signature_parse_der
         secp256k1_ecdsa_signature_serialize_compact
         secp256k1_ecdsa_signature_serialize_der
         secp256k1_ecdsa_verify
         SECP256K1_EC_COMPRESSED
         SECP256K1_EC_UNCOMPRESSED)

(define SECP256K1_CONTEXT_NONE 1)
(define SECP256K1_EC_COMPRESSED #x102)
(define SECP256K1_EC_UNCOMPRESSED #x2)

(define (libsecp256k1-error make-exn who fmt . args)
  (make-exn (format "~a: ~a" who (apply format fmt args)) (current-continuation-marks)))

(define (raise-libsecp256k1 make-exn who fmt . args)
  (raise (apply libsecp256k1-error make-exn who fmt args)))

(define (illegal-callback message _data)
  (raise-libsecp256k1 exn:fail:libsecp256k1:illegal-argument 'libsecp256k1
                      "illegal argument: ~a" message))

(define (error-callback message _data)
  (raise-libsecp256k1 exn:fail:libsecp256k1:internal 'libsecp256k1 "internal error: ~a" message))

(define _callback (_fun #:atomic? #t _string/utf-8 _pointer -> _void))

(define-values (origin lib load-failure)
  (locate-library (getenv "LIBSECP256K1_LIBRARY")))

(define (foreign c-name type)
  (get-ffi-obj c-name lib type))

;; One context per module instance, never destroyed: a custodian could free it under an
;; instance shared between namespaces.
(define context
  (and lib ((foreign "secp256k1_context_create" (_fun _uint -> _pointer)) SECP256K1_CONTEXT_NONE)))

(when context
  (define set-callback (_fun _pointer _callback _pointer -> _void))
  ((foreign "secp256k1_context_set_illegal_callback" set-callback) context illegal-callback #f)
  ((foreign "secp256k1_context_set_error_callback" set-callback) context error-callback #f))

(define randomized?
  (and context
       ((foreign "secp256k1_context_randomize" (_fun _pointer _bytes -> _bool))
        context
        (crypto-random-bytes 32))))

(define failure
  (cond
    [load-failure load-failure]
    [(not context)
     (libsecp256k1-error exn:fail:libsecp256k1:internal 'libsecp256k1
                         "internal error: could not create a context")]
    [(not randomized?)
     (libsecp256k1-error exn:fail:libsecp256k1:internal 'libsecp256k1
                         "internal error: could not randomize the context")]
    [else #f]))

(define (libsecp256k1-origin)
  (if failure (raise failure) origin))

(define (callout c-name type)
  (if failure
      (lambda _ (raise failure))
      (foreign c-name type)))

;; A callback may raise, and Racket CS loses track of the foreign frame when a thread swap
;; separates the callout from that raise, so every call runs in atomic mode.
(define (atomic-call raw args)
  (call-as-atomic (lambda () (apply raw args))))

(define (call-or-fail raw args make-exn who message)
  (or (atomic-call raw args)
      (and make-exn (raise-libsecp256k1 make-exn who "~a" message))))

(begin-for-syntax
  (define-syntax-class failure
    #:description
    "a failure action: #f, (key-error message), (signature-error message) or (internal-error message)"
    #:attributes (make-exn message)
    (pattern #f
             #:with make-exn #'#f
             #:with message #'"")
    (pattern ((~datum key-error) message:expr)
             #:with make-exn #'exn:fail:libsecp256k1:key)
    (pattern ((~datum signature-error) message:expr)
             #:with make-exn #'exn:fail:libsecp256k1:signature)
    (pattern ((~datum internal-error) message:expr)
             #:with make-exn #'exn:fail:libsecp256k1:internal)))

(define-syntax-parser define-secp
  [(_ name:id argument:expr ... #:result result:expr #:failure on-failure:failure)
   #:with c-name (datum->syntax #'name (symbol->string (syntax-e #'name)))
   #'(define name
       (let ([raw (callout c-name
                           (_fun #:callback-exns? #t (_pointer = context) argument ...
                                 -> (ok : _int) -> (and (= ok 1) result)))])
         (lambda (who . args)
           (call-or-fail raw args on-failure.make-exn who on-failure.message))))]
  [(_ name:id argument:expr ... #:predicate)
   #:with c-name (datum->syntax #'name (symbol->string (syntax-e #'name)))
   #'(define name
       (let ([raw (callout c-name
                           (_fun #:callback-exns? #t (_pointer = context) argument ...
                                 -> (ok : _int) -> (= ok 1)))])
         (lambda (_who . args)
           (atomic-call raw args))))])

(define-secp secp256k1_ec_seckey_verify _bytes #:predicate)

(define-secp secp256k1_ec_seckey_tweak_add
  (key : _?) (sum : _bytes = (bytes-copy key)) _bytes
  #:result sum
  #:failure (key-error (string-append "invalid tweak;\n the tweak is not less than the curve"
                                      " order, or the sum is zero")))

(define-secp secp256k1_ec_seckey_negate
  (key : _?) (negated : _bytes = (bytes-copy key))
  #:result negated
  #:failure (internal-error "could not negate the key"))

(define-secp secp256k1_ec_pubkey_create
  (pubkey : (_bytes o 64)) _bytes
  #:result pubkey
  #:failure (internal-error "could not derive the public key"))

(define-secp secp256k1_ec_pubkey_parse
  (pubkey : (_bytes o 64)) (input : _bytes) (_size = (bytes-length input))
  #:result pubkey
  #:failure (key-error "invalid public key;\n the bytes do not encode a point on the curve"))

(define-secp secp256k1_ec_pubkey_serialize
  (out : (_bytes o 65)) (len : (_ptr io _size) = 65) _bytes _uint
  #:result (subbytes out 0 len)
  #:failure (internal-error "could not serialize the public key"))

(define-secp secp256k1_ec_pubkey_tweak_add
  (key : _?) (sum : _bytes = (bytes-copy key)) _bytes
  #:result sum
  #:failure (key-error (string-append "invalid tweak;\n the tweak is not less than the curve"
                                      " order, or the sum is the point at infinity")))

(define-secp secp256k1_ec_pubkey_negate
  (key : _?) (negated : _bytes = (bytes-copy key))
  #:result negated
  #:failure (internal-error "could not negate the key"))

(define-secp secp256k1_ec_pubkey_combine
  (out : (_bytes o 64)) (ins : (_list i _bytes)) (_size = (length ins))
  #:result out
  #:failure (key-error "the sum is the point at infinity"))

(define-secp secp256k1_ecdsa_sign
  (sig : (_bytes o 64)) _bytes _bytes (_pointer = #f) (_pointer = #f)
  #:result sig
  #:failure (internal-error "the nonce function failed"))

(define-secp secp256k1_ecdsa_verify _bytes _bytes _bytes #:predicate)

(define-secp secp256k1_ecdsa_signature_parse_compact
  (sig : (_bytes o 64)) _bytes
  #:result sig
  #:failure (signature-error "invalid signature;\n r or s is not less than the curve order"))

(define-secp secp256k1_ecdsa_signature_serialize_compact
  (out : (_bytes o 64)) _bytes
  #:result out
  #:failure (internal-error "could not serialize the signature"))

(define-secp secp256k1_ecdsa_signature_parse_der
  (sig : (_bytes o 64)) (input : _bytes) (_size = (bytes-length input))
  #:result sig
  #:failure #f)

(define-secp secp256k1_ecdsa_signature_serialize_der
  (out : (_bytes o 72)) (len : (_ptr io _size) = 72) _bytes
  #:result (subbytes out 0 len)
  #:failure (internal-error "could not serialize the signature"))

(define-secp secp256k1_ecdsa_sign_recoverable
  (sig : (_bytes o 65)) _bytes _bytes (_pointer = #f) (_pointer = #f)
  #:result sig
  #:failure (internal-error "the nonce function failed"))

(define-secp secp256k1_ecdsa_recoverable_signature_parse_compact
  (sig : (_bytes o 65)) _bytes _int
  #:result sig
  #:failure (signature-error "invalid signature;\n r or s is not less than the curve order"))

(define-secp secp256k1_ecdsa_recoverable_signature_serialize_compact
  (out : (_bytes o 64)) (id : (_ptr o _int)) _bytes
  #:result (cons out id)
  #:failure (internal-error "could not serialize the signature"))

(define-secp secp256k1_ecdsa_recover
  (pubkey : (_bytes o 64)) _bytes _bytes
  #:result pubkey
  #:failure #f)
