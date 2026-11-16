#lang racket/base

(require (for-syntax racket/base)
         ffi/unsafe
         (only-in racket/random crypto-random-bytes)
         syntax/parse/define
         "exn.rkt"
         "locate.rkt")

(provide error-callback
         illegal-callback
         libsecp256k1-origin
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

(define (illegal-callback message _data)
  (raise (exn:fail:libsecp256k1:illegal-argument
          (string-append "libsecp256k1: illegal argument: " message)
          (current-continuation-marks))))

(define (error-callback message _data)
  (raise (exn:fail:libsecp256k1:internal
          (string-append "libsecp256k1: internal error: " message)
          (current-continuation-marks))))

(define _callback (_fun #:atomic? #t _string/utf-8 _pointer -> _void))

(define-values (origin lib load-failure)
  (locate-library (getenv "LIBSECP256K1_LIBRARY")))

(define (setup name type)
  (get-ffi-obj name lib type))

;; One context per module instance, never destroyed: a custodian could free
;; it under an instance shared between namespaces.
(define context
  (and lib ((setup "secp256k1_context_create" (_fun _uint -> _pointer)) SECP256K1_CONTEXT_NONE)))

(when context
  (define set-callback (_fun #:callback-exns? #t _pointer _callback _pointer -> _void))
  ((setup "secp256k1_context_set_illegal_callback" set-callback) context illegal-callback #f)
  ((setup "secp256k1_context_set_error_callback" set-callback) context error-callback #f))

(define randomized?
  (and context
       ((setup "secp256k1_context_randomize" (_fun #:callback-exns? #t _pointer _bytes -> _bool))
        context
        (crypto-random-bytes 32))))

(define (internal-failure what)
  (exn:fail:libsecp256k1:internal (string-append "libsecp256k1: internal error: " what)
                                  (current-continuation-marks)))

(define failure
  (cond
    [load-failure load-failure]
    [(not context) (internal-failure "could not create a context")]
    [(not randomized?) (internal-failure "could not randomize the context")]
    [else #f]))

(define (libsecp256k1-origin)
  (if failure (raise failure) origin))

(define (callout name type)
  (if failure
      (lambda _ (raise failure))
      (get-ffi-obj name lib type)))

(define-syntax-parse-rule (define-callout name:id type:expr)
  #:with c-name (datum->syntax #'name (symbol->string (syntax-e #'name)))
  (define name (callout c-name type)))

(define-syntax-parse-rule (_secp-fun part ...)
  (_fun #:callback-exns? #t (_pointer = context) part ...))

(define-callout secp256k1_ec_seckey_verify
  (_secp-fun _bytes -> _bool))

(define-callout secp256k1_ec_seckey_tweak_add
  (_secp-fun (seckey : _bytes) _bytes -> (ok : _bool) -> (and ok seckey)))

(define-callout secp256k1_ec_seckey_negate
  (_secp-fun (seckey : _bytes) -> (ok : _bool) -> (and ok seckey)))

(define-callout secp256k1_ec_pubkey_create
  (_secp-fun (pubkey : (_bytes o 64)) _bytes -> (ok : _bool) -> (and ok pubkey)))

(define-callout secp256k1_ec_pubkey_parse
  (_secp-fun (pubkey : (_bytes o 64)) (input : _bytes) (_size = (bytes-length input))
             -> (ok : _bool) -> (and ok pubkey)))

(define-callout secp256k1_ec_pubkey_serialize
  (_secp-fun (out : (_bytes o 65)) (len : (_ptr io _size) = 65) _bytes _uint
             -> _int -> (subbytes out 0 len)))

(define-callout secp256k1_ec_pubkey_tweak_add
  (_secp-fun (pubkey : _bytes) _bytes -> (ok : _bool) -> (and ok pubkey)))

(define-callout secp256k1_ec_pubkey_negate
  (_secp-fun (pubkey : _bytes) -> (ok : _bool) -> (and ok pubkey)))

(define-callout secp256k1_ec_pubkey_combine
  (_secp-fun (out : (_bytes o 64)) (ins : (_list i _bytes)) (_size = (length ins))
             -> (ok : _bool) -> (and ok out)))

(define-callout secp256k1_ecdsa_sign
  (_secp-fun (sig : (_bytes o 64)) _bytes _bytes (_pointer = #f) (_pointer = #f)
             -> (ok : _bool) -> (and ok sig)))

(define-callout secp256k1_ecdsa_verify
  (_secp-fun _bytes _bytes _bytes -> _bool))

(define-callout secp256k1_ecdsa_signature_parse_compact
  (_secp-fun (sig : (_bytes o 64)) _bytes -> (ok : _bool) -> (and ok sig)))

(define-callout secp256k1_ecdsa_signature_serialize_compact
  (_secp-fun (out : (_bytes o 64)) _bytes -> _int -> out))

(define-callout secp256k1_ecdsa_signature_parse_der
  (_secp-fun (sig : (_bytes o 64)) (input : _bytes) (_size = (bytes-length input))
             -> (ok : _bool) -> (and ok sig)))

(define-callout secp256k1_ecdsa_signature_serialize_der
  (_secp-fun (out : (_bytes o 72)) (len : (_ptr io _size) = 72) _bytes
             -> (ok : _bool) -> (and ok (subbytes out 0 len))))

(define-callout secp256k1_ecdsa_sign_recoverable
  (_secp-fun (sig : (_bytes o 65)) _bytes _bytes (_pointer = #f) (_pointer = #f)
             -> (ok : _bool) -> (and ok sig)))

(define-callout secp256k1_ecdsa_recoverable_signature_parse_compact
  (_secp-fun (sig : (_bytes o 65)) _bytes _int -> (ok : _bool) -> (and ok sig)))

(define-callout secp256k1_ecdsa_recoverable_signature_serialize_compact
  (_secp-fun (out : (_bytes o 64)) (id : (_ptr o _int)) _bytes -> _int -> (values out id)))

(define-callout secp256k1_ecdsa_recover
  (_secp-fun (pubkey : (_bytes o 64)) _bytes _bytes -> (ok : _bool) -> (and ok pubkey)))
