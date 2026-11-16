#lang racket/base

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

(define SECP256K1_EC_COMPRESSED #x102)
(define SECP256K1_EC_UNCOMPRESSED #x2)

(define (unimplemented . _) (error 'unimplemented))

(define error-callback unimplemented)
(define illegal-callback unimplemented)
(define libsecp256k1-origin unimplemented)
(define secp256k1_ec_pubkey_combine unimplemented)
(define secp256k1_ec_pubkey_create unimplemented)
(define secp256k1_ec_pubkey_negate unimplemented)
(define secp256k1_ec_pubkey_parse unimplemented)
(define secp256k1_ec_pubkey_serialize unimplemented)
(define secp256k1_ec_pubkey_tweak_add unimplemented)
(define secp256k1_ec_seckey_negate unimplemented)
(define secp256k1_ec_seckey_tweak_add unimplemented)
(define secp256k1_ec_seckey_verify unimplemented)
(define secp256k1_ecdsa_recover unimplemented)
(define secp256k1_ecdsa_recoverable_signature_parse_compact unimplemented)
(define secp256k1_ecdsa_recoverable_signature_serialize_compact unimplemented)
(define secp256k1_ecdsa_sign unimplemented)
(define secp256k1_ecdsa_sign_recoverable unimplemented)
(define secp256k1_ecdsa_signature_parse_compact unimplemented)
(define secp256k1_ecdsa_signature_parse_der unimplemented)
(define secp256k1_ecdsa_signature_serialize_compact unimplemented)
(define secp256k1_ecdsa_signature_serialize_der unimplemented)
(define secp256k1_ecdsa_verify unimplemented)
