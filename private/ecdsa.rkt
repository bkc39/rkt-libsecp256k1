#lang racket/base

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

(struct ecdsa-signature (r s))

(struct ecdsa-recoverable-signature ecdsa-signature (recovery-id))

(define (ecdsa-sign _digest _key) (error 'unimplemented))
(define (ecdsa-sign-recoverable _digest _key) (error 'unimplemented))
(define (ecdsa-verify _sig _digest _key) (error 'unimplemented))
(define (ecdsa-recover _sig _digest) (error 'unimplemented))
(define (ecdsa-signature-low-s? _sig) (error 'unimplemented))
(define (ecdsa-signature-normalize _sig) (error 'unimplemented))
(define (ecdsa-signature->compact _sig) (error 'unimplemented))
(define (compact->ecdsa-signature _compact #:recovery-id [_id #f]) (error 'unimplemented))
(define (ecdsa-signature->der _sig) (error 'unimplemented))
(define (der->ecdsa-signature _der) (error 'unimplemented))
