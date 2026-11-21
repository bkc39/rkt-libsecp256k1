#lang info
(define collection "libsecp256k1")
(define deps '(("base" #:version "8.8")))
(define build-deps '("racket-doc" "rackunit-lib" "scribble-lib"))
(define scribblings '(("scribblings/libsecp256k1.scrbl" () (library))))
(define pkg-desc
  (string-append "FFI bindings to Bitcoin Core's libsecp256k1: secp256k1 keys and ECDSA "
                 "signatures with public key recovery"))
(define version "0.1.1")
(define pkg-authors '(bkc))
(define license '((Apache-2.0 OR MIT) AND MIT))
(define pre-install-collection "private/install.rkt")
(define compile-omit-paths '("result" ".direnv" "native" "native-libs" "scripts"))
(define test-omit-paths '("result" ".direnv" "native" "native-libs" "scripts" "tests/helpers"))
