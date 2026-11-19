#lang racket/base

(provide (struct-out exn:fail:libsecp256k1)
         (struct-out exn:fail:libsecp256k1:load)
         (struct-out exn:fail:libsecp256k1:key)
         (struct-out exn:fail:libsecp256k1:signature)
         (struct-out exn:fail:libsecp256k1:illegal-argument)
         (struct-out exn:fail:libsecp256k1:internal))

(struct exn:fail:libsecp256k1 exn:fail ())
(struct exn:fail:libsecp256k1:load exn:fail:libsecp256k1 ())
(struct exn:fail:libsecp256k1:key exn:fail:libsecp256k1 ())
(struct exn:fail:libsecp256k1:signature exn:fail:libsecp256k1 ())
(struct exn:fail:libsecp256k1:illegal-argument exn:fail:libsecp256k1 ())
(struct exn:fail:libsecp256k1:internal exn:fail:libsecp256k1 ())
