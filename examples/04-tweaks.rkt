#lang racket/base

(require file/sha1
         libsecp256k1)

(provide child-public-key
         child-secret-key
         child-tweak
         public-key->hex
         run)

(define (child-tweak parent index)
  (sha256-bytes (bytes-append (public-key->bytes parent)
                              (integer->integer-bytes index 4 #f #t))))

(define (child-secret-key parent index)
  (secret-key-tweak-add parent (child-tweak (secret-key->public-key parent) index)))

(define (child-public-key parent index)
  (public-key-tweak-add parent (child-tweak parent index)))

(define (public-key->hex key)
  (bytes->hex-string (public-key->bytes key)))

(define (run parent)
  (define parent-public (secret-key->public-key parent))
  (printf "parent public key: ~a\n" (public-key->hex parent-public))
  (for ([index (in-range 3)])
    (printf "child ~a public key: ~a\n"
            index
            (public-key->hex (child-public-key parent-public index))))
  (printf "child secret keys match: ~a\n"
          (for/and ([index (in-range 3)])
            (equal? (secret-key->public-key (child-secret-key parent index))
                    (child-public-key parent-public index)))))

(module+ main
  (run (generate-secret-key)))
