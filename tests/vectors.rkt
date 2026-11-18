#lang racket/base

(module+ test
  (require (only-in file/sha1 bytes->hex-string)
           racket/file
           racket/list
           racket/string
           rackunit
           "helpers/vectors.rkt")

  (define (file-sha256 path)
    (bytes->hex-string (call-with-input-file path sha256-bytes)))

  (define recorded-vector-hashes
    (for/list ([line (in-list (file->lines (build-path vectors-dir "README")))]
               #:when (regexp-match? #px"^[0-9a-f]{64}  \\S+$" line))
      (define parts (string-split line))
      (cons (second parts) (first parts))))

  (test-case "every vector file matches the hash recorded in its README"
    (check-equal? (length recorded-vector-hashes) 6)
    (for ([row (in-list recorded-vector-hashes)])
      (check-equal? (file-sha256 (build-path vectors-dir (car row))) (cdr row) (car row)))
    (check-equal? (cdr (assoc "wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json"
                              recorded-vector-hashes))
                  "1be8742064fec73d670339f0036dec56b21baa94cb2d8e0fbbb6fb480f733869")))
