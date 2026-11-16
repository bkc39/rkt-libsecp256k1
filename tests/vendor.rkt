#lang racket/base

(module+ test
  (require (only-in file/sha1 bytes->hex-string)
           racket/file
           racket/list
           (only-in racket/path file-name-from-path find-relative-path simple-form-path)
           racket/runtime-path
           racket/string
           rackunit
           (file "../native/vendor.rkt")
           "vectors.rkt")

  (define-runtime-path vendored-dir "../native/secp256k1")

  (define manifest (file->value (build-path vendored-dir "MANIFEST.rktd")))

  (define (field name)
    (cadr (assq name manifest)))

  (define manifest-files (cdr (assq 'files manifest)))

  (define (file-sha256 path)
    (bytes->hex-string (call-with-input-file path sha256-bytes)))

  (define (relative-files dir)
    (for/list ([p (in-directory dir)]
               #:when (file-exists? p))
      (path->string (find-relative-path (simple-form-path dir) (simple-form-path p)))))

  (test-case "the vendored sources are libsecp256k1 0.8.0 from the pinned tarball"
    (check-equal? (field 'version) "0.8.0")
    (check-equal? (field 'upstream) "https://github.com/bitcoin-core/secp256k1")
    (check-equal? (field 'tarball)
                  "https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.8.0.tar.gz")
    (check-equal? (field 'tarball-sha256)
                  "eb52b0e9239dff7dc26be5f9623567141b8720ec47da29eb3c1e0a660d17c8bb"))

  (test-case "every vendored file matches its manifest hash"
    (check-equal? (length manifest-files) 56)
    (for ([row (in-list manifest-files)])
      (check-equal? (file-sha256 (build-path vendored-dir (car row))) (cadr row) (car row)))
    (check-equal? (cadr (assoc "COPYING" manifest-files))
                  "a735999c7e5649df6fcda6fb06ab97435851c392b1b93494ae8725f37441632f"))

  (test-case "the vendored directory holds exactly the manifest's files"
    (check-equal? (sort (relative-files vendored-dir) string<?)
                  (sort (cons "MANIFEST.rktd" (map car manifest-files)) string<?))
    (check-equal? (sort vendored-paths string<?) (sort (map car manifest-files) string<?)))

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
