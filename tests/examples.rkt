#lang racket/base

(module+ test
  (require file/sha1
           racket/list
           racket/port
           racket/runtime-path
           rackunit
           libsecp256k1)

  (define-runtime-path examples-dir "../examples")

  (define (example-number name)
    (string->number (cadr (regexp-match #px"^([0-9]{2})-" name))))

  (define example-names
    (sort (for/list ([p (in-list (directory-list examples-dir))]
                     #:when (regexp-match? #px"^[0-9]{2}-.*[.]rkt$" (path->string p)))
            (path->string p))
          string<?))

  (define (example-submodule name submodule)
    `(submod (file ,(path->string (build-path examples-dir name))) ,submodule))

  (define (run-main name)
    (with-output-to-string
      (lambda ()
        (parameterize ([current-namespace (make-base-namespace)])
          (dynamic-require (example-submodule name 'main) #f)))))

  (define (public-key-hex-of window)
    (define k (string->number window 16))
    (and (< 0 k secp256k1-order)
         (bytes->hex-string (public-key->bytes (secret-key->public-key (integer->secret-key k))))))

  (define (printed-secret-keys out)
    (define hex-runs (regexp-match* #px"[0-9a-fA-F]{64,}" out))
    (define x-coordinates (map (lambda (pk) (substring pk 2))
                               (regexp-match* #px"0[23][0-9a-f]{64}" out)))
    (for*/list ([run (in-list hex-runs)]
                [i (in-range (- (string-length run) 63))]
                [window (in-value (string-downcase (substring run i (+ i 64))))]
                [pk (in-value (public-key-hex-of window))]
                #:when (and pk (member (substring pk 2) x-coordinates)))
      window))

  (test-case "examples are numbered 00, 01, ... without gaps"
    (check-equal? (map example-number example-names)
                  (range (length example-names)))
    (check-true (>= (length example-names) 5)))

  (test-case "the secret-key scan finds a secret key printed beside its public key"
    (define key (integer->secret-key 5))
    (define out (format "~a ~a"
                        (bytes->hex-string (secret-key->bytes key))
                        (bytes->hex-string (public-key->bytes (secret-key->public-key key)))))
    (check-equal? (printed-secret-keys out) (list (bytes->hex-string (secret-key->bytes key)))))

  (for ([name (in-list example-names)])
    (test-case (format "~a has a test submodule" name)
      (check-true (module-declared? (example-submodule name 'test) #t)))
    (test-case (format "~a's main prints public keys and no secret key" name)
      (define out (run-main name))
      (check-regexp-match #px"0[23][0-9a-f]{64}" out)
      (check-equal? (printed-secret-keys out) '()))))
