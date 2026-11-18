#lang racket/base

(module+ test
  (require (only-in file/sha1 bytes->hex-string)
           (only-in racket/list range)
           (only-in racket/port with-output-to-bytes with-output-to-string)
           racket/runtime-path
           (only-in racket/string string-contains? string-split)
           rackunit
           libsecp256k1
           (only-in "helpers/util.rkt" example-key-integer integer->bytes32))

  (define-runtime-path examples-dir "../examples")
  (define-runtime-path example-tests-dir "examples")

  (define (example-number name)
    (string->number (substring name 0 2)))

  (define (example-names dir)
    (sort (for/list ([p (in-list (directory-list dir))]
                     #:when (regexp-match? #px"^[0-9]{2}-.*[.]rkt$" (path->string p)))
            (path->string p))
          string<?))

  (define examples (example-names examples-dir))

  (define (example-path name)
    `(file ,(path->string (build-path examples-dir name))))

  (define (run-main name)
    (with-output-to-string
      (lambda ()
        (parameterize ([current-namespace (make-base-namespace)])
          (dynamic-require `(submod ,(example-path name) main) #f)))))

  (define (run-with-example-key name)
    (with-output-to-bytes
      (lambda ()
        ((dynamic-require (example-path name) 'run) (integer->secret-key example-key-integer)))))

  (define (secret-key-forms v)
    (define bs (integer->bytes32 v))
    (list (bytes->hex-string bs) (number->string v) (format "~s" bs) (bytes->string/latin-1 bs)))

  (define (leaked-forms v out)
    (define text (string-downcase (bytes->string/latin-1 out)))
    (for/list ([form (in-list (secret-key-forms v))]
               #:when (string-contains? text (string-downcase form)))
      form))

  (define example-hex (bytes->hex-string (integer->bytes32 example-key-integer)))

  (test-case "examples are numbered 00, 01, ... without gaps"
    (check-equal? (map example-number examples) (range (length examples)))
    (check-true (>= (length examples) 5)))

  (test-case "every example has its test file, and every test file its example"
    (check-equal? (example-names example-tests-dir) examples))

  (test-case "the leak scan finds a secret key's hex in any case, run into other hex"
    (check-equal? (leaked-forms example-key-integer
                                (string->bytes/latin-1
                                 (string-append "04" (string-upcase example-hex) "ab")))
                  (list example-hex)))

  (test-case "the leak scan finds a secret key printed in decimal"
    (check-equal? (leaked-forms example-key-integer
                                (string->bytes/latin-1 (format "key=~a." example-key-integer)))
                  (list (number->string example-key-integer))))

  (test-case "the leak scan finds a secret key's bytes, written or displayed"
    (define bs (integer->bytes32 example-key-integer))
    (check-equal? (leaked-forms example-key-integer (string->bytes/latin-1 (format "(~s)" bs)))
                  (list (format "~s" bs)))
    (check-equal? (leaked-forms example-key-integer (bytes-append #"\n" bs #"\n"))
                  (list (bytes->string/latin-1 bs))))

  (test-case "the leak scan passes a public key, a signature and another key"
    (define key (integer->secret-key example-key-integer))
    (define out
      (bytes-append (public-key->bytes (secret-key->public-key key) #:compressed? #f)
                    (ecdsa-signature->compact (ecdsa-sign (make-bytes 32 7) key))
                    (string->bytes/latin-1
                     (format "~a ~a" (- example-key-integer 1)
                             (bytes->hex-string (integer->bytes32 (+ example-key-integer 1)))))))
    (check-equal? (leaked-forms example-key-integer out) '()))

  (for ([name (in-list examples)])
    (test-case (format "~a holds only its program: no test submodule" name)
      (check-false (module-declared? `(submod ,(example-path name) test) #t)))
    (test-case (format "~a's run prints no form of the secret key it is given" name)
      (check-equal? (leaked-forms example-key-integer (run-with-example-key name)) '()))
    (test-case (format "~a's main runs and prints as many lines as run" name)
      (check-equal? (length (string-split (run-main name) "\n"))
                    (length (string-split (bytes->string/latin-1 (run-with-example-key name))
                                          "\n"))))))
