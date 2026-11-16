#lang racket/base

(module+ test
  (require racket/file
           racket/list
           (only-in racket/path file-name-from-path)
           racket/runtime-path
           racket/string
           rackunit
           "helpers/modules.rkt")

  (define-runtime-path package-root "..")

  (define (source-files)
    (for/list ([p (in-directory package-root
                                (lambda (dir)
                                  (not (member (path->string (file-name-from-path dir))
                                               '("compiled" ".git" "build" ".direnv" "doc")))))]
               #:when (regexp-match? #rx"[.](rkt|scrbl)$" (path->string p)))
      p))

  (define forbidden
    (list (string-append "define-syntax" "-rule")
          (string-append "(" "malloc ")
          (string-append "(" "free ")
          (string-append "register" "-finalizer")))

  (test-case "no source defines macros with syntax-rules shorthand or manages native memory"
    (check-true (> (length (source-files)) 20))
    (for* ([p (in-list (source-files))]
           [text (in-value (file->string p))]
           [word (in-list forbidden)])
      (check-false (string-contains? text word) (format "~a contains ~a" p word))))

  (define (closure-names root)
    (filter values (map module-name (import-closure root))))

  (test-case "the library does not load the C toolchain"
    (check-false (findf (lambda (name) (string-prefix? name "dynext/"))
                        (closure-names 'libsecp256k1))))

  (test-case "the pre-installer does not load the library it builds"
    (define names (closure-names 'libsecp256k1/private/install))
    (for ([m (in-list '("libsecp256k1/main" "libsecp256k1/private/ffi"
                        "libsecp256k1/private/keys" "libsecp256k1/private/ecdsa"))])
      (check-false (member m names) m)))

  (test-case "the exception module requires only racket/base"
    (check-equal? (remove-duplicates
                   (filter values (map module-name (direct-imports
                                                    (module-path-index-resolve
                                                     (module-path-index-join
                                                      'libsecp256k1/private/exn #f))))))
                  '("racket/base"))))
