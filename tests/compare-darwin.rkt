#lang racket/base

(module+ test
  (require racket/file
           racket/port
           racket/runtime-path
           racket/system
           rackunit
           (only-in libsecp256k1/private/locate with-temporary-directory)
           "../scripts/compare-darwin.rkt")

  (define-runtime-path package-root "..")

  (define script (build-path package-root "scripts" "compare-darwin.rkt"))

  (define committed
    (file->bytes (build-path package-root "native-libs" "candidates" "darwin"
                             "libsecp256k1.dylib")))

  (define (u32 bs offset)
    (integer-bytes->integer bs #f #f offset (+ offset 4)))

  (define (u64 bs offset)
    (integer-bytes->integer bs #f #f offset (+ offset 8)))

  (define (command-offset bs cmd)
    (cdr (assv cmd (load-commands bs))))

  (define (text-segment bs)
    (for/first ([command (in-list (load-commands bs))]
                #:when (and (= (car command) #x19)
                            (equal? (subbytes bs (+ (cdr command) 8) (+ (cdr command) 15))
                                    #"__TEXT\0")))
      (define offset (cdr command))
      (cons (u64 bs (+ offset 40)) (u64 bs (+ offset 48)))))

  (define (altered bs offset)
    (define copy (bytes-copy bs))
    (bytes-set! copy offset (bitwise-xor (bytes-ref copy offset) #xff))
    copy)

  (define uuid-offset (+ (command-offset committed #x1b) 8))

  (define signature-offset (u32 committed (+ (command-offset committed #x1d) 8)))

  (define text-byte
    (let ([segment (text-segment committed)])
      (+ (car segment) (quotient (cdr segment) 2))))

  (define (compare a b)
    (with-temporary-directory dir
      (define a-path (build-path dir "a.dylib"))
      (define b-path (build-path dir "b.dylib"))
      (call-with-output-file a-path (lambda (out) (write-bytes a out)))
      (call-with-output-file b-path (lambda (out) (write-bytes b out)))
      (define racket (find-system-path 'exec-file))
      (parameterize ([current-error-port (open-output-nowhere)]
                     [current-output-port (open-output-nowhere)])
        (system* (if (absolute-path? racket) racket (find-executable-path racket))
                 script a-path b-path))))

  (test-case "builds that differ only in their LC_UUID bytes compare equal"
    (define other (bytes-copy committed))
    (bytes-copy! other uuid-offset (make-bytes 16 #xab))
    (check-not-equal? other committed)
    (check-equal? (normalised-macho other) (normalised-macho committed))
    (check-true (compare committed other)))

  (test-case "builds that differ only in their code signature compare equal"
    (define other (altered committed (+ signature-offset 100)))
    (check-equal? (normalised-macho other) (normalised-macho committed))
    (check-true (compare committed other)))

  (test-case "builds that differ in one __TEXT byte compare different"
    (check-true (< (+ uuid-offset 16) text-byte signature-offset))
    (define other (altered committed text-byte))
    (check-not-equal? (normalised-macho other) (normalised-macho committed))
    (check-false (compare committed other)))

  (test-case "builds of different sizes compare different"
    (check-false (compare committed (bytes-append committed #"\0"))))

  (test-case "a file that is not a 64-bit Mach-O is refused"
    (check-exn #rx"not a 64-bit little-endian Mach-O file"
               (lambda () (normalised-macho #"\177ELF and more bytes than a header needs"))))

  (test-case "normalising leaves the original untouched"
    (define copy (bytes-copy committed))
    (normalised-macho copy)
    (check-equal? copy committed)))
