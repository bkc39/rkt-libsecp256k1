#lang racket/base

(require (for-syntax racket/base)
         racket/runtime-path)

(provide bundled-library
         library-file-name
         locate-library
         missing-reason
         missing-symbols
         native-build-dir
         native-library-path
         open-candidate
         required-symbols
         system-candidates
         (struct-out candidate))

(define library-file-name
  (string-append "libsecp256k1" (bytes->string/utf-8 (system-type 'so-suffix))))

(define (native-build-dir root)
  (build-path root "native" "build" (system-library-subpath #f)))

(define (native-library-path root)
  (build-path (native-build-dir root) library-file-name))

(define-runtime-path bundled-library
  (build-path 'up "native" "build" (system-library-subpath #f)
              (string-append "libsecp256k1" (bytes->string/utf-8 (system-type 'so-suffix)))))

(define required-symbols '())

(struct candidate (origin label open))

(define system-candidates '())

(define (missing-symbols _lib) (error 'unimplemented))
(define (missing-reason _missing) (error 'unimplemented))
(define (open-candidate _c) (error 'unimplemented))
(define (locate-library _setting) (error 'unimplemented))
