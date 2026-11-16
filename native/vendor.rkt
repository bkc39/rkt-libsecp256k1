#lang racket/base

;; Maintainer tool: extracts the vendored subset of a libsecp256k1 release
;; tarball into native/secp256k1/ and rewrites its MANIFEST.rktd.
;;
;;   racket native/vendor.rkt secp256k1-0.8.0.tar.gz 0.8.0

(require (only-in file/sha1 bytes->hex-string)
         (only-in file/untgz untgz)
         (only-in racket/file delete-directory/files make-directory*)
         (only-in racket/list rest)
         racket/runtime-path)

(provide vendored-paths
         vendor!)

(define-runtime-path vendored-dir "secp256k1")

(define upstream "https://github.com/bitcoin-core/secp256k1")

(define vendored-paths
  '("COPYING"
    "include/secp256k1.h" "include/secp256k1_preallocated.h" "include/secp256k1_recovery.h"
    "src/secp256k1.c" "src/precomputed_ecmult.c" "src/precomputed_ecmult_gen.c"
    "src/assumptions.h" "src/checkmem.h" "src/ecdsa.h" "src/ecdsa_impl.h" "src/eckey.h"
    "src/eckey_impl.h" "src/ecmult.h" "src/ecmult_impl.h" "src/ecmult_const.h"
    "src/ecmult_const_impl.h" "src/ecmult_gen.h" "src/ecmult_gen_impl.h" "src/field.h"
    "src/field_impl.h" "src/field_10x26.h" "src/field_10x26_impl.h" "src/field_5x52.h"
    "src/field_5x52_impl.h" "src/field_5x52_int128_impl.h" "src/group.h" "src/group_impl.h"
    "src/hash.h" "src/hash_impl.h" "src/hsort.h" "src/hsort_impl.h" "src/int128.h"
    "src/int128_impl.h" "src/int128_native.h" "src/int128_native_impl.h" "src/int128_struct.h"
    "src/int128_struct_impl.h" "src/modinv32.h" "src/modinv32_impl.h" "src/modinv64.h"
    "src/modinv64_impl.h" "src/modules/recovery/main_impl.h" "src/precomputed_ecmult.h"
    "src/precomputed_ecmult_gen.h" "src/scalar.h" "src/scalar_impl.h" "src/scalar_4x64.h"
    "src/scalar_4x64_impl.h" "src/scalar_8x32.h" "src/scalar_8x32_impl.h" "src/scratch.h"
    "src/scratch_impl.h" "src/selftest.h" "src/util.h" "src/util_local_visibility.h"))

(define (file-sha256 path)
  (bytes->hex-string (call-with-input-file path sha256-bytes)))

(define (archive-relative name)
  (define parts (rest (explode-path (if (path? name) name (bytes->path name)))))
  (and (pair? parts) (path->string (apply build-path parts))))

(define (vendor! tarball version #:into [dir vendored-dir])
  (when (directory-exists? dir)
    (delete-directory/files dir))
  (make-directory* dir)
  (parameterize ([current-directory dir])
    (untgz tarball
           #:strip-count 1
           #:filter (lambda (name _unpacked type _size _target _time _mode)
                      (and (eq? type 'file)
                           (member (archive-relative name) vendored-paths)
                           #t))))
  (define missing
    (for/list ([p (in-list vendored-paths)]
               #:unless (file-exists? (build-path dir p)))
      p))
  (unless (null? missing)
    (error 'vendor! "the tarball lacks ~s" missing))
  (call-with-output-file (build-path dir "MANIFEST.rktd")
    (lambda (out)
      (fprintf out "((upstream ~s)\n" upstream)
      (fprintf out " (version ~s)\n" version)
      (fprintf out " (tarball ~s)\n" (format "~a/archive/refs/tags/v~a.tar.gz" upstream version))
      (fprintf out " (tarball-sha256 ~s)\n" (file-sha256 tarball))
      (fprintf out " (files")
      (for ([p (in-list (sort vendored-paths string<?))])
        (fprintf out "\n  (~s ~s)" p (file-sha256 (build-path dir p))))
      (fprintf out "))\n"))))

(module+ main
  (require racket/cmdline)
  (command-line
   #:args (tarball version)
   (vendor! tarball version)))
