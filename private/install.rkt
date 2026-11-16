#lang racket/base

(require (for-syntax racket/base)
         (only-in racket/file delete-directory/files make-temporary-directory)
         syntax/parse/define)

(provide build-library
         install-native!
         pre-installer
         probe-system
         recipe
         stamp-path
         with-temporary-directory)

(define-syntax-parse-rule (with-temporary-directory dir:id body:expr ...+)
  (let ([dir (make-temporary-directory)])
    (dynamic-wind
     void
     (lambda () body ...)
     (lambda () (delete-directory/files dir #:must-exist? #f)))))

(define (recipe _root) (error 'unimplemented))
(define (stamp-path _root) (error 'unimplemented))
(define (build-library _root _out) (error 'unimplemented))
(define (probe-system) (error 'unimplemented))
(define (install-native! _root #:build _build #:probe _probe) (error 'unimplemented))
(define (pre-installer _collections-top-path _this-collection-path) (error 'unimplemented))
