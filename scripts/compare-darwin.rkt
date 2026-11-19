#lang racket/base

;; Compare two builds of the darwin candidate apart from what ld64 and codesign vary between
;; otherwise identical links: the LC_UUID bytes and the code-signature blob.
;;
;; Usage: racket scripts/compare-darwin.rkt <committed.dylib> <fresh.dylib>

(require (only-in racket/file file->bytes))

(provide load-commands
         normalised-macho)

(define mh-magic-64 #xfeedfacf)
(define lc-uuid #x1b)
(define lc-code-signature #x1d)

(define (u32 bs offset)
  (integer-bytes->integer bs #f #f offset (+ offset 4)))

(define (load-commands bs)
  (unless (and (>= (bytes-length bs) 32) (= (u32 bs 0) mh-magic-64))
    (error 'compare-darwin "not a 64-bit little-endian Mach-O file"))
  (define end (+ 32 (u32 bs 20)))
  (unless (<= end (bytes-length bs))
    (error 'compare-darwin "load commands run past the end of the file"))
  (let loop ([offset 32] [left (u32 bs 16)] [found '()])
    (cond
      [(zero? left) (reverse found)]
      [(> (+ offset 8) end) (error 'compare-darwin "truncated load command at ~a" offset)]
      [else
       (define size (u32 bs (+ offset 4)))
       (when (or (< size 8) (> (+ offset size) end))
         (error 'compare-darwin "load command at ~a has size ~a" offset size))
       (loop (+ offset size) (sub1 left) (cons (cons (u32 bs offset) offset) found))])))

(define (zero! bs start len)
  (unless (<= (+ start len) (bytes-length bs))
    (error 'compare-darwin "region ~a+~a runs past the end of the file" start len))
  (bytes-copy! bs start (make-bytes len 0)))

(define (normalised-macho original)
  (define bs (bytes-copy original))
  (for ([command (in-list (load-commands bs))])
    (define offset (cdr command))
    (cond
      [(= (car command) lc-uuid) (zero! bs (+ offset 8) 16)]
      [(= (car command) lc-code-signature)
       (zero! bs (u32 bs (+ offset 8)) (u32 bs (+ offset 12)))]
      [else (void)]))
  bs)

(define (first-difference a b)
  (for/first ([x (in-bytes a)] [y (in-bytes b)] [i (in-naturals)] #:unless (= x y))
    i))

(module+ main
  (require (only-in racket/cmdline command-line))
  (command-line
   #:args (committed fresh)
   (define a (normalised-macho (file->bytes committed)))
   (define b (normalised-macho (file->bytes fresh)))
   (cond
     [(not (= (bytes-length a) (bytes-length b)))
      (eprintf "~a is ~a bytes, ~a is ~a\n" committed (bytes-length a) fresh (bytes-length b))
      (exit 1)]
     [(first-difference a b)
      => (lambda (offset)
           (eprintf "~a and ~a differ at byte ~a beyond LC_UUID and the code signature\n"
                    committed fresh offset)
           (exit 1))]
     [else
      (printf "~a and ~a are the same apart from LC_UUID and the code signature\n"
              committed fresh)])))
