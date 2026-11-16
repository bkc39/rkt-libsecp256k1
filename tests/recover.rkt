#lang racket/base

(module+ test
  (require racket/list
           rackunit
           libsecp256k1
           "util.rkt")

  (define (random-pair rng)
    (values (bytes->secret-key (random-secret-bytes rng)) (random-digest rng)))

  (test-seeded "recovery gives the signer's public key" #:seed (131 132 133 134 135 136) rng
    (for ([_ (in-range 500)])
      (define-values (key digest) (random-pair rng))
      (check-equal? (ecdsa-recover (ecdsa-sign-recoverable digest key) digest)
                    (secret-key->public-key key))))

  (test-seeded "recoverable and plain signatures share r and s" #:seed (141 142 143 144 145 146) rng
    (for ([_ (in-range 200)])
      (define-values (key digest) (random-pair rng))
      (define sig (ecdsa-sign digest key))
      (define rsig (ecdsa-sign-recoverable digest key))
      (check-equal? (ecdsa-signature-r rsig) (ecdsa-signature-r sig))
      (check-equal? (ecdsa-signature-s rsig) (ecdsa-signature-s sig))))

  (test-seeded "recovery with another digest does not give the signer" #:seed (151 152 153 154 155 156)
    rng
    (for ([_ (in-range 200)])
      (define-values (key digest) (random-pair rng))
      (define recovered (ecdsa-recover (ecdsa-sign-recoverable digest key) (random-digest rng)))
      (check-not-equal? recovered (secret-key->public-key key))))

  (test-seeded "produced recovery ids are 0 or 1, and both occur" #:seed (161 162 163 164 165 166) rng
    (define ids
      (for/list ([_ (in-range 500)])
        (define-values (key digest) (random-pair rng))
        (ecdsa-recoverable-signature-recovery-id (ecdsa-sign-recoverable digest key))))
    (check-equal? (sort (remove-duplicates ids) <) '(0 1)))

  (test-case "an r that is no x-coordinate recovers nothing"
    (check-false (quadratic-residue? (modulo (+ (expt non-residue-x 3) 7) field-prime)))
    (define digest (make-bytes 32 3))
    (for ([id (in-list '(0 1))])
      (check-false (ecdsa-recover (ecdsa-recoverable-signature non-residue-x 1 id) digest))))

  (test-case "ids 2 and 3 with r + n >= p recover nothing"
    (define digest (make-bytes 32 3))
    (for* ([r (list (- field-prime n) (- n 1))]
           [id (in-list '(2 3))])
      (check-false (ecdsa-recover (ecdsa-recoverable-signature r 1 id) digest))))

  (test-case "zero r or s recovers nothing"
    (define digest (make-bytes 32 3))
    (for* ([rs (list '(0 1) '(1 0) '(0 0))]
           [id (in-list '(0 1 2 3))])
      (check-false (ecdsa-recover (ecdsa-recoverable-signature (car rs) (cadr rs) id) digest)))))
